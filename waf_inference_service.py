"""
Real-time WAF Inference Sidecar Service
=======================================
FastAPI-based microservice that receives HTTP requests,
processes them through the trained LogBERT model,
and returns anomaly scores in real-time.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
import uvicorn
import torch
import numpy as np
import time
import logging
from collections import deque
import json
from datetime import datetime
import threading
from queue import Queue, Empty
import onnxruntime as ort
from log_parser_normalizer import LogNormalizer, AccessLogParser
from logbert_transformer_model import LogBERTModel, LogTokenizer, ModelConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RequestData(BaseModel):
    """Request data for anomaly detection"""
    ip: str
    method: str
    path: str
    query_params: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    user_agent: str = ""
    timestamp: Optional[str] = None

class AnomalyResponse(BaseModel):
    """Response with anomaly score"""
    request_id: str
    anomaly_score: float
    is_anomalous: bool
    confidence: float
    processing_time_ms: float
    details: Dict[str, any] = {}

class BatchProcessor:
    """Batches requests for efficient model inference"""
    
    def __init__(self, model_service, batch_size=8, max_wait_time=0.01):
        self.model_service = model_service
        self.batch_size = batch_size
        self.max_wait_time = max_wait_time
        self.pending_requests = []
        self.request_queue = Queue()
        self.response_futures = {}
        self.processing = False
        
        # Start batch processing thread
        self.batch_thread = threading.Thread(target=self._batch_processing_loop)
        self.batch_thread.daemon = True
        self.batch_thread.start()
    
    async def process_request(self, request_data: RequestData) -> AnomalyResponse:
        """Add request to batch processing queue"""
        request_id = f"{time.time()}_{id(request_data)}"
        
        # Create future for response
        future = asyncio.Future()
        
        # Add to queue
        self.request_queue.put((request_id, request_data, future))
        
        # Wait for result
        try:
            response = await asyncio.wait_for(future, timeout=5.0)
            return response
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Request processing timeout")
    
    def _batch_processing_loop(self):
        """Background thread for batch processing"""
        while True:
            batch = []
            batch_futures = {}
            
            # Collect batch
            start_time = time.time()
            while len(batch) < self.batch_size and (time.time() - start_time) < self.max_wait_time:
                try:
                    request_id, request_data, future = self.request_queue.get(timeout=0.001)
                    batch.append((request_id, request_data))
                    batch_futures[request_id] = future
                except Empty:
                    continue
            
            # Process batch if we have requests
            if batch:
                try:
                    responses = self.model_service.process_batch([req[1] for req in batch])
                    
                    # Send responses back
                    for i, (request_id, _) in enumerate(batch):
                        if request_id in batch_futures:
                            if not batch_futures[request_id].done():
                                batch_futures[request_id].get_loop().call_soon_threadsafe(
                                    batch_futures[request_id].set_result, responses[i]
                                )
                            
                except Exception as e:
                    logger.error(f"Batch processing error: {e}")
                    # Send error responses
                    for request_id, _ in batch:
                        if request_id in batch_futures and not batch_futures[request_id].done():
                            error_response = AnomalyResponse(
                                request_id=request_id,
                                anomaly_score=0.5,
                                is_anomalous=False,
                                confidence=0.0,
                                processing_time_ms=0.0,
                                details={"error": str(e)}
                            )
                            batch_futures[request_id].get_loop().call_soon_threadsafe(
                                batch_futures[request_id].set_result, error_response
                            )

class ModelInferenceService:
    """Core model inference service"""
    
    def __init__(self, model_path: str, tokenizer_path: str, use_onnx: bool = False):
        self.model_path = model_path
        self.tokenizer_path = tokenizer_path
        self.use_onnx = use_onnx
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Components
        self.model = None
        self.tokenizer = None
        self.normalizer = LogNormalizer()
        self.parser = AccessLogParser()
        
        # Performance tracking
        self.request_count = 0
        self.total_processing_time = 0
        self.anomaly_threshold = 0.7
        
        # Sliding window for sequence context
        self.sequence_window = deque(maxlen=32)
        
        # Load model and tokenizer
        self._load_model()
        
        logger.info(f"Model loaded. Device: {self.device}, ONNX: {use_onnx}")
    
    def _load_model(self):
        """Load model and tokenizer"""
        try:
            # Load tokenizer
            self.tokenizer = LogTokenizer()
            self.tokenizer.load(self.tokenizer_path)
            
            if self.use_onnx:
                # Load ONNX model for faster inference
                self.onnx_session = ort.InferenceSession(self.model_path)
                logger.info("Loaded ONNX model for optimized inference")
            else:
                # Load PyTorch model
                checkpoint = torch.load(self.model_path, map_location=self.device)
                
                config = checkpoint['config']
                self.model = LogBERTModel(config)
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.model.hypersphere_center = checkpoint['hypersphere_center']
                self.model.to(self.device)
                self.model.eval()
                
                logger.info("Loaded PyTorch model")
                
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def _request_to_tokens(self, request: RequestData) -> List[str]:
        """Convert request to normalized tokens"""
        # Create normalized path
        normalized_path = self.normalizer.normalize_path(request.path)
        
        # Normalize query parameters
        normalized_params = self.normalizer.normalize_query_params(request.query_params)
        
        # Create event for feature extraction
        event_data = {
            'method': request.method,
            'path': request.path,
            'query_params': request.query_params,
            'status_code': 200,  # Default, we don't know yet
            'response_size': 0,
            'user_agent': request.user_agent
        }
        
        features = self.normalizer.extract_features(event_data)
        
        # Create token sequence
        tokens = [
            f"<METHOD_{request.method}>",
            f"<PATH_{normalized_path}>",
        ]
        
        # Add parameter tokens
        for key in sorted(normalized_params.keys()):
            tokens.append(f"<PARAM_{key}>")
        
        # Add feature tokens
        if features.get('has_query_params'):
            tokens.append('<HAS_PARAMS>')
        if features.get('contains_sql_keywords'):
            tokens.append('<SQL_PATTERN>')
        if features.get('contains_script_tags'):
            tokens.append('<SCRIPT_PATTERN>')
        if features.get('contains_traversal'):
            tokens.append('<TRAVERSAL_PATTERN>')
        if features.get('contains_admin_paths'):
            tokens.append('<ADMIN_PATTERN>')
        
        return tokens
    
    def process_batch(self, requests: List[RequestData]) -> List[AnomalyResponse]:
        """Process a batch of requests"""
        start_time = time.time()
        responses = []
        
        try:
            # Convert requests to token sequences
            batch_sequences = []
            for request in requests:
                tokens = self._request_to_tokens(request)
                
                # Add to sliding window for context
                self.sequence_window.extend(tokens)
                
                # Use recent context as sequence
                sequence_tokens = list(self.sequence_window)[-32:]  # Last 32 tokens
                batch_sequences.append(sequence_tokens)
            
            # Encode sequences
            encoded_sequences = [self.tokenizer.encode(seq) for seq in batch_sequences]
            
            # Pad sequences to same length
            max_len = min(64, max(len(seq) for seq in encoded_sequences) if encoded_sequences else 64)
            
            input_ids = []
            attention_masks = []
            
            for seq in encoded_sequences:
                # Truncate or pad
                if len(seq) > max_len:
                    seq = seq[:max_len]
                else:
                    seq = seq + [self.tokenizer.pad_token_id] * (max_len - len(seq))
                
                input_ids.append(seq)
                attention_masks.append([1 if token != self.tokenizer.pad_token_id else 0 for token in seq])
            
            # Convert to tensors
            input_ids = torch.tensor(input_ids, dtype=torch.long).to(self.device)
            attention_masks = torch.tensor(attention_masks, dtype=torch.long).to(self.device)
            
            # Run inference
            if self.use_onnx:
                # ONNX inference
                ort_inputs = {
                    'input_ids': input_ids.cpu().numpy(),
                    'attention_mask': attention_masks.cpu().numpy()
                }
                scores = self.onnx_session.run(None, ort_inputs)[0]
                scores = torch.from_numpy(scores)
            else:
                # PyTorch inference
                with torch.no_grad():
                    scores = self.model.compute_anomaly_score(input_ids, attention_masks)
            
            # Create responses
            processing_time = (time.time() - start_time) * 1000  # ms
            
            for i, (request, score) in enumerate(zip(requests, scores)):
                anomaly_score = float(score)
                is_anomalous = anomaly_score > self.anomaly_threshold
                confidence = abs(anomaly_score - 0.5) * 2  # Distance from 0.5, scaled to [0,1]
                
                response = AnomalyResponse(
                    request_id=f"{time.time()}_{i}",
                    anomaly_score=anomaly_score,
                    is_anomalous=is_anomalous,
                    confidence=confidence,
                    processing_time_ms=processing_time / len(requests),
                    details={
                        'tokens_used': batch_sequences[i],
                        'sequence_length': len(batch_sequences[i]),
                        'threshold': self.anomaly_threshold
                    }
                )
                responses.append(response)
            
            # Update metrics
            self.request_count += len(requests)
            self.total_processing_time += processing_time
            
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            
            # Return error responses
            for i, request in enumerate(requests):
                response = AnomalyResponse(
                    request_id=f"error_{time.time()}_{i}",
                    anomaly_score=0.5,
                    is_anomalous=False,
                    confidence=0.0,
                    processing_time_ms=0.0,
                    details={"error": str(e)}
                )
                responses.append(response)
        
        return responses

# Create FastAPI app
app = FastAPI(
    title="WAF Anomaly Detection Service",
    description="Real-time HTTP request anomaly detection using LogBERT",
    version="1.0.0"
)

# Global model service (initialized on startup)
model_service = None
batch_processor = None

@app.on_event("startup")
async def startup_event():
    """Initialize model service on startup"""
    global model_service, batch_processor
    
    try:
        # Initialize model service
        model_service = ModelInferenceService(
            model_path="./models/logbert_model.pt",
            tokenizer_path="./models/tokenizer.pkl",
            use_onnx=False  # Set to True for ONNX inference
        )
        
        # Initialize batch processor
        batch_processor = BatchProcessor(model_service, batch_size=8, max_wait_time=0.01)
        
        logger.info("WAF service initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize service: {e}")
        raise

@app.post("/detect", response_model=AnomalyResponse)
async def detect_anomaly(request: RequestData):
    """Detect anomaly in HTTP request"""
    if not batch_processor:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        response = await batch_processor.process_request(request)
        return response
        
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/detect/batch", response_model=List[AnomalyResponse])
async def detect_batch_anomalies(requests: List[RequestData]):
    """Detect anomalies in batch of requests"""
    if not model_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        responses = model_service.process_batch(requests)
        return responses
        
    except Exception as e:
        logger.error(f"Batch detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": model_service is not None,
        "device": str(model_service.device) if model_service else "unknown",
        "requests_processed": model_service.request_count if model_service else 0,
        "avg_processing_time_ms": (
            model_service.total_processing_time / model_service.request_count 
            if model_service and model_service.request_count > 0 else 0
        )
    }

@app.get("/metrics")
async def get_metrics():
    """Get service metrics"""
    if not model_service:
        return {"error": "Service not initialized"}
    
    return {
        "requests_processed": model_service.request_count,
        "total_processing_time_ms": model_service.total_processing_time,
        "avg_processing_time_ms": (
            model_service.total_processing_time / model_service.request_count
            if model_service.request_count > 0 else 0
        ),
        "anomaly_threshold": model_service.anomaly_threshold,
        "sequence_window_size": len(model_service.sequence_window),
        "device": str(model_service.device)
    }

@app.post("/update_threshold")
async def update_threshold(threshold: float):
    """Update anomaly detection threshold"""
    if not model_service:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    if not 0.0 <= threshold <= 1.0:
        raise HTTPException(status_code=400, detail="Threshold must be between 0.0 and 1.0")
    
    old_threshold = model_service.anomaly_threshold
    model_service.anomaly_threshold = threshold
    
    return {
        "message": "Threshold updated",
        "old_threshold": old_threshold,
        "new_threshold": threshold
    }

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "WAF Anomaly Detection",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "detect": "POST /detect - Single request detection",
            "batch": "POST /detect/batch - Batch request detection", 
            "health": "GET /health - Health check",
            "metrics": "GET /metrics - Service metrics"
        }
    }

if __name__ == "__main__":
    # Run the service
    uvicorn.run(
        "waf_inference_service:app",
        host="0.0.0.0",
        port=8000,
        workers=1,  # Single worker to maintain model state
        log_level="info"
    )
