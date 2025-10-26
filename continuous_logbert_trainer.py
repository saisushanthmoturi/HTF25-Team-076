#!/usr/bin/env python3
"""
Continuous LogBERT Trainer for Transformer WAF
Trains LogBERT model continuously on live benign traffic logs
"""

import json
import time
import logging
import threading
import asyncio
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque
import queue
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
import numpy as np
from typing import Dict, List, Optional, Tuple
import sys

# Import WAF components
from logbert_transformer_model import LogBERTModel, LogBERTConfig
from log_parser_normalizer import LogParserNormalizer
from incremental_lora_learning import LoRAIncrementalLearner

class LogDataset(Dataset):
    """Dataset for LogBERT training"""
    
    def __init__(self, log_entries: List[Dict], tokenizer, max_length: int = 512):
        self.log_entries = log_entries
        self.tokenizer = tokenizer
        self.max_length = max_length
        
    def __len__(self):
        return len(self.log_entries)
        
    def __getitem__(self, idx):
        log_entry = self.log_entries[idx]
        
        # Extract sequence from log entry
        sequence = self.create_sequence(log_entry)
        
        # Tokenize
        tokens = self.tokenizer.encode(sequence, max_length=self.max_length)
        
        return {
            'input_ids': torch.tensor(tokens, dtype=torch.long),
            'labels': torch.tensor(tokens, dtype=torch.long),  # For MLM
            'log_entry': log_entry
        }
        
    def create_sequence(self, log_entry: Dict) -> str:
        """Create sequence from log entry for training"""
        parts = [
            log_entry.get('method', ''),
            log_entry.get('uri', ''),
            log_entry.get('template', ''),
            str(log_entry.get('status', '')),
            log_entry.get('user_agent', '')[:100]  # Truncate user agent
        ]
        
        return ' '.join(part for part in parts if part)

class ContinuousTrainer:
    """Continuous LogBERT trainer for live logs"""
    
    def __init__(self,
                 model_path: str = "models/logbert_model.pth",
                 config_path: str = "models/logbert_config.json",
                 vocab_path: str = "models/vocab.json"):
        
        self.model_path = Path(model_path)
        self.config_path = Path(config_path)
        self.vocab_path = Path(vocab_path)
        
        # Training configuration
        self.batch_size = 16
        self.learning_rate = 1e-5
        self.accumulation_steps = 4
        self.max_sequence_length = 512
        self.training_interval = 300  # 5 minutes
        self.min_training_samples = 100
        self.max_training_samples = 1000
        
        # Data management
        self.training_queue = queue.Queue(maxsize=10000)
        self.training_buffer = deque(maxlen=self.max_training_samples)
        
        # Model components
        self.model = None
        self.tokenizer = None
        self.lora_learner = None
        self.log_parser = None
        
        # Training state
        self.training_stats = {
            'total_samples_trained': 0,
            'training_iterations': 0,
            'last_training_time': None,
            'current_loss': 0.0,
            'learning_rate': self.learning_rate
        }
        
        # Threading
        self.training_thread = None
        self.data_collection_thread = None
        self.running = False
        
        # Device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging for continuous trainer"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('logs/continuous_trainer.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('ContinuousTrainer')
        
    async def initialize(self):
        """Initialize the continuous trainer"""
        self.logger.info("Initializing Continuous LogBERT Trainer...")
        
        # Create directories
        Path("models").mkdir(exist_ok=True)
        Path("logs").mkdir(exist_ok=True)
        
        # Initialize log parser
        self.log_parser = LogParserNormalizer()
        await self.log_parser.initialize()
        
        # Initialize or load model
        await self.initialize_model()
        
        # Initialize LoRA learner
        self.lora_learner = LoRAIncrementalLearner(
            model=self.model,
            rank=8,
            alpha=16,
            dropout=0.1
        )
        
        self.logger.info("Continuous LogBERT Trainer initialized successfully")
        
    async def initialize_model(self):
        """Initialize or load LogBERT model"""
        try:
            if self.model_path.exists() and self.config_path.exists():
                # Load existing model
                self.logger.info("Loading existing LogBERT model...")
                
                with open(self.config_path, 'r') as f:
                    config_dict = json.load(f)
                    
                config = LogBERTConfig(**config_dict)
                self.model = LogBERTModel(config)
                
                checkpoint = torch.load(self.model_path, map_location=self.device)
                self.model.load_state_dict(checkpoint['model_state_dict'])
                
                # Load tokenizer
                if self.vocab_path.exists():
                    with open(self.vocab_path, 'r') as f:
                        vocab = json.load(f)
                    self.tokenizer = SimpleTokenizer(vocab)
                else:
                    self.tokenizer = SimpleTokenizer()
                    
                # Update training stats
                if 'training_stats' in checkpoint:
                    self.training_stats.update(checkpoint['training_stats'])
                    
            else:
                # Create new model
                self.logger.info("Creating new LogBERT model...")
                
                config = LogBERTConfig(
                    vocab_size=10000,
                    hidden_size=256,
                    num_hidden_layers=6,
                    num_attention_heads=8,
                    intermediate_size=1024,
                    max_position_embeddings=512
                )
                
                self.model = LogBERTModel(config)
                self.tokenizer = SimpleTokenizer()
                
                # Save initial configuration
                with open(self.config_path, 'w') as f:
                    json.dump(config.to_dict(), f, indent=2)
                    
            self.model.to(self.device)
            self.logger.info(f"Model initialized on device: {self.device}")
            
        except Exception as e:
            self.logger.error(f"Error initializing model: {e}")
            raise
            
    def add_training_sample(self, log_entry: Dict):
        """Add a log entry for training"""
        if not self.is_benign_log(log_entry):
            return  # Only train on benign logs
            
        try:
            self.training_queue.put_nowait(log_entry)
        except queue.Full:
            self.logger.warning("Training queue is full, dropping sample")
            
    def is_benign_log(self, log_entry: Dict) -> bool:
        """Determine if a log entry is benign"""
        # Simple heuristics for benign traffic
        status = log_entry.get('status', 0)
        uri = log_entry.get('uri', '')
        method = log_entry.get('method', '')
        
        # Filter out obvious attack patterns
        suspicious_patterns = [
            'sql', 'script', 'alert', 'eval', 'exec',
            '../', '..\\', 'cmd', 'shell', 'union',
            'select', 'drop', 'insert', 'update', 'delete'
        ]
        
        uri_lower = uri.lower()
        if any(pattern in uri_lower for pattern in suspicious_patterns):
            return False
            
        # Accept common benign status codes
        if status in [200, 201, 301, 302, 304, 404]:
            return True
            
        # Accept common HTTP methods
        if method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']:
            return True
            
        return False
        
    async def start(self):
        """Start continuous training"""
        self.logger.info("Starting Continuous LogBERT Trainer...")
        self.running = True
        
        # Start worker threads
        self.data_collection_thread = threading.Thread(
            target=self.data_collection_worker, daemon=True
        )
        self.training_thread = threading.Thread(
            target=self.training_worker, daemon=True
        )
        
        self.data_collection_thread.start()
        self.training_thread.start()
        
        self.logger.info("Continuous LogBERT Trainer started successfully")
        
    def data_collection_worker(self):
        """Worker thread for collecting training data"""
        self.logger.info("Data collection worker started")
        
        while self.running:
            try:
                # Get training sample
                try:
                    log_entry = self.training_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                    
                # Add to training buffer
                self.training_buffer.append(log_entry)
                
                self.training_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in data collection worker: {e}")
                
    def training_worker(self):
        """Worker thread for model training"""
        self.logger.info("Training worker started")
        
        while self.running:
            try:
                time.sleep(self.training_interval)
                
                # Check if we have enough samples
                if len(self.training_buffer) < self.min_training_samples:
                    continue
                    
                # Perform training
                self.perform_training()
                
            except Exception as e:
                self.logger.error(f"Error in training worker: {e}")
                
    def perform_training(self):
        """Perform one training iteration"""
        try:
            self.logger.info(f"Starting training with {len(self.training_buffer)} samples")
            
            # Prepare training data
            training_samples = list(self.training_buffer)
            dataset = LogDataset(training_samples, self.tokenizer, self.max_sequence_length)
            dataloader = DataLoader(
                dataset, 
                batch_size=self.batch_size, 
                shuffle=True,
                drop_last=True
            )
            
            # Training setup
            optimizer = torch.optim.AdamW(
                self.model.parameters(), 
                lr=self.learning_rate,
                weight_decay=0.01
            )
            
            # Use LoRA for incremental learning
            self.lora_learner.enable_lora()
            
            self.model.train()
            total_loss = 0.0
            num_batches = 0
            
            # Training loop
            for batch_idx, batch in enumerate(dataloader):
                input_ids = batch['input_ids'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                # Forward pass
                outputs = self.model(input_ids, labels=labels)
                loss = outputs.loss
                
                # Backward pass
                loss = loss / self.accumulation_steps
                loss.backward()
                
                total_loss += loss.item()
                num_batches += 1
                
                # Update weights
                if (batch_idx + 1) % self.accumulation_steps == 0:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                    optimizer.step()
                    optimizer.zero_grad()
                    
            # Calculate average loss
            avg_loss = total_loss / max(num_batches, 1)
            
            # Update training stats
            self.training_stats['current_loss'] = avg_loss
            self.training_stats['total_samples_trained'] += len(training_samples)
            self.training_stats['training_iterations'] += 1
            self.training_stats['last_training_time'] = datetime.now()
            
            # Save model checkpoint
            self.save_checkpoint()
            
            # Clear training buffer (keep some samples for next iteration)
            samples_to_keep = min(100, len(self.training_buffer) // 2)
            new_buffer = deque(
                list(self.training_buffer)[-samples_to_keep:], 
                maxlen=self.max_training_samples
            )
            self.training_buffer = new_buffer
            
            self.logger.info(
                f"Training completed - Loss: {avg_loss:.4f}, "
                f"Samples: {len(training_samples)}, "
                f"Total trained: {self.training_stats['total_samples_trained']}"
            )
            
        except Exception as e:
            self.logger.error(f"Error during training: {e}")
            
    def save_checkpoint(self):
        """Save model checkpoint"""
        try:
            checkpoint = {
                'model_state_dict': self.model.state_dict(),
                'training_stats': self.training_stats,
                'timestamp': datetime.now().isoformat()
            }
            
            torch.save(checkpoint, self.model_path)
            
            # Save vocabulary
            vocab = self.tokenizer.get_vocab()
            with open(self.vocab_path, 'w') as f:
                json.dump(vocab, f, indent=2)
                
            self.logger.info("Model checkpoint saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving checkpoint: {e}")
            
    def get_training_stats(self) -> Dict:
        """Get current training statistics"""
        stats = self.training_stats.copy()
        stats['training_buffer_size'] = len(self.training_buffer)
        stats['training_queue_size'] = self.training_queue.qsize()
        return stats
        
    async def stop(self):
        """Stop continuous training"""
        self.logger.info("Stopping Continuous LogBERT Trainer...")
        self.running = False
        
        # Wait for threads to finish
        if self.data_collection_thread:
            self.data_collection_thread.join(timeout=5)
        if self.training_thread:
            self.training_thread.join(timeout=5)
            
        # Final checkpoint save
        if self.model:
            self.save_checkpoint()
            
        self.logger.info("Continuous LogBERT Trainer stopped")

class SimpleTokenizer:
    """Simple tokenizer for LogBERT"""
    
    def __init__(self, vocab: Optional[Dict[str, int]] = None):
        if vocab:
            self.vocab = vocab
            self.inv_vocab = {v: k for k, v in vocab.items()}
        else:
            self.vocab = {'[PAD]': 0, '[UNK]': 1, '[CLS]': 2, '[SEP]': 3, '[MASK]': 4}
            self.inv_vocab = {v: k for k, v in self.vocab.items()}
            
    def encode(self, text: str, max_length: int = 512) -> List[int]:
        """Encode text to token IDs"""
        tokens = text.lower().split()
        token_ids = [self.vocab.get('[CLS]', 2)]
        
        for token in tokens[:max_length-2]:
            if token not in self.vocab:
                # Add new token to vocabulary
                self.vocab[token] = len(self.vocab)
                self.inv_vocab[len(self.inv_vocab)] = token
                
            token_ids.append(self.vocab[token])
            
        token_ids.append(self.vocab.get('[SEP]', 3))
        
        # Pad sequence
        while len(token_ids) < max_length:
            token_ids.append(self.vocab.get('[PAD]', 0))
            
        return token_ids[:max_length]
        
    def decode(self, token_ids: List[int]) -> str:
        """Decode token IDs to text"""
        tokens = [self.inv_vocab.get(token_id, '[UNK]') for token_id in token_ids]
        return ' '.join(tokens)
        
    def get_vocab(self) -> Dict[str, int]:
        """Get vocabulary"""
        return self.vocab.copy()

async def main():
    """Main function for testing"""
    trainer = ContinuousTrainer()
    
    try:
        await trainer.initialize()
        await trainer.start()
        
        # Simulate adding training samples
        for i in range(100):
            sample_log = {
                'method': 'GET',
                'uri': f'/api/users/{i}',
                'status': 200,
                'user_agent': 'Mozilla/5.0',
                'template': 'GET /api/users/*'
            }
            trainer.add_training_sample(sample_log)
            await asyncio.sleep(0.1)
            
        # Keep running
        while True:
            await asyncio.sleep(30)
            stats = trainer.get_training_stats()
            print(f"Training stats: {stats}")
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await trainer.stop()

if __name__ == "__main__":
    asyncio.run(main())
