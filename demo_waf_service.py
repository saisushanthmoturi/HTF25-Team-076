
import json
from fastapi import FastAPI
from pydantic import BaseModel
import random

app = FastAPI(title="Demo WAF Service")

class RequestData(BaseModel):
    ip: str
    method: str  
    path: str
    query_params: dict = {}

@app.post("/detect")
async def detect_anomaly(request: RequestData):
    # Demo anomaly scoring
    score = 0.1  # Default low score
    
    # Higher scores for suspicious patterns
    if "admin" in request.path.lower():
        score += 0.3
    if ".." in request.path:
        score += 0.4
    if any(sql in str(request.query_params).lower() for sql in ["union", "select", "drop"]):
        score += 0.5
    if "<script" in str(request.query_params).lower():
        score += 0.4
        
    # Add some randomness
    score += random.uniform(0, 0.1)
    score = min(score, 1.0)
    
    return {
        "request_id": f"demo_{hash(request.path)}",
        "anomaly_score": score,
        "is_anomalous": score > 0.7,
        "confidence": abs(score - 0.5) * 2,
        "processing_time_ms": random.uniform(1, 5),
        "details": {"demo_mode": True}
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "mode": "demo"}

@app.get("/")
async def root():
    return {"service": "Demo WAF", "version": "1.0.0"}
