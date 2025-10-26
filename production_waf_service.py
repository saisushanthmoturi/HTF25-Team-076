#!/usr/bin/env python3
"""
Production WAF Service
======================
Production-ready WAF service with enhanced features for real deployment
"""

import os
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/waf/waf.log', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("production_waf")

class RequestData(BaseModel):
    """Request data for analysis"""
    ip: str
    method: str
    path: str
    query_params: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    user_agent: str = ""
    timestamp: Optional[str] = None

class WAFResponse(BaseModel):
    """WAF analysis response"""
    request_id: str
    anomaly_score: float
    is_anomalous: bool
    risk_level: str
    attack_types: List[str]
    confidence: float
    processing_time_ms: float
    blocked: bool
    reason: str

class ProductionWAF:
    """Production WAF engine with enhanced detection"""
    
    def __init__(self):
        self.request_count = 0
        self.blocked_count = 0
        self.start_time = time.time()
        self.rate_limiter = {}  # Simple rate limiting
        self.threat_threshold = 0.6  # Lower threshold for demonstration
        
        # Load configuration
        self.config = self.load_config()
        
        # Initialize detection engines
        self.sql_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
            r"(\b(or|and)\s+\d+\s*=\s*\d+)",
            r"(--|/\*|\*/|;)",
            r"(\bwhere\s+\d+\s*=\s*\d+)",
            r"(\b(char|ascii|substring|concat)\s*\()"
        ]
        
        self.xss_patterns = [
            r"(<script[^>]*>.*?</script>)",
            r"(javascript\s*:)",
            r"(on\w+\s*=)",
            r"(<iframe[^>]*>)",
            r"(<object[^>]*>)",
            r"(alert\s*\(|confirm\s*\(|prompt\s*\()"
        ]
        
        self.path_traversal_patterns = [
            r"(\.\./|\.\.\x5c)",
            r"(%2e%2e[/%5c])",
            r"(\.{2,}[/%5c])",
            r"(/etc/passwd|/windows/system32)"
        ]
        
        self.command_injection_patterns = [
            r"(;\s*(ls|cat|wget|curl|nc|netcat|ping))",
            r"(\|\s*(ls|cat|wget|curl|nc|netcat|ping))",
            r"(&&\s*(ls|cat|wget|curl|nc|netcat|ping))",
            r"(`[^`]*`)",
            r"(\$\([^)]*\))"
        ]
    
    def load_config(self) -> Dict:
        """Load WAF configuration"""
        config_path = Path("production_config.json")
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        
        # Default configuration
        return {
            "security": {
                "threat_threshold": 0.7,
                "rate_limiting": {"enabled": True, "max_requests": 100, "window": 60},
                "ip_whitelist": [],
                "ip_blacklist": []
            },
            "logging": {"level": "INFO", "detailed": True},
            "monitoring": {"enabled": True}
        }
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if IP is rate limited"""
        if not self.config["security"]["rate_limiting"]["enabled"]:
            return False
        
        current_time = time.time()
        max_requests = self.config["security"]["rate_limiting"]["max_requests"]
        window = self.config["security"]["rate_limiting"]["window"]
        
        if ip not in self.rate_limiter:
            self.rate_limiter[ip] = []
        
        # Clean old requests
        self.rate_limiter[ip] = [
            t for t in self.rate_limiter[ip] 
            if current_time - t < window
        ]
        
        # Check limit
        if len(self.rate_limiter[ip]) >= max_requests:
            return True
        
        # Add current request
        self.rate_limiter[ip].append(current_time)
        return False
    
    def detect_sql_injection(self, text: str) -> float:
        """Detect SQL injection attempts"""
        import re
        score = 0.0
        text_lower = text.lower()
        
        for pattern in self.sql_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += 0.3
        
        # Additional heuristics
        if "'" in text and ("or" in text_lower or "and" in text_lower):
            score += 0.4
        if "--" in text or "/*" in text:
            score += 0.2
        
        return min(score, 1.0)
    
    def detect_xss(self, text: str) -> float:
        """Detect XSS attempts"""
        import re
        score = 0.0
        text_lower = text.lower()
        
        for pattern in self.xss_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += 0.4
        
        # Additional heuristics
        if "<" in text and ">" in text and ("script" in text_lower or "iframe" in text_lower):
            score += 0.3
        
        return min(score, 1.0)
    
    def detect_path_traversal(self, path: str) -> float:
        """Detect path traversal attempts"""
        import re
        score = 0.0
        
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                score += 0.5
        
        return min(score, 1.0)
    
    def detect_command_injection(self, text: str) -> float:
        """Detect command injection attempts"""
        import re
        score = 0.0
        
        for pattern in self.command_injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.4
        
        return min(score, 1.0)
    
    def analyze_request(self, request_data: RequestData) -> WAFResponse:
        """Analyze incoming request for threats"""
        start_time = time.time()
        self.request_count += 1
        
        # Generate request ID
        request_id = f"req_{int(time.time())}_{self.request_count}"
        
        # Check rate limiting
        if self.check_rate_limit(request_data.ip):
            self.blocked_count += 1
            return WAFResponse(
                request_id=request_id,
                anomaly_score=1.0,
                is_anomalous=True,
                risk_level="HIGH",
                attack_types=["Rate Limiting"],
                confidence=1.0,
                processing_time_ms=(time.time() - start_time) * 1000,
                blocked=True,
                reason="Rate limit exceeded"
            )
        
        # Combine all text for analysis
        full_text = f"{request_data.path} {str(request_data.query_params)} {request_data.user_agent}"
        
        # Run detection engines
        sql_score = self.detect_sql_injection(full_text)
        xss_score = self.detect_xss(full_text)
        path_score = self.detect_path_traversal(request_data.path)
        cmd_score = self.detect_command_injection(full_text)
        
        # Calculate overall anomaly score
        anomaly_score = max(sql_score, xss_score, path_score, cmd_score)
        
        # Add some randomness for demo (remove in real production)
        import random
        anomaly_score += random.uniform(0, 0.1)
        anomaly_score = min(anomaly_score, 1.0)
        
        # Determine attack types
        attack_types = []
        if sql_score > 0.3:
            attack_types.append("SQL Injection")
        if xss_score > 0.3:
            attack_types.append("XSS")
        if path_score > 0.3:
            attack_types.append("Path Traversal")
        if cmd_score > 0.3:
            attack_types.append("Command Injection")
        
        # Check for admin access
        if any(admin in request_data.path.lower() for admin in ['/admin', '/wp-admin', '/phpmyadmin']):
            attack_types.append("Admin Access")
            anomaly_score = max(anomaly_score, 0.5)
        
        # Check for suspicious user agents
        suspicious_ua = ['sqlmap', 'nikto', 'nessus', 'burp', 'zap']
        if any(ua in request_data.user_agent.lower() for ua in suspicious_ua):
            attack_types.append("Automated Tool")
            anomaly_score = max(anomaly_score, 0.6)
        
        if not attack_types:
            attack_types = ["None"]
        
        # Determine risk level
        if anomaly_score >= 0.7:
            risk_level = "HIGH"
        elif anomaly_score >= 0.4:
            risk_level = "MEDIUM"
        elif anomaly_score >= 0.2:
            risk_level = "LOW"
        else:
            risk_level = "NORMAL"
        
        # Determine if request should be blocked
        is_anomalous = anomaly_score >= self.threat_threshold
        blocked = is_anomalous
        
        if blocked:
            self.blocked_count += 1
        
        processing_time = (time.time() - start_time) * 1000
        
        # Log the analysis
        logger.info(f"Request {request_id}: {request_data.ip} {request_data.method} {request_data.path} - Score: {anomaly_score:.3f}, Blocked: {blocked}")
        
        return WAFResponse(
            request_id=request_id,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
            risk_level=risk_level,
            attack_types=attack_types,
            confidence=abs(anomaly_score - 0.5) * 2,
            processing_time_ms=processing_time,
            blocked=blocked,
            reason=f"Anomaly score {anomaly_score:.3f}" if blocked else "Request appears legitimate"
        )
    
    def get_stats(self) -> Dict:
        """Get WAF statistics"""
        uptime = time.time() - self.start_time
        return {
            "uptime_seconds": uptime,
            "total_requests": self.request_count,
            "blocked_requests": self.blocked_count,
            "allowed_requests": self.request_count - self.blocked_count,
            "block_rate": self.blocked_count / max(self.request_count, 1) * 100,
            "requests_per_second": self.request_count / max(uptime, 1),
            "version": "1.0.0",
            "status": "operational"
        }

# Initialize WAF engine
waf_engine = ProductionWAF()

# FastAPI app with lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🛡️ Production WAF Service Starting...")
    logger.info(f"🔧 Configuration loaded: {waf_engine.config}")
    yield
    # Shutdown
    logger.info("🛡️ Production WAF Service Shutting Down...")

app = FastAPI(
    title="Production WAF Service",
    description="Production-ready Web Application Firewall with real-time threat detection",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/detect", response_model=WAFResponse)
async def detect_threat(request_data: RequestData):
    """Analyze request for security threats"""
    try:
        result = waf_engine.analyze_request(request_data)
        
        # Set response headers for integration
        headers = {
            "X-WAF-Score": str(result.anomaly_score),
            "X-WAF-Blocked": str(result.blocked).lower(),
            "X-WAF-Risk": result.risk_level,
            "X-WAF-Request-ID": result.request_id
        }
        
        return JSONResponse(
            content=result.dict(),
            headers=headers
        )
    except Exception as e:
        logger.error(f"Error analyzing request: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Production WAF",
        "version": "1.0.0",
        "uptime": time.time() - waf_engine.start_time
    }

@app.get("/metrics")
async def get_metrics():
    """Get WAF performance metrics"""
    return waf_engine.get_stats()

@app.get("/config")
async def get_config():
    """Get WAF configuration"""
    return waf_engine.config

@app.post("/config")
async def update_config(config: Dict):
    """Update WAF configuration"""
    waf_engine.config.update(config)
    logger.info(f"Configuration updated: {config}")
    return {"status": "updated", "config": waf_engine.config}

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "Production WAF",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "detection": "/detect",
            "health": "/health",
            "metrics": "/metrics",
            "config": "/config"
        },
        "features": [
            "SQL Injection Detection",
            "XSS Protection",
            "Path Traversal Prevention",
            "Command Injection Detection",
            "Rate Limiting",
            "Real-time Monitoring"
        ]
    }

if __name__ == "__main__":
    # Create log directory
    os.makedirs("/var/log/waf", exist_ok=True)
    
    # Run production server
    uvicorn.run(
        "production_waf_service:app",
        host="0.0.0.0",
        port=8000,
        workers=1,  # Use 1 worker for demo, increase for production
        access_log=True,
        log_level="info"
    )
