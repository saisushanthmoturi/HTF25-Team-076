# 🛡️ Transformer-Based WAF Architecture Implementation

## Challenge Overview
Build a modern, data-driven WAF that learns "normal" HTTP traffic patterns for three Java web apps and flags anomalous requests in real-time using Transformer models.

## Architecture Pipeline

```
Browser/Attacker → Nginx → WAR Applications (Tomcat)
                      ↓ (access logs)
                 Log Ingestion → Parser → Tokenizer → Queue → Model Inference → Alert/Block
```

## Implementation Steps

### Phase 1: Traffic Generation & Log Collection ✅
- Deploy 3 WAR applications (already done)
- Generate diverse benign traffic using Locust/k6
- Configure Nginx access logs in JSON format
- Create synthetic user journeys

### Phase 2: Log Processing Pipeline
- **Parser**: Extract structured events from raw logs
- **Normalizer**: Replace dynamic tokens (IDs, timestamps) with placeholders
- **Template Extractor**: Use Drain algorithm for log template mining
- **Tokenizer**: Convert to Transformer-compatible sequences

### Phase 3: Transformer Model
- **LogBERT-style encoder** trained on benign sequences only
- **Masked token prediction** + compactness loss
- **Export to ONNX** for production serving

### Phase 4: Real-time Inference
- **Async sidecar microservice** (FastAPI)
- **Batched inference** for performance
- **Non-blocking detection** with eventual enforcement

### Phase 5: Incremental Updates
- **LoRA-based fine-tuning** on new benign data
- **No full retrain** - parameter-efficient updates
- **Automated incremental learning**

## Key Technologies
- **Nginx** with Lua for request interception
- **Drain3** for log template extraction  
- **PyTorch + HuggingFace** for Transformer model
- **ONNX Runtime** for optimized inference
- **FastAPI** for sidecar service
- **Locust** for traffic generation
- **LoRA/PEFT** for incremental updates
 