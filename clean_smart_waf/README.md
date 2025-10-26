# Smart Web Application Firewall (WAF)
# Transformer-based Anomaly Detection System

This is a complete Smart WAF system that uses Transformer models with LoRA adaptation for real-time HTTP request anomaly detection.

## 🏗️ Architecture

- **Data Pipeline**: Ingests HTTP logs from Tomcat WAR applications
- **Transformer Model**: Uses Hugging Face transformers with LoRA for adaptive learning
- **Real-time Detection**: FastAPI endpoint for live anomaly detection
- **Dashboard**: Streamlit interface for monitoring and retraining

## 📁 Project Structure

```
smart_waf/
├── src/
│   ├── data_pipeline.py          # Log ingestion & preprocessing
│   ├── train_model.py           # Transformer training with LoRA
│   ├── inference_api.py         # FastAPI detection endpoint
│   └── dashboard.py             # Streamlit monitoring UI
├── war_apps/                    # Sample web applications
│   ├── ecommerce-app/           # E-commerce web app (WAR)
│   ├── admin-panel/             # Admin panel (WAR)
│   └── api-service/             # REST API service (WAR)
├── data/
│   ├── sample_logs/             # Sample HTTP logs
│   └── models/                  # Trained model storage
├── requirements.txt             # Dependencies
├── docker-compose.yml           # Tomcat + WAF deployment
└── README.md                    # This file
```

## 🚀 Quick Start

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Deploy WAR Applications**
```bash
# Copy WAR files to Tomcat
cp war_apps/*.war $TOMCAT_HOME/webapps/

# Start Tomcat
$TOMCAT_HOME/bin/startup.sh
```

3. **Train Model**
```bash
python src/train_model.py
```

4. **Start Detection API**
```bash
python src/inference_api.py
```

5. **Launch Dashboard**
```bash
streamlit run src/dashboard.py
```

## 🎯 Features

- ✅ Real-time HTTP request anomaly detection
- ✅ Transformer model with LoRA adaptive learning
- ✅ Live Streamlit dashboard with charts
- ✅ FastAPI inference endpoint
- ✅ Sample WAR applications for testing
- ✅ Docker deployment ready

## 📊 Dashboard Features

- Live request monitoring
- Anomaly detection visualization
- Model retraining interface
- Performance metrics
- Attack pattern analysis

## 🔧 Configuration

Edit `src/config.py` to customize:
- Model parameters
- Detection thresholds
- Log file paths
- Database settings

## 📝 API Usage

```python
import requests

# Send request for analysis
response = requests.post("http://localhost:8000/detect", 
    json={
        "method": "GET",
        "url": "/admin/users",
        "headers": {"User-Agent": "curl/7.68.0"},
        "body": ""
    })

print(response.json())
# {"anomaly_score": 0.23, "is_malicious": false}
```
