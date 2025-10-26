#!/bin/bash

# 🛡️ Transformer-based WAF Startup Script
# ========================================
# Launches the complete WAF system with dashboard

echo "🛡️ TRANSFORMER-BASED WAF SYSTEM STARTUP"
echo "========================================"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if web applications are running
echo "📋 Checking Web Applications..."
if curl -s http://localhost:8080/ecommerce/ > /dev/null; then
    echo "   ✅ E-commerce application is running"
else
    echo "   ⚠️  E-commerce application not detected"
    echo "   💡 Start Tomcat server first if you want live traffic"
fi

if curl -s http://localhost:8080/rest-api/ > /dev/null; then
    echo "   ✅ REST API application is running"
else
    echo "   ⚠️  REST API application not detected"
    echo "   💡 Start Tomcat server first if you want live traffic"
fi

echo ""

# Install dependencies
echo "📦 Installing Dependencies..."
pip install -q -r requirements_waf.txt
if [ $? -eq 0 ]; then
    echo "   ✅ Dependencies installed successfully"
else
    echo "   ❌ Failed to install dependencies"
    exit 1
fi

echo ""

# Check WAF inference service
echo "🔍 Checking WAF Inference Service..."
if curl -s http://localhost:8000/health > /dev/null; then
    echo "   ✅ WAF service is already running"
else
    echo "   🚀 Starting WAF inference service in background..."
    nohup python3 waf_inference_service.py > waf_service.log 2>&1 &
    sleep 3
    
    if curl -s http://localhost:8000/health > /dev/null; then
        echo "   ✅ WAF service started successfully"
    else
        echo "   ⚠️  WAF service not responding, using demo mode"
    fi
fi

echo ""

# Start dashboard
echo "🌐 Starting Transformer WAF Dashboard..."
echo "📊 Dashboard will be available at: http://localhost:8501"
echo ""
echo "🎯 Features available:"
echo "   • Real-time anomaly detection monitoring"
echo "   • Interactive attack testing interface"
echo "   • Performance analytics and insights"
echo "   • System status and health checks"
echo "   • Architecture documentation"
echo ""
echo "🛡️ Ready to demonstrate advanced WAF capabilities!"
echo ""

# Launch Streamlit dashboard
streamlit run transformer_waf_dashboard.py --server.port 8501 --server.address 0.0.0.0
