#!/bin/bash

# 🛡️ Transformer WAF System Startup
# =================================

echo "🛡️ TRANSFORMER-BASED WAF SYSTEM STARTUP"
echo "========================================"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 required but not installed"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install -q streamlit requests pandas numpy
echo "✅ Dependencies installed"

# Check web apps
echo "📋 Checking web applications..."
if curl -s http://localhost:8080/ecommerce/ > /dev/null 2>&1; then
    echo "✅ E-commerce app running"
else
    echo "⚠️  E-commerce app offline"
fi

if curl -s http://localhost:8080/rest-api/ > /dev/null 2>&1; then
    echo "✅ REST API app running"
else
    echo "⚠️  REST API app offline"
fi

# Start WAF service in background if not running
echo "🔍 Checking WAF service..."
if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "🚀 Starting WAF service..."
    python3 demo_transformer_waf.py > /dev/null 2>&1 &
    sleep 5
fi

# Launch dashboard
echo ""
echo "🌐 Starting WAF Dashboard..."
echo "📊 Dashboard: http://localhost:8501"
echo "🔧 WAF API: http://localhost:8000"
echo ""

streamlit run simple_waf_dashboard.py --server.port 8501 --server.address 0.0.0.0
