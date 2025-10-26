#!/bin/bash
# Judge Attack Testing Script
# Run this script to test various attacks against the WAF

echo "🎯 WAF ATTACK TESTING SCRIPT FOR JUDGES"
echo "========================================"

echo ""
echo "1. Testing SQL Injection Attacks..."
curl -s "http://localhost:5000/search?q=%27%20OR%201%3D1--" | grep -o "blocked\|detected\|prevented" || echo "Request processed"

echo ""
echo "2. Testing XSS Attacks..."
curl -s "http://localhost:5000/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" | grep -o "blocked\|detected\|prevented" || echo "Request processed"

echo ""
echo "3. Testing Path Traversal..."
curl -s "http://localhost:5001/api/../../../etc/passwd" | grep -o "blocked\|detected\|prevented" || echo "Request processed"

echo ""
echo "4. Testing Command Injection..."
curl -s "http://localhost:5001/api/stats?cmd=%3B%20cat%20%2Fetc%2Fpasswd" | grep -o "blocked\|detected\|prevented" || echo "Request processed"

echo ""
echo "5. Testing Rate Limiting..."
for i in {1..10}; do
    curl -s "http://localhost:5000/" > /dev/null
    echo -n "."
done
echo " Rate limiting test complete"

echo ""
echo "🔍 Check the WAF Dashboard at http://localhost:8501 to see attack detection!"
echo "📊 Check WAF logs and metrics for real-time analysis"
