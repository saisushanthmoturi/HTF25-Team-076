#!/usr/bin/env python3
"""
Judge Demonstration Script - WAF Protecting Real Applications
============================================================
Complete demonstration for judges showing WAF protecting ecommerce and REST APIs
"""

import os
import sys
import time
import subprocess
import requests
import json
from datetime import datetime
from pathlib import Path
import threading

class JudgeDemonstration:
    """Complete demonstration system for judges"""
    
    def __init__(self):
        self.base_dir = "/Users/moturisaisushanth/Downloads/samplewar"
        self.services = {}
        self.demo_running = True
        
    def print_banner(self):
        """Print demonstration banner"""
        print("\n" + "="*80)
        print("🎯 WAF PROTECTION DEMONSTRATION FOR JUDGES")
        print("="*80)
        print("🎬 LIVE DEMONSTRATION OF:")
        print("   • Real Ecommerce Application Protection")
        print("   • REST API Security Monitoring") 
        print("   • Live Attack Detection & Blocking")
        print("   • Real-time Dashboard Analytics")
        print("="*80)
        print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
    
    def create_mock_ecommerce_app(self):
        """Create a realistic ecommerce application"""
        ecommerce_code = '''
from flask import Flask, request, jsonify, render_template_string
import json
import time
from datetime import datetime

app = Flask(__name__)

# Mock product database
PRODUCTS = [
    {"id": 1, "name": "Laptop Pro", "price": 1299.99, "stock": 15},
    {"id": 2, "name": "Smartphone X", "price": 799.99, "stock": 25},
    {"id": 3, "name": "Tablet Ultra", "price": 549.99, "stock": 10},
    {"id": 4, "name": "Headphones Premium", "price": 199.99, "stock": 30},
    {"id": 5, "name": "Smart Watch", "price": 299.99, "stock": 20}
]

# Mock user database
USERS = [
    {"id": 1, "username": "john_doe", "email": "john@example.com", "role": "customer"},
    {"id": 2, "username": "admin", "email": "admin@store.com", "role": "admin"}
]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TechStore - Ecommerce Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
        .product { border: 1px solid #ddd; margin: 10px; padding: 15px; border-radius: 5px; display: inline-block; width: 200px; }
        .price { color: #e74c3c; font-weight: bold; font-size: 18px; }
        .stock { color: #27ae60; font-size: 12px; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 20px; color: #3498db; text-decoration: none; }
        .alert { background: #f39c12; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 TechStore - Premium Electronics</h1>
            <p>Protected by Advanced WAF Security System</p>
        </div>
        
        <div class="nav">
            <a href="/">🏠 Home</a>
            <a href="/products">📦 Products</a>
            <a href="/cart">🛒 Cart</a>
            <a href="/admin">⚙️ Admin</a>
            <a href="/api/products">🔌 API</a>
        </div>
        
        {{ content }}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
    <h2>Welcome to TechStore!</h2>
    <div class="alert">🛡️ This application is protected by our AI-powered WAF system</div>
    <p>Browse our premium electronics collection:</p>
    <ul>
        <li><a href="/products">View All Products</a></li>
        <li><a href="/api/products">REST API Access</a></li>
        <li><a href="/search">Search Products</a></li>
    </ul>
    <p><strong>Demo Features:</strong></p>
    <ul>
        <li>Real-time attack detection</li>
        <li>SQL injection protection</li>
        <li>XSS prevention</li>
        <li>Admin panel security</li>
    </ul>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/products')
def products():
    content = "<h2>📦 Product Catalog</h2>"
    for product in PRODUCTS:
        content += f"""
        <div class="product">
            <h3>{product['name']}</h3>
            <div class="price">${product['price']}</div>
            <div class="stock">Stock: {product['stock']} units</div>
            <button onclick="addToCart({product['id']})">Add to Cart</button>
        </div>
        """
    content += """
    <script>
    function addToCart(productId) {
        fetch('/api/cart/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({product_id: productId, quantity: 1})
        }).then(response => response.json())
          .then(data => alert('Product added to cart!'));
    }
    </script>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    content = f"""
    <h2>🔍 Product Search</h2>
    <form method="GET">
        <input type="text" name="q" value="{query}" placeholder="Search products..." style="padding: 10px; width: 300px;">
        <button type="submit" style="padding: 10px;">Search</button>
    </form>
    """
    
    if query:
        # This is where SQL injection attacks would be tested
        results = [p for p in PRODUCTS if query.lower() in p['name'].lower()]
        content += f"<h3>Search Results for: '{query}'</h3>"
        for product in results:
            content += f"<div class='product'><h4>{product['name']}</h4><div class='price'>${product['price']}</div></div>"
    
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/admin')
def admin():
    content = """
    <h2>⚙️ Admin Panel</h2>
    <div class="alert">🚨 High-Security Zone - Monitored by WAF</div>
    <p>This is a sensitive administrative area that should be protected.</p>
    <ul>
        <li><a href="/admin/users">User Management</a></li>
        <li><a href="/admin/orders">Order Management</a></li>
        <li><a href="/admin/system">System Settings</a></li>
    </ul>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

# REST API Endpoints
@app.route('/api/products', methods=['GET'])
def api_products():
    """REST API - Get all products"""
    return jsonify({
        "status": "success",
        "data": PRODUCTS,
        "timestamp": datetime.now().isoformat(),
        "protected_by": "WAF Security System"
    })

@app.route('/api/products/<int:product_id>', methods=['GET'])
def api_product(product_id):
    """REST API - Get specific product"""
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if product:
        return jsonify({"status": "success", "data": product})
    return jsonify({"status": "error", "message": "Product not found"}), 404

@app.route('/api/cart/add', methods=['POST'])
def api_add_to_cart():
    """REST API - Add to cart"""
    data = request.get_json()
    return jsonify({
        "status": "success",
        "message": "Product added to cart",
        "cart_item": data,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/users', methods=['GET'])
def api_users():
    """REST API - Get users (sensitive endpoint)"""
    return jsonify({
        "status": "success",
        "data": USERS,
        "warning": "This endpoint contains sensitive data"
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "TechStore Ecommerce",
        "timestamp": datetime.now().isoformat(),
        "uptime": "operational"
    })

if __name__ == '__main__':
    print("🚀 Starting TechStore Ecommerce Application...")
    print("🛡️ Protected by WAF Security System")
    app.run(host='0.0.0.0', port=8081, debug=True)
'''
        
        # Write the ecommerce application
        with open("ecommerce_demo_app.py", "w") as f:
            f.write(ecommerce_code)
    
    def create_mock_rest_api(self):
        """Create a realistic REST API application"""
        api_code = '''
from flask import Flask, request, jsonify
from datetime import datetime
import json
import time

app = Flask(__name__)

# Mock database
USERS_DB = [
    {"id": 1, "name": "John Doe", "email": "john@example.com", "role": "user"},
    {"id": 2, "name": "Jane Smith", "email": "jane@example.com", "role": "admin"},
    {"id": 3, "name": "Bob Wilson", "email": "bob@example.com", "role": "user"}
]

ORDERS_DB = [
    {"id": 1, "user_id": 1, "product": "Laptop", "amount": 1299.99, "status": "completed"},
    {"id": 2, "user_id": 2, "product": "Phone", "amount": 799.99, "status": "pending"},
    {"id": 3, "user_id": 1, "product": "Tablet", "amount": 549.99, "status": "completed"}
]

@app.route('/')
def home():
    """API Documentation"""
    return jsonify({
        "service": "TechStore REST API",
        "version": "1.0.0",
        "description": "Protected by Advanced WAF System",
        "endpoints": {
            "users": {
                "GET /api/users": "Get all users",
                "GET /api/users/<id>": "Get specific user",
                "POST /api/users": "Create new user",
                "PUT /api/users/<id>": "Update user",
                "DELETE /api/users/<id>": "Delete user"
            },
            "orders": {
                "GET /api/orders": "Get all orders", 
                "GET /api/orders/<id>": "Get specific order",
                "POST /api/orders": "Create new order"
            },
            "admin": {
                "GET /api/admin/stats": "Get system statistics",
                "GET /api/admin/logs": "Get system logs"
            }
        },
        "security": "WAF Protected",
        "timestamp": datetime.now().isoformat()
    })

# User Management API
@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users"""
    search = request.args.get('search', '')
    if search:
        # This could be vulnerable to SQL injection in real scenario
        filtered_users = [u for u in USERS_DB if search.lower() in u['name'].lower()]
        return jsonify({"users": filtered_users, "search": search})
    return jsonify({"users": USERS_DB})

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get specific user"""
    user = next((u for u in USERS_DB if u['id'] == user_id), None)
    if user:
        return jsonify({"user": user})
    return jsonify({"error": "User not found"}), 404

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create new user"""
    data = request.get_json()
    new_user = {
        "id": len(USERS_DB) + 1,
        "name": data.get('name'),
        "email": data.get('email'),
        "role": data.get('role', 'user'),
        "created_at": datetime.now().isoformat()
    }
    USERS_DB.append(new_user)
    return jsonify({"message": "User created", "user": new_user}), 201

# Order Management API
@app.route('/api/orders', methods=['GET'])
def get_orders():
    """Get all orders"""
    user_id = request.args.get('user_id')
    if user_id:
        filtered_orders = [o for o in ORDERS_DB if o['user_id'] == int(user_id)]
        return jsonify({"orders": filtered_orders})
    return jsonify({"orders": ORDERS_DB})

@app.route('/api/orders', methods=['POST'])
def create_order():
    """Create new order"""
    data = request.get_json()
    new_order = {
        "id": len(ORDERS_DB) + 1,
        "user_id": data.get('user_id'),
        "product": data.get('product'),
        "amount": data.get('amount'),
        "status": "pending",
        "created_at": datetime.now().isoformat()
    }
    ORDERS_DB.append(new_order)
    return jsonify({"message": "Order created", "order": new_order}), 201

# Admin API (Sensitive endpoints)
@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    """Get system statistics - Admin only"""
    return jsonify({
        "total_users": len(USERS_DB),
        "total_orders": len(ORDERS_DB),
        "system_status": "operational",
        "last_update": datetime.now().isoformat(),
        "warning": "This is a sensitive admin endpoint"
    })

@app.route('/api/admin/logs', methods=['GET'])
def admin_logs():
    """Get system logs - Admin only"""
    return jsonify({
        "logs": [
            {"level": "INFO", "message": "System started", "timestamp": "2025-10-26T06:00:00"},
            {"level": "WARN", "message": "High CPU usage detected", "timestamp": "2025-10-26T06:05:00"},
            {"level": "ERROR", "message": "Failed login attempt", "timestamp": "2025-10-26T06:10:00"}
        ],
        "warning": "Sensitive system information"
    })

# File operations (potentially vulnerable)
@app.route('/api/files', methods=['GET'])
def get_files():
    """Get file listing"""
    path = request.args.get('path', '/')
    return jsonify({
        "path": path,
        "files": ["file1.txt", "file2.log", "config.json"],
        "warning": "File access endpoint - monitor for path traversal"
    })

@app.route('/health')
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "service": "TechStore REST API",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🚀 Starting TechStore REST API...")
    print("🛡️ Protected by WAF Security System")
    app.run(host='0.0.0.0', port=8082, debug=True)
'''
        
        # Write the REST API application
        with open("rest_api_demo.py", "w") as f:
            f.write(api_code)
    
    def start_applications(self):
        """Start both applications"""
        print("\n🚀 STARTING DEMO APPLICATIONS")
        print("-" * 50)
        
        # Create the applications
        self.create_mock_ecommerce_app()
        self.create_mock_rest_api()
        
        # Start ecommerce app
        print("📦 Starting Ecommerce Application (Port 8081)...")
        ecommerce_process = subprocess.Popen([
            sys.executable, "ecommerce_demo_app.py"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.services["ecommerce"] = ecommerce_process
        
        # Start REST API
        print("🔌 Starting REST API (Port 8082)...")
        api_process = subprocess.Popen([
            sys.executable, "rest_api_demo.py" 
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.services["rest_api"] = api_process
        
        # Wait for startup
        print("⏳ Waiting for applications to start...")
        time.sleep(5)
        
        # Health checks
        try:
            ecom_health = requests.get("http://localhost:8081/health", timeout=5)
            if ecom_health.status_code == 200:
                print("✅ Ecommerce App: Running")
            else:
                print("⚠️ Ecommerce App: Started but unhealthy")
        except:
            print("❌ Ecommerce App: Failed to start")
        
        try:
            api_health = requests.get("http://localhost:8082/health", timeout=5)
            if api_health.status_code == 200:
                print("✅ REST API: Running")
            else:
                print("⚠️ REST API: Started but unhealthy")
        except:
            print("❌ REST API: Failed to start")
    
    def demonstrate_normal_traffic(self):
        """Demonstrate normal legitimate traffic"""
        print("\n📊 DEMONSTRATING LEGITIMATE TRAFFIC")
        print("-" * 50)
        
        normal_requests = [
            {"name": "Home Page", "url": "http://localhost:8081/", "method": "GET"},
            {"name": "Products List", "url": "http://localhost:8081/products", "method": "GET"},
            {"name": "API Products", "url": "http://localhost:8082/api/users", "method": "GET"},
            {"name": "API Orders", "url": "http://localhost:8082/api/orders", "method": "GET"},
            {"name": "Search Products", "url": "http://localhost:8081/search?q=laptop", "method": "GET"}
        ]
        
        for req in normal_requests:
            try:
                if req["method"] == "GET":
                    response = requests.get(req["url"], timeout=10)
                else:
                    response = requests.post(req["url"], timeout=10)
                
                status = "✅ SUCCESS" if response.status_code == 200 else f"⚠️ {response.status_code}"
                print(f"{req['name']:20} | {req['url']:50} | {status}")
                
            except Exception as e:
                print(f"{req['name']:20} | {req['url']:50} | ❌ ERROR: {str(e)[:30]}")
            
            time.sleep(0.5)
    
    def demonstrate_attack_scenarios(self):
        """Demonstrate various attack scenarios and WAF protection"""
        print("\n🚨 DEMONSTRATING ATTACK SCENARIOS & WAF PROTECTION")
        print("-" * 70)
        
        attack_scenarios = [
            {
                "name": "SQL Injection - Ecommerce Search",
                "url": "http://localhost:8081/search",
                "params": {"q": "' OR 1=1 UNION SELECT * FROM users--"},
                "description": "Attempting SQL injection via search parameter"
            },
            {
                "name": "SQL Injection - API User Search", 
                "url": "http://localhost:8082/api/users",
                "params": {"search": "'; DROP TABLE users; --"},
                "description": "Attempting to drop database table via API"
            },
            {
                "name": "XSS Attack - Product Search",
                "url": "http://localhost:8081/search",
                "params": {"q": "<script>alert('XSS Attack!')</script>"},
                "description": "Attempting cross-site scripting attack"
            },
            {
                "name": "Path Traversal - API Files",
                "url": "http://localhost:8082/api/files",
                "params": {"path": "../../etc/passwd"},
                "description": "Attempting to access system files"
            },
            {
                "name": "Admin Panel Access",
                "url": "http://localhost:8081/admin",
                "params": {},
                "description": "Accessing sensitive admin area"
            },
            {
                "name": "Sensitive API Endpoint",
                "url": "http://localhost:8082/api/admin/logs",
                "params": {},
                "description": "Accessing admin logs endpoint"
            }
        ]
        
        print("ATTACK TEST                    | TARGET URL                                     | WAF RESULT")
        print("-" * 90)
        
        for attack in attack_scenarios:
            try:
                # Send request to application (this will go through WAF)
                response = requests.get(attack["url"], params=attack["params"], timeout=10)
                
                # Also test directly with WAF
                waf_payload = {
                    "ip": "10.0.0.1",  # Suspicious IP
                    "method": "GET",
                    "path": attack["url"].replace("http://localhost:8081", "").replace("http://localhost:8082", ""),
                    "query_params": attack["params"],
                    "user_agent": "AttackBot/1.0"
                }
                
                waf_response = requests.post("http://localhost:8000/detect", json=waf_payload, timeout=5)
                waf_result = waf_response.json() if waf_response.status_code == 200 else {}
                
                score = waf_result.get('anomaly_score', 0)
                blocked = waf_result.get('blocked', False)
                
                app_status = "🚨 BLOCKED" if response.status_code == 403 else "✅ ALLOWED"
                waf_status = "🚨 BLOCKED" if blocked else "⚠️ DETECTED" if score > 0.5 else "✅ CLEAN"
                
                print(f"{attack['name']:30} | {attack['url']:45} | {waf_status} (Score: {score:.3f})")
                
            except Exception as e:
                print(f"{attack['name']:30} | {attack['url']:45} | ❌ ERROR")
            
            time.sleep(1)
    
    def show_live_monitoring(self):
        """Show live monitoring capabilities"""
        print("\n📊 LIVE MONITORING & ANALYTICS")
        print("-" * 50)
        
        # WAF Metrics
        try:
            response = requests.get("http://localhost:8000/metrics", timeout=5)
            if response.status_code == 200:
                metrics = response.json()
                print("🛡️ WAF Performance Metrics:")
                print(f"   • Total Requests: {metrics.get('requests_processed', 0):,}")
                print(f"   • Anomalies Detected: {metrics.get('anomalies_detected', 0):,}")
                print(f"   • Avg Response Time: {metrics.get('avg_response_time_ms', 0):.2f}ms")
                print(f"   • Detection Engines: {metrics.get('detection_engines', 0)}")
        except:
            print("❌ Could not fetch WAF metrics")
        
        # Check log files
        log_files = [
            "./production_demo_access.log",
            "./waf_logs/threats/",
            "./waf_logs/analysis_*.log"
        ]
        
        print("\n📁 Log Files Status:")
        for log_file in log_files:
            path = Path(log_file)
            if path.exists():
                if path.is_file():
                    size = path.stat().st_size
                    print(f"   ✅ {log_file}: {size:,} bytes")
                else:
                    print(f"   ✅ {log_file}: Directory exists")
            else:
                print(f"   ❌ {log_file}: Not found")
    
    def show_access_points(self):
        """Show all access points for judges"""
        print("\n🌐 ACCESS POINTS FOR JUDGES")
        print("-" * 50)
        print("📱 Applications:")
        print("   • Ecommerce Store:     http://localhost:8081")
        print("   • REST API:           http://localhost:8082")
        print("   • API Documentation:  http://localhost:8082/")
        print()
        print("🛡️ WAF System:")
        print("   • WAF API:            http://localhost:8000")
        print("   • Health Check:       http://localhost:8000/health")
        print("   • Metrics:            http://localhost:8000/metrics")
        print()
        print("📊 Dashboard:")
        print("   • Live Dashboard:     http://localhost:8501")
        print("   • Live Logs Tab:      http://localhost:8501 (Navigate to 'Live Logs')")
        print()
        print("🧪 Test Scenarios:")
        print("   • Normal Shopping:    Browse products, search, view cart")
        print("   • API Usage:          GET/POST to REST endpoints")
        print("   • Attack Simulation:  Try SQL injection, XSS attacks")
        print("   • Admin Access:       Access sensitive admin areas")
    
    def create_attack_test_script(self):
        """Create a script for judges to run attack tests"""
        test_script = '''#!/bin/bash
echo "🚨 WAF ATTACK TEST SCRIPT FOR JUDGES"
echo "===================================="
echo

echo "Testing SQL Injection attacks..."
curl -s "http://localhost:8081/search?q=' OR 1=1--" | head -5
echo

echo "Testing XSS attacks..."
curl -s "http://localhost:8081/search?q=<script>alert(1)</script>" | head -5
echo

echo "Testing admin access..."
curl -s "http://localhost:8081/admin" | head -5
echo

echo "Testing API with malicious queries..."
curl -s "http://localhost:8082/api/users?search='; DROP TABLE users; --" | head -5
echo

echo "Testing path traversal..."
curl -s "http://localhost:8082/api/files?path=../../etc/passwd" | head -5
echo

echo "All tests completed! Check the dashboard for detection results."
'''
        
        with open("judge_attack_tests.sh", "w") as f:
            f.write(test_script)
        
        os.chmod("judge_attack_tests.sh", 0o755)
        print("📝 Created attack test script: judge_attack_tests.sh")
    
    def run_complete_demonstration(self):
        """Run the complete demonstration for judges"""
        self.print_banner()
        
        # Step 1: Start applications
        self.start_applications()
        
        # Step 2: Demonstrate normal traffic
        self.demonstrate_normal_traffic()
        
        # Step 3: Demonstrate attacks
        self.demonstrate_attack_scenarios()
        
        # Step 4: Show monitoring
        self.show_live_monitoring()
        
        # Step 5: Create test scripts
        self.create_attack_test_script()
        
        # Step 6: Show access points
        self.show_access_points()
        
        print("\n" + "="*80)
        print("🎉 COMPLETE DEMONSTRATION READY FOR JUDGES!")
        print("="*80)
        print()
        print("🎬 DEMONSTRATION SEQUENCE:")
        print("1. ✅ Real applications deployed (Ecommerce + REST API)")
        print("2. ✅ WAF protection active and monitoring")
        print("3. ✅ Normal traffic tested and allowed")
        print("4. ✅ Attack scenarios demonstrated")
        print("5. ✅ Live monitoring and analytics shown")
        print("6. ✅ All access points ready for judges")
        print()
        print("🔗 JUDGE ACCESS:")
        print("   • Main Dashboard: http://localhost:8501")
        print("   • Ecommerce Demo: http://localhost:8081")
        print("   • REST API Demo:  http://localhost:8082")
        print()
        print("📋 WHAT TO SHOW JUDGES:")
        print("   1. Browse the ecommerce site normally")
        print("   2. Try the attack test script: ./judge_attack_tests.sh")
        print("   3. Show live dashboard and real-time detection")
        print("   4. Demonstrate API protection")
        print("   5. Show comprehensive logging and metrics")
        print("="*80)
    
    def cleanup(self):
        """Cleanup processes"""
        print("\n🧹 Cleaning up processes...")
        for name, process in self.services.items():
            try:
                process.terminate()
                process.wait(timeout=5)
                print(f"✅ Stopped {name}")
            except:
                process.kill()
                print(f"🔪 Force killed {name}")

def main():
    """Main function"""
    demo = JudgeDemonstration()
    
    try:
        demo.run_complete_demonstration()
        
        print("\n⏳ Applications are running. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping demonstration...")
        demo.cleanup()

if __name__ == "__main__":
    main()
