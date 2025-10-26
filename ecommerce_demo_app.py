
from flask import Flask, request, jsonify, render_template_string
import json
import time
from datetime import datetime
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ecommerce_access.log'),
        logging.StreamHandler()
    ]
)

# Mock product database
PRODUCTS = [
    {"id": 1, "name": "Premium Laptop", "price": 1299.99, "stock": 15},
    {"id": 2, "name": "Wireless Headphones", "price": 199.99, "stock": 50},
    {"id": 3, "name": "Smart Watch", "price": 399.99, "stock": 25},
    {"id": 4, "name": "Gaming Mouse", "price": 79.99, "stock": 100},
    {"id": 5, "name": "4K Monitor", "price": 549.99, "stock": 8}
]

USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "user": {"password": "user123", "role": "user"}
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TechStore - AI Protected Ecommerce</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 30px; }
        .alert { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .product { border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 8px; background: #fafafa; }
        .price { font-size: 24px; font-weight: bold; color: #28a745; }
        .stock { color: #6c757d; margin: 10px 0; }
        button { background: #007bff; color: white; border: none; padding: 12px 20px; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 20px; color: #007bff; text-decoration: none; font-weight: bold; }
        .nav a:hover { text-decoration: underline; }
        .waf-status { background: #e7f3ff; border-left: 4px solid #007bff; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 TechStore - Premium Electronics</h1>
            <p>🛡️ AI-Powered WAF Protection Active</p>
        </div>
        <div class="waf-status">
            <strong>🔒 Security Status:</strong> This application is protected by an advanced Transformer-based WAF system
            that detects and blocks malicious requests in real-time.
        </div>
        <div class="nav">
            <a href="/">🏠 Home</a>
            <a href="/products">📦 Products</a>
            <a href="/search">🔍 Search</a>
            <a href="/api/products">🔌 API</a>
            <a href="/admin">👑 Admin</a>
        </div>
        {{ content }}
    </div>
</body>
</html>
"""

@app.before_request
def log_request():
    """Log all incoming requests"""
    app.logger.info(f"Request: {request.method} {request.url} from {request.remote_addr}")

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
        <li><a href="/admin">Admin Panel (Demo: admin/admin123)</a></li>
    </ul>
    <p><strong>🎯 Demo Features for Judges:</strong></p>
    <ul>
        <li>✅ Real-time attack detection and blocking</li>
        <li>✅ SQL injection protection</li>
        <li>✅ XSS prevention</li>
        <li>✅ Admin panel security</li>
        <li>✅ Rate limiting</li>
        <li>✅ Live log analysis</li>
    </ul>
    <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px;">
        <strong>🎬 For Judges:</strong> Try attacking this application! The WAF will detect and block malicious requests.
        <br>Example attacks to try:
        <ul>
            <li>SQL Injection: <code>/search?q=' OR 1=1--</code></li>
            <li>XSS: <code>/search?q=&lt;script&gt;alert('xss')&lt;/script&gt;</code></li>
            <li>Path Traversal: <code>/api/products/../../../etc/passwd</code></li>
        </ul>
    </div>
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
        <input type="text" name="q" value="{query}" placeholder="Search products..." style="padding: 10px; width: 300px; margin-right: 10px;">
        <button type="submit">Search</button>
    </form>
    """
    
    if query:
        # Vulnerable search (for demo purposes)
        results = [p for p in PRODUCTS if query.lower() in p['name'].lower()]
        content += f"<h3>Search Results for: {query}</h3>"
        for product in results:
            content += f"<div class='product'><h4>{product['name']}</h4><div class='price'>${product['price']}</div></div>"
    
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/admin')
def admin():
    content = """
    <h2>👑 Admin Panel</h2>
    <div style="background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <strong>⚠️ Admin Access Required</strong>
    </div>
    <form method="POST" action="/admin/login">
        <div style="margin: 15px 0;">
            <label>Username:</label><br>
            <input type="text" name="username" style="padding: 8px; width: 200px;">
        </div>
        <div style="margin: 15px 0;">
            <label>Password:</label><br>
            <input type="password" name="password" style="padding: 8px; width: 200px;">
        </div>
        <button type="submit">Login</button>
    </form>
    <p><em>Demo credentials: admin/admin123</em></p>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/api/products')
def api_products():
    return jsonify({
        "products": PRODUCTS,
        "timestamp": datetime.now().isoformat(),
        "protected_by": "Transformer WAF"
    })

@app.route('/api/cart/add', methods=['POST'])
def api_cart_add():
    data = request.get_json()
    return jsonify({
        "status": "success",
        "message": f"Added product {data.get('product_id')} to cart",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🛒 Starting Ecommerce Application on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
