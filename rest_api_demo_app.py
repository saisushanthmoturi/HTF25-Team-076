
from flask import Flask, request, jsonify
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
        logging.FileHandler('rest_api_access.log'),
        logging.StreamHandler()
    ]
)

# Mock data
API_DATA = {
    "users": [
        {"id": 1, "name": "John Doe", "email": "john@example.com"},
        {"id": 2, "name": "Jane Smith", "email": "jane@example.com"}
    ],
    "orders": [
        {"id": 1, "user_id": 1, "total": 299.99, "status": "completed"},
        {"id": 2, "user_id": 2, "total": 199.99, "status": "pending"}
    ]
}

@app.before_request
def log_request():
    """Log all incoming requests"""
    app.logger.info(f"API Request: {request.method} {request.url} from {request.remote_addr}")

@app.route('/')
def api_home():
    return jsonify({
        "api": "TechStore REST API",
        "version": "1.0",
        "protection": "Transformer WAF",
        "endpoints": {
            "/api/users": "GET - List users",
            "/api/users/<id>": "GET - Get user by ID",
            "/api/orders": "GET - List orders",
            "/api/orders/<id>": "GET - Get order by ID",
            "/api/stats": "GET - API statistics"
        },
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/users')
def get_users():
    return jsonify({
        "users": API_DATA["users"],
        "count": len(API_DATA["users"]),
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = next((u for u in API_DATA["users"] if u["id"] == user_id), None)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404

@app.route('/api/orders')
def get_orders():
    return jsonify({
        "orders": API_DATA["orders"],
        "count": len(API_DATA["orders"]),
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    order = next((o for o in API_DATA["orders"] if o["id"] == order_id), None)
    if order:
        return jsonify(order)
    return jsonify({"error": "Order not found"}), 404

@app.route('/api/stats')
def get_stats():
    return jsonify({
        "total_users": len(API_DATA["users"]),
        "total_orders": len(API_DATA["orders"]),
        "uptime": "Active",
        "waf_protection": "Enabled",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🔌 Starting REST API on http://localhost:5001")
    app.run(host='0.0.0.0', port=5001, debug=False)
