#!/usr/bin/env python3
"""
WAR Application Integration System
=================================
Integrates WAF with Java WAR applications for real-time protection
"""

import os
import sys
import json
import time
import subprocess
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional
import requests
from flask import Flask, request, jsonify, Response
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("war_integration")

class WAFIntegratedProxy:
    """WAF-integrated proxy for WAR applications"""
    
    def __init__(self, config_file: str = "production_config.json"):
        self.config = self.load_config(config_file)
        self.waf_url = "http://localhost:8000"
        self.app = Flask(__name__)
        self.setup_routes()
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "avg_response_time": 0.0
        }
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration"""
        try:
            with open(config_file) as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Default configuration"""
        return {
            "applications": {
                "blog-cms": {"port": 8081, "context": "/blog"},
                "ecommerce": {"port": 8082, "context": "/shop"},
                "rest-api": {"port": 8083, "context": "/api"}
            },
            "proxy": {
                "port": 9090,
                "enable_waf": True,
                "log_requests": True
            }
        }
    
    def check_waf_service(self) -> bool:
        """Check if WAF service is available"""
        try:
            response = requests.get(f"{self.waf_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def analyze_with_waf(self, request_data: Dict) -> Dict:
        """Analyze request with WAF"""
        try:
            response = requests.post(
                f"{self.waf_url}/detect",
                json=request_data,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"WAF analysis failed: {response.status_code}")
                
        except requests.RequestException as e:
            logger.warning(f"Failed to contact WAF: {e}")
        
        # Fallback: allow request
        return {
            "blocked": False,
            "anomaly_score": 0.0,
            "risk_level": "UNKNOWN",
            "reason": "WAF service unavailable"
        }
    
    def proxy_request(self, target_url: str, method: str, headers: Dict, data: bytes = None) -> Response:
        """Proxy request to target application"""
        try:
            proxy_headers = {k: v for k, v in headers.items() 
                           if k.lower() not in ['host', 'connection']}
            
            if method == 'GET':
                response = requests.get(target_url, headers=proxy_headers, timeout=30)
            elif method == 'POST':
                response = requests.post(target_url, headers=proxy_headers, data=data, timeout=30)
            elif method == 'PUT':
                response = requests.put(target_url, headers=proxy_headers, data=data, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(target_url, headers=proxy_headers, timeout=30)
            else:
                response = requests.request(method, target_url, headers=proxy_headers, data=data, timeout=30)
            
            # Create Flask response
            flask_response = Response(
                response.content,
                status=response.status_code,
                headers=dict(response.headers)
            )
            
            return flask_response
            
        except requests.RequestException as e:
            logger.error(f"Proxy request failed: {e}")
            return Response(
                f"Proxy Error: {str(e)}",
                status=502,
                content_type="text/plain"
            )
    
    def setup_routes(self):
        """Setup Flask routes for WAF-protected applications"""
        
        @self.app.before_request
        def before_request():
            """Process request through WAF before proxying"""
            start_time = time.time()
            
            # Extract request information
            request_data = {
                "ip": request.remote_addr or "127.0.0.1",
                "method": request.method,
                "path": request.path,
                "query_params": dict(request.args),
                "headers": dict(request.headers),
                "user_agent": request.headers.get('User-Agent', ''),
                "timestamp": str(time.time())
            }
            
            # Analyze with WAF if enabled
            if self.config.get("proxy", {}).get("enable_waf", True):
                waf_result = self.analyze_with_waf(request_data)
                
                # Check if request should be blocked
                if waf_result.get("blocked", False):
                    self.stats["blocked_requests"] += 1
                    
                    # Log blocked request
                    logger.warning(f"Blocked request: {request_data['ip']} {request_data['method']} {request_data['path']} - Score: {waf_result.get('anomaly_score', 0):.3f}")
                    
                    # Return blocked response
                    return jsonify({
                        "error": "Request blocked by WAF",
                        "reason": waf_result.get("reason", "Security policy violation"),
                        "anomaly_score": waf_result.get("anomaly_score", 0),
                        "risk_level": waf_result.get("risk_level", "HIGH"),
                        "request_id": waf_result.get("request_id", "unknown")
                    }), 403
                
                # Store WAF analysis for logging
                request.waf_analysis = waf_result
            
            self.stats["total_requests"] += 1
            request.start_time = start_time
        
        @self.app.after_request
        def after_request(response):
            """Log request after processing"""
            if hasattr(request, 'start_time'):
                response_time = (time.time() - request.start_time) * 1000
                self.stats["avg_response_time"] = (
                    (self.stats["avg_response_time"] * (self.stats["total_requests"] - 1) + response_time) 
                    / self.stats["total_requests"]
                )
            
            if response.status_code != 403:
                self.stats["allowed_requests"] += 1
            
            # Log request
            if self.config.get("proxy", {}).get("log_requests", True):
                waf_score = getattr(request, 'waf_analysis', {}).get('anomaly_score', 0.0)
                logger.info(f"{request.remote_addr} {request.method} {request.path} - {response.status_code} (WAF: {waf_score:.3f})")
            
            return response
        
        # Dynamic routing for applications
        apps = self.config.get("applications", {})
        
        for app_name, app_config in apps.items():
            context = app_config.get("context", f"/{app_name}")
            port = app_config.get("port", 8080)
            
            # Create route for each application
            def create_proxy_route(app_port, app_context):
                def proxy_route():
                    # Determine target URL
                    target_path = request.path.replace(app_context, "", 1)
                    if not target_path.startswith("/"):
                        target_path = "/" + target_path
                    
                    target_url = f"http://localhost:{app_port}{target_path}"
                    if request.query_string:
                        target_url += f"?{request.query_string.decode()}"
                    
                    # Proxy the request
                    return self.proxy_request(
                        target_url,
                        request.method,
                        request.headers,
                        request.get_data()
                    )
                
                return proxy_route
            
            # Register route
            route_pattern = f"{context}/<path:path>"
            self.app.add_url_rule(
                route_pattern,
                f"proxy_{app_name}",
                create_proxy_route(port, context),
                methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
            )
            
            # Register root context route
            self.app.add_url_rule(
                context,
                f"proxy_{app_name}_root",
                create_proxy_route(port, context),
                methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
            )
        
        # Status and metrics endpoints
        @self.app.route('/waf-proxy/status')
        def proxy_status():
            """Proxy status endpoint"""
            waf_available = self.check_waf_service()
            
            return jsonify({
                "status": "running",
                "waf_service": "available" if waf_available else "unavailable",
                "statistics": self.stats,
                "applications": list(self.config.get("applications", {}).keys())
            })
        
        @self.app.route('/waf-proxy/metrics')
        def proxy_metrics():
            """Proxy metrics endpoint"""
            block_rate = (self.stats["blocked_requests"] / max(self.stats["total_requests"], 1)) * 100
            
            return jsonify({
                "total_requests": self.stats["total_requests"],
                "allowed_requests": self.stats["allowed_requests"],
                "blocked_requests": self.stats["blocked_requests"],
                "block_rate_percent": round(block_rate, 2),
                "avg_response_time_ms": round(self.stats["avg_response_time"], 2)
            })
        
        @self.app.route('/')
        def root():
            """Root endpoint with application links"""
            apps = self.config.get("applications", {})
            app_links = []
            
            for app_name, app_config in apps.items():
                context = app_config.get("context", f"/{app_name}")
                app_links.append({
                    "name": app_name.title(),
                    "url": context,
                    "description": f"WAF-Protected {app_name.title()} Application"
                })
            
            return jsonify({
                "message": "WAF-Protected Application Proxy",
                "version": "1.0.0",
                "waf_enabled": self.config.get("proxy", {}).get("enable_waf", True),
                "applications": app_links,
                "endpoints": {
                    "status": "/waf-proxy/status",
                    "metrics": "/waf-proxy/metrics"
                }
            })
    
    def run(self, host="0.0.0.0", port=None):
        """Run the proxy server"""
        if port is None:
            port = self.config.get("proxy", {}).get("port", 9090)
        
        logger.info(f"🚀 Starting WAF-Integrated Proxy on {host}:{port}")
        
        # Check WAF service
        if not self.check_waf_service():
            logger.warning("⚠️  WAF service not available - running in passthrough mode")
        
        # Print application mappings
        apps = self.config.get("applications", {})
        for app_name, app_config in apps.items():
            context = app_config.get("context", f"/{app_name}")
            app_port = app_config.get("port", 8080)
            logger.info(f"📱 {app_name.title()}: http://{host}:{port}{context} -> http://localhost:{app_port}")
        
        self.app.run(host=host, port=port, debug=False, threaded=True)

class MockWARApplication:
    """Mock WAR application for testing"""
    
    def __init__(self, name: str, port: int, context: str = "/"):
        self.name = name
        self.port = port
        self.context = context
        self.app = Flask(__name__)
        self.setup_routes()
        
    def setup_routes(self):
        """Setup mock application routes"""
        
        @self.app.route('/')
        def home():
            return jsonify({
                "application": self.name,
                "message": f"Welcome to {self.name.title()}",
                "version": "1.0.0",
                "endpoints": ["/", "/login", "/admin", "/api/data"]
            })
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username', request.json.get('username', '') if request.json else '')
                return jsonify({
                    "status": "success",
                    "message": f"Logged in as {username}",
                    "user": username
                })
            else:
                return jsonify({
                    "login_form": True,
                    "message": "POST username to login"
                })
        
        @self.app.route('/admin')
        def admin():
            return jsonify({
                "admin_panel": True,
                "message": "Administrative interface",
                "warning": "This is a sensitive area"
            })
        
        @self.app.route('/api/data')
        def api_data():
            return jsonify({
                "data": [
                    {"id": 1, "name": "Item 1"},
                    {"id": 2, "name": "Item 2"},
                    {"id": 3, "name": "Item 3"}
                ],
                "total": 3
            })
        
        @self.app.route('/search')
        def search():
            query = request.args.get('q', '')
            return jsonify({
                "query": query,
                "results": f"Search results for: {query}",
                "count": 5
            })
    
    def run(self):
        """Run the mock application"""
        logger.info(f"🚀 Starting {self.name} on port {self.port}")
        self.app.run(host="0.0.0.0", port=self.port, debug=False, threaded=True)

def start_mock_applications(config: Dict):
    """Start mock WAR applications"""
    apps = config.get("applications", {})
    threads = []
    
    for app_name, app_config in apps.items():
        port = app_config.get("port", 8080)
        context = app_config.get("context", f"/{app_name}")
        
        # Create and start mock application
        mock_app = MockWARApplication(app_name, port, context)
        
        thread = threading.Thread(
            target=mock_app.run,
            daemon=True
        )
        thread.start()
        threads.append(thread)
        
        time.sleep(1)  # Stagger startup
    
    return threads

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="WAR Application Integration System")
    parser.add_argument("--config", default="production_config.json", help="Configuration file")
    parser.add_argument("--start-apps", action="store_true", help="Start mock applications")
    parser.add_argument("--proxy-only", action="store_true", help="Start proxy only")
    parser.add_argument("--port", type=int, default=9090, help="Proxy port")
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        with open(args.config) as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {
            "applications": {
                "blog-cms": {"port": 8081, "context": "/blog"},
                "ecommerce": {"port": 8082, "context": "/shop"},
                "rest-api": {"port": 8083, "context": "/api"}
            },
            "proxy": {"port": args.port, "enable_waf": True}
        }
    
    threads = []
    
    # Start mock applications if requested
    if args.start_apps and not args.proxy_only:
        logger.info("🚀 Starting mock WAR applications...")
        threads = start_mock_applications(config)
        time.sleep(3)  # Wait for applications to start
    
    # Start WAF-integrated proxy
    proxy = WAFIntegratedProxy(args.config)
    
    def signal_handler(sig, frame):
        logger.info("🛑 Shutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        proxy.run(port=args.port)
    except KeyboardInterrupt:
        logger.info("🛑 Proxy stopped")

if __name__ == "__main__":
    main()
