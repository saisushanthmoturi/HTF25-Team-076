#!/usr/bin/env python3
"""
WAF Integration Example
======================
Shows how to integrate your existing applications with the WAF
"""

import requests
import time
from flask import Flask, request, jsonify, abort
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WAFIntegration:
    """WAF integration middleware for applications"""
    
    def __init__(self, waf_url="http://localhost:8000", block_threats=True):
        self.waf_url = waf_url
        self.block_threats = block_threats
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'allowed_requests': 0
        }
    
    def check_request(self, ip, method, path, query_params=None, headers=None):
        """Check request with WAF and return threat assessment"""
        self.stats['total_requests'] += 1
        
        # Prepare WAF payload
        waf_payload = {
            'ip': ip,
            'method': method,
            'path': path,
            'query_params': query_params or {},
            'headers': headers or {}
        }
        
        try:
            # Send to WAF for analysis
            response = requests.post(f"{self.waf_url}/detect", 
                                   json=waf_payload, timeout=3)
            
            if response.status_code == 200:
                result = response.json()
                is_threat = result.get('is_anomalous', False)
                score = result.get('anomaly_score', 0.0)
                
                # Log the assessment
                logger.info(f"WAF Analysis: {ip} {method} {path} - Score: {score:.3f}, Threat: {is_threat}")
                
                if is_threat:
                    self.stats['blocked_requests'] += 1
                    return {
                        'blocked': True,
                        'score': score,
                        'reason': f"Anomaly score {score:.3f} exceeds threshold",
                        'details': result
                    }
                else:
                    self.stats['allowed_requests'] += 1
                    return {
                        'blocked': False,
                        'score': score,
                        'reason': "Request appears legitimate",
                        'details': result
                    }
            else:
                logger.error(f"WAF service error: {response.status_code}")
                # Fail open - allow request if WAF is down
                self.stats['allowed_requests'] += 1
                return {'blocked': False, 'score': 0.0, 'reason': 'WAF service unavailable'}
                
        except Exception as e:
            logger.error(f"WAF integration error: {e}")
            # Fail open - allow request if WAF is down
            self.stats['allowed_requests'] += 1
            return {'blocked': False, 'score': 0.0, 'reason': f'WAF error: {e}'}

# Example Flask application with WAF integration
app = Flask(__name__)
waf = WAFIntegration()

@app.before_request
def waf_protection():
    """WAF protection middleware - runs before every request"""
    
    # Get request details
    client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    method = request.method
    path = request.path
    query_params = dict(request.args)
    headers = dict(request.headers)
    
    # Check with WAF
    assessment = waf.check_request(client_ip, method, path, query_params, headers)
    
    # Block if threat detected and blocking is enabled
    if assessment['blocked'] and waf.block_threats:
        logger.warning(f"Blocked malicious request: {client_ip} {method} {path}")
        abort(403, description=f"Request blocked by WAF: {assessment['reason']}")
    
    # Add WAF score to request context
    request.waf_score = assessment['score']
    request.waf_assessment = assessment

@app.route('/')
def home():
    """Sample home page"""
    waf_score = getattr(request, 'waf_score', 0.0)
    return jsonify({
        'message': 'Hello from protected application!',
        'waf_score': waf_score,
        'status': 'protected'
    })

@app.route('/api/users')
def get_users():
    """Sample API endpoint"""
    return jsonify({
        'users': [
            {'id': 1, 'name': 'John Doe'},
            {'id': 2, 'name': 'Jane Smith'}
        ],
        'waf_score': getattr(request, 'waf_score', 0.0)
    })

@app.route('/search')
def search():
    """Sample search endpoint (vulnerable to attacks)"""
    query = request.args.get('q', '')
    return jsonify({
        'query': query,
        'results': f'Search results for: {query}',
        'waf_score': getattr(request, 'waf_score', 0.0)
    })

@app.route('/waf/stats')
def waf_stats():
    """WAF protection statistics"""
    return jsonify({
        'waf_stats': waf.stats,
        'protection_rate': waf.stats['blocked_requests'] / max(waf.stats['total_requests'], 1) * 100
    })

if __name__ == '__main__':
    print("🛡️ Starting WAF-Protected Application")
    print("=====================================")
    print("🌐 Application: http://localhost:5000")
    print("🛡️  WAF Service: http://localhost:8000")
    print("📊 WAF Stats: http://localhost:5000/waf/stats")
    print()
    print("🧪 Test with these URLs:")
    print("   Normal: http://localhost:5000/")
    print("   Search: http://localhost:5000/search?q=laptop")
    print("   Attack: http://localhost:5000/search?q=<script>alert(1)</script>")
    print()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
