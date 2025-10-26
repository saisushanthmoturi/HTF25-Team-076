#!/usr/bin/env python3
"""
Simple Traffic Generator for WAF Testing
========================================
Generates HTTP requests to test the WAF system without complex locust setup.
"""

import random
import time
import requests
import threading
import json
from datetime import datetime
import uuid

class SimpleTrafficGenerator:
    """Simple traffic generator using requests library"""
    
    def __init__(self, waf_endpoint="http://localhost:8000", duration=30, rps=5):
        self.waf_endpoint = waf_endpoint
        self.duration = duration
        self.rps = rps
        self.requests_sent = 0
        self.responses_received = 0
        self.anomalies_detected = 0
        self.start_time = None
        self.stop_flag = False
        
    def generate_normal_request(self):
        """Generate normal HTTP request"""
        paths = [
            "/products",
            "/search",
            "/api/users",
            "/api/tasks",
            "/home",
            "/about",
            "/contact",
            "/login",
            "/api/status"
        ]
        
        methods = ["GET", "POST"]
        
        return {
            "ip": f"192.168.1.{random.randint(1, 254)}",
            "method": random.choice(methods),
            "path": random.choice(paths),
            "query_params": {
                "page": str(random.randint(1, 10)),
                "limit": str(random.randint(10, 100))
            }
        }
    
    def generate_suspicious_request(self):
        """Generate suspicious HTTP request"""
        suspicious_patterns = [
            {
                "ip": f"192.168.1.{random.randint(1, 254)}",
                "method": "GET",
                "path": "/../../../etc/passwd",
                "query_params": {}
            },
            {
                "ip": f"192.168.1.{random.randint(1, 254)}",
                "method": "GET", 
                "path": "/admin/config",
                "query_params": {"id": "1 UNION SELECT * FROM users"}
            },
            {
                "ip": f"192.168.1.{random.randint(1, 254)}",
                "method": "GET",
                "path": "/search",
                "query_params": {"q": "<script>alert('xss')</script>"}
            },
            {
                "ip": f"192.168.1.{random.randint(1, 254)}",
                "method": "POST",
                "path": "/api/exec",
                "query_params": {"cmd": "rm -rf /"}
            }
        ]
        
        return random.choice(suspicious_patterns)
    
    def send_request(self, request_data):
        """Send request to WAF service"""
        try:
            response = requests.post(
                f"{self.waf_endpoint}/detect",
                json=request_data,
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                self.responses_received += 1
                
                if result.get("is_anomalous", False):
                    self.anomalies_detected += 1
                    print(f"🚨 ANOMALY DETECTED: {request_data['path']} (Score: {result.get('anomaly_score', 0):.3f})")
                
                return result
            else:
                print(f"❌ WAF service error: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Request failed: {e}")
            
        return None
    
    def traffic_worker(self):
        """Worker thread for generating traffic"""
        while not self.stop_flag:
            # 90% normal traffic, 10% suspicious
            if random.random() < 0.9:
                request_data = self.generate_normal_request()
            else:
                request_data = self.generate_suspicious_request()
            
            self.send_request(request_data)
            self.requests_sent += 1
            
            # Control rate
            time.sleep(1.0 / self.rps)
    
    def run(self):
        """Run traffic generation"""
        print(f"🚀 Starting simple traffic generator...")
        print(f"   WAF Endpoint: {self.waf_endpoint}")
        print(f"   Duration: {self.duration} seconds")
        print(f"   Rate: {self.rps} requests/second")
        print(f"   Expected total: {self.duration * self.rps} requests")
        print()
        
        self.start_time = time.time()
        
        # Start worker threads
        workers = []
        for _ in range(min(5, self.rps)):  # Max 5 threads
            worker = threading.Thread(target=self.traffic_worker)
            worker.daemon = True
            workers.append(worker)
            worker.start()
        
        # Run for specified duration
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            print("\n⚠️ Interrupted by user")
        
        # Stop workers
        self.stop_flag = True
        
        # Wait for workers to finish
        for worker in workers:
            worker.join(timeout=1)
        
        # Print results
        elapsed_time = time.time() - self.start_time
        actual_rps = self.requests_sent / elapsed_time if elapsed_time > 0 else 0
        
        print(f"\n📊 Traffic Generation Complete:")
        print(f"   Duration: {elapsed_time:.1f} seconds")
        print(f"   Requests sent: {self.requests_sent}")
        print(f"   Responses received: {self.responses_received}")
        print(f"   Anomalies detected: {self.anomalies_detected}")
        print(f"   Actual RPS: {actual_rps:.1f}")
        print(f"   Success rate: {(self.responses_received/max(1,self.requests_sent))*100:.1f}%")
        print(f"   Anomaly rate: {(self.anomalies_detected/max(1,self.responses_received))*100:.1f}%")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Simple Traffic Generator for WAF Testing")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("--rps", type=int, default=5, help="Requests per second")
    parser.add_argument("--waf-endpoint", default="http://localhost:8000", help="WAF service endpoint")
    
    args = parser.parse_args()
    
    # Check if WAF service is running
    try:
        response = requests.get(f"{args.waf_endpoint}/health", timeout=5)
        if response.status_code == 200:
            print(f"✅ WAF service is healthy: {response.json()}")
        else:
            print(f"⚠️ WAF service returned status {response.status_code}")
    except Exception as e:
        print(f"❌ Cannot connect to WAF service: {e}")
        print(f"   Make sure the service is running at {args.waf_endpoint}")
        return
    
    # Generate traffic
    generator = SimpleTrafficGenerator(
        waf_endpoint=args.waf_endpoint,
        duration=args.duration, 
        rps=args.rps
    )
    
    generator.run()

if __name__ == "__main__":
    main()
