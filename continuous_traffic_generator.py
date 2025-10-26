#!/usr/bin/env python3
"""
Continuous Live Traffic Generator
================================
Generates continuous traffic for live dashboard demonstration
"""

import time
import random
import requests
import json
from datetime import datetime
from pathlib import Path
import threading
import sys

class ContinuousTrafficGenerator:
    """Generates continuous traffic for live monitoring"""
    
    def __init__(self, waf_url="http://localhost:8000", log_file="./production_demo_access.log"):
        self.waf_url = waf_url
        self.log_file = log_file
        self.running = True
        self.stats = {"total": 0, "blocked": 0, "high_risk": 0}
        
        # Traffic patterns with realistic variety
        self.normal_patterns = [
            {"ip": "192.168.1.10", "method": "GET", "path": "/", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            {"ip": "192.168.1.11", "method": "GET", "path": "/products", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
            {"ip": "192.168.1.12", "method": "GET", "path": "/about", "ua": "Mozilla/5.0 (X11; Linux x86_64)"},
            {"ip": "192.168.1.13", "method": "POST", "path": "/login", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1)"},
            {"ip": "192.168.1.14", "method": "GET", "path": "/api/users", "ua": "Mozilla/5.0 (Android 11; Mobile)"},
            {"ip": "192.168.1.15", "method": "GET", "path": "/contact", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            {"ip": "192.168.1.16", "method": "GET", "path": "/search", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
        ]
        
        self.suspicious_patterns = [
            {"ip": "10.1.1.1", "method": "GET", "path": "/admin", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            {"ip": "10.1.1.2", "method": "GET", "path": "/wp-admin", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
            {"ip": "10.1.1.3", "method": "GET", "path": "/phpmyadmin", "ua": "Mozilla/5.0 (X11; Linux x86_64)"},
            {"ip": "10.1.1.4", "method": "GET", "path": "/administrator", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        ]
        
        self.attack_patterns = [
            {"ip": "10.0.0.1", "method": "GET", "path": "/search?q=' OR 1=1--", "ua": "sqlmap/1.4.7"},
            {"ip": "10.0.0.2", "method": "GET", "path": "/<script>alert(1)</script>", "ua": "curl/7.68.0"},
            {"ip": "10.0.0.3", "method": "GET", "path": "/../../etc/passwd", "ua": "Python-urllib/3.9"},
            {"ip": "10.0.0.4", "method": "POST", "path": "/exec", "ua": "Nikto/2.1.6"},
            {"ip": "10.0.0.5", "method": "GET", "path": "/search?q=<img src=x onerror=alert(1)>", "ua": "Burp Suite"},
            {"ip": "10.0.0.6", "method": "GET", "path": "/../../../windows/system32/drivers/etc/hosts", "ua": "curl/7.68.0"},
        ]
    
    def generate_request(self):
        """Generate a single request"""
        # 70% normal, 20% suspicious, 10% attacks
        rand = random.random()
        
        if rand < 0.7:
            pattern = random.choice(self.normal_patterns)
            risk_type = "normal"
        elif rand < 0.9:
            pattern = random.choice(self.suspicious_patterns)
            risk_type = "suspicious"
        else:
            pattern = random.choice(self.attack_patterns)
            risk_type = "attack"
        
        # Add some randomness to IPs
        ip_parts = pattern["ip"].split(".")
        if risk_type == "normal":
            ip_parts[3] = str(random.randint(10, 50))
        elif risk_type == "suspicious":
            ip_parts[3] = str(random.randint(1, 10))
        else:
            ip_parts[3] = str(random.randint(1, 20))
        
        request_data = {
            "ip": ".".join(ip_parts),
            "method": pattern["method"],
            "path": pattern["path"],
            "query_params": {},
            "headers": {"User-Agent": pattern["ua"]},
            "user_agent": pattern["ua"],
            "timestamp": str(time.time())
        }
        
        return request_data, risk_type
    
    def send_to_waf(self, request_data):
        """Send request to WAF and get response"""
        try:
            response = requests.post(f"{self.waf_url}/detect", json=request_data, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def log_request(self, request_data, waf_result, risk_type):
        """Log request to file in Apache format"""
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        status = 403 if waf_result.get('blocked', False) else 200
        
        log_entry = f'{request_data["ip"]} - - [{timestamp}] "{request_data["method"]} {request_data["path"]} HTTP/1.1" {status} 1234 "-" "{request_data["user_agent"]}"'
        
        # Write to log file
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")
            f.flush()
    
    def generate_continuous_traffic(self, interval=2.0):
        """Generate continuous traffic"""
        print(f"🚀 Starting continuous traffic generation...")
        print(f"📁 Logging to: {self.log_file}")
        print(f"🛡️  WAF URL: {self.waf_url}")
        print(f"⏱️  Interval: {interval} seconds")
        print("\nPress Ctrl+C to stop\n")
        
        request_count = 0
        
        while self.running:
            try:
                # Generate request
                request_data, risk_type = self.generate_request()
                
                # Send to WAF
                waf_result = self.send_to_waf(request_data)
                
                # Log request
                self.log_request(request_data, waf_result, risk_type)
                
                # Update statistics
                self.stats["total"] += 1
                if waf_result.get('blocked', False):
                    self.stats["blocked"] += 1
                if waf_result.get('anomaly_score', 0) >= 0.7:
                    self.stats["high_risk"] += 1
                
                request_count += 1
                
                # Print status every 10 requests
                if request_count % 10 == 0:
                    blocked_rate = (self.stats["blocked"] / self.stats["total"]) * 100
                    high_risk_rate = (self.stats["high_risk"] / self.stats["total"]) * 100
                    
                    print(f"📊 Request {request_count:4d}: {request_data['ip']:15} {request_data['method']:4} {request_data['path'][:30]:30} | "
                          f"Score: {waf_result.get('anomaly_score', 0):.3f} | "
                          f"{'🚨 BLOCKED' if waf_result.get('blocked') else '✅ ALLOWED'} | "
                          f"Block Rate: {blocked_rate:.1f}%")
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                time.sleep(1)
        
        print(f"\n⏹️  Traffic generation stopped")
        print(f"📊 Final Statistics:")
        print(f"   Total Requests: {self.stats['total']}")
        print(f"   Blocked: {self.stats['blocked']} ({(self.stats['blocked']/max(self.stats['total'], 1))*100:.1f}%)")
        print(f"   High Risk: {self.stats['high_risk']} ({(self.stats['high_risk']/max(self.stats['total'], 1))*100:.1f}%)")
    
    def run_burst_mode(self, count=50, delay=0.5):
        """Generate a burst of traffic for testing"""
        print(f"🚀 Generating {count} requests in burst mode...")
        
        for i in range(count):
            request_data, risk_type = self.generate_request()
            waf_result = self.send_to_waf(request_data)
            self.log_request(request_data, waf_result, risk_type)
            
            self.stats["total"] += 1
            if waf_result.get('blocked', False):
                self.stats["blocked"] += 1
            if waf_result.get('anomaly_score', 0) >= 0.7:
                self.stats["high_risk"] += 1
            
            if i % 10 == 0:
                print(f"   Generated {i+1}/{count} requests...")
            
            time.sleep(delay)
        
        print(f"✅ Burst complete: {count} requests generated")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Continuous Live Traffic Generator")
    parser.add_argument("--waf-url", default="http://localhost:8000", help="WAF service URL")
    parser.add_argument("--log-file", default="./production_demo_access.log", help="Log file path")
    parser.add_argument("--interval", type=float, default=2.0, help="Request interval in seconds")
    parser.add_argument("--burst", type=int, help="Generate burst of N requests and exit")
    parser.add_argument("--burst-delay", type=float, default=0.5, help="Delay between burst requests")
    
    args = parser.parse_args()
    
    generator = ContinuousTrafficGenerator(args.waf_url, args.log_file)
    
    try:
        if args.burst:
            generator.run_burst_mode(args.burst, args.burst_delay)
        else:
            generator.generate_continuous_traffic(args.interval)
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user")

if __name__ == "__main__":
    main()
