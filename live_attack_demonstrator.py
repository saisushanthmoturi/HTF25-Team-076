#!/usr/bin/env python3
"""
Live WAF Attack Demonstrator
============================
Demonstrates real-time attack detection against Tomcat applications
with live dashboard updates for judges
"""

import requests
import time
import json
import threading
from datetime import datetime
import random
import subprocess
import os

class LiveAttackDemonstrator:
    """Demonstrates live attacks against Tomcat applications"""
    
    def __init__(self):
        self.tomcat_base = "http://localhost:8080"
        self.waf_service = "http://localhost:8000"  # If WAF proxy is running
        self.attack_log = []
        self.demo_running = True
        
    def log_attack(self, attack_type, url, status_code, blocked=False):
        """Log attack attempt with timestamp"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'url': url,
            'status_code': status_code,
            'blocked': blocked,
            'source_ip': f"192.168.1.{random.randint(100, 255)}"
        }
        self.attack_log.append(entry)
        
        # Write to log file for dashboard consumption
        with open("live_attack_log.json", "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        # Also write in Apache log format for live_log_analyzer
        apache_entry = f'{entry["source_ip"]} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {url} HTTP/1.1" {status_code} 1024 "-" "AttackBot/1.0"\n'
        with open("demo_access.log", "a") as f:
            f.write(apache_entry)
    
    def test_ecommerce_attacks(self):
        """Test attacks against ecommerce application"""
        base_url = f"{self.tomcat_base}/ecommerce-app"
        
        attacks = [
            ("SQL Injection", "/search.jsp?query=' OR 1=1--"),
            ("XSS Attack", "/search.jsp?query=<script>alert('xss')</script>"),
            ("Path Traversal", "/../../../etc/passwd"),
            ("Admin Bypass", "/admin.jsp?user=admin' OR '1'='1"),
            ("Command Injection", "/search.jsp?query=; cat /etc/passwd"),
            ("File Inclusion", "/index.jsp?page=../../../etc/passwd"),
        ]
        
        for attack_type, payload in attacks:
            try:
                url = base_url + payload
                print(f"🎯 Testing {attack_type}: {url}")
                
                response = requests.get(url, timeout=5)
                blocked = response.status_code in [403, 406, 500] or "blocked" in response.text.lower()
                
                self.log_attack(attack_type, url, response.status_code, blocked)
                
                if blocked:
                    print(f"   🚫 BLOCKED - Status: {response.status_code}")
                else:
                    print(f"   ⚠️  PASSED - Status: {response.status_code}")
                    
                time.sleep(2)
                
            except Exception as e:
                print(f"   ❌ ERROR: {e}")
                self.log_attack(attack_type, url, 0, False)
    
    def test_rest_api_attacks(self):
        """Test attacks against REST API application"""
        base_url = f"{self.tomcat_base}/rest-api-app"
        
        attacks = [
            ("SQL Injection", "/api/users?id=' OR 1=1--"),
            ("XSS Attack", "/api/search?q=<script>alert('xss')</script>"),
            ("Path Traversal", "/api/../../../etc/passwd"),
            ("JSON Injection", "/api/users"),  # Will be POST with malicious JSON
            ("API Abuse", "/api/admin/users?delete=*"),
        ]
        
        for attack_type, payload in attacks:
            try:
                url = base_url + payload
                print(f"🎯 Testing {attack_type}: {url}")
                
                if attack_type == "JSON Injection":
                    # POST request with malicious JSON
                    malicious_json = {"user": "admin", "password": "' OR '1'='1", "cmd": "; rm -rf /"}
                    response = requests.post(url, json=malicious_json, timeout=5)
                else:
                    response = requests.get(url, timeout=5)
                
                blocked = response.status_code in [403, 406, 500] or "blocked" in response.text.lower()
                
                self.log_attack(attack_type, url, response.status_code, blocked)
                
                if blocked:
                    print(f"   🚫 BLOCKED - Status: {response.status_code}")
                else:
                    print(f"   ⚠️  PASSED - Status: {response.status_code}")
                    
                time.sleep(2)
                
            except Exception as e:
                print(f"   ❌ ERROR: {e}")
                self.log_attack(attack_type, url, 0, False)
    
    def simulate_normal_traffic(self):
        """Simulate normal user traffic"""
        normal_requests = [
            f"{self.tomcat_base}/ecommerce-app/",
            f"{self.tomcat_base}/ecommerce-app/products.jsp",
            f"{self.tomcat_base}/ecommerce-app/search.jsp?query=laptop",
            f"{self.tomcat_base}/rest-api-app/api/products",
            f"{self.tomcat_base}/rest-api-app/api/users",
        ]
        
        for url in normal_requests:
            try:
                print(f"✅ Normal request: {url}")
                response = requests.get(url, timeout=5)
                self.log_attack("Normal Traffic", url, response.status_code, False)
                time.sleep(1)
            except Exception as e:
                print(f"   ❌ ERROR: {e}")
    
    def start_continuous_demo(self):
        """Start continuous attack demonstration"""
        print("🎬 Starting Live WAF Attack Demonstration")
        print("=" * 60)
        
        while self.demo_running:
            try:
                print(f"\n🕐 {datetime.now().strftime('%H:%M:%S')} - Running attack simulation cycle...")
                
                # Normal traffic
                print("\n📊 Simulating normal traffic...")
                self.simulate_normal_traffic()
                
                # Ecommerce attacks
                print("\n🛒 Testing ecommerce application attacks...")
                self.test_ecommerce_attacks()
                
                # REST API attacks
                print("\n🔌 Testing REST API attacks...")
                self.test_rest_api_attacks()
                
                # Summary
                total_attacks = len([entry for entry in self.attack_log if entry['attack_type'] != 'Normal Traffic'])
                blocked_attacks = len([entry for entry in self.attack_log if entry['blocked']])
                
                print(f"\n📈 Session Summary:")
                print(f"   Total Attacks: {total_attacks}")
                print(f"   Blocked: {blocked_attacks}")
                print(f"   Success Rate: {(blocked_attacks/total_attacks*100) if total_attacks > 0 else 0:.1f}%")
                
                print(f"\n⏳ Waiting 30 seconds before next cycle...")
                time.sleep(30)
                
            except KeyboardInterrupt:
                self.demo_running = False
                print("\n🛑 Demo stopped by user")
                break
            except Exception as e:
                print(f"❌ Demo error: {e}")
                time.sleep(5)
    
    def generate_demo_report(self):
        """Generate attack demonstration report"""
        if not self.attack_log:
            return
            
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_requests': len(self.attack_log),
            'attack_types': {},
            'blocked_attacks': 0,
            'success_rate': 0
        }
        
        for entry in self.attack_log:
            attack_type = entry['attack_type']
            if attack_type not in report['attack_types']:
                report['attack_types'][attack_type] = {'total': 0, 'blocked': 0}
            
            report['attack_types'][attack_type]['total'] += 1
            if entry['blocked']:
                report['attack_types'][attack_type]['blocked'] += 1
                report['blocked_attacks'] += 1
        
        if report['total_requests'] > 0:
            report['success_rate'] = (report['blocked_attacks'] / report['total_requests']) * 100
        
        with open("attack_demo_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("\n📊 Attack Demonstration Report Generated")
        print(json.dumps(report, indent=2))

def main():
    """Main demonstration function"""
    print("🎯 LIVE WAF ATTACK DEMONSTRATION FOR JUDGES")
    print("=" * 60)
    print("This script demonstrates live attacks against Tomcat applications")
    print("and shows real-time WAF protection for judges to evaluate.")
    print("=" * 60)
    
    # Check if Tomcat is running
    try:
        response = requests.get("http://localhost:8080", timeout=5)
        print("✅ Tomcat server is running")
    except:
        print("❌ Tomcat server is not running. Please start it first:")
        print("   brew services start tomcat")
        return
    
    # Check applications
    apps = [
        ("Ecommerce App", "http://localhost:8080/ecommerce-app/"),
        ("REST API App", "http://localhost:8080/rest-api-app/")
    ]
    
    for name, url in apps:
        try:
            response = requests.get(url, timeout=5)
            print(f"✅ {name} is accessible")
        except:
            print(f"⚠️  {name} may not be fully deployed")
    
    print("\n🚀 Starting live attack demonstration...")
    print("💡 Tip: Start the WAF dashboard to see real-time detection:")
    print("   streamlit run transformer_waf_dashboard.py")
    print("   python live_log_analyzer.py")
    
    demonstrator = LiveAttackDemonstrator()
    
    try:
        demonstrator.start_continuous_demo()
    finally:
        demonstrator.generate_demo_report()

if __name__ == "__main__":
    main()
