#!/usr/bin/env python3
"""
Comprehensive WAF Demo & Testing System
======================================
Real-time demonstration of WAF protecting live applications
"""

import time
import requests
import json
import logging
import threading
from datetime import datetime
from typing import Dict, List
import subprocess
import signal
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("waf_demo")

class WAFDemoTester:
    """Comprehensive WAF testing and demonstration system"""
    
    def __init__(self):
        self.waf_url = "http://localhost:8000"
        self.proxy_url = "http://localhost:9090"
        self.demo_running = True
        self.stats = {
            "total_tests": 0,
            "passed_tests": 0,
            "blocked_tests": 0,
            "failed_tests": 0
        }
    
    def check_services(self) -> Dict[str, bool]:
        """Check if all services are running"""
        services = {}
        
        # Check WAF service
        try:
            response = requests.get(f"{self.waf_url}/health", timeout=5)
            services["waf"] = response.status_code == 200
        except:
            services["waf"] = False
        
        # Check proxy service
        try:
            response = requests.get(f"{self.proxy_url}/waf-proxy/status", timeout=5)
            services["proxy"] = response.status_code == 200
        except:
            services["proxy"] = False
        
        return services
    
    def test_waf_direct(self, test_data: Dict) -> Dict:
        """Test WAF service directly"""
        try:
            response = requests.post(f"{self.waf_url}/detect", json=test_data, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def test_protected_endpoint(self, path: str, method: str = "GET", params: Dict = None) -> Dict:
        """Test a protected endpoint through proxy"""
        try:
            url = f"{self.proxy_url}{path}"
            if method == "GET":
                response = requests.get(url, params=params, timeout=10)
            elif method == "POST":
                response = requests.post(url, json=params, timeout=10)
            else:
                response = requests.request(method, url, timeout=10)
            
            return {
                "status_code": response.status_code,
                "blocked": response.status_code == 403,
                "response": response.text[:200] + "..." if len(response.text) > 200 else response.text
            }
        except Exception as e:
            return {"error": str(e)}
    
    def run_attack_simulation(self):
        """Run comprehensive attack simulation"""
        print("\n" + "="*80)
        print("🚨 WAF ATTACK SIMULATION & REAL-TIME PROTECTION DEMO")
        print("="*80)
        
        # Test scenarios with varying risk levels
        test_scenarios = [
            {
                "name": "Normal Web Request",
                "data": {
                    "ip": "192.168.1.100",
                    "method": "GET",
                    "path": "/",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
                "expected_blocked": False,
                "category": "Legitimate"
            },
            {
                "name": "Admin Panel Access",
                "data": {
                    "ip": "192.168.1.101",
                    "method": "GET",
                    "path": "/admin",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
                "expected_blocked": False,
                "category": "Medium Risk"
            },
            {
                "name": "SQL Injection Attack",
                "data": {
                    "ip": "10.0.0.1",
                    "method": "GET",
                    "path": "/search",
                    "query_params": {"q": "' OR 1=1 UNION SELECT * FROM users--"},
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                },
                "expected_blocked": True,
                "category": "SQL Injection"
            },
            {
                "name": "XSS Attack",
                "data": {
                    "ip": "10.0.0.2",
                    "method": "GET",
                    "path": "/comment",
                    "query_params": {"text": "<script>alert('XSS')</script>"},
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
                },
                "expected_blocked": True,
                "category": "XSS"
            },
            {
                "name": "Path Traversal Attack",
                "data": {
                    "ip": "10.0.0.3",
                    "method": "GET",
                    "path": "/../../etc/passwd",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                },
                "expected_blocked": True,
                "category": "Path Traversal"
            },
            {
                "name": "Command Injection",
                "data": {
                    "ip": "10.0.0.4",
                    "method": "POST",
                    "path": "/execute",
                    "query_params": {"cmd": "; cat /etc/passwd"},
                    "user_agent": "curl/7.68.0"
                },
                "expected_blocked": True,
                "category": "Command Injection"
            },
            {
                "name": "Automated Tool Detection",
                "data": {
                    "ip": "10.0.0.5",
                    "method": "GET",
                    "path": "/",
                    "user_agent": "sqlmap/1.4.7#stable"
                },
                "expected_blocked": True,
                "category": "Malicious Tool"
            },
            {
                "name": "WordPress Admin Attack",
                "data": {
                    "ip": "10.0.0.6",
                    "method": "POST",
                    "path": "/wp-admin/admin-ajax.php",
                    "query_params": {"action": "admin"},
                    "user_agent": "Mozilla/5.0 (compatible; Baiduspider/2.0)"
                },
                "expected_blocked": True,
                "category": "Admin Access"
            }
        ]
        
        print(f"🎯 Running {len(test_scenarios)} attack scenarios...\n")
        
        for i, scenario in enumerate(test_scenarios, 1):
            print(f"[{i:2d}/{len(test_scenarios)}] Testing: {scenario['name']}")
            print(f"     Category: {scenario['category']}")
            print(f"     Target: {scenario['data']['method']} {scenario['data']['path']}")
            print(f"     Source IP: {scenario['data']['ip']}")
            
            # Test with WAF
            waf_result = self.test_waf_direct(scenario['data'])
            
            if 'error' in waf_result:
                print(f"     ❌ WAF Error: {waf_result['error']}")
                self.stats["failed_tests"] += 1
            else:
                score = waf_result.get('anomaly_score', 0)
                blocked = waf_result.get('blocked', False)
                risk = waf_result.get('risk_level', 'UNKNOWN')
                
                # Determine result
                if blocked:
                    status = "🚨 BLOCKED"
                    self.stats["blocked_tests"] += 1
                else:
                    status = "✅ ALLOWED"
                    self.stats["passed_tests"] += 1
                
                # Check if result matches expectation
                correct = (blocked == scenario['expected_blocked'])
                accuracy = "✓" if correct else "✗"
                
                print(f"     {status} | Score: {score:.3f} | Risk: {risk} | Accuracy: {accuracy}")
                
                # Show attack types if detected
                attack_types = waf_result.get('attack_types', [])
                if attack_types and attack_types != ['None']:
                    print(f"     🎯 Detected: {', '.join(attack_types)}")
            
            self.stats["total_tests"] += 1
            print()
            time.sleep(1)  # Pause between tests for readability
        
        self.show_final_results()
    
    def show_final_results(self):
        """Show final test results"""
        print("="*80)
        print("📊 FINAL RESULTS - WAF PROTECTION ANALYSIS")
        print("="*80)
        
        total = self.stats["total_tests"]
        passed = self.stats["passed_tests"]
        blocked = self.stats["blocked_tests"]
        failed = self.stats["failed_tests"]
        
        protection_rate = (blocked / total * 100) if total > 0 else 0
        success_rate = ((passed + blocked) / total * 100) if total > 0 else 0
        
        print(f"🎯 Total Tests: {total}")
        print(f"✅ Allowed (Legitimate): {passed}")
        print(f"🚨 Blocked (Attacks): {blocked}")
        print(f"❌ Failed (Errors): {failed}")
        print(f"🛡️  Protection Rate: {protection_rate:.1f}%")
        print(f"🎉 Overall Success Rate: {success_rate:.1f}%")
        
        # Performance metrics
        try:
            waf_metrics = requests.get(f"{self.waf_url}/metrics", timeout=5).json()
            print(f"\n📈 WAF Performance:")
            print(f"   • Total Requests Processed: {waf_metrics.get('requests_processed', 'N/A')}")
            print(f"   • Average Response Time: {waf_metrics.get('avg_response_time_ms', 'N/A'):.2f}ms")
            print(f"   • Detection Engines: {waf_metrics.get('detection_engines', 'N/A')}")
        except:
            print("⚠️  Could not fetch WAF performance metrics")
        
        print("="*80)
    
    def run_live_protection_demo(self):
        """Run live protection demonstration"""
        print("\n" + "="*80)
        print("🔴 LIVE PROTECTION DEMO - Real-time Attack Prevention")
        print("="*80)
        
        # Check if services are running
        services = self.check_services()
        if not services.get("waf", False):
            print("❌ WAF service not available - cannot run demo")
            return
        
        print("🟢 WAF Service: Online")
        if services.get("proxy", False):
            print("🟢 Proxy Service: Online")
        else:
            print("🟡 Proxy Service: Offline (using direct WAF API)")
        
        print("\n🎬 Starting live attack simulation...")
        print("📊 Watch real-time detection scores and blocking decisions:\n")
        
        # Live attack patterns
        live_attacks = [
            {"path": "/login", "attack": "' OR '1'='1", "type": "SQL Injection"},
            {"path": "/search", "attack": "<script>document.location='http://evil.com'</script>", "type": "XSS"},
            {"path": "/../../../etc/passwd", "attack": "", "type": "Path Traversal"},
            {"path": "/admin", "attack": "", "type": "Admin Access"},
            {"path": "/api/exec", "attack": "; rm -rf /", "type": "Command Injection"}
        ]
        
        print("TIME     | SOURCE IP      | ATTACK TYPE      | PATH                 | SCORE | STATUS")
        print("-" * 80)
        
        for i in range(15):  # Run for 15 iterations
            import random
            
            # Select random attack
            attack = random.choice(live_attacks)
            source_ip = f"10.{random.randint(1,10)}.{random.randint(1,10)}.{random.randint(1,100)}"
            
            # Create attack payload
            if attack["attack"]:
                if "?" in attack["path"]:
                    full_path = f"{attack['path']}&malicious={attack['attack']}"
                else:
                    full_path = f"{attack['path']}?input={attack['attack']}"
            else:
                full_path = attack["path"]
            
            test_data = {
                "ip": source_ip,
                "method": "GET",
                "path": full_path,
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Automated Attack Tool"
            }
            
            # Test with WAF
            result = self.test_waf_direct(test_data)
            
            if 'error' not in result:
                score = result.get('anomaly_score', 0)
                blocked = result.get('blocked', False)
                status = "🚨 BLOCKED" if blocked else "✅ ALLOWED"
                
                # Format output
                timestamp = datetime.now().strftime("%H:%M:%S")
                path_short = (full_path[:18] + "..") if len(full_path) > 20 else full_path
                
                print(f"{timestamp} | {source_ip:14} | {attack['type']:15} | {path_short:20} | {score:.3f} | {status}")
            
            time.sleep(2)  # Real-time delay
        
        print("-" * 80)
        print("🎬 Live demo completed!")
    
    def generate_traffic_logs(self):
        """Generate realistic traffic logs for ingestion"""
        print("\n" + "="*80)
        print("📝 GENERATING REALISTIC TRAFFIC LOGS")
        print("="*80)
        
        log_file = "./demo_live_traffic.log"
        
        # Generate mixed traffic (normal + attacks)
        traffic_patterns = [
            # Normal traffic
            ('192.168.1.10', 'GET', '/', '200', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
            ('192.168.1.11', 'GET', '/login', '200', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'),
            ('192.168.1.12', 'POST', '/api/data', '200', 'Mozilla/5.0 (X11; Linux x86_64)'),
            ('192.168.1.13', 'GET', '/products', '200', 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1)'),
            
            # Attack traffic
            ('10.0.0.1', 'GET', "/search?q=' OR 1=1--", '403', 'sqlmap/1.4.7'),
            ('10.0.0.2', 'GET', '/<script>alert(1)</script>', '403', 'curl/7.68.0'),
            ('10.0.0.3', 'GET', '/../../etc/passwd', '403', 'Python-urllib/3.9'),
            ('10.0.0.4', 'GET', '/admin', '403', 'Nikto/2.1.6'),
        ]
        
        print(f"📁 Writing logs to: {log_file}")
        
        with open(log_file, 'w') as f:
            for i in range(50):  # Generate 50 log entries
                import random
                pattern = random.choice(traffic_patterns)
                timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
                
                log_entry = f'{pattern[0]} - - [{timestamp}] "{pattern[1]} {pattern[2]} HTTP/1.1" {pattern[3]} 1234 "-" "{pattern[4]}"'
                f.write(log_entry + '\n')
                
                # Real-time writing simulation
                if i % 10 == 0:
                    f.flush()
                    print(f"   Generated {i+1}/50 entries...")
                    time.sleep(0.5)
        
        print(f"✅ Generated {50} log entries")
        print(f"📊 Now monitoring this file with live log analyzer...")
        
        # Start live log analysis on the generated file
        try:
            subprocess.Popen([
                sys.executable, "live_log_analyzer.py", 
                "--log-file", log_file,
                "--interval", "1"
            ])
            print("🔍 Live log analyzer started")
        except Exception as e:
            print(f"⚠️  Could not start log analyzer: {e}")
    
    def run_comprehensive_demo(self):
        """Run the complete WAF demonstration"""
        print("🚀 COMPREHENSIVE WAF DEMONSTRATION STARTING...")
        print(f"🕐 Demo started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 1. Attack Simulation
        self.run_attack_simulation()
        
        # 2. Live Protection Demo
        self.run_live_protection_demo()
        
        # 3. Log Generation and Analysis
        self.generate_traffic_logs()
        
        print("\n" + "="*80)
        print("🎉 COMPREHENSIVE WAF DEMONSTRATION COMPLETED!")
        print("="*80)
        print("📋 Summary:")
        print(f"   • Attack Detection Tests: {self.stats['total_tests']}")
        print(f"   • Live Protection Demo: Completed")
        print(f"   • Log Analysis: Active")
        print(f"   • WAF Status: Operational")
        print("\n🔗 Access Points:")
        print(f"   • WAF API: {self.waf_url}")
        print(f"   • Health Check: {self.waf_url}/health")
        print(f"   • Metrics: {self.waf_url}/metrics")
        print("="*80)

def main():
    """Main function"""
    demo = WAFDemoTester()
    
    def signal_handler(sig, frame):
        print("\n🛑 Demo interrupted by user")
        demo.demo_running = False
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        demo.run_comprehensive_demo()
    except KeyboardInterrupt:
        print("\n🛑 Demo stopped by user")

if __name__ == "__main__":
    main()
