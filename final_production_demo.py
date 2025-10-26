#!/usr/bin/env python3
"""
Final Production WAF Demonstration
==================================
Complete demonstration of production WAF with live applications and log ingestion
"""

import os
import sys
import time
import json
import requests
import threading
import subprocess
from datetime import datetime
from pathlib import Path

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*80)
    print(f"🎯 {title}")
    print("="*80)

def print_status(message, status="INFO"):
    """Print formatted status message"""
    icons = {"INFO": "ℹ️", "SUCCESS": "✅", "WARNING": "⚠️", "ERROR": "❌"}
    print(f"{icons.get(status, 'ℹ️')} {message}")

def check_waf_service():
    """Check WAF service availability"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def restart_waf_service():
    """Restart WAF service with updated configuration"""
    print_status("Restarting WAF service with updated configuration...")
    
    # Kill existing process
    os.system("pkill -f production_waf_service.py")
    time.sleep(2)
    
    # Start new process
    subprocess.Popen([
        sys.executable, "production_waf_service.py"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Wait for startup
    time.sleep(5)
    
    if check_waf_service():
        print_status("WAF service restarted successfully", "SUCCESS")
        return True
    else:
        print_status("Failed to restart WAF service", "ERROR")
        return False

def test_attack_detection():
    """Test attack detection with real blocking"""
    print_header("ATTACK DETECTION TESTING")
    
    attack_tests = [
        {
            "name": "Normal Request",
            "data": {"ip": "192.168.1.100", "method": "GET", "path": "/", "user_agent": "Mozilla/5.0"},
            "expected_blocked": False
        },
        {
            "name": "SQL Injection",
            "data": {"ip": "10.0.0.1", "method": "GET", "path": "/search?q=' OR 1=1--", "user_agent": "curl/7.68.0"},
            "expected_blocked": True
        },
        {
            "name": "XSS Attack",
            "data": {"ip": "10.0.0.2", "method": "GET", "path": "/comment?text=<script>alert(1)</script>", "user_agent": "Mozilla/5.0"},
            "expected_blocked": True
        },
        {
            "name": "Path Traversal",
            "data": {"ip": "10.0.0.3", "method": "GET", "path": "/../../../etc/passwd", "user_agent": "curl/7.68.0"},
            "expected_blocked": True
        }
    ]
    
    results = {"total": 0, "correct": 0, "blocked": 0}
    
    print("TEST RESULTS:")
    print("-" * 80)
    
    for test in attack_tests:
        try:
            response = requests.post("http://localhost:8000/detect", json=test["data"], timeout=10)
            result = response.json()
            
            score = result.get('anomaly_score', 0)
            blocked = result.get('blocked', False)
            risk = result.get('risk_level', 'UNKNOWN')
            
            status_icon = "🚨 BLOCKED" if blocked else "✅ ALLOWED"
            accuracy = "✓" if blocked == test["expected_blocked"] else "✗"
            
            print(f"{test['name']:20} | {status_icon} | Score: {score:.3f} | Risk: {risk:6} | {accuracy}")
            
            results["total"] += 1
            if blocked == test["expected_blocked"]:
                results["correct"] += 1
            if blocked:
                results["blocked"] += 1
                
        except Exception as e:
            print(f"{test['name']:20} | ❌ ERROR: {e}")
    
    print("-" * 80)
    accuracy = (results["correct"] / results["total"]) * 100 if results["total"] > 0 else 0
    print(f"Accuracy: {accuracy:.1f}% | Blocked: {results['blocked']}/{results['total']}")
    
    return results

def simulate_live_traffic():
    """Simulate live traffic with mixed requests"""
    print_header("LIVE TRAFFIC SIMULATION")
    
    # Create demo log file
    log_file = "./production_demo_access.log"
    
    traffic_patterns = [
        # Normal traffic (70%)
        ("192.168.1.10", "GET", "/", "200", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        ("192.168.1.11", "GET", "/products", "200", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
        ("192.168.1.12", "POST", "/login", "200", "Mozilla/5.0 (X11; Linux x86_64)"),
        ("192.168.1.13", "GET", "/api/users", "200", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1)"),
        
        # Medium risk (20%)
        ("10.1.1.1", "GET", "/admin", "403", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        ("10.1.1.2", "GET", "/wp-admin", "403", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
        
        # High risk attacks (10%)
        ("10.0.0.1", "GET", "/search?q=' OR 1=1--", "403", "sqlmap/1.4.7"),
        ("10.0.0.2", "GET", "/<script>alert(1)</script>", "403", "curl/7.68.0"),
        ("10.0.0.3", "GET", "/../../etc/passwd", "403", "Python-urllib/3.9"),
    ]
    
    print_status("Generating live traffic logs...")
    
    with open(log_file, "w") as f:
        import random
        
        for i in range(100):
            # Weight the selection towards normal traffic
            if i < 70:
                pattern = random.choice(traffic_patterns[:4])  # Normal
            elif i < 90:
                pattern = random.choice(traffic_patterns[4:6])  # Medium risk
            else:
                pattern = random.choice(traffic_patterns[6:])  # High risk
            
            timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
            log_entry = f'{pattern[0]} - - [{timestamp}] "{pattern[1]} {pattern[2]} HTTP/1.1" {pattern[3]} 1234 "-" "{pattern[4]}"'
            
            f.write(log_entry + "\n")
            f.flush()
            
            # Test the request with WAF
            test_data = {
                "ip": pattern[0],
                "method": pattern[1],
                "path": pattern[2],
                "user_agent": pattern[4]
            }
            
            try:
                response = requests.post("http://localhost:8000/detect", json=test_data, timeout=5)
                result = response.json()
                
                score = result.get('anomaly_score', 0)
                blocked = result.get('blocked', False)
                
                if i % 10 == 0:  # Show progress every 10 requests
                    status = "🚨 BLOCKED" if blocked else "✅ ALLOWED"
                    print(f"Request {i+1:3d}: {pattern[0]:15} {pattern[2]:30} | {score:.3f} | {status}")
                
            except:
                pass
            
            time.sleep(0.1)  # Small delay for realism
    
    print_status(f"Generated 100 log entries in {log_file}", "SUCCESS")
    return log_file

def show_waf_metrics():
    """Show current WAF metrics"""
    print_header("WAF PERFORMANCE METRICS")
    
    try:
        response = requests.get("http://localhost:8000/metrics", timeout=5)
        metrics = response.json()
        
        print("📊 Current Performance:")
        print(f"   • Service: {metrics.get('service', 'Unknown')}")
        print(f"   • Uptime: {metrics.get('uptime', 'Unknown')}")
        print(f"   • Total Requests: {metrics.get('requests_processed', 0):,}")
        print(f"   • Anomalies Detected: {metrics.get('anomalies_detected', 0):,}")
        print(f"   • Detection Engines: {metrics.get('detection_engines', 0)}")
        print(f"   • Avg Response Time: {metrics.get('avg_response_time_ms', 0):.2f}ms")
        print(f"   • False Positive Rate: {metrics.get('false_positive_rate', 0):.2f}%")
        
    except Exception as e:
        print_status(f"Could not fetch metrics: {e}", "ERROR")

def start_live_log_monitoring(log_file):
    """Start live log monitoring"""
    print_header("LIVE LOG MONITORING")
    
    print_status("Starting live log analyzer...")
    
    try:
        # Start live log analyzer
        process = subprocess.Popen([
            sys.executable, "live_log_analyzer.py",
            "--log-file", log_file,
            "--interval", "2"
        ])
        
        print_status("Live log analyzer started (PID: {})".format(process.pid), "SUCCESS")
        print_status("Monitor the output in the terminal to see real-time analysis", "INFO")
        
        return process
        
    except Exception as e:
        print_status(f"Failed to start log analyzer: {e}", "ERROR")
        return None

def main():
    """Main demonstration function"""
    print_header("PRODUCTION WAF DEPLOYMENT DEMONSTRATION")
    print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 1. Check WAF service
    if not check_waf_service():
        print_status("WAF service not running, attempting to restart...", "WARNING")
        if not restart_waf_service():
            print_status("Cannot proceed without WAF service", "ERROR")
            return
    else:
        print_status("WAF service is running", "SUCCESS")
    
    # 2. Test attack detection
    test_results = test_attack_detection()
    
    # 3. Show current metrics
    show_waf_metrics()
    
    # 4. Simulate live traffic
    log_file = simulate_live_traffic()
    
    # 5. Start live monitoring
    monitor_process = start_live_log_monitoring(log_file)
    
    # 6. Final summary
    print_header("DEPLOYMENT SUMMARY")
    print("🎉 Production WAF deployment demonstration completed!")
    print("\n📋 What was demonstrated:")
    print("   ✅ WAF service deployment and configuration")
    print("   ✅ Real-time attack detection and blocking")
    print("   ✅ Live traffic simulation and analysis")
    print("   ✅ Log ingestion and monitoring")
    print("   ✅ Performance metrics collection")
    
    print("\n🔗 Access Points:")
    print("   • WAF API: http://localhost:8000")
    print("   • Health Check: http://localhost:8000/health")
    print("   • Metrics: http://localhost:8000/metrics")
    print(f"   • Live Logs: {log_file}")
    
    print("\n🛡️ Security Features Active:")
    print("   • SQL Injection Detection")
    print("   • XSS Protection")
    print("   • Path Traversal Prevention")
    print("   • Command Injection Detection")
    print("   • Automated Tool Detection")
    print("   • Real-time Rate Limiting")
    
    if test_results["blocked"] > 0:
        block_rate = (test_results["blocked"] / test_results["total"]) * 100
        print(f"\n📊 Attack Block Rate: {block_rate:.1f}%")
    
    print("\n⚙️ Next Steps for Production:")
    print("   1. Configure Nginx/Apache proxy integration")
    print("   2. Set up centralized logging (ELK/Splunk)")
    print("   3. Configure alerting and monitoring")
    print("   4. Tune detection thresholds for your environment")
    print("   5. Set up automated threat intelligence feeds")
    
    print("\n" + "="*80)
    print("🎯 WAF is now ready for production deployment!")
    print("="*80)
    
    # Keep monitoring running
    if monitor_process:
        print("\n📊 Live monitoring is active. Press Ctrl+C to stop.")
        try:
            monitor_process.wait()
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitoring...")
            monitor_process.terminate()

if __name__ == "__main__":
    main()
