#!/usr/bin/env python3
"""
Real-time WAF Metrics Monitor
============================
Continuously monitors and displays attack prevention ratios
"""

import requests
import json
import time
from datetime import datetime
import sys

class WAFMetricsMonitor:
    def __init__(self, waf_url="http://localhost:8000"):
        self.waf_url = waf_url
        self.previous_metrics = {}
    
    def get_current_metrics(self):
        """Get current WAF metrics"""
        try:
            response = requests.get(f"{self.waf_url}/metrics", timeout=5)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_prevention_stats(self, metrics):
        """Calculate prevention statistics from metrics"""
        if not metrics or 'error' in metrics:
            return None
        
        total_requests = metrics.get('requests_processed', 0)
        anomalies_detected = metrics.get('anomalies_detected', 0)
        false_positive_rate = metrics.get('false_positive_rate', 0)
        
        if total_requests > 0:
            detection_rate = (anomalies_detected / total_requests) * 100
            legitimate_rate = 100 - detection_rate
        else:
            detection_rate = 0
            legitimate_rate = 0
        
        return {
            'total_requests': total_requests,
            'anomalies_detected': anomalies_detected,
            'detection_rate': detection_rate,
            'false_positive_rate': false_positive_rate,
            'legitimate_rate': legitimate_rate,
            'avg_response_time': metrics.get('avg_response_time_ms', 0)
        }
    
    def display_metrics(self, stats):
        """Display formatted metrics"""
        if not stats:
            print("❌ Unable to retrieve metrics")
            return
        
        print(f"\n🛡️  WAF METRICS - {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 50)
        print(f"📊 Total Requests: {stats['total_requests']:,}")
        print(f"🚨 Anomalies Detected: {stats['anomalies_detected']:,}")
        print(f"🎯 Detection Rate: {stats['detection_rate']:.1f}%")
        print(f"⚠️  False Positive Rate: {stats['false_positive_rate']:.1f}%")
        print(f"✅ Legitimate Traffic: {stats['legitimate_rate']:.1f}%")
        print(f"⏱️  Avg Response Time: {stats['avg_response_time']:.1f}ms")
        
        # Show prevention effectiveness
        if stats['detection_rate'] > 0:
            effectiveness = 100 - stats['false_positive_rate']
            print(f"🛡️  Prevention Effectiveness: {effectiveness:.1f}%")
    
    def run_continuous_monitoring(self, interval=5, duration=60):
        """Run continuous monitoring for specified duration"""
        print("🔍 Starting WAF Metrics Monitoring...")
        print(f"📍 Monitoring URL: {self.waf_url}")
        print(f"⏱️  Update Interval: {interval} seconds")
        print(f"🕐 Duration: {duration} seconds")
        
        start_time = time.time()
        iteration = 0
        
        try:
            while time.time() - start_time < duration:
                iteration += 1
                print(f"\n📈 Update #{iteration}")
                
                metrics = self.get_current_metrics()
                stats = self.calculate_prevention_stats(metrics)
                self.display_metrics(stats)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
        
        print(f"\n✅ Monitoring completed after {iteration} updates")

if __name__ == "__main__":
    monitor = WAFMetricsMonitor()
    
    # Show current snapshot
    print("📊 CURRENT WAF METRICS SNAPSHOT")
    print("=" * 40)
    metrics = monitor.get_current_metrics()
    stats = monitor.calculate_prevention_stats(metrics)
    monitor.display_metrics(stats)
    
    # Ask user if they want continuous monitoring
    response = input("\n🔄 Run continuous monitoring? (y/n): ").lower().strip()
    if response in ['y', 'yes']:
        monitor.run_continuous_monitoring(interval=3, duration=30)
