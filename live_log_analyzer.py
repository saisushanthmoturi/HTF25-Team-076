#!/usr/bin/env python3
"""
Live WAF Log Analyzer
=====================
Real-time analysis of WAF log files with attack detection and scoring
"""

import re
import time
import json
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import threading
from collections import deque
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LiveLogAnalyzer:
    """Real-time log file analyzer with attack detection"""
    
    def __init__(self, log_file_path: str, waf_url: str = "http://localhost:8000"):
        self.log_file_path = Path(log_file_path)
        self.waf_url = waf_url
        self.last_position = 0
        self.processed_logs = deque(maxlen=1000)  # Keep last 1000 entries
        self.attack_stats = {
            'total_requests': 0,
            'attacks_detected': 0,
            'high_risk_requests': 0,
            'medium_risk_requests': 0,
            'low_risk_requests': 0,
            'attack_types': {}
        }
        
    def parse_apache_log(self, log_line: str) -> Optional[Dict]:
        """Parse Apache/Nginx common log format"""
        # Common Log Format: IP - - [timestamp] "METHOD path HTTP/1.1" status size "referer" "user_agent"
        pattern = r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+).*?" (\d{3}) (\d+) "([^"]*)" "([^"]*)"'
        match = re.match(pattern, log_line)
        
        if match:
            ip, timestamp, method, full_path, status, size, referer, user_agent = match.groups()
            
            # Parse path and query parameters
            if '?' in full_path:
                path, query_string = full_path.split('?', 1)
                query_params = self.parse_query_string(query_string)
            else:
                path = full_path
                query_params = {}
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'query_params': query_params,
                'status': int(status),
                'size': int(size),
                'referer': referer if referer != '-' else '',
                'user_agent': user_agent,
                'raw_log': log_line.strip()
            }
        return None
    
    def parse_query_string(self, query_string: str) -> Dict[str, str]:
        """Parse URL query string into dictionary"""
        params = {}
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value
            else:
                params[param] = ''
        return params
    
    def analyze_with_waf(self, request_data: Dict) -> Tuple[float, bool, Dict]:
        """Send request to WAF for analysis"""
        try:
            waf_payload = {
                'ip': request_data['ip'],
                'method': request_data['method'],
                'path': request_data['path'],
                'query_params': request_data['query_params'],
                'headers': {'User-Agent': request_data['user_agent']}
            }
            
            response = requests.post(f"{self.waf_url}/detect", 
                                   json=waf_payload, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                return (
                    result.get('anomaly_score', 0.0),
                    result.get('is_anomalous', False),
                    result
                )
            else:
                logger.warning(f"WAF service returned {response.status_code}")
                return 0.0, False, {"error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error contacting WAF service: {e}")
            return 0.0, False, {"error": str(e)}
    
    def classify_attack_type(self, request_data: Dict, score: float) -> List[str]:
        """Classify potential attack types based on request data"""
        attack_types = []
        path = request_data['path'].lower()
        query_params = str(request_data['query_params']).lower()
        user_agent = request_data['user_agent'].lower()
        
        # SQL Injection patterns
        sql_patterns = ['union', 'select', 'drop', 'insert', '--', '/*', 'or 1=1', 'or 1 = 1']
        if any(pattern in query_params or pattern in path for pattern in sql_patterns):
            attack_types.append('SQL Injection')
        
        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'alert(', 'document.cookie']
        if any(pattern in query_params or pattern in path for pattern in xss_patterns):
            attack_types.append('XSS')
        
        # Path traversal patterns
        traversal_patterns = ['../', '..\\', '/etc/passwd', '/windows/system32', '..%2f']
        if any(pattern in path for pattern in traversal_patterns):
            attack_types.append('Path Traversal')
        
        # Admin access patterns
        admin_patterns = ['/admin', '/wp-admin', '/phpmyadmin', '/administrator', '/config']
        if any(pattern in path for pattern in admin_patterns):
            attack_types.append('Admin Access')
        
        # Command injection patterns
        cmd_patterns = [';', '|', '&&', '$(', '`', 'wget', 'curl', 'nc ']
        if any(pattern in query_params for pattern in cmd_patterns):
            attack_types.append('Command Injection')
        
        # Suspicious user agents
        suspicious_ua = ['sqlmap', 'nikto', 'nessus', 'burp', 'zap', 'bot', 'crawler']
        if any(ua in user_agent for ua in suspicious_ua):
            attack_types.append('Automated Tool')
        
        return attack_types if attack_types else ['Unknown']
    
    def get_risk_level(self, score: float) -> str:
        """Determine risk level based on anomaly score"""
        if score >= 0.7:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "NORMAL"
    
    def read_new_logs(self) -> List[str]:
        """Read new log entries since last check"""
        try:
            if not self.log_file_path.exists():
                return []
            
            with open(self.log_file_path, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
            return [line.strip() for line in new_lines if line.strip()]
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
            return []
    
    def process_log_entry(self, log_line: str) -> Optional[Dict]:
        """Process a single log entry"""
        parsed = self.parse_apache_log(log_line)
        if not parsed:
            return None
        
        # Analyze with WAF
        score, is_anomalous, waf_result = self.analyze_with_waf(parsed)
        
        # Classify attack types
        attack_types = self.classify_attack_type(parsed, score)
        
        # Determine risk level
        risk_level = self.get_risk_level(score)
        
        # Update statistics
        self.attack_stats['total_requests'] += 1
        if is_anomalous:
            self.attack_stats['attacks_detected'] += 1
        
        if risk_level == "HIGH":
            self.attack_stats['high_risk_requests'] += 1
        elif risk_level == "MEDIUM":
            self.attack_stats['medium_risk_requests'] += 1
        elif risk_level == "LOW":
            self.attack_stats['low_risk_requests'] += 1
        
        for attack_type in attack_types:
            if attack_type in self.attack_stats['attack_types']:
                self.attack_stats['attack_types'][attack_type] += 1
            else:
                self.attack_stats['attack_types'][attack_type] = 1
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'log_timestamp': parsed['timestamp'],
            'ip': parsed['ip'],
            'method': parsed['method'],
            'path': parsed['path'],
            'query_params': parsed['query_params'],
            'status': parsed['status'],
            'user_agent': parsed['user_agent'],
            'anomaly_score': score,
            'is_anomalous': is_anomalous,
            'risk_level': risk_level,
            'attack_types': attack_types,
            'waf_response': waf_result,
            'raw_log': parsed['raw_log']
        }
        
        self.processed_logs.append(result)
        return result
    
    def display_analysis_result(self, result: Dict):
        """Display formatted analysis result"""
        timestamp = result['timestamp'][:19]  # Remove microseconds
        ip = result['ip']
        method = result['method']
        path = result['path'][:50] + '...' if len(result['path']) > 50 else result['path']
        score = result['anomaly_score']
        risk = result['risk_level']
        attack_types = ', '.join(result['attack_types'])
        
        # Color coding for risk levels
        risk_colors = {
            'HIGH': '🔴',
            'MEDIUM': '🟠', 
            'LOW': '🟡',
            'NORMAL': '🟢'
        }
        
        risk_icon = risk_colors.get(risk, '⚪')
        block_status = '🚨 BLOCKED' if result['is_anomalous'] else '✅ ALLOWED'
        
        print(f"{timestamp} | {ip:15} | {method:4} | {path:30} | {score:.3f} | {risk_icon} {risk:6} | {block_status} | {attack_types}")
    
    def display_statistics(self):
        """Display current statistics"""
        stats = self.attack_stats
        total = stats['total_requests']
        
        if total == 0:
            print("📊 No requests processed yet")
            return
        
        print("\n" + "="*80)
        print("📊 LIVE WAF LOG ANALYSIS STATISTICS")
        print("="*80)
        print(f"📈 Total Requests: {total:,}")
        print(f"🚨 Attacks Detected: {stats['attacks_detected']:,} ({stats['attacks_detected']/total*100:.1f}%)")
        print(f"🔴 High Risk: {stats['high_risk_requests']:,} ({stats['high_risk_requests']/total*100:.1f}%)")
        print(f"🟠 Medium Risk: {stats['medium_risk_requests']:,} ({stats['medium_risk_requests']/total*100:.1f}%)")
        print(f"🟡 Low Risk: {stats['low_risk_requests']:,} ({stats['low_risk_requests']/total*100:.1f}%)")
        
        if stats['attack_types']:
            print(f"\n🎯 Attack Types Detected:")
            for attack_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total) * 100
                print(f"   {attack_type}: {count:,} ({percentage:.1f}%)")
        
        print("="*80)
    
    def start_monitoring(self, interval: float = 2.0, show_stats_interval: int = 10):
        """Start real-time log monitoring"""
        print("🔍 Starting Live WAF Log Analysis")
        print(f"📁 Monitoring: {self.log_file_path}")
        print(f"🛡️  WAF Service: {self.waf_url}")
        print(f"⏱️  Check Interval: {interval} seconds")
        print("\n" + "="*120)
        print("TIMESTAMP           | IP ADDRESS      | METHOD | PATH                          | SCORE | RISK   | STATUS    | ATTACK TYPES")
        print("="*120)
        
        iteration = 0
        try:
            while True:
                iteration += 1
                
                # Read new log entries
                new_logs = self.read_new_logs()
                
                # Process each new log entry
                for log_line in new_logs:
                    result = self.process_log_entry(log_line)
                    if result:
                        self.display_analysis_result(result)
                
                # Show statistics periodically
                if iteration % show_stats_interval == 0:
                    self.display_statistics()
                    print("\nContinuing monitoring... (Press Ctrl+C to stop)")
                    print("="*120)
                    print("TIMESTAMP           | IP ADDRESS      | METHOD | PATH                          | SCORE | RISK   | STATUS    | ATTACK TYPES")
                    print("="*120)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
            self.display_statistics()

def main():
    """Main function to start live log analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Live WAF Log Analyzer')
    parser.add_argument('--log-file', default='/Users/moturisaisushanth/Downloads/samplewar/demo_access.log',
                       help='Path to log file to monitor')
    parser.add_argument('--waf-url', default='http://localhost:8000',
                       help='WAF service URL')
    parser.add_argument('--interval', type=float, default=2.0,
                       help='Check interval in seconds')
    
    args = parser.parse_args()
    
    analyzer = LiveLogAnalyzer(args.log_file, args.waf_url)
    analyzer.start_monitoring(args.interval)

if __name__ == "__main__":
    main()
