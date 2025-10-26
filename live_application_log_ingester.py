#!/usr/bin/env python3
"""
Live Application Log Ingester
=============================
Real-time log ingestion from actual applications with WAF integration
"""

import os
import re
import time
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import asyncio
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("log_ingester")

class LogEventHandler(FileSystemEventHandler):
    """File system event handler for log file changes"""
    
    def __init__(self, log_processor):
        self.log_processor = log_processor
        
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and event.src_path.endswith('.log'):
            self.log_processor.process_new_logs(event.src_path)

class LiveLogProcessor:
    """Live log processing and WAF integration"""
    
    def __init__(self, waf_url: str = "http://localhost:8000"):
        self.waf_url = waf_url
        self.log_positions = {}  # Track file positions
        self.stats = {
            "total_entries": 0,
            "waf_analyzed": 0,
            "threats_detected": 0,
            "last_update": None
        }
        
        # Common log patterns
        self.log_patterns = {
            'apache_combined': re.compile(
                r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
                r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ),
            'nginx_access': re.compile(
                r'(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
                r'(?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
            ),
            'tomcat_access': re.compile(
                r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
                r'(?P<status>\d+) (?P<size>\d+)'
            ),
            'simple': re.compile(
                r'(?P<timestamp>\S+ \S+) (?P<level>\S+) (?P<ip>\S+) '
                r'(?P<method>\S+) (?P<path>\S+) (?P<status>\d+)'
            )
        }
        
        # Create output directories
        self.create_output_dirs()
        
    def create_output_dirs(self):
        """Create output directories for processed logs"""
        dirs = ['./waf_logs', './waf_logs/threats', './waf_logs/metrics']
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
    
    def parse_log_entry(self, line: str) -> Optional[Dict]:
        """Parse a log entry using various patterns"""
        line = line.strip()
        if not line:
            return None
        
        for pattern_name, pattern in self.log_patterns.items():
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                data['pattern'] = pattern_name
                data['raw_line'] = line
                return data
        
        # Fallback: try to extract basic info
        parts = line.split()
        if len(parts) >= 6:
            try:
                return {
                    'ip': parts[0] if '.' in parts[0] else '127.0.0.1',
                    'timestamp': f"{parts[0]} {parts[1]}" if ':' in parts[1] else str(datetime.now()),
                    'method': 'GET',
                    'path': parts[2] if parts[2].startswith('/') else '/',
                    'status': parts[3] if parts[3].isdigit() else '200',
                    'user_agent': ' '.join(parts[4:]) if len(parts) > 4 else 'unknown',
                    'pattern': 'fallback',
                    'raw_line': line
                }
            except:
                pass
        
        return None
    
    def send_to_waf(self, log_data: Dict) -> Optional[Dict]:
        """Send log entry to WAF for analysis"""
        try:
            request_data = {
                "ip": log_data.get('ip', '127.0.0.1'),
                "method": log_data.get('method', 'GET'),
                "path": log_data.get('path', '/'),
                "query_params": {},
                "headers": {},
                "user_agent": log_data.get('user_agent', ''),
                "timestamp": log_data.get('timestamp', str(datetime.now()))
            }
            
            response = requests.post(
                f"{self.waf_url}/detect",
                json=request_data,
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"WAF analysis failed: {response.status_code}")
                
        except requests.RequestException as e:
            logger.warning(f"Failed to contact WAF: {e}")
        
        return None
    
    def process_log_line(self, line: str) -> bool:
        """Process a single log line"""
        # Parse log entry
        log_data = self.parse_log_entry(line)
        if not log_data:
            return False
        
        self.stats["total_entries"] += 1
        
        # Send to WAF for analysis
        waf_result = self.send_to_waf(log_data)
        if waf_result:
            self.stats["waf_analyzed"] += 1
            
            # Combine log data with WAF analysis
            combined_data = {
                "log_entry": log_data,
                "waf_analysis": waf_result,
                "processed_at": datetime.now().isoformat()
            }
            
            # Check if threat detected
            if waf_result.get('is_anomalous', False):
                self.stats["threats_detected"] += 1
                self.log_threat(combined_data)
            
            # Log all analyzed entries
            self.log_analysis(combined_data)
            
            # Print real-time updates
            if self.stats["total_entries"] % 10 == 0:
                self.print_stats()
        
        self.stats["last_update"] = datetime.now().isoformat()
        return True
    
    def log_threat(self, data: Dict):
        """Log detected threats to separate file"""
        threat_file = f"./waf_logs/threats/threats_{datetime.now().strftime('%Y%m%d')}.log"
        
        threat_entry = {
            "timestamp": data["processed_at"],
            "ip": data["log_entry"].get("ip"),
            "method": data["log_entry"].get("method"),
            "path": data["log_entry"].get("path"),
            "anomaly_score": data["waf_analysis"].get("anomaly_score"),
            "risk_level": data["waf_analysis"].get("risk_level"),
            "attack_types": data["waf_analysis"].get("attack_types"),
            "blocked": data["waf_analysis"].get("blocked"),
            "raw_log": data["log_entry"].get("raw_line")
        }
        
        with open(threat_file, 'a') as f:
            f.write(json.dumps(threat_entry) + '\n')
        
        # Print threat alert
        print(f"\n🚨 THREAT DETECTED: {threat_entry['ip']} -> {threat_entry['path']}")
        print(f"   Score: {threat_entry['anomaly_score']:.3f}, Risk: {threat_entry['risk_level']}")
        print(f"   Types: {', '.join(threat_entry['attack_types'])}")
    
    def log_analysis(self, data: Dict):
        """Log all analysis results"""
        analysis_file = f"./waf_logs/analysis_{datetime.now().strftime('%Y%m%d')}.log"
        
        with open(analysis_file, 'a') as f:
            f.write(json.dumps(data) + '\n')
    
    def print_stats(self):
        """Print current statistics"""
        detection_rate = (self.stats["threats_detected"] / max(self.stats["waf_analyzed"], 1)) * 100
        
        print(f"\n📊 Live Log Processing Stats:")
        print(f"   Total Entries: {self.stats['total_entries']}")
        print(f"   WAF Analyzed: {self.stats['waf_analyzed']}")
        print(f"   Threats Detected: {self.stats['threats_detected']}")
        print(f"   Detection Rate: {detection_rate:.1f}%")
        print(f"   Last Update: {self.stats['last_update']}")
    
    def get_file_position(self, file_path: str) -> int:
        """Get the last read position for a file"""
        return self.log_positions.get(file_path, 0)
    
    def set_file_position(self, file_path: str, position: int):
        """Set the last read position for a file"""
        self.log_positions[file_path] = position
    
    def process_new_logs(self, file_path: str):
        """Process new lines in a log file"""
        try:
            current_position = self.get_file_position(file_path)
            
            with open(file_path, 'r') as f:
                f.seek(current_position)
                new_lines = f.readlines()
                new_position = f.tell()
            
            if new_lines:
                logger.info(f"Processing {len(new_lines)} new lines from {file_path}")
                
                for line in new_lines:
                    self.process_log_line(line)
                
                self.set_file_position(file_path, new_position)
                
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
    
    def process_existing_logs(self, file_path: str, max_lines: int = 100):
        """Process existing log entries (latest entries)"""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            # Process last N lines
            recent_lines = lines[-max_lines:] if len(lines) > max_lines else lines
            
            logger.info(f"Processing {len(recent_lines)} recent lines from {file_path}")
            
            for line in recent_lines:
                self.process_log_line(line)
            
            # Set position to end of file
            self.set_file_position(file_path, sum(len(line.encode()) for line in lines))
            
        except Exception as e:
            logger.error(f"Error processing existing logs in {file_path}: {e}")
    
    def monitor_directory(self, directory: str):
        """Monitor a directory for log file changes"""
        event_handler = LogEventHandler(self)
        observer = Observer()
        observer.schedule(event_handler, directory, recursive=True)
        observer.start()
        
        logger.info(f"Started monitoring directory: {directory}")
        return observer
    
    def start_monitoring(self, directories: List[str], process_existing: bool = True):
        """Start monitoring multiple directories"""
        observers = []
        
        # Process existing log files first
        if process_existing:
            for directory in directories:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            if file.endswith('.log'):
                                file_path = os.path.join(root, file)
                                logger.info(f"Processing existing log file: {file_path}")
                                self.process_existing_logs(file_path)
        
        # Start real-time monitoring
        for directory in directories:
            if os.path.exists(directory):
                observer = self.monitor_directory(directory)
                observers.append(observer)
            else:
                logger.warning(f"Directory not found: {directory}")
        
        return observers

class ProductionLogIngester:
    """Production-ready log ingestion system"""
    
    def __init__(self, config_file: str = "production_config.json"):
        self.config = self.load_config(config_file)
        self.processor = LiveLogProcessor()
        self.observers = []
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration"""
        try:
            with open(config_file) as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using defaults")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "log_directories": [
                "./logs",
                "./waf_logs",
                "/var/log/nginx",
                "/var/log/apache2",
                "/opt/tomcat/logs"
            ],
            "specific_files": [
                "./demo_access.log",
                "./live_waf_logs.log"
            ],
            "monitoring": {
                "process_existing": True,
                "max_existing_lines": 100
            }
        }
    
    def start(self):
        """Start the log ingestion system"""
        logger.info("🚀 Starting Production Log Ingester...")
        
        # Check WAF service
        if not self.check_waf_service():
            logger.error("❌ WAF service not available")
            return False
        
        # Get directories to monitor
        directories = self.config.get("log_directories", [])
        specific_files = self.config.get("specific_files", [])
        
        # Add directories containing specific files
        for file_path in specific_files:
            if os.path.exists(file_path):
                directory = os.path.dirname(os.path.abspath(file_path))
                if directory not in directories:
                    directories.append(directory)
        
        # Start monitoring
        process_existing = self.config.get("monitoring", {}).get("process_existing", True)
        self.observers = self.processor.start_monitoring(directories, process_existing)
        
        if self.observers:
            logger.info("✅ Log ingestion started successfully")
            self.print_status()
            return True
        else:
            logger.error("❌ No log directories found to monitor")
            return False
    
    def check_waf_service(self) -> bool:
        """Check if WAF service is available"""
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def print_status(self):
        """Print ingestion status"""
        print("\n" + "="*60)
        print("📊 LIVE LOG INGESTION ACTIVE")
        print("="*60)
        print(f"🔍 Monitoring {len(self.observers)} directories")
        print(f"🛡️  WAF Integration: Active")
        print(f"📂 Output Directory: ./waf_logs/")
        print(f"🚨 Threat Logs: ./waf_logs/threats/")
        print("\n📈 Real-time Statistics:")
        self.processor.print_stats()
        print("\n⌨️  Press Ctrl+C to stop")
        print("="*60)
    
    def stop(self):
        """Stop monitoring"""
        logger.info("🛑 Stopping log ingestion...")
        
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        logger.info("✅ Log ingestion stopped")
    
    def run(self):
        """Run the ingestion system"""
        if self.start():
            try:
                while True:
                    time.sleep(10)
                    self.processor.print_stats()
            except KeyboardInterrupt:
                self.stop()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Live Application Log Ingester")
    parser.add_argument("--config", default="production_config.json", help="Configuration file")
    parser.add_argument("--test", action="store_true", help="Test mode with sample logs")
    
    args = parser.parse_args()
    
    if args.test:
        # Test mode: generate some sample logs
        logger.info("🧪 Running in test mode...")
        
        # Create sample log entries
        sample_logs = [
            '192.168.1.100 - - [28/Dec/2024:10:15:23 +0000] "GET / HTTP/1.1" 200 1234',
            '192.168.1.101 - - [28/Dec/2024:10:15:24 +0000] "GET /admin HTTP/1.1" 200 567',
            '192.168.1.102 - - [28/Dec/2024:10:15:25 +0000] "POST /login HTTP/1.1" 200 890',
            '192.168.1.103 - - [28/Dec/2024:10:15:26 +0000] "GET /search?q=\' OR 1=1-- HTTP/1.1" 200 234',
            '192.168.1.104 - - [28/Dec/2024:10:15:27 +0000] "GET /<script>alert(1)</script> HTTP/1.1" 403 0',
        ]
        
        # Write sample logs
        test_log_file = "./test_access.log"
        with open(test_log_file, 'w') as f:
            for log in sample_logs:
                f.write(log + '\n')
        
        # Process sample logs
        processor = LiveLogProcessor()
        for log in sample_logs:
            processor.process_log_line(log)
        
        processor.print_stats()
    else:
        # Production mode
        ingester = ProductionLogIngester(args.config)
        ingester.run()

if __name__ == "__main__":
    main()
