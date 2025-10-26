#!/usr/bin/env python3
"""
Live Log Processor for Transformer WAF
Watches Tomcat access logs in real-time and processes them for anomaly detection
"""

import json
import time
import logging
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import deque
import queue
import asyncio
import aiofiles
from datetime import datetime, timedelta
import re
from typing import Dict, List, Optional
import sys

# Import WAF components
from log_parser_normalizer import LogParserNormalizer
from waf_inference_service import WAFInferenceService

class LogFileHandler(FileSystemEventHandler):
    """Handles file system events for Tomcat access logs"""
    
    def __init__(self, processor):
        self.processor = processor
        self.log_queue = queue.Queue()
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        if event.src_path.endswith('.log'):
            self.processor.process_log_file(event.src_path)

class LiveLogProcessor:
    """Real-time log processor for Tomcat access logs"""
    
    def __init__(self, 
                 log_directories: List[str],
                 model_path: str = "models/logbert_model.pth",
                 drain_config_path: str = "models/drain_config.json"):
        
        self.log_directories = [Path(d) for d in log_directories]
        self.model_path = model_path
        self.drain_config_path = drain_config_path
        
        # Initialize components
        self.log_parser = LogParserNormalizer()
        self.inference_service = None
        
        # Processing queues
        self.raw_log_queue = queue.Queue(maxsize=10000)
        self.processed_log_queue = queue.Queue(maxsize=10000)
        self.anomaly_queue = queue.Queue(maxsize=1000)
        
        # Statistics
        self.stats = {
            'logs_processed': 0,
            'anomalies_detected': 0,
            'processing_rate': 0,
            'start_time': datetime.now()
        }
        
        # Configuration
        self.batch_size = 32
        self.processing_interval = 0.1  # 100ms
        self.max_log_age = timedelta(hours=24)
        
        # File tracking
        self.file_positions = {}
        self.watched_files = set()
        
        # Threading
        self.observer = Observer()
        self.processing_threads = []
        self.running = False
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the processor"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('logs/live_log_processor.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('LiveLogProcessor')
        
    async def initialize(self):
        """Initialize the live log processor"""
        self.logger.info("Initializing Live Log Processor...")
        
        # Create necessary directories
        Path("logs").mkdir(exist_ok=True)
        Path("models").mkdir(exist_ok=True)
        
        # Initialize log parser
        await self.log_parser.initialize()
        
        # Initialize inference service
        self.inference_service = WAFInferenceService()
        await self.inference_service.initialize()
        
        # Setup file watchers
        self.setup_file_watchers()
        
        # Scan existing log files
        await self.scan_existing_logs()
        
        self.logger.info("Live Log Processor initialized successfully")
        
    def setup_file_watchers(self):
        """Setup file system watchers for log directories"""
        handler = LogFileHandler(self)
        
        for log_dir in self.log_directories:
            if log_dir.exists():
                self.observer.schedule(handler, str(log_dir), recursive=True)
                self.logger.info(f"Watching directory: {log_dir}")
            else:
                self.logger.warning(f"Log directory does not exist: {log_dir}")
                
    async def scan_existing_logs(self):
        """Scan existing log files and start processing from the end"""
        for log_dir in self.log_directories:
            if not log_dir.exists():
                continue
                
            for log_file in log_dir.glob("*.log"):
                await self.initialize_log_file(log_file)
                
    async def initialize_log_file(self, log_file: Path):
        """Initialize tracking for a log file"""
        try:
            file_size = log_file.stat().st_size
            self.file_positions[str(log_file)] = file_size
            self.watched_files.add(str(log_file))
            self.logger.info(f"Initialized log file: {log_file} (size: {file_size})")
        except Exception as e:
            self.logger.error(f"Error initializing log file {log_file}: {e}")
            
    def process_log_file(self, file_path: str):
        """Process new lines added to a log file"""
        try:
            file_path = Path(file_path)
            
            # Get current file size
            current_size = file_path.stat().st_size
            last_position = self.file_positions.get(str(file_path), 0)
            
            if current_size <= last_position:
                return  # No new data
                
            # Read new lines
            with open(file_path, 'r', encoding='utf-8') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                
            # Update position
            self.file_positions[str(file_path)] = current_size
            
            # Queue new lines for processing
            for line in new_lines:
                line = line.strip()
                if line:
                    log_entry = {
                        'raw_log': line,
                        'file_path': str(file_path),
                        'timestamp': datetime.now(),
                        'file_position': last_position
                    }
                    
                    try:
                        self.raw_log_queue.put_nowait(log_entry)
                    except queue.Full:
                        self.logger.warning("Raw log queue is full, dropping log entry")
                        
        except Exception as e:
            self.logger.error(f"Error processing log file {file_path}: {e}")
            
    async def start(self):
        """Start the live log processor"""
        self.logger.info("Starting Live Log Processor...")
        self.running = True
        
        # Start file observer
        self.observer.start()
        
        # Start processing threads
        self.processing_threads = [
            threading.Thread(target=self.log_parsing_worker, daemon=True),
            threading.Thread(target=self.anomaly_detection_worker, daemon=True),
            threading.Thread(target=self.statistics_worker, daemon=True),
            threading.Thread(target=self.cleanup_worker, daemon=True)
        ]
        
        for thread in self.processing_threads:
            thread.start()
            
        self.logger.info("Live Log Processor started successfully")
        
    def log_parsing_worker(self):
        """Worker thread for parsing raw logs"""
        self.logger.info("Log parsing worker started")
        
        while self.running:
            try:
                # Get raw log entry
                try:
                    log_entry = self.raw_log_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                    
                # Parse log entry
                parsed_entry = self.parse_log_entry(log_entry)
                
                if parsed_entry:
                    # Add to processed queue
                    try:
                        self.processed_log_queue.put_nowait(parsed_entry)
                        self.stats['logs_processed'] += 1
                    except queue.Full:
                        self.logger.warning("Processed log queue is full")
                        
                self.raw_log_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in log parsing worker: {e}")
                
    def parse_log_entry(self, log_entry: Dict) -> Optional[Dict]:
        """Parse a single log entry"""
        try:
            raw_log = log_entry['raw_log']
            
            # Try to parse as JSON (Tomcat JSON format)
            if raw_log.startswith('{'):
                try:
                    json_log = json.loads(raw_log)
                    return self.normalize_json_log(json_log, log_entry)
                except json.JSONDecodeError:
                    pass
                    
            # Parse as Common Log Format or Combined Log Format
            return self.parse_clf_log(raw_log, log_entry)
            
        except Exception as e:
            self.logger.error(f"Error parsing log entry: {e}")
            return None
            
    def normalize_json_log(self, json_log: Dict, log_entry: Dict) -> Dict:
        """Normalize JSON format log entry"""
        normalized = {
            'timestamp': json_log.get('timestamp', log_entry['timestamp'].isoformat()),
            'remote_addr': json_log.get('remote_addr', ''),
            'method': json_log.get('method', ''),
            'uri': json_log.get('uri', ''),
            'query_string': json_log.get('query_string', ''),
            'protocol': json_log.get('protocol', ''),
            'status': json_log.get('status', 0),
            'bytes_sent': json_log.get('bytes_sent', 0),
            'referer': json_log.get('referer', ''),
            'user_agent': json_log.get('user_agent', ''),
            'session_id': json_log.get('session_id', ''),
            'processing_time': json_log.get('processing_time', 0),
            'file_path': log_entry['file_path'],
            'file_position': log_entry['file_position']
        }
        
        # Parse with Drain algorithm
        template = self.log_parser.parse_log(normalized['uri'])
        normalized['template'] = template
        
        return normalized
        
    def parse_clf_log(self, raw_log: str, log_entry: Dict) -> Optional[Dict]:
        """Parse Common Log Format or Combined Log Format"""
        # Combined Log Format regex
        clf_pattern = re.compile(
            r'(?P<remote_addr>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<uri>\S+) (?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes_sent>\S+)'
            r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
        )
        
        match = clf_pattern.match(raw_log)
        if not match:
            return None
            
        groups = match.groupdict()
        
        # Parse URI and query string
        uri = groups.get('uri', '')
        query_string = ''
        if '?' in uri:
            uri, query_string = uri.split('?', 1)
            
        normalized = {
            'timestamp': groups.get('timestamp', log_entry['timestamp'].isoformat()),
            'remote_addr': groups.get('remote_addr', ''),
            'method': groups.get('method', ''),
            'uri': uri,
            'query_string': query_string,
            'protocol': groups.get('protocol', ''),
            'status': int(groups.get('status', 0)),
            'bytes_sent': int(groups.get('bytes_sent', 0)) if groups.get('bytes_sent', '-') != '-' else 0,
            'referer': groups.get('referer', ''),
            'user_agent': groups.get('user_agent', ''),
            'session_id': '',
            'processing_time': 0,
            'file_path': log_entry['file_path'],
            'file_position': log_entry['file_position']
        }
        
        # Parse with Drain algorithm
        template = self.log_parser.parse_log(normalized['uri'])
        normalized['template'] = template
        
        return normalized
        
    def anomaly_detection_worker(self):
        """Worker thread for anomaly detection"""
        self.logger.info("Anomaly detection worker started")
        batch = []
        
        while self.running:
            try:
                # Collect batch of processed logs
                try:
                    log_entry = self.processed_log_queue.get(timeout=1.0)
                    batch.append(log_entry)
                except queue.Empty:
                    if batch:
                        # Process partial batch
                        self.process_anomaly_batch(batch)
                        batch = []
                    continue
                    
                # Process batch when full
                if len(batch) >= self.batch_size:
                    self.process_anomaly_batch(batch)
                    batch = []
                    
                self.processed_log_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in anomaly detection worker: {e}")
                
        # Process remaining batch
        if batch:
            self.process_anomaly_batch(batch)
            
    def process_anomaly_batch(self, batch: List[Dict]):
        """Process a batch of logs for anomaly detection"""
        try:
            if not self.inference_service:
                return
                
            # Extract features for the batch
            features = []
            for log_entry in batch:
                feature_vector = self.extract_features(log_entry)
                features.append(feature_vector)
                
            # Run inference
            predictions = self.inference_service.predict_batch(features)
            
            # Process predictions
            for log_entry, prediction in zip(batch, predictions):
                if prediction.get('is_anomaly', False):
                    anomaly = {
                        'log_entry': log_entry,
                        'prediction': prediction,
                        'detected_at': datetime.now(),
                        'anomaly_score': prediction.get('anomaly_score', 0.0),
                        'confidence': prediction.get('confidence', 0.0)
                    }
                    
                    try:
                        self.anomaly_queue.put_nowait(anomaly)
                        self.stats['anomalies_detected'] += 1
                        self.logger.warning(f"Anomaly detected: {log_entry['uri']}")
                    except queue.Full:
                        self.logger.warning("Anomaly queue is full")
                        
        except Exception as e:
            self.logger.error(f"Error processing anomaly batch: {e}")
            
    def extract_features(self, log_entry: Dict) -> Dict:
        """Extract features from log entry for anomaly detection"""
        return {
            'template': log_entry.get('template', ''),
            'method': log_entry.get('method', ''),
            'uri': log_entry.get('uri', ''),
            'status': log_entry.get('status', 0),
            'bytes_sent': log_entry.get('bytes_sent', 0),
            'processing_time': log_entry.get('processing_time', 0),
            'user_agent': log_entry.get('user_agent', ''),
            'remote_addr': log_entry.get('remote_addr', '')
        }
        
    def statistics_worker(self):
        """Worker thread for updating statistics"""
        self.logger.info("Statistics worker started")
        last_count = 0
        
        while self.running:
            try:
                time.sleep(10)  # Update every 10 seconds
                
                current_count = self.stats['logs_processed']
                rate = (current_count - last_count) / 10.0
                self.stats['processing_rate'] = rate
                last_count = current_count
                
                uptime = datetime.now() - self.stats['start_time']
                
                self.logger.info(
                    f"Stats - Processed: {current_count}, "
                    f"Anomalies: {self.stats['anomalies_detected']}, "
                    f"Rate: {rate:.2f} logs/sec, "
                    f"Uptime: {uptime}"
                )
                
            except Exception as e:
                self.logger.error(f"Error in statistics worker: {e}")
                
    def cleanup_worker(self):
        """Worker thread for cleanup tasks"""
        self.logger.info("Cleanup worker started")
        
        while self.running:
            try:
                time.sleep(300)  # Run every 5 minutes
                
                # Clean up old file positions
                current_time = datetime.now()
                files_to_remove = []
                
                for file_path in self.file_positions:
                    try:
                        if not Path(file_path).exists():
                            files_to_remove.append(file_path)
                    except Exception:
                        files_to_remove.append(file_path)
                        
                for file_path in files_to_remove:
                    del self.file_positions[file_path]
                    self.watched_files.discard(file_path)
                    
                if files_to_remove:
                    self.logger.info(f"Cleaned up {len(files_to_remove)} old file references")
                    
            except Exception as e:
                self.logger.error(f"Error in cleanup worker: {e}")
                
    def get_anomalies(self, max_count: int = 100) -> List[Dict]:
        """Get recent anomalies"""
        anomalies = []
        try:
            for _ in range(min(max_count, self.anomaly_queue.qsize())):
                anomaly = self.anomaly_queue.get_nowait()
                anomalies.append(anomaly)
        except queue.Empty:
            pass
        return anomalies
        
    def get_stats(self) -> Dict:
        """Get current statistics"""
        stats = self.stats.copy()
        stats['queue_sizes'] = {
            'raw_logs': self.raw_log_queue.qsize(),
            'processed_logs': self.processed_log_queue.qsize(),
            'anomalies': self.anomaly_queue.qsize()
        }
        stats['uptime'] = str(datetime.now() - self.stats['start_time'])
        return stats
        
    async def stop(self):
        """Stop the live log processor"""
        self.logger.info("Stopping Live Log Processor...")
        self.running = False
        
        # Stop file observer
        self.observer.stop()
        self.observer.join()
        
        # Wait for threads to finish
        for thread in self.processing_threads:
            thread.join(timeout=5)
            
        self.logger.info("Live Log Processor stopped")

async def main():
    """Main function for testing"""
    # Configure log directories
    log_directories = [
        "/opt/tomcat/logs",
        "/var/log/tomcat",
        "logs"  # Local logs directory
    ]
    
    # Create processor
    processor = LiveLogProcessor(log_directories)
    
    try:
        # Initialize and start
        await processor.initialize()
        await processor.start()
        
        # Run until interrupted
        while True:
            await asyncio.sleep(10)
            stats = processor.get_stats()
            print(f"Processing stats: {stats}")
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await processor.stop()

if __name__ == "__main__":
    asyncio.run(main())
