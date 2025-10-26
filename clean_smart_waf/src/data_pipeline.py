"""
Smart WAF - Data Pipeline
Handles HTTP log ingestion, preprocessing, and tokenization for Transformer input.
"""

import json
import sqlite3
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
import re
from typing import Dict, List, Optional, Tuple
import logging
from urllib.parse import urlparse, parse_qs
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTTPLogProcessor:
    """
    Processes HTTP request logs for anomaly detection.
    Supports multiple log formats and extracts relevant features.
    """
    
    def __init__(self, db_path: str = "data/waf_logs.db"):
        """
        Initialize the log processor.
        
        Args:
            db_path: Path to SQLite database for storing processed logs
        """
        self.db_path = db_path
        self.init_database()
        
        # Suspicious patterns for feature extraction
        self.attack_patterns = {
            'sql_injection': [
                r'union\s+select', r'or\s+1\s*=\s*1', r'drop\s+table',
                r'insert\s+into', r'update\s+\w+\s+set', r'delete\s+from'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'on\w+\s*=',
                r'<iframe[^>]*>', r'<object[^>]*>', r'alert\s*\('
            ],
            'directory_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*pwd', r';\s*whoami',
                r'\|\s*nc\s+', r'`[^`]*`', r'\$\([^)]*\)'
            ],
            'file_inclusion': [
                r'php://filter', r'php://input', r'data://text',
                r'file://', r'ftp://', r'http://.*\?.*='
            ]
        }
    
    def init_database(self):
        """Initialize SQLite database for storing logs."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS http_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    method TEXT,
                    url TEXT,
                    query_params TEXT,
                    headers TEXT,
                    body TEXT,
                    status_code INTEGER,
                    response_size INTEGER,
                    user_agent TEXT,
                    remote_ip TEXT,
                    is_malicious INTEGER DEFAULT 0,
                    anomaly_score REAL DEFAULT 0.0,
                    features TEXT,
                    processed_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON http_logs(timestamp);
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_malicious ON http_logs(is_malicious);
            ''')
    
    def parse_access_log_line(self, log_line: str) -> Optional[Dict]:
        """
        Parse a single access log line (Common Log Format or JSON).
        
        Args:
            log_line: Raw log line from access.log
            
        Returns:
            Parsed log entry as dictionary or None if parsing fails
        """
        log_line = log_line.strip()
        
        # Try JSON format first
        if log_line.startswith('{'):
            try:
                return json.loads(log_line)
            except json.JSONDecodeError:
                pass
        
        # Parse Common Log Format
        # Example: 127.0.0.1 - - [09/Jan/2024:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234
        clf_pattern = re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<size>\d+)'
            r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
        )
        
        match = clf_pattern.match(log_line)
        if match:
            groups = match.groupdict()
            return {
                'remote_ip': groups['ip'],
                'timestamp': groups['timestamp'],
                'method': groups['method'],
                'url': groups['url'],
                'status_code': int(groups['status']),
                'response_size': int(groups['size']),
                'user_agent': groups.get('user_agent', ''),
                'referer': groups.get('referer', ''),
                'headers': json.dumps({'User-Agent': groups.get('user_agent', '')}),
                'body': ''
            }
        
        logger.warning(f"Could not parse log line: {log_line[:100]}...")
        return None
    
    def extract_features(self, log_entry: Dict) -> Dict:
        """
        Extract features from HTTP request for ML model.
        
        Args:
            log_entry: Parsed HTTP log entry
            
        Returns:
            Feature dictionary
        """
        url = log_entry.get('url', '')
        method = log_entry.get('method', '')
        user_agent = log_entry.get('user_agent', '')
        body = log_entry.get('body', '')
        query_params = log_entry.get('query_params', '')
        
        # Parse URL components
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query or query_params
        
        features = {
            # Basic request features
            'method': method,
            'path': path,
            'query': query,
            'status_code': log_entry.get('status_code', 0),
            'response_size': log_entry.get('response_size', 0),
            
            # URL analysis
            'url_length': len(url),
            'path_depth': path.count('/'),
            'has_query': len(query) > 0,
            'query_length': len(query),
            'has_fragment': '#' in url,
            
            # Character analysis
            'special_chars_count': len(re.findall(r'[<>&"\'%$]', url)),
            'encoded_chars_count': len(re.findall(r'%[0-9a-fA-F]{2}', url)),
            'num_params': len(parse_qs(query)),
            
            # User agent analysis
            'user_agent': user_agent,
            'is_bot': any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider']),
            'browser_fingerprint': hashlib.md5(user_agent.encode()).hexdigest()[:8],
            
            # Attack pattern detection
            **self.detect_attack_patterns(url + ' ' + body + ' ' + query),
            
            # Time-based features
            'hour': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            
            # Request size features
            'headers_size': len(str(log_entry.get('headers', ''))),
            'body_size': len(body),
            'total_request_size': len(url) + len(body) + len(str(log_entry.get('headers', '')))
        }
        
        return features
    
    def detect_attack_patterns(self, text: str) -> Dict[str, bool]:
        """
        Detect attack patterns in request text.
        
        Args:
            text: Combined request text (URL + body + query)
            
        Returns:
            Dictionary of attack pattern flags
        """
        text_lower = text.lower()
        pattern_flags = {}
        
        for attack_type, patterns in self.attack_patterns.items():
            pattern_flags[f'has_{attack_type}'] = any(
                re.search(pattern, text_lower, re.IGNORECASE) 
                for pattern in patterns
            )
        
        # Additional suspicious indicators
        pattern_flags.update({
            'has_suspicious_encoding': len(re.findall(r'%[0-9a-fA-F]{2}', text)) > 5,
            'has_long_param': any(len(param) > 100 for param in text.split('&')),
            'has_nested_data': text.count('{') > 2 or text.count('[') > 2,
            'has_base64': bool(re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text))
        })
        
        return pattern_flags
    
    def create_model_input(self, log_entry: Dict) -> str:
        """
        Create tokenizable string from log entry for Transformer input.
        
        Args:
            log_entry: Parsed HTTP log entry
            
        Returns:
            Formatted string for model tokenization
        """
        method = log_entry.get('method', '')
        url = log_entry.get('url', '')
        user_agent = log_entry.get('user_agent', '')[:100]  # Truncate long user agents
        status = str(log_entry.get('status_code', ''))
        
        # Create structured sequence
        sequence_parts = [
            f"METHOD:{method}",
            f"URL:{url}",
            f"STATUS:{status}",
            f"UA:{user_agent}"
        ]
        
        # Add query parameters if present
        query = urlparse(url).query
        if query:
            # Anonymize parameter values for privacy
            params = []
            for param_pair in query.split('&'):
                if '=' in param_pair:
                    key, _ = param_pair.split('=', 1)
                    params.append(f"{key}=<VALUE>")
                else:
                    params.append(param_pair)
            sequence_parts.append(f"PARAMS:{' '.join(params)}")
        
        return ' '.join(sequence_parts)
    
    def process_log_file(self, log_file_path: str, batch_size: int = 1000) -> int:
        """
        Process an entire log file and store in database.
        
        Args:
            log_file_path: Path to the log file
            batch_size: Number of entries to process in each batch
            
        Returns:
            Number of successfully processed entries
        """
        log_file_path = Path(log_file_path)
        if not log_file_path.exists():
            logger.error(f"Log file not found: {log_file_path}")
            return 0
        
        processed_count = 0
        batch_data = []
        
        logger.info(f"Processing log file: {log_file_path}")
        
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_num, line in enumerate(file, 1):
                try:
                    parsed_entry = self.parse_access_log_line(line)
                    if parsed_entry:
                        features = self.extract_features(parsed_entry)
                        model_input = self.create_model_input(parsed_entry)
                        
                        # Add to batch
                        batch_data.append({
                            'timestamp': parsed_entry.get('timestamp', datetime.now().isoformat()),
                            'method': parsed_entry.get('method', ''),
                            'url': parsed_entry.get('url', ''),
                            'query_params': parsed_entry.get('query_params', ''),
                            'headers': parsed_entry.get('headers', ''),
                            'body': parsed_entry.get('body', ''),
                            'status_code': parsed_entry.get('status_code', 0),
                            'response_size': parsed_entry.get('response_size', 0),
                            'user_agent': parsed_entry.get('user_agent', ''),
                            'remote_ip': parsed_entry.get('remote_ip', ''),
                            'features': json.dumps(features),
                            'model_input': model_input
                        })
                        
                        processed_count += 1
                        
                        # Process batch
                        if len(batch_data) >= batch_size:
                            self.store_batch(batch_data)
                            batch_data = []
                            
                except Exception as e:
                    logger.error(f"Error processing line {line_num}: {e}")
                    
        # Process remaining batch
        if batch_data:
            self.store_batch(batch_data)
            
        logger.info(f"Successfully processed {processed_count} log entries")
        return processed_count
    
    def store_batch(self, batch_data: List[Dict]):
        """Store a batch of processed entries in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany('''
                INSERT INTO http_logs 
                (timestamp, method, url, query_params, headers, body, 
                 status_code, response_size, user_agent, remote_ip, features)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', [
                (entry['timestamp'], entry['method'], entry['url'],
                 entry['query_params'], entry['headers'], entry['body'],
                 entry['status_code'], entry['response_size'],
                 entry['user_agent'], entry['remote_ip'], entry['features'])
                for entry in batch_data
            ])
    
    def get_training_data(self, limit: Optional[int] = None, 
                         only_benign: bool = True) -> Tuple[List[str], List[int]]:
        """
        Get training data for model training.
        
        Args:
            limit: Maximum number of samples to return
            only_benign: Whether to return only benign samples
            
        Returns:
            Tuple of (sequences, labels)
        """
        query = '''
            SELECT url, method, user_agent, status_code, is_malicious, features
            FROM http_logs
        '''
        
        if only_benign:
            query += ' WHERE is_malicious = 0'
            
        if limit:
            query += f' LIMIT {limit}'
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            
        sequences = []
        labels = []
        
        for row in rows:
            # Create model input sequence
            log_entry = {
                'url': row[0],
                'method': row[1],
                'user_agent': row[2],
                'status_code': row[3]
            }
            
            sequence = self.create_model_input(log_entry)
            sequences.append(sequence)
            labels.append(row[4])  # is_malicious
            
        logger.info(f"Retrieved {len(sequences)} training samples")
        return sequences, labels
    
    def generate_sample_logs(self, output_path: str, num_samples: int = 1000):
        """
        Generate sample HTTP logs for testing.
        
        Args:
            output_path: Path to save sample logs
            num_samples: Number of sample entries to generate
        """
        import random
        from datetime import datetime, timedelta
        
        # Sample data for generation
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        paths = [
            '/index.html', '/login', '/api/users', '/api/products',
            '/admin/dashboard', '/search', '/checkout', '/profile',
            '/api/orders', '/static/js/app.js', '/favicon.ico'
        ]
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'curl/7.68.0',
            'PostmanRuntime/7.28.4'
        ]
        
        # Some malicious patterns for testing
        malicious_paths = [
            '/admin/../../../etc/passwd',
            '/search?q=<script>alert(1)</script>',
            '/api/users?id=1 UNION SELECT password FROM users',
            '/upload.php?file=../../../etc/passwd'
        ]
        
        sample_logs = []
        base_time = datetime.now() - timedelta(hours=24)
        
        for i in range(num_samples):
            timestamp = base_time + timedelta(minutes=i)
            ip = f"192.168.1.{random.randint(1, 255)}"
            method = random.choice(methods)
            
            # 90% benign, 10% malicious
            if random.random() < 0.9:
                path = random.choice(paths)
                if random.random() < 0.3:  # Add query parameters sometimes
                    path += f"?id={random.randint(1, 1000)}"
            else:
                path = random.choice(malicious_paths)
            
            status = random.choices([200, 404, 500, 403], weights=[80, 15, 3, 2])[0]
            size = random.randint(100, 10000)
            user_agent = random.choice(user_agents)
            
            # Format as Common Log Format
            log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] ' \
                      f'"{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
            
            sample_logs.append(log_line)
        
        # Save to file
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write('\n'.join(sample_logs))
        
        logger.info(f"Generated {num_samples} sample log entries in {output_path}")

def main():
    """Demo usage of the data pipeline."""
    processor = HTTPLogProcessor()
    
    # Generate sample data if needed
    sample_log_path = "data/sample_logs/access.log"
    processor.generate_sample_logs(sample_log_path, 1000)
    
    # Process the sample logs
    processed_count = processor.process_log_file(sample_log_path)
    print(f"Processed {processed_count} log entries")
    
    # Get training data
    sequences, labels = processor.get_training_data(limit=100)
    print(f"Training data: {len(sequences)} sequences, {sum(labels)} malicious")
    
    # Show sample sequences
    for i in range(3):
        print(f"Sample {i+1}: {sequences[i][:100]}...")

if __name__ == "__main__":
    main()
