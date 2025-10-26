"""
Log Parser and Normalizer for WAF Training
==========================================
Parses raw access logs, extracts templates using Drain algorithm,
and normalizes dynamic tokens for Transformer training.
"""

import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import pandas as pd
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class LogEvent:
    """Structured representation of a log event"""
    timestamp: datetime
    ip: str
    method: str
    path: str
    path_template: str
    query_params: Dict[str, str]
    status_code: int
    response_size: int
    user_agent: str
    referer: str
    template_id: int
    normalized_tokens: List[str]
    features: Dict[str, any]

class LogNormalizer:
    """Normalizes dynamic tokens in log data"""
    
    def __init__(self):
        self.patterns = {
            'number': re.compile(r'\b\d+\b'),
            'uuid': re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I),
            'hash': re.compile(r'\b[0-9a-f]{32,64}\b', re.I),
            'timestamp': re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),
            'session_id': re.compile(r'(session|sid|token)=([^&\s]+)', re.I),
            'csrf_token': re.compile(r'(csrf|_token)=([^&\s]+)', re.I),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        }
    
    def normalize_path(self, path: str) -> str:
        """Normalize URL path by replacing dynamic segments"""
        # Replace numeric IDs
        path = self.patterns['number'].sub('<ID>', path)
        
        # Replace UUIDs
        path = self.patterns['uuid'].sub('<UUID>', path)
        
        # Replace hashes
        path = self.patterns['hash'].sub('<HASH>', path)
        
        # Normalize common patterns
        path = re.sub(r'/users?/\d+', '/user/<ID>', path)
        path = re.sub(r'/products?/\d+', '/product/<ID>', path)
        path = re.sub(r'/tasks?/\d+', '/task/<ID>', path)
        path = re.sub(r'/api/v\d+/', '/api/<VERSION>/', path)
        
        return path
    
    def normalize_query_params(self, params: Dict[str, str]) -> Dict[str, str]:
        """Normalize query parameters"""
        normalized = {}
        
        for key, value in params.items():
            # Normalize values
            if self.patterns['number'].match(value):
                normalized[key] = '<NUM>'
            elif self.patterns['uuid'].match(value):
                normalized[key] = '<UUID>'
            elif self.patterns['email'].match(value):
                normalized[key] = '<EMAIL>'
            elif key.lower() in ['session', 'sid', 'token', 'csrf', '_token']:
                normalized[key] = '<TOKEN>'
            else:
                # Keep first few chars for pattern recognition
                if len(value) > 10:
                    normalized[key] = f"{value[:3]}..."
                else:
                    normalized[key] = value
                    
        return normalized
    
    def extract_features(self, event: Dict) -> Dict[str, any]:
        """Extract additional features for anomaly detection"""
        features = {}
        
        # Basic features
        features['method_category'] = 'safe' if event['method'] in ['GET', 'HEAD', 'OPTIONS'] else 'state_changing'
        features['status_category'] = self._categorize_status(event['status_code'])
        features['path_depth'] = len([p for p in event['path'].split('/') if p])
        features['has_query_params'] = len(event.get('query_params', {})) > 0
        features['response_size_category'] = self._categorize_size(event['response_size'])
        
        # Security-related features
        path = event['path'].lower()
        query = str(event.get('query_params', {})).lower()
        
        features['contains_sql_keywords'] = any(kw in path + query for kw in 
                                               ['select', 'union', 'insert', 'delete', 'drop', 'update'])
        features['contains_script_tags'] = any(tag in path + query for tag in 
                                              ['<script', 'javascript:', 'onerror', 'onload'])
        features['contains_traversal'] = any(pattern in path for pattern in 
                                           ['../', '.\\', '/etc/', '/proc/'])
        features['contains_admin_paths'] = any(admin in path for admin in 
                                              ['/admin', '/administrator', '/wp-admin', '/phpmyadmin'])
        
        # User agent features
        ua = event.get('user_agent', '').lower()
        features['is_bot'] = any(bot in ua for bot in ['bot', 'crawler', 'spider', 'scraper'])
        features['browser_category'] = self._categorize_browser(ua)
        
        return features
    
    def _categorize_status(self, status: int) -> str:
        """Categorize HTTP status codes"""
        if 200 <= status < 300:
            return 'success'
        elif 300 <= status < 400:
            return 'redirect'
        elif 400 <= status < 500:
            return 'client_error'
        elif 500 <= status < 600:
            return 'server_error'
        else:
            return 'unknown'
    
    def _categorize_size(self, size: int) -> str:
        """Categorize response sizes"""
        if size < 1024:
            return 'small'
        elif size < 10240:
            return 'medium' 
        elif size < 102400:
            return 'large'
        else:
            return 'xlarge'
    
    def _categorize_browser(self, ua: str) -> str:
        """Categorize user agents"""
        if 'chrome' in ua:
            return 'chrome'
        elif 'firefox' in ua:
            return 'firefox'
        elif 'safari' in ua and 'chrome' not in ua:
            return 'safari'
        elif 'edge' in ua:
            return 'edge'
        elif any(bot in ua for bot in ['bot', 'crawler', 'spider']):
            return 'bot'
        else:
            return 'other'

class AccessLogParser:
    """Parses access logs and extracts structured events"""
    
    def __init__(self):
        self.normalizer = LogNormalizer()
        
        # Initialize Drain template miner
        config = TemplateMinerConfig()
        config.load('./drain_config.ini')  # We'll create this config
        config.profiling_enabled = False
        
        self.template_miner = TemplateMiner(config=config)
        
        # Common log format patterns
        self.nginx_pattern = re.compile(
            r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<size>\d+|-) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
        
        # JSON log format (if logs are in JSON)
        self.json_logs = True  # Set based on your log format
    
    def parse_nginx_log(self, line: str) -> Optional[Dict]:
        """Parse nginx access log line"""
        if self.json_logs:
            try:
                return json.loads(line.strip())
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse JSON log: {line[:100]}...")
                return None
        else:
            match = self.nginx_pattern.match(line.strip())
            if match:
                return match.groupdict()
            return None
    
    def parse_query_params(self, path: str) -> Tuple[str, Dict[str, str]]:
        """Extract query parameters from path"""
        if '?' in path:
            path_part, query_part = path.split('?', 1)
            params = {}
            
            for param in query_part.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
                else:
                    params[param] = ''
            
            return path_part, params
        
        return path, {}
    
    def process_log_line(self, line: str) -> Optional[LogEvent]:
        """Process a single log line into structured event"""
        raw_event = self.parse_nginx_log(line)
        if not raw_event:
            return None
        
        try:
            # Parse timestamp
            timestamp = datetime.strptime(raw_event['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
            
            # Parse path and query params
            full_path = raw_event['path']
            path, query_params = self.parse_query_params(full_path)
            
            # Normalize path
            normalized_path = self.normalizer.normalize_path(path)
            
            # Normalize query parameters
            normalized_params = self.normalizer.normalize_query_params(query_params)
            
            # Create message for template mining
            message = f"{raw_event['method']} {normalized_path}"
            if normalized_params:
                param_str = '&'.join(f"{k}={v}" for k, v in sorted(normalized_params.items()))
                message += f"?{param_str}"
            
            # Extract template
            result = self.template_miner.add_log_message(message)
            template_id = result['template_id'] if result else 0
            
            # Create structured event
            event_data = {
                'ip': raw_event['ip'],
                'method': raw_event['method'],
                'path': path,
                'query_params': query_params,
                'status_code': int(raw_event['status']),
                'response_size': int(raw_event['size']) if raw_event['size'] != '-' else 0,
                'user_agent': raw_event.get('user_agent', ''),
                'referer': raw_event.get('referer', ''),
                'timestamp': timestamp
            }
            
            # Extract features
            features = self.normalizer.extract_features(event_data)
            
            # Create tokens for transformer
            tokens = [
                f"<METHOD_{raw_event['method']}>",
                f"<PATH_{normalized_path}>",
                f"<STATUS_{self.normalizer._categorize_status(int(raw_event['status']))}>",
            ]
            
            # Add parameter tokens
            for key in sorted(normalized_params.keys()):
                tokens.append(f"<PARAM_{key}>")
            
            # Add feature tokens
            if features['has_query_params']:
                tokens.append('<HAS_PARAMS>')
            if features['contains_sql_keywords']:
                tokens.append('<SQL_PATTERN>')
            if features['contains_script_tags']:
                tokens.append('<SCRIPT_PATTERN>')
            if features['contains_traversal']:
                tokens.append('<TRAVERSAL_PATTERN>')
            
            return LogEvent(
                timestamp=timestamp,
                ip=raw_event['ip'],
                method=raw_event['method'],
                path=path,
                path_template=normalized_path,
                query_params=normalized_params,
                status_code=int(raw_event['status']),
                response_size=int(raw_event['size']) if raw_event['size'] != '-' else 0,
                user_agent=raw_event.get('user_agent', ''),
                referer=raw_event.get('referer', ''),
                template_id=template_id,
                normalized_tokens=tokens,
                features=features
            )
            
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
            return None
    
    def process_log_file(self, file_path: str, output_path: str = None) -> List[LogEvent]:
        """Process entire log file"""
        events = []
        
        logger.info(f"Processing log file: {file_path}")
        
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if line_num % 10000 == 0:
                    logger.info(f"Processed {line_num} lines...")
                
                event = self.process_log_line(line)
                if event:
                    events.append(event)
        
        logger.info(f"Processed {len(events)} valid events from {line_num} lines")
        
        # Save processed events
        if output_path:
            self.save_events(events, output_path)
        
        return events
    
    def save_events(self, events: List[LogEvent], output_path: str):
        """Save processed events to file"""
        data = []
        for event in events:
            data.append({
                'timestamp': event.timestamp.isoformat(),
                'ip': event.ip,
                'method': event.method,
                'path': event.path,
                'path_template': event.path_template,
                'query_params': json.dumps(event.query_params),
                'status_code': event.status_code,
                'response_size': event.response_size,
                'user_agent': event.user_agent,
                'template_id': event.template_id,
                'normalized_tokens': json.dumps(event.normalized_tokens),
                'features': json.dumps(event.features)
            })
        
        df = pd.DataFrame(data)
        df.to_csv(output_path, index=False)
        logger.info(f"Saved {len(events)} processed events to {output_path}")

# Create Drain configuration
def create_drain_config():
    """Create Drain configuration file"""
    config_content = """
[DRAIN]
sim_th = 0.4
depth = 4
max_children = 100
max_clusters = 1000
extra_delimiters = []

[MASKING]
masking = [
    {"regex_pattern": "\\d+", "mask_with": "<NUM>"},
    {"regex_pattern": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "mask_with": "<UUID>"},
    {"regex_pattern": "\\b[0-9a-f]{32,64}\\b", "mask_with": "<HASH>"},
]
"""
    
    with open('./drain_config.ini', 'w') as f:
        f.write(config_content)

if __name__ == "__main__":
    # Create Drain config
    create_drain_config()
    
    # Example usage
    parser = AccessLogParser()
    
    # Process a sample log file (you'll need to generate this first)
    sample_log = """192.168.1.1 - - [23/Sep/2025:10:30:00 +0000] "GET /ecommerce/products?category=electronics HTTP/1.1" 200 1234 "http://localhost:8080/ecommerce/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
192.168.1.2 - - [23/Sep/2025:10:30:01 +0000] "POST /rest-api/api/tasks HTTP/1.1" 201 567 "-" "curl/7.64.1"
192.168.1.1 - - [23/Sep/2025:10:30:02 +0000] "GET /ecommerce/products/123 HTTP/1.1" 200 2048 "http://localhost:8080/ecommerce/products" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
"""
    
    # Process sample lines
    for line in sample_log.strip().split('\n'):
        event = parser.process_log_line(line)
        if event:
            print(f"Template ID: {event.template_id}")
            print(f"Tokens: {event.normalized_tokens}")
            print(f"Features: {event.features}")
            print("---")
