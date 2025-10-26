"""
Data Loading & Preprocessing Module
Handles loading and preprocessing of web server log data from various formats
"""

import pandas as pd
import numpy as np
import json
import re
from typing import Dict, List, Optional, Tuple, Union
from pathlib import Path
import logging
from datetime import datetime, timedelta
import urllib.parse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LogDataLoader:
    """Handles loading and preprocessing of web server log data"""
    
    def __init__(self):
        self.required_fields = ['timestamp', 'method', 'path', 'status', 'score']
        self.optional_fields = ['headers', 'payload', 'label', 'user_agent', 'ip']
        
    def load_data(self, file_path: Union[str, Path]) -> pd.DataFrame:
        """
        Load log data from various formats (CSV, JSONL, Apache/Nginx logs)
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Processed DataFrame with normalized columns
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        logger.info(f"Loading log data from: {file_path}")
        
        # Determine file format and load accordingly
        if file_path.suffix.lower() == '.csv':
            return self._load_csv(file_path)
        elif file_path.suffix.lower() in ['.jsonl', '.ndjson']:
            return self._load_jsonl(file_path)
        elif file_path.suffix.lower() == '.json':
            return self._load_json(file_path)
        else:
            # Try to parse as raw log format (Apache/Nginx style)
            return self._load_raw_logs(file_path)
    
    def _load_csv(self, file_path: Path) -> pd.DataFrame:
        """Load CSV format logs"""
        try:
            df = pd.read_csv(file_path)
            logger.info(f"Loaded {len(df)} records from CSV")
            return self._normalize_dataframe(df)
        except Exception as e:
            logger.error(f"Error loading CSV: {e}")
            raise
    
    def _load_jsonl(self, file_path: Path) -> pd.DataFrame:
        """Load JSONL format logs"""
        try:
            records = []
            with open(file_path, 'r') as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))
            
            df = pd.DataFrame(records)
            logger.info(f"Loaded {len(df)} records from JSONL")
            return self._normalize_dataframe(df)
        except Exception as e:
            logger.error(f"Error loading JSONL: {e}")
            raise
    
    def _load_json(self, file_path: Path) -> pd.DataFrame:
        """Load JSON format logs"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict) and 'logs' in data:
                df = pd.DataFrame(data['logs'])
            else:
                df = pd.DataFrame([data])
            
            logger.info(f"Loaded {len(df)} records from JSON")
            return self._normalize_dataframe(df)
        except Exception as e:
            logger.error(f"Error loading JSON: {e}")
            raise
    
    def _load_raw_logs(self, file_path: Path) -> pd.DataFrame:
        """Load raw Apache/Nginx style logs"""
        try:
            # Common log format patterns
            apache_pattern = re.compile(
                r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
                r'(?P<status>\d+) (?P<size>\S+)'
                r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
            )
            
            records = []
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    match = apache_pattern.match(line.strip())
                    if match:
                        record = match.groupdict()
                        # Convert status to int
                        record['status'] = int(record['status'])
                        # Add default score (will be computed later)
                        record['score'] = 0.0
                        records.append(record)
                    else:
                        if line_num <= 10:  # Log first few parse failures
                            logger.warning(f"Failed to parse line {line_num}: {line[:100]}")
            
            if not records:
                raise ValueError("No valid log entries found")
            
            df = pd.DataFrame(records)
            logger.info(f"Loaded {len(df)} records from raw logs")
            return self._normalize_dataframe(df)
        except Exception as e:
            logger.error(f"Error loading raw logs: {e}")
            raise
    
    def _normalize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize DataFrame columns and data types"""
        logger.info("Normalizing DataFrame...")
        
        # Ensure required columns exist
        for col in self.required_fields:
            if col not in df.columns:
                if col == 'score':
                    df[col] = 0.0  # Default score
                else:
                    raise ValueError(f"Required column '{col}' not found in data")
        
        # Add optional columns if missing
        for col in self.optional_fields:
            if col not in df.columns:
                df[col] = None
        
        # Normalize timestamp
        df['timestamp'] = self._normalize_timestamp(df['timestamp'])
        
        # Normalize HTTP method
        df['method'] = df['method'].str.upper()
        
        # Ensure numeric types
        df['status'] = pd.to_numeric(df['status'], errors='coerce')
        df['score'] = pd.to_numeric(df['score'], errors='coerce').fillna(0.0)
        
        # Parse and clean paths
        df['path'] = df['path'].apply(self._normalize_path)
        
        # Extract additional features
        df = self._extract_features(df)
        
        # Remove rows with invalid data
        initial_count = len(df)
        df = df.dropna(subset=['timestamp', 'method', 'path', 'status'])
        final_count = len(df)
        
        if initial_count != final_count:
            logger.warning(f"Dropped {initial_count - final_count} rows with invalid data")
        
        logger.info(f"Normalized DataFrame: {len(df)} records, {len(df.columns)} columns")
        return df
    
    def _normalize_timestamp(self, timestamps: pd.Series) -> pd.Series:
        """Normalize timestamp formats"""
        try:
            # Try pandas automatic parsing first
            return pd.to_datetime(timestamps, errors='coerce')
        except:
            # Handle common log formats manually
            normalized = []
            for ts in timestamps:
                try:
                    if isinstance(ts, str):
                        # Apache log format: [21/Sep/2025:16:24:25 +0530]
                        if ts.startswith('[') and ts.endswith(']'):
                            ts = ts[1:-1]
                        # Try multiple formats
                        for fmt in ['%d/%b/%Y:%H:%M:%S %z', '%Y-%m-%d %H:%M:%S', 
                                  '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d']:
                            try:
                                normalized.append(datetime.strptime(ts, fmt))
                                break
                            except:
                                continue
                        else:
                            normalized.append(pd.NaT)
                    else:
                        normalized.append(pd.to_datetime(ts))
                except:
                    normalized.append(pd.NaT)
            
            return pd.Series(normalized)
    
    def _normalize_path(self, path: str) -> str:
        """Normalize URL paths"""
        if pd.isna(path) or not isinstance(path, str):
            return '/'
        
        # Remove query parameters for base path
        if '?' in path:
            path = path.split('?')[0]
        
        # Ensure starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # URL decode
        try:
            path = urllib.parse.unquote(path)
        except:
            pass
        
        return path
    
    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract additional features from log data"""
        logger.info("Extracting additional features...")
        
        # Extract query parameters and count them
        df['query_params'] = df.apply(lambda row: self._extract_query_params(row), axis=1)
        df['query_param_count'] = df['query_params'].apply(lambda x: len(x) if x else 0)
        
        # Path length and depth
        df['path_length'] = df['path'].str.len()
        df['path_depth'] = df['path'].str.count('/')
        
        # Status code categories
        df['status_category'] = df['status'].apply(self._categorize_status)
        
        # Time-based features
        if 'timestamp' in df.columns and not df['timestamp'].isna().all():
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_weekend'] = df['day_of_week'].isin([5, 6])
        
        # User agent analysis (if available)
        if 'user_agent' in df.columns:
            df['user_agent_category'] = df['user_agent'].apply(self._categorize_user_agent)
        
        return df
    
    def _extract_query_params(self, row) -> Optional[Dict]:
        """Extract query parameters from request"""
        try:
            full_request = row.get('path', '') or row.get('request', '')
            if '?' in full_request:
                query_string = full_request.split('?', 1)[1]
                return dict(urllib.parse.parse_qsl(query_string))
            return {}
        except:
            return {}
    
    def _categorize_status(self, status: int) -> str:
        """Categorize HTTP status codes"""
        if pd.isna(status):
            return 'Unknown'
        elif 200 <= status < 300:
            return 'Success'
        elif 300 <= status < 400:
            return 'Redirect'
        elif 400 <= status < 500:
            return 'Client Error'
        elif 500 <= status < 600:
            return 'Server Error'
        else:
            return 'Other'
    
    def _categorize_user_agent(self, user_agent: str) -> str:
        """Categorize user agents"""
        if pd.isna(user_agent) or user_agent == '-':
            return 'Unknown'
        
        ua_lower = str(user_agent).lower()
        
        # Security tools
        security_tools = ['sqlmap', 'nikto', 'nessus', 'burp', 'zap', 'nmap']
        if any(tool in ua_lower for tool in security_tools):
            return 'Security Tool'
        
        # Browsers
        if 'chrome' in ua_lower:
            return 'Chrome'
        elif 'firefox' in ua_lower:
            return 'Firefox'
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            return 'Safari'
        elif 'edge' in ua_lower:
            return 'Edge'
        
        # Bots and crawlers
        if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']):
            return 'Bot/Crawler'
        
        # Command line tools
        if 'curl' in ua_lower:
            return 'cURL'
        elif 'wget' in ua_lower:
            return 'Wget'
        
        return 'Other'

    def generate_synthetic_data(self, num_samples: int = 1000, anomaly_rate: float = 0.1) -> pd.DataFrame:
        """Generate synthetic log data for demo purposes"""
        logger.info(f"Generating {num_samples} synthetic log samples with {anomaly_rate*100}% anomalies")
        
        np.random.seed(42)
        
        records = []
        base_time = datetime.now() - timedelta(hours=24)
        
        # Normal request patterns
        normal_paths = ['/home', '/products', '/api/users', '/login', '/search', '/about', '/contact']
        normal_methods = ['GET', 'POST', 'PUT', 'DELETE']
        normal_status = [200, 201, 302, 404]
        normal_user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        # Anomalous patterns
        attack_paths = [
            "/admin/../../../etc/passwd",
            "/login?id=1' OR '1'='1",
            "/search?q=<script>alert('xss')</script>",
            "/api/users?id=1 UNION SELECT * FROM passwords",
            "/config.php?file=../../../windows/system32/config/sam"
        ]
        attack_user_agents = ['sqlmap/1.0', 'Nikto/2.1.6', 'Burp Suite Professional']
        
        for i in range(num_samples):
            # Determine if this should be an anomaly
            is_anomaly = np.random.random() < anomaly_rate
            
            # Generate timestamp
            timestamp = base_time + timedelta(
                seconds=np.random.randint(0, 24*3600),
                microseconds=np.random.randint(0, 1000000)
            )
            
            if is_anomaly:
                # Generate anomalous request
                method = np.random.choice(['GET', 'POST'])
                path = np.random.choice(attack_paths)
                status = np.random.choice([200, 400, 403, 404, 500])
                user_agent = np.random.choice(attack_user_agents)
                score = np.random.uniform(5.0, 10.0)  # High anomaly score
                label = 1
            else:
                # Generate normal request
                method = np.random.choice(normal_methods, p=[0.7, 0.2, 0.05, 0.05])
                path = np.random.choice(normal_paths)
                status = np.random.choice(normal_status, p=[0.8, 0.1, 0.05, 0.05])
                user_agent = np.random.choice(normal_user_agents)
                score = np.random.uniform(0.0, 2.0)  # Low anomaly score
                label = 0
            
            record = {
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'status': status,
                'score': score,
                'label': label,
                'user_agent': user_agent,
                'ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'headers': {'Content-Type': 'application/json'} if method == 'POST' else {},
                'payload': '{"test": "data"}' if method == 'POST' and is_anomaly else None
            }
            
            records.append(record)
        
        df = pd.DataFrame(records)
        return self._normalize_dataframe(df)

    def preprocess_for_analysis(self, df: pd.DataFrame) -> pd.DataFrame:
        """Final preprocessing steps for analysis"""
        logger.info("Performing final preprocessing for analysis...")
        
        # Sort by timestamp
        if 'timestamp' in df.columns and not df['timestamp'].isna().all():
            df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Create anomaly flag based on score if no labels
        if 'label' not in df.columns or df['label'].isna().all():
            # Use threshold-based approach (e.g., top 10% of scores)
            threshold = df['score'].quantile(0.9)
            df['predicted_anomaly'] = (df['score'] > threshold).astype(int)
        else:
            df['predicted_anomaly'] = df['label']
        
        # Add row index for timeline plots
        df['row_index'] = range(len(df))
        
        logger.info(f"Final dataset: {len(df)} records ready for analysis")
        return df

# Example usage and testing
if __name__ == "__main__":
    loader = LogDataLoader()
    
    # Test with synthetic data
    synthetic_data = loader.generate_synthetic_data(num_samples=1000, anomaly_rate=0.15)
    print("Synthetic data generated:")
    print(synthetic_data.head())
    print(f"\nDataset shape: {synthetic_data.shape}")
    print(f"Columns: {list(synthetic_data.columns)}")
    print(f"Anomaly rate: {synthetic_data['label'].mean():.2%}")
