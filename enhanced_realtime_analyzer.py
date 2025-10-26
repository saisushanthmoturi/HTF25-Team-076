"""
Enhanced Real-time Log Analyzer with Dashboard Integration
Advanced LogBERT-based anomaly detection with modern UI integration
"""

import os
import time
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import re
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import deque, defaultdict
import logging
from pathlib import Path
import json
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
import warnings
import glob
from typing import Dict, List, Optional, Tuple
import asyncio

warnings.filterwarnings('ignore')

# Import configuration
from monitoring_config import config

# Set up logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logbert_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnhancedTomcatLogMonitor(FileSystemEventHandler):
    """Enhanced Tomcat log monitor with better file handling"""
    
    def __init__(self, analyzer, log_paths):
        self.analyzer = analyzer
        self.log_paths = log_paths
        self.file_positions = {}  # Track file read positions
        self.last_modified = {}   # Track last modification times
        
        # Initialize file positions
        self.initialize_file_positions()
    
    def initialize_file_positions(self):
        """Initialize file positions for all log files"""
        for path_pattern in self.log_paths:
            if '*' in path_pattern:
                files = glob.glob(path_pattern)
            else:
                files = [path_pattern] if os.path.exists(path_pattern) else []
                
            for filepath in files:
                if os.path.exists(filepath):
                    # Start from end of file for real-time monitoring
                    self.file_positions[filepath] = os.path.getsize(filepath)
                    self.last_modified[filepath] = os.path.getmtime(filepath)
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
            
        filepath = event.src_path
        
        # Check if this is a log file we're monitoring
        if not any(self.matches_pattern(filepath, pattern) for pattern in self.log_paths):
            return
        
        try:
            self.process_file_changes(filepath)
        except Exception as e:
            logger.error(f"Error processing file {filepath}: {str(e)}")
    
    def matches_pattern(self, filepath, pattern):
        """Check if filepath matches the given pattern"""
        if '*' in pattern:
            return filepath in glob.glob(pattern)
        return filepath == pattern
    
    def process_file_changes(self, filepath):
        """Process changes in a log file"""
        if not os.path.exists(filepath):
            return
        
        current_size = os.path.getsize(filepath)
        current_modified = os.path.getmtime(filepath)
        
        # Initialize if first time seeing this file
        if filepath not in self.file_positions:
            self.file_positions[filepath] = 0
            self.last_modified[filepath] = 0
        
        # Check if file was modified
        if current_modified <= self.last_modified[filepath]:
            return
        
        # Check if file was truncated (log rotation)
        if current_size < self.file_positions[filepath]:
            logger.info(f"Log rotation detected for {filepath}")
            self.file_positions[filepath] = 0
        
        # Read new content
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(self.file_positions[filepath])
            new_lines = f.readlines()
            self.file_positions[filepath] = f.tell()
        
        self.last_modified[filepath] = current_modified
        
        # Process new log entries
        if new_lines:
            log_entries = self.parse_log_lines(new_lines, filepath)
            if log_entries:
                self.analyzer.process_logs(log_entries)
                logger.info(f"Processed {len(log_entries)} new log entries from {filepath}")
    
    def parse_log_lines(self, lines, source_file):
        """Parse log lines into structured entries"""
        entries = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            try:
                entry = self.parse_tomcat_log_line(line)
                if entry:
                    entry['source_file'] = source_file
                    entries.append(entry)
            except Exception as e:
                logger.debug(f"Failed to parse log line: {line[:100]}... Error: {str(e)}")
        
        return entries
    
    def parse_tomcat_log_line(self, line):
        """Parse a single Tomcat access log line"""
        # Common log format: IP - - [timestamp] "METHOD path" status size "referer" "user_agent"
        pattern = config.LOG_FORMAT_REGEX
        
        match = re.match(pattern, line)
        if not match:
            # Try alternative parsing for different formats
            return self.parse_alternative_format(line)
        
        groups = match.groups()
        
        try:
            return {
                'ip_address': groups[0],
                'timestamp': self.parse_timestamp(groups[1]),
                'method': groups[2],
                'path': groups[3],
                'status': int(groups[4]),
                'size': int(groups[5]) if groups[5] != '-' else 0,
                'referer': groups[6] if groups[6] != '-' else '',
                'user_agent': groups[7],
                'raw_line': line
            }
        except (ValueError, IndexError) as e:
            logger.debug(f"Error parsing log entry: {str(e)}")
            return None
    
    def parse_alternative_format(self, line):
        """Parse alternative log formats"""
        # Simple fallback parsing
        parts = line.split()
        if len(parts) < 7:
            return None
        
        try:
            return {
                'ip_address': parts[0],
                'timestamp': datetime.now(),
                'method': 'GET',
                'path': parts[6] if len(parts) > 6 else '/',
                'status': 200,
                'size': 0,
                'referer': '',
                'user_agent': ' '.join(parts[7:]) if len(parts) > 7 else '',
                'raw_line': line
            }
        except Exception:
            return None
    
    def parse_timestamp(self, timestamp_str):
        """Parse timestamp from log format"""
        try:
            # Format: [dd/MMM/yyyy:HH:mm:ss +0000]
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                # Alternative format
                return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                # Fallback to current time
                return datetime.now()

class EnhancedLogFeatureExtractor:
    """Enhanced feature extraction with more sophisticated analysis"""
    
    def __init__(self):
        self.path_patterns = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.ip_addresses = defaultdict(int)
        self.status_codes = defaultdict(int)
        
        # Load patterns from config
        self.suspicious_path_patterns = config.SUSPICIOUS_PATH_PATTERNS
        self.suspicious_ua_patterns = config.SUSPICIOUS_UA_PATTERNS
    
    def extract_features(self, log_entry) -> Dict:
        """Extract comprehensive features from log entry"""
        features = {}
        
        # Temporal features
        timestamp = log_entry['timestamp']
        features['hour'] = timestamp.hour
        features['day_of_week'] = timestamp.weekday()
        features['is_weekend'] = 1 if timestamp.weekday() >= 5 else 0
        features['is_business_hours'] = 1 if 9 <= timestamp.hour <= 17 else 0
        
        # Basic request features
        features['status_code'] = log_entry['status']
        features['response_size'] = log_entry['size']
        features['method_get'] = 1 if log_entry['method'] == 'GET' else 0
        features['method_post'] = 1 if log_entry['method'] == 'POST' else 0
        features['method_put'] = 1 if log_entry['method'] == 'PUT' else 0
        features['method_delete'] = 1 if log_entry['method'] == 'DELETE' else 0
        
        # Path analysis
        path = log_entry['path']
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/')
        features['has_query_params'] = 1 if '?' in path else 0
        features['query_param_count'] = path.count('&') + (1 if '?' in path else 0)
        features['path_suspicious'] = self.check_suspicious_path(path)
        features['has_file_extension'] = 1 if '.' in path.split('/')[-1] else 0
        
        # User agent analysis
        ua = log_entry['user_agent']
        features['ua_length'] = len(ua)
        features['ua_suspicious'] = self.check_suspicious_ua(ua)
        features['ua_is_bot'] = self.check_bot_user_agent(ua)
        features['ua_is_mobile'] = self.check_mobile_user_agent(ua)
        
        # IP address features
        ip = log_entry['ip_address']
        features['ip_is_private'] = self.check_private_ip(ip)
        features['ip_entropy'] = self.calculate_ip_entropy(ip)
        
        # Status code categories
        status = log_entry['status']
        features['status_success'] = 1 if 200 <= status < 300 else 0
        features['status_redirect'] = 1 if 300 <= status < 400 else 0
        features['status_client_error'] = 1 if 400 <= status < 500 else 0
        features['status_server_error'] = 1 if status >= 500 else 0
        
        # Frequency-based features
        features['path_frequency'] = self.path_patterns.get(path, 0)
        features['ua_frequency'] = self.user_agents.get(ua, 0)
        features['ip_frequency'] = self.ip_addresses.get(ip, 0)
        
        # Update frequency counters
        self.path_patterns[path] += 1
        self.user_agents[ua] += 1
        self.ip_addresses[ip] += 1
        self.status_codes[status] += 1
        
        # Advanced features
        features['entropy_score'] = self.calculate_request_entropy(log_entry)
        features['anomaly_score_basic'] = self.calculate_basic_anomaly_score(features)
        
        return features
    
    def check_suspicious_path(self, path):
        """Enhanced suspicious path detection"""
        path_lower = path.lower()
        
        # Check against patterns
        for pattern in self.suspicious_path_patterns:
            if re.search(pattern, path_lower):
                return 1
        
        # Additional checks
        suspicious_keywords = ['admin', 'config', 'backup', 'test', 'debug', 'tmp']
        for keyword in suspicious_keywords:
            if keyword in path_lower:
                return 1
        
        # Check for excessive parameters
        if path.count('=') > 5 or path.count('&') > 10:
            return 1
        
        # Check for encoded characters
        if '%' in path and path.count('%') > 3:
            return 1
        
        return 0
    
    def check_suspicious_ua(self, user_agent):
        """Enhanced suspicious user agent detection"""
        ua_lower = user_agent.lower()
        
        # Check against known patterns
        for pattern in self.suspicious_ua_patterns:
            if pattern in ua_lower:
                return 1
        
        # Check for empty or very short user agents
        if len(user_agent.strip()) < 10:
            return 1
        
        # Check for automated tool signatures
        automated_signatures = ['python', 'curl', 'wget', 'java', 'go-http', 'libwww']
        for sig in automated_signatures:
            if sig in ua_lower:
                return 1
        
        return 0
    
    def check_bot_user_agent(self, user_agent):
        """Check if user agent indicates a bot"""
        ua_lower = user_agent.lower()
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'googlebot', 'bingbot']
        return 1 if any(indicator in ua_lower for indicator in bot_indicators) else 0
    
    def check_mobile_user_agent(self, user_agent):
        """Check if user agent indicates mobile device"""
        ua_lower = user_agent.lower()
        mobile_indicators = ['mobile', 'android', 'iphone', 'ipad', 'tablet']
        return 1 if any(indicator in ua_lower for indicator in mobile_indicators) else 0
    
    def check_private_ip(self, ip_address):
        """Check if IP address is private"""
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_address)
            return 1 if ip.is_private else 0
        except ValueError:
            return 0
    
    def calculate_ip_entropy(self, ip_address):
        """Calculate entropy of IP address"""
        parts = ip_address.split('.')
        if len(parts) != 4:
            return 0
        
        try:
            variance = np.var([int(part) for part in parts])
            return min(variance / 255.0, 1.0)
        except ValueError:
            return 0
    
    def calculate_request_entropy(self, log_entry):
        """Calculate overall entropy of the request"""
        text = f"{log_entry['method']} {log_entry['path']} {log_entry['user_agent']}"
        
        # Character frequency analysis
        char_counts = defaultdict(int)
        for char in text.lower():
            char_counts[char] += 1
        
        # Calculate entropy
        total_chars = len(text)
        entropy = 0
        for count in char_counts.values():
            if count > 0:
                p = count / total_chars
                entropy -= p * np.log2(p)
        
        return min(entropy / 8.0, 1.0)  # Normalize to 0-1
    
    def calculate_basic_anomaly_score(self, features):
        """Calculate a basic anomaly score based on feature values"""
        score = 0
        
        # High score for suspicious patterns
        score += features.get('path_suspicious', 0) * 0.3
        score += features.get('ua_suspicious', 0) * 0.3
        
        # High score for unusual status codes
        if features.get('status_server_error', 0):
            score += 0.2
        elif features.get('status_client_error', 0):
            score += 0.1
        
        # High score for unusual times
        if not features.get('is_business_hours', 0):
            score += 0.1
        
        # High score for unusual methods
        if features.get('method_put', 0) or features.get('method_delete', 0):
            score += 0.1
        
        return min(score, 1.0)

class EnhancedLogBERTModel(nn.Module):
    """Enhanced BERT-like model for log analysis with better architecture"""
    
    def __init__(self, vocab_size=config.VOCAB_SIZE, embed_dim=config.EMBED_DIM, 
                 hidden_dim=config.HIDDEN_DIM, num_layers=config.NUM_LAYERS):
        super().__init__()
        
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.positional_encoding = self.create_positional_encoding(config.MAX_SEQUENCE_LENGTH, embed_dim)
        
        # Multi-head attention transformer
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=8,
            dim_feedforward=hidden_dim,
            dropout=0.1,
            activation='gelu'
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, 2)  # Normal vs Anomaly
        )
        
        self.dropout = nn.Dropout(0.1)
    
    def create_positional_encoding(self, max_len, embed_dim):
        """Create positional encoding for transformer"""
        pe = torch.zeros(max_len, embed_dim)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, embed_dim, 2).float() * 
                           (-np.log(10000.0) / embed_dim))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        
        return pe.unsqueeze(0)
    
    def forward(self, x, attention_mask=None):
        batch_size, seq_len = x.shape
        
        # Embedding and positional encoding
        embedded = self.embedding(x.long())
        
        # Add positional encoding
        if seq_len <= self.positional_encoding.size(1):
            embedded += self.positional_encoding[:, :seq_len, :]
        
        # Transformer encoding
        embedded = embedded.transpose(0, 1)  # (seq_len, batch, embed_dim)
        transformed = self.transformer(embedded, src_key_padding_mask=attention_mask)
        
        # Global average pooling
        pooled = transformed.mean(dim=0)  # (batch, embed_dim)
        
        # Classification
        output = self.classifier(self.dropout(pooled))
        return output

class EnhancedRealTimeLogAnalyzer:
    """Enhanced real-time log analyzer with better integration capabilities"""
    
    def __init__(self, log_paths=None, model_save_path=None):
        # Configuration
        self.log_paths = log_paths or config.get_valid_log_paths()
        self.model_save_path = Path(model_save_path or config.MODEL_SAVE_PATH)
        self.model_save_path.mkdir(exist_ok=True, parents=True)
        
        # Data storage
        self.normal_logs = deque(maxlen=config.MAX_NORMAL_LOGS)
        self.recent_logs = deque(maxlen=config.MAX_RECENT_LOGS)
        self.anomaly_logs = []
        self.processed_lines = set()  # Prevent duplicate processing
        
        # Feature extraction and preprocessing
        self.feature_extractor = EnhancedLogFeatureExtractor()
        self.scaler = StandardScaler()
        
        # Models
        self.isolation_forest = IsolationForest(
            contamination=config.ISOLATION_FOREST_CONTAMINATION,
            random_state=42,
            n_estimators=100
        )
        self.logbert_model = None
        self.is_trained = False
        
        # Training parameters
        self.training_threshold = config.TRAINING_THRESHOLD
        self.retrain_interval = config.RETRAIN_INTERVAL
        self.last_training_time = 0
        
        # Statistics and monitoring
        self.stats = {
            'total_requests': 0,
            'normal_requests': 0,
            'anomaly_requests': 0,
            'last_anomaly_time': None,
            'training_count': 0,
            'model_accuracy': 0.0,
            'processing_rate': 0.0,
            'start_time': datetime.now()
        }
        
        # File monitoring
        self.observer = None
        self.is_monitoring = False
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Load existing models
        self.load_models()
        
        logger.info(f"Enhanced analyzer initialized with {len(self.log_paths)} log paths")
    
    def start_monitoring(self):
        """Start monitoring log files"""
        if self.is_monitoring:
            logger.warning("Monitoring already active")
            return
        
        if not self.log_paths:
            logger.error("No valid log paths found")
            return
        
        try:
            # Set up file system observer
            self.observer = Observer()
            monitor = EnhancedTomcatLogMonitor(self, self.log_paths)
            
            # Monitor directories containing log files
            monitored_dirs = set()
            for log_path in self.log_paths:
                if '*' in log_path:
                    # Handle glob patterns
                    dir_path = os.path.dirname(log_path)
                else:
                    dir_path = os.path.dirname(log_path)
                
                if os.path.exists(dir_path) and dir_path not in monitored_dirs:
                    self.observer.schedule(monitor, dir_path, recursive=False)
                    monitored_dirs.add(dir_path)
                    logger.info(f"Monitoring directory: {dir_path}")
            
            if monitored_dirs:
                self.observer.start()
                self.is_monitoring = True
                logger.info("File monitoring started successfully")
                
                # Process existing log files
                self.process_existing_logs()
            else:
                logger.error("No valid directories to monitor")
        
        except Exception as e:
            logger.error(f"Failed to start monitoring: {str(e)}")
    
    def stop_monitoring(self):
        """Stop monitoring log files"""
        if self.observer and self.is_monitoring:
            self.observer.stop()
            self.observer.join()
            self.is_monitoring = False
            logger.info("File monitoring stopped")
    
    def process_existing_logs(self):
        """Process existing log files to build baseline"""
        logger.info("Processing existing logs for baseline...")
        
        processed_count = 0
        for log_path in self.log_paths:
            if '*' in log_path:
                files = glob.glob(log_path)
            else:
                files = [log_path] if os.path.exists(log_path) else []
            
            for filepath in files:
                try:
                    processed_count += self.process_existing_file(filepath)
                except Exception as e:
                    logger.error(f"Error processing {filepath}: {str(e)}")
        
        logger.info(f"Processed {processed_count} existing log entries")
        
        # Train initial models if we have enough data
        if len(self.normal_logs) >= self.training_threshold:
            self.train_models()
    
    def process_existing_file(self, filepath, max_lines=1000):
        """Process an existing log file (tail only for baseline)"""
        if not os.path.exists(filepath):
            return 0
        
        try:
            # Read last N lines for baseline
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Take last max_lines for baseline
            recent_lines = lines[-max_lines:] if len(lines) > max_lines else lines
            
            entries = []
            for line in recent_lines:
                line = line.strip()
                if not line or line in self.processed_lines:
                    continue
                
                try:
                    monitor = EnhancedTomcatLogMonitor(self, [])
                    entry = monitor.parse_tomcat_log_line(line)
                    if entry:
                        entry['source_file'] = filepath
                        entries.append(entry)
                        self.processed_lines.add(line)
                except Exception:
                    continue
            
            if entries:
                # Assume existing logs are mostly normal for baseline
                self.process_logs(entries, assume_normal=True)
            
            return len(entries)
            
        except Exception as e:
            logger.error(f"Error processing existing file {filepath}: {str(e)}")
            return 0
    
    def process_logs(self, log_entries, assume_normal=False):
        """Process new log entries"""
        with self.lock:
            for entry in log_entries:
                try:
                    # Extract features
                    features = self.feature_extractor.extract_features(entry)
                    entry['features'] = features
                    
                    # Add to recent logs
                    self.recent_logs.append(entry)
                    self.stats['total_requests'] += 1
                    
                    # Detect anomaly (unless we're processing baseline data)
                    if assume_normal or not self.is_trained:
                        is_anomaly = False
                    else:
                        is_anomaly = self.detect_anomaly(entry)
                    
                    entry['is_anomaly'] = is_anomaly
                    
                    if is_anomaly:
                        self.anomaly_logs.append(entry)
                        self.stats['anomaly_requests'] += 1
                        self.stats['last_anomaly_time'] = entry['timestamp']
                        
                        logger.warning(
                            f"ANOMALY DETECTED: {entry['ip_address']} - "
                            f"{entry['method']} {entry['path']} - "
                            f"Status: {entry['status']}"
                        )
                    else:
                        self.normal_logs.append(entry)
                        self.stats['normal_requests'] += 1
                    
                except Exception as e:
                    logger.error(f"Error processing log entry: {str(e)}")
            
            # Update processing rate
            self.update_processing_rate()
            
            # Check if we need to retrain
            if self.should_retrain():
                threading.Thread(target=self.train_models, daemon=True).start()
    
    def detect_anomaly(self, log_entry):
        """Enhanced anomaly detection using multiple methods"""
        if not self.is_trained:
            return False
        
        try:
            features = list(log_entry['features'].values())
            features_scaled = self.scaler.transform([features])
            
            # Isolation Forest prediction
            if_prediction = self.isolation_forest.predict(features_scaled)[0]
            
            # LogBERT prediction (if available)
            logbert_anomaly = False
            if self.logbert_model is not None:
                try:
                    # Simple prediction for now
                    logbert_anomaly = self.predict_with_logbert(log_entry)
                except Exception as e:
                    logger.debug(f"LogBERT prediction failed: {str(e)}")
            
            # Basic anomaly score from features
            basic_score = log_entry['features'].get('anomaly_score_basic', 0)
            
            # Combine predictions
            anomaly_indicators = [
                if_prediction == -1,  # Isolation Forest
                logbert_anomaly,      # LogBERT
                basic_score > 0.5     # Basic feature score
            ]
            
            # Anomaly if any method detects it (can be made more sophisticated)
            return any(anomaly_indicators)
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            return False
    
    def predict_with_logbert(self, log_entry):
        """Predict anomaly using LogBERT model"""
        if self.logbert_model is None:
            return False
        
        try:
            # Create sequence representation
            sequence = f"{log_entry['method']} {log_entry['path']} {log_entry['status']} {log_entry['user_agent'][:50]}"
            
            # Simple tokenization (in production, use proper tokenizer)
            tokens = sequence.split()[:config.MAX_SEQUENCE_LENGTH]
            
            # Create feature vector
            feature_vector = torch.zeros(config.MAX_SEQUENCE_LENGTH)
            for i, token in enumerate(tokens):
                feature_vector[i] = hash(token) % config.VOCAB_SIZE
            
            # Predict
            self.logbert_model.eval()
            with torch.no_grad():
                output = self.logbert_model(feature_vector.unsqueeze(0))
                prediction = torch.softmax(output, dim=1)
                
                # Return True if anomaly probability > 0.5
                return prediction[0][1].item() > 0.5
                
        except Exception as e:
            logger.debug(f"LogBERT prediction error: {str(e)}")
            return False
    
    def should_retrain(self):
        """Check if models should be retrained"""
        current_time = time.time()
        return (len(self.normal_logs) >= self.training_threshold and 
                current_time - self.last_training_time > self.retrain_interval)
    
    def train_models(self):
        """Train/retrain anomaly detection models"""
        with self.lock:
            if len(self.normal_logs) < self.training_threshold:
                return
            
            logger.info(f"Starting model training with {len(self.normal_logs)} samples...")
            
            try:
                # Prepare training data
                training_features = []
                for entry in list(self.normal_logs):
                    if 'features' in entry:
                        training_features.append(list(entry['features'].values()))
                
                if not training_features:
                    logger.warning("No training features available")
                    return
                
                # Train Isolation Forest
                training_array = np.array(training_features)
                self.scaler.fit(training_array)
                scaled_features = self.scaler.transform(training_array)
                self.isolation_forest.fit(scaled_features)
                
                # Train LogBERT
                self.train_logbert()
                
                # Update training statistics
                self.is_trained = True
                self.last_training_time = time.time()
                self.stats['training_count'] += 1
                self.stats['model_accuracy'] = self.calculate_model_accuracy()
                
                # Save models
                self.save_models()
                
                logger.info(f"Models trained successfully - Accuracy: {self.stats['model_accuracy']:.2f}%")
                
            except Exception as e:
                logger.error(f"Error during model training: {str(e)}")
    
    def train_logbert(self):
        """Train the LogBERT model"""
        try:
            if not self.normal_logs:
                return
            
            # Initialize model
            self.logbert_model = EnhancedLogBERTModel()
            
            # Create dataset (simplified for real-time training)
            dataset = self.create_logbert_dataset(list(self.normal_logs))
            if len(dataset) == 0:
                return
            
            dataloader = DataLoader(dataset, batch_size=config.BATCH_SIZE, shuffle=True)
            
            # Training setup
            optimizer = torch.optim.Adam(self.logbert_model.parameters(), lr=config.LEARNING_RATE)
            criterion = nn.CrossEntropyLoss()
            
            self.logbert_model.train()
            for epoch in range(config.TRAINING_EPOCHS):
                total_loss = 0
                for batch_data, batch_labels in dataloader:
                    optimizer.zero_grad()
                    outputs = self.logbert_model(batch_data)
                    loss = criterion(outputs, batch_labels)
                    loss.backward()
                    optimizer.step()
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(dataloader)
                logger.debug(f"LogBERT Epoch {epoch + 1}/{config.TRAINING_EPOCHS}, Loss: {avg_loss:.4f}")
            
            logger.info("LogBERT model trained successfully")
            
        except Exception as e:
            logger.error(f"Error training LogBERT: {str(e)}")
    
    def create_logbert_dataset(self, log_entries):
        """Create dataset for LogBERT training"""
        data = []
        labels = []
        
        for entry in log_entries:
            try:
                # Create sequence representation
                sequence = f"{entry['method']} {entry['path']} {entry['status']} {entry['user_agent'][:50]}"
                
                # Simple tokenization
                tokens = sequence.split()[:config.MAX_SEQUENCE_LENGTH]
                
                # Create feature vector
                feature_vector = torch.zeros(config.MAX_SEQUENCE_LENGTH)
                for i, token in enumerate(tokens):
                    feature_vector[i] = hash(token) % config.VOCAB_SIZE
                
                data.append(feature_vector)
                labels.append(0)  # Normal logs are label 0
                
            except Exception as e:
                logger.debug(f"Error creating dataset entry: {str(e)}")
                continue
        
        if not data:
            return []
        
        return list(zip(torch.stack(data), torch.tensor(labels)))
    
    def calculate_model_accuracy(self):
        """Calculate current model accuracy (simplified)"""
        if not self.is_trained or len(self.recent_logs) < 10:
            return 0.0
        
        try:
            # Use recent logs for validation (simplified approach)
            correct_predictions = 0
            total_predictions = 0
            
            for entry in list(self.recent_logs)[-100:]:
                if 'features' not in entry:
                    continue
                
                # True label (simplified - assume normal unless has anomaly indicators)
                true_anomaly = entry.get('is_anomaly', False)
                
                # Predict
                predicted_anomaly = self.detect_anomaly(entry)
                
                if true_anomaly == predicted_anomaly:
                    correct_predictions += 1
                total_predictions += 1
            
            accuracy = (correct_predictions / total_predictions * 100) if total_predictions > 0 else 0
            return min(accuracy, 100.0)  # Cap at 100%
            
        except Exception as e:
            logger.error(f"Error calculating accuracy: {str(e)}")
            return 0.0
    
    def update_processing_rate(self):
        """Update processing rate statistics"""
        try:
            elapsed_time = (datetime.now() - self.stats['start_time']).total_seconds()
            if elapsed_time > 0:
                self.stats['processing_rate'] = self.stats['total_requests'] / elapsed_time
        except Exception:
            self.stats['processing_rate'] = 0.0
    
    def save_models(self):
        """Save trained models"""
        try:
            # Save isolation forest and scaler
            joblib.dump(self.isolation_forest, self.model_save_path / "isolation_forest.pkl")
            joblib.dump(self.scaler, self.model_save_path / "scaler.pkl")
            
            # Save LogBERT
            if self.logbert_model:
                torch.save(self.logbert_model.state_dict(), self.model_save_path / "logbert_model.pth")
            
            # Save feature extractor state
            extractor_state = {
                'path_patterns': dict(self.feature_extractor.path_patterns),
                'user_agents': dict(self.feature_extractor.user_agents),
                'ip_addresses': dict(self.feature_extractor.ip_addresses)
            }
            
            with open(self.model_save_path / "feature_extractor.json", 'w') as f:
                json.dump(extractor_state, f)
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
    
    def load_models(self):
        """Load pre-trained models"""
        try:
            if (self.model_save_path / "isolation_forest.pkl").exists():
                self.isolation_forest = joblib.load(self.model_save_path / "isolation_forest.pkl")
                self.scaler = joblib.load(self.model_save_path / "scaler.pkl")
                
                # Load LogBERT
                if (self.model_save_path / "logbert_model.pth").exists():
                    self.logbert_model = EnhancedLogBERTModel()
                    self.logbert_model.load_state_dict(torch.load(self.model_save_path / "logbert_model.pth"))
                
                # Load feature extractor state
                if (self.model_save_path / "feature_extractor.json").exists():
                    with open(self.model_save_path / "feature_extractor.json", 'r') as f:
                        extractor_state = json.load(f)
                    
                    self.feature_extractor.path_patterns.update(extractor_state.get('path_patterns', {}))
                    self.feature_extractor.user_agents.update(extractor_state.get('user_agents', {}))
                    self.feature_extractor.ip_addresses.update(extractor_state.get('ip_addresses', {}))
                
                self.is_trained = True
                logger.info("Pre-trained models loaded successfully")
                
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    def get_statistics(self):
        """Get comprehensive statistics"""
        with self.lock:
            return {
                **self.stats,
                'model_trained': self.is_trained,
                'normal_logs_count': len(self.normal_logs),
                'recent_logs_count': len(self.recent_logs),
                'anomaly_logs_count': len(self.anomaly_logs),
                'is_monitoring': self.is_monitoring,
                'log_paths_count': len(self.log_paths),
                'anomaly_rate': (self.stats['anomaly_requests'] / max(self.stats['total_requests'], 1)) * 100
            }
    
    def get_recent_anomalies(self, limit=10):
        """Get recent anomalies"""
        with self.lock:
            return self.anomaly_logs[-limit:] if self.anomaly_logs else []
    
    def get_recent_logs(self, limit=100):
        """Get recent logs"""
        with self.lock:
            return list(self.recent_logs)[-limit:] if self.recent_logs else []
    
    def get_log_data_for_dashboard(self):
        """Get formatted log data for dashboard display"""
        with self.lock:
            logs = []
            for entry in self.recent_logs:
                logs.append({
                    'timestamp': entry['timestamp'].isoformat() if isinstance(entry['timestamp'], datetime) else str(entry['timestamp']),
                    'ip_address': entry['ip_address'],
                    'method': entry['method'],
                    'path': entry['path'][:100],  # Truncate long paths
                    'status_code': entry['status'],
                    'user_agent': entry['user_agent'][:100],  # Truncate long UAs
                    'is_anomaly': entry.get('is_anomaly', False),
                    'response_size': entry['size']
                })
            
            return logs

def main():
    """Main function for standalone execution"""
    # Ensure configuration directories exist
    config.ensure_directories()
    
    # Create analyzer instance
    analyzer = EnhancedRealTimeLogAnalyzer()
    
    # Start monitoring
    analyzer.start_monitoring()
    
    try:
        logger.info("Enhanced LogBERT analyzer is running. Press Ctrl+C to stop.")
        
        # Main monitoring loop
        while True:
            time.sleep(10)
            
            # Print statistics
            stats = analyzer.get_statistics()
            logger.info(
                f"Stats - Total: {stats['total_requests']}, "
                f"Anomalies: {stats['anomaly_requests']} ({stats['anomaly_rate']:.1f}%), "
                f"Rate: {stats['processing_rate']:.1f} req/s, "
                f"Trained: {'Yes' if stats['model_trained'] else 'No'}"
            )
            
    except KeyboardInterrupt:
        logger.info("Shutting down analyzer...")
        analyzer.stop_monitoring()

if __name__ == "__main__":
    main()
