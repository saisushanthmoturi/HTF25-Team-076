"""
Real-time Log Monitor & LogBERT Training System
Continuously monitors Tomcat access logs, trains LogBERT on normal traffic, and detects anomalies
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

warnings.filterwarnings('ignore')

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TomcatLogMonitor(FileSystemEventHandler):
    """Monitor Tomcat access logs for real-time analysis"""
    
    def __init__(self, log_paths, callback):
        self.log_paths = [Path(p) for p in log_paths]
        self.callback = callback
        self.last_positions = {path: 0 for path in self.log_paths}
        
    def on_modified(self, event):
        """Called when a log file is modified"""
        if event.is_directory:
            return
            
        file_path = Path(event.src_path)
        if file_path in self.log_paths:
            self.process_new_entries(file_path)
    
    def process_new_entries(self, file_path):
        """Process new log entries from the specified file"""
        try:
            with open(file_path, 'r') as f:
                # Move to last known position
                f.seek(self.last_positions[file_path])
                new_lines = f.readlines()
                # Update position
                self.last_positions[file_path] = f.tell()
                
            if new_lines:
                parsed_logs = [self.parse_log_line(line.strip()) for line in new_lines if line.strip()]
                valid_logs = [log for log in parsed_logs if log is not None]
                
                if valid_logs:
                    self.callback(valid_logs)
                    
        except Exception as e:
            logger.error(f"Error processing log file {file_path}: {str(e)}")
    
    def parse_log_line(self, line):
        """Parse a single Apache/Tomcat access log line"""
        # Common Log Format pattern
        pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'
        
        match = re.match(pattern, line)
        if not match:
            return None
            
        try:
            return {
                'ip': match.group(1),
                'timestamp': datetime.strptime(match.group(2), '%d/%b/%Y:%H:%M:%S %z'),
                'method': match.group(3),
                'path': match.group(4),
                'protocol': match.group(5),
                'status': int(match.group(6)),
                'size': int(match.group(7)) if match.group(7) != '-' else 0,
                'referer': match.group(8),
                'user_agent': match.group(9),
                'raw_line': line
            }
        except Exception as e:
            logger.warning(f"Failed to parse log line: {line}, error: {e}")
            return None

class LogFeatureExtractor:
    """Extract features from log entries for ML training"""
    
    def __init__(self):
        self.path_patterns = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.ip_addresses = defaultdict(int)
        
    def extract_features(self, log_entry):
        """Extract numerical features from a log entry"""
        features = {}
        
        # Basic features
        features['hour'] = log_entry['timestamp'].hour
        features['day_of_week'] = log_entry['timestamp'].weekday()
        features['status_code'] = log_entry['status']
        features['response_size'] = log_entry['size']
        features['method_get'] = 1 if log_entry['method'] == 'GET' else 0
        features['method_post'] = 1 if log_entry['method'] == 'POST' else 0
        
        # Path analysis
        path = log_entry['path']
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/')
        features['has_query_params'] = 1 if '?' in path else 0
        features['path_suspicious'] = self.check_suspicious_path(path)
        
        # User agent analysis
        ua = log_entry['user_agent']
        features['ua_length'] = len(ua)
        features['ua_suspicious'] = self.check_suspicious_ua(ua)
        
        # Status code categories
        features['status_success'] = 1 if 200 <= log_entry['status'] < 300 else 0
        features['status_client_error'] = 1 if 400 <= log_entry['status'] < 500 else 0
        features['status_server_error'] = 1 if log_entry['status'] >= 500 else 0
        
        return features
    
    def check_suspicious_path(self, path):
        """Check for suspicious patterns in the request path"""
        suspicious_patterns = [
            r'\.\./', r'<script', r'<img', r'javascript:', 
            r'union.*select', r'drop.*table', r'insert.*into',
            r'cmd\.exe', r'powershell', r'bash', r'sh'
        ]
        
        path_lower = path.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, path_lower):
                return 1
        return 0
    
    def check_suspicious_ua(self, user_agent):
        """Check for suspicious user agent patterns"""
        suspicious_ua_patterns = [
            'sqlmap', 'nikto', 'nmap', 'burp', 'acunetix',
            'metasploit', 'nessus', 'openvas', 'w3af'
        ]
        
        ua_lower = user_agent.lower()
        for pattern in suspicious_ua_patterns:
            if pattern in ua_lower:
                return 1
        return 0

class LogBERTDataset(Dataset):
    """Dataset class for LogBERT training"""
    
    def __init__(self, log_entries, max_length=128):
        self.log_entries = log_entries
        self.max_length = max_length
        
    def __len__(self):
        return len(self.log_entries)
    
    def __getitem__(self, idx):
        entry = self.log_entries[idx]
        # Create sequence representation
        sequence = f"{entry['method']} {entry['path']} {entry['status']} {entry['user_agent'][:50]}"
        
        # Simple tokenization (in practice, you'd use proper tokenizers)
        tokens = sequence.split()[:self.max_length]
        
        # Create feature vector
        feature_vector = torch.zeros(self.max_length)
        for i, token in enumerate(tokens):
            feature_vector[i] = hash(token) % 1000  # Simple hash-based encoding
            
        return feature_vector

class SimpleLogBERT(nn.Module):
    """Simplified BERT-like model for log analysis"""
    
    def __init__(self, vocab_size=1000, embed_dim=128, hidden_dim=256, num_layers=2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.transformer = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(embed_dim, nhead=8, dim_feedforward=hidden_dim),
            num_layers=num_layers
        )
        self.classifier = nn.Linear(embed_dim, 2)  # Normal vs Anomaly
        self.dropout = nn.Dropout(0.1)
        
    def forward(self, x):
        embedded = self.embedding(x.long())
        transformed = self.transformer(embedded)
        pooled = transformed.mean(dim=1)  # Simple pooling
        output = self.classifier(self.dropout(pooled))
        return output

class RealTimeLogAnalyzer:
    """Main class for real-time log analysis and anomaly detection"""
    
    def __init__(self, log_paths, model_save_path="./models"):
        self.log_paths = log_paths
        self.model_save_path = Path(model_save_path)
        self.model_save_path.mkdir(exist_ok=True)
        
        # Data storage
        self.normal_logs = deque(maxlen=10000)  # Store recent normal logs
        self.recent_logs = deque(maxlen=1000)   # Store all recent logs
        self.anomaly_logs = []
        
        # Feature extraction
        self.feature_extractor = LogFeatureExtractor()
        self.scaler = StandardScaler()
        
        # Models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.logbert_model = None
        self.is_trained = False
        
        # Training parameters
        self.training_threshold = 100  # Minimum samples for training
        self.retrain_interval = 300    # Retrain every 5 minutes
        self.last_training_time = 0
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'normal_requests': 0,
            'anomaly_requests': 0,
            'last_anomaly_time': None,
            'training_count': 0
        }
        
        # Start log monitoring
        self.start_monitoring()
        
    def start_monitoring(self):
        """Start monitoring log files"""
        self.observer = Observer()
        handler = TomcatLogMonitor(self.log_paths, self.process_logs)
        
        for log_path in self.log_paths:
            if log_path.parent.exists():
                self.observer.schedule(handler, str(log_path.parent), recursive=False)
                logger.info(f"Monitoring {log_path}")
        
        self.observer.start()
        logger.info("Log monitoring started")
        
    def process_logs(self, log_entries):
        """Process new log entries"""
        for entry in log_entries:
            self.recent_logs.append(entry)
            self.stats['total_requests'] += 1
            
            # Extract features
            features = self.feature_extractor.extract_features(entry)
            entry['features'] = features
            
            # Check if anomaly
            is_anomaly = self.detect_anomaly(entry)
            entry['is_anomaly'] = is_anomaly
            
            if is_anomaly:
                self.anomaly_logs.append(entry)
                self.stats['anomaly_requests'] += 1
                self.stats['last_anomaly_time'] = entry['timestamp']
                logger.warning(f"ANOMALY DETECTED: {entry['method']} {entry['path']} - Status: {entry['status']}")
            else:
                self.normal_logs.append(entry)
                self.stats['normal_requests'] += 1
            
            # Periodic retraining
            if self.should_retrain():
                self.train_models()
    
    def detect_anomaly(self, log_entry):
        """Detect if a log entry is anomalous"""
        if not self.is_trained:
            return False
            
        try:
            features = list(log_entry['features'].values())
            features_scaled = self.scaler.transform([features])
            
            # Use isolation forest
            prediction = self.isolation_forest.predict(features_scaled)
            
            # -1 indicates anomaly, 1 indicates normal
            return prediction[0] == -1
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            return False
    
    def should_retrain(self):
        """Check if models should be retrained"""
        current_time = time.time()
        return (len(self.normal_logs) >= self.training_threshold and 
                current_time - self.last_training_time > self.retrain_interval)
    
    def train_models(self):
        """Train/retrain anomaly detection models"""
        if len(self.normal_logs) < self.training_threshold:
            return
            
        logger.info("Starting model training...")
        
        try:
            # Prepare training data
            training_features = []
            for entry in list(self.normal_logs):
                if 'features' in entry:
                    training_features.append(list(entry['features'].values()))
            
            if not training_features:
                logger.warning("No training features available")
                return
            
            # Train isolation forest
            training_array = np.array(training_features)
            self.scaler.fit(training_array)
            scaled_features = self.scaler.transform(training_array)
            self.isolation_forest.fit(scaled_features)
            
            # Train LogBERT (simplified)
            self.train_logbert()
            
            self.is_trained = True
            self.last_training_time = time.time()
            self.stats['training_count'] += 1
            
            # Save models
            self.save_models()
            
            logger.info(f"Models trained successfully with {len(training_features)} samples")
            
        except Exception as e:
            logger.error(f"Error during model training: {str(e)}")
    
    def train_logbert(self):
        """Train the LogBERT model"""
        try:
            # Initialize model
            self.logbert_model = SimpleLogBERT()
            
            # Create dataset
            dataset = LogBERTDataset(list(self.normal_logs))
            dataloader = DataLoader(dataset, batch_size=32, shuffle=True)
            
            # Simple training loop (normally this would be more sophisticated)
            optimizer = torch.optim.Adam(self.logbert_model.parameters())
            criterion = nn.CrossEntropyLoss()
            
            self.logbert_model.train()
            for epoch in range(3):  # Limited epochs for real-time training
                for batch in dataloader:
                    optimizer.zero_grad()
                    # For normal logs, predict class 0
                    targets = torch.zeros(len(batch), dtype=torch.long)
                    outputs = self.logbert_model(batch)
                    loss = criterion(outputs, targets)
                    loss.backward()
                    optimizer.step()
            
            logger.info("LogBERT model trained successfully")
            
        except Exception as e:
            logger.error(f"Error training LogBERT: {str(e)}")
    
    def save_models(self):
        """Save trained models"""
        try:
            # Save isolation forest and scaler
            joblib.dump(self.isolation_forest, self.model_save_path / "isolation_forest.pkl")
            joblib.dump(self.scaler, self.model_save_path / "scaler.pkl")
            
            # Save LogBERT
            if self.logbert_model:
                torch.save(self.logbert_model.state_dict(), self.model_save_path / "logbert_model.pth")
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
    
    def load_models(self):
        """Load pre-trained models"""
        try:
            if (self.model_save_path / "isolation_forest.pkl").exists():
                self.isolation_forest = joblib.load(self.model_save_path / "isolation_forest.pkl")
                self.scaler = joblib.load(self.model_save_path / "scaler.pkl")
                
                if (self.model_save_path / "logbert_model.pth").exists():
                    self.logbert_model = SimpleLogBERT()
                    self.logbert_model.load_state_dict(torch.load(self.model_save_path / "logbert_model.pth"))
                
                self.is_trained = True
                logger.info("Pre-trained models loaded successfully")
                
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    def get_statistics(self):
        """Get current statistics"""
        return {
            **self.stats,
            'model_trained': self.is_trained,
            'normal_logs_count': len(self.normal_logs),
            'recent_logs_count': len(self.recent_logs),
            'anomaly_logs_count': len(self.anomaly_logs)
        }
    
    def get_recent_anomalies(self, limit=10):
        """Get recent anomalies"""
        return self.anomaly_logs[-limit:] if self.anomaly_logs else []
    
    def get_recent_logs(self, limit=100):
        """Get recent logs"""
        return list(self.recent_logs)[-limit:] if self.recent_logs else []
    
    def stop_monitoring(self):
        """Stop log monitoring"""
        if hasattr(self, 'observer'):
            self.observer.stop()
            self.observer.join()
            logger.info("Log monitoring stopped")

if __name__ == "__main__":
    # Example usage
    log_paths = [
        "/opt/tomcat/logs/access_log.txt",
        "/var/log/tomcat/localhost_access_log.txt"
    ]
    
    analyzer = RealTimeLogAnalyzer(log_paths)
    analyzer.load_models()  # Try to load existing models
    
    try:
        # Keep running
        while True:
            time.sleep(10)
            stats = analyzer.get_statistics()
            logger.info(f"Stats: {stats}")
            
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        analyzer.stop_monitoring()
