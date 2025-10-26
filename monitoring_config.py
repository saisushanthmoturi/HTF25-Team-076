"""
Configuration file for LogBERT Security Monitoring System
Contains paths, settings, and parameters for real-time log analysis
"""

import os
from pathlib import Path

class MonitoringConfig:
    """Configuration class for the monitoring system"""
    
    # Tomcat Log Paths (adjust these to your actual Tomcat installation)
    TOMCAT_LOG_PATHS = [
        "/Users/majjipradeepkumar/Downloads/apache-tomcat-9.0.109/logs/localhost_access_log.*.txt",
        "/opt/tomcat/logs/localhost_access_log.*.txt",
        "/var/log/tomcat/localhost_access_log.*.txt",
        "/usr/local/tomcat/logs/localhost_access_log.*.txt"
    ]
    
    # Model Storage
    MODEL_SAVE_PATH = "./models"
    
    # Training Parameters
    TRAINING_THRESHOLD = 100  # Minimum samples before training
    RETRAIN_INTERVAL = 300    # Retrain every 5 minutes (seconds)
    MAX_NORMAL_LOGS = 10000   # Maximum normal logs to keep in memory
    MAX_RECENT_LOGS = 1000    # Maximum recent logs to keep
    
    # Anomaly Detection
    ISOLATION_FOREST_CONTAMINATION = 0.1  # Expected proportion of anomalies
    ANOMALY_THRESHOLD = 0.1  # Threshold for anomaly scoring
    
    # LogBERT Model Parameters
    VOCAB_SIZE = 1000
    EMBED_DIM = 128
    HIDDEN_DIM = 256
    NUM_LAYERS = 2
    MAX_SEQUENCE_LENGTH = 128
    BATCH_SIZE = 32
    LEARNING_RATE = 0.001
    TRAINING_EPOCHS = 3
    
    # Log Parsing
    LOG_FORMAT_REGEX = r'(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] "(\w+) ([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    
    # Security Patterns
    SUSPICIOUS_PATH_PATTERNS = [
        r'\.\./', r'<script', r'<img', r'javascript:', 
        r'union.*select', r'drop.*table', r'insert.*into',
        r'cmd\.exe', r'powershell', r'bash', r'sh',
        r'etc/passwd', r'proc/version', r'etc/shadow',
        r'admin/config', r'wp-admin', r'phpMyAdmin'
    ]
    
    SUSPICIOUS_UA_PATTERNS = [
        'sqlmap', 'nikto', 'nmap', 'burp', 'acunetix',
        'metasploit', 'nessus', 'openvas', 'w3af',
        'dirbuster', 'gobuster', 'dirb'
    ]
    
    # Dashboard Settings
    DASHBOARD_REFRESH_RATE = 5  # seconds
    MAX_DISPLAYED_LOGS = 500
    CHART_UPDATE_INTERVAL = 10  # seconds
    
    # Alert Settings
    ALERT_ANOMALY_THRESHOLD = 5  # Alert if anomaly rate > 5%
    ALERT_HIGH_TRAFFIC_THRESHOLD = 1000  # Alert if requests/min > 1000
    
    # File Monitoring
    POLLING_INTERVAL = 1  # File system polling interval in seconds
    
    @classmethod
    def get_valid_log_paths(cls):
        """Get list of existing log paths"""
        import glob
        valid_paths = []
        
        for path_pattern in cls.TOMCAT_LOG_PATHS:
            # Handle glob patterns
            if '*' in path_pattern:
                matches = glob.glob(path_pattern)
                valid_paths.extend(matches)
            else:
                if os.path.exists(path_pattern):
                    valid_paths.append(path_pattern)
        
        return valid_paths
    
    @classmethod
    def ensure_directories(cls):
        """Ensure required directories exist"""
        Path(cls.MODEL_SAVE_PATH).mkdir(exist_ok=True, parents=True)
    
    @classmethod
    def get_config_summary(cls):
        """Get configuration summary for display"""
        valid_paths = cls.get_valid_log_paths()
        
        return {
            'tomcat_logs_found': len(valid_paths),
            'valid_log_paths': valid_paths,
            'model_path': cls.MODEL_SAVE_PATH,
            'training_threshold': cls.TRAINING_THRESHOLD,
            'retrain_interval_minutes': cls.RETRAIN_INTERVAL // 60,
            'anomaly_detection_rate': cls.ISOLATION_FOREST_CONTAMINATION * 100
        }

# Default configuration instance
config = MonitoringConfig()
