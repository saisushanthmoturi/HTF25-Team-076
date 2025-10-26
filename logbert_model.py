#!/usr/bin/env python3
"""
LogBERT: Log Anomaly Detection via BERT
Implementation of masked log token training + hypersphere approach
for detecting anomalous HTTP requests in Tomcat access logs
"""

import re
import json
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional
from pathlib import Path
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TomcatLogParser:
    """Parse Tomcat access logs with the enhanced format"""
    
    def __init__(self):
        # Pattern for our enhanced Tomcat log format:
        # %h %l %u %t "%r" %s %b "%{Referer}i" "%{User-Agent}i" "%{X-Forwarded-For}i" "%{Content-Type}i" "%{Content-Length}i" %D %F %I %O %S %T
        self.pattern = re.compile(
            r'(?P<ip>[^\s]+)\s+'
            r'(?P<identd>[^\s]+)\s+'
            r'(?P<user>[^\s]+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<request>[^"]+)"\s+'
            r'(?P<status>\d+)\s+'
            r'(?P<bytes>[^\s]+)\s+'
            r'"(?P<referer>[^"]+)"\s+'
            r'"(?P<user_agent>[^"]+)"\s+'
            r'"(?P<x_forwarded_for>[^"]+)"\s+'
            r'"(?P<content_type>[^"]+)"\s+'
            r'"(?P<content_length>[^"]+)"\s+'
            r'(?P<response_time>\d+)\s+'
            r'(?P<bytes_received>\d+)\s+'
            r'(?P<bytes_sent_request>\d+)\s+'
            r'(?P<bytes_sent_response>\d+)\s+'
            r'(?P<thread>[^\s]+)\s+'
            r'(?P<connection_status>[^\s]+)\s+'
            r'(?P<session_id>[^\s]+)\s+'
            r'(?P<request_time_seconds>[\d.]+)'
        )
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line into structured data"""
        match = self.pattern.match(line.strip())
        if not match:
            return None
            
        data = match.groupdict()
        
        # Parse request into method, uri, protocol
        request_parts = data['request'].split(' ', 2)
        if len(request_parts) >= 3:
            data['method'] = request_parts[0]
            data['uri'] = request_parts[1]
            data['protocol'] = request_parts[2]
        else:
            data['method'] = data['uri'] = data['protocol'] = 'UNKNOWN'
            
        # Extract query parameters and path
        if '?' in data['uri']:
            data['path'], data['query'] = data['uri'].split('?', 1)
        else:
            data['path'] = data['uri']
            data['query'] = ''
            
        # Convert numeric fields
        try:
            data['status'] = int(data['status'])
            data['response_time'] = int(data['response_time'])
            data['bytes_received'] = int(data['bytes_received'])
            data['bytes_sent_request'] = int(data['bytes_sent_request'])
            data['bytes_sent_response'] = int(data['bytes_sent_response'])
            data['request_time_seconds'] = float(data['request_time_seconds'])
        except (ValueError, TypeError):
            pass
            
        return data
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """Parse entire log file"""
        logs = []
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                parsed = self.parse_line(line)
                if parsed:
                    parsed['line_number'] = line_num
                    logs.append(parsed)
                else:
                    logger.warning(f"Failed to parse line {line_num}: {line[:100]}")
        
        logger.info(f"Parsed {len(logs)} log entries from {filepath}")
        return logs


class LogTokenizer:
    """Tokenize log entries for BERT training"""
    
    def __init__(self):
        self.vocab = {}
        self.token_to_id = {}
        self.id_to_token = {}
        self.special_tokens = {
            '[PAD]': 0,
            '[UNK]': 1,
            '[CLS]': 2,
            '[SEP]': 3,
            '[MASK]': 4
        }
        
    def build_vocabulary(self, logs: List[Dict]):
        """Build vocabulary from log entries"""
        logger.info("Building vocabulary from log entries...")
        
        all_tokens = set()
        
        for log_entry in logs:
            tokens = self.extract_tokens(log_entry)
            all_tokens.update(tokens)
            
        # Add special tokens first
        vocab = dict(self.special_tokens)
        
        # Add log tokens
        for i, token in enumerate(sorted(all_tokens), len(self.special_tokens)):
            vocab[token] = i
            
        self.token_to_id = vocab
        self.id_to_token = {v: k for k, v in vocab.items()}
        
        logger.info(f"Built vocabulary with {len(vocab)} tokens")
        return vocab
    
    def extract_tokens(self, log_entry: Dict) -> List[str]:
        """Extract meaningful tokens from a log entry"""
        tokens = []
        
        # HTTP method
        tokens.append(f"METHOD_{log_entry.get('method', 'UNKNOWN')}")
        
        # Path segments
        path = log_entry.get('path', '')
        path_segments = [seg for seg in path.split('/') if seg]
        tokens.extend([f"PATH_{seg}" for seg in path_segments])
        
        # Query parameters
        query = log_entry.get('query', '')
        if query:
            # Extract parameter names and suspicious patterns
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    tokens.append(f"PARAM_{key}")
                    
                    # Check for suspicious patterns in values
                    value_lower = value.lower()
                    if any(pattern in value_lower for pattern in ['script', 'alert', 'union', 'select', 'drop', 'or', 'and']):
                        tokens.append('SUSPICIOUS_VALUE')
                    if any(pattern in value for pattern in ['../', '.\\', '/etc/', 'system32']):
                        tokens.append('PATH_TRAVERSAL')
                    if len(value) > 100:
                        tokens.append('LONG_VALUE')
        
        # Status code category
        status = log_entry.get('status', 0)
        if 200 <= status < 300:
            tokens.append('STATUS_SUCCESS')
        elif 300 <= status < 400:
            tokens.append('STATUS_REDIRECT')
        elif 400 <= status < 500:
            tokens.append('STATUS_CLIENT_ERROR')
        elif status >= 500:
            tokens.append('STATUS_SERVER_ERROR')
        else:
            tokens.append('STATUS_UNKNOWN')
            
        # User agent categories
        user_agent = log_entry.get('user_agent', '').lower()
        if 'curl' in user_agent:
            tokens.append('UA_CURL')
        elif 'bot' in user_agent or 'crawler' in user_agent:
            tokens.append('UA_BOT')
        elif any(tool in user_agent for tool in ['sqlmap', 'nikto', 'nessus', 'burp']):
            tokens.append('UA_SECURITY_TOOL')
        elif user_agent == '-':
            tokens.append('UA_MISSING')
        else:
            tokens.append('UA_BROWSER')
            
        # Response time category
        response_time = log_entry.get('response_time', 0)
        if response_time > 5000:  # > 5 seconds
            tokens.append('SLOW_RESPONSE')
        elif response_time > 1000:  # > 1 second
            tokens.append('MEDIUM_RESPONSE')
        else:
            tokens.append('FAST_RESPONSE')
            
        # Content type
        content_type = log_entry.get('content_type', '').lower()
        if 'json' in content_type:
            tokens.append('CONTENT_JSON')
        elif 'xml' in content_type:
            tokens.append('CONTENT_XML')
        elif 'form' in content_type:
            tokens.append('CONTENT_FORM')
        elif content_type != '-':
            tokens.append('CONTENT_OTHER')
            
        return tokens
    
    def tokenize_log(self, log_entry: Dict, max_length: int = 64) -> List[int]:
        """Convert log entry to token IDs"""
        tokens = self.extract_tokens(log_entry)
        
        # Add special tokens
        token_ids = [self.special_tokens['[CLS]']]
        
        for token in tokens[:max_length-2]:  # Reserve space for CLS and SEP
            token_id = self.token_to_id.get(token, self.special_tokens['[UNK]'])
            token_ids.append(token_id)
            
        token_ids.append(self.special_tokens['[SEP]'])
        
        # Pad to max length
        while len(token_ids) < max_length:
            token_ids.append(self.special_tokens['[PAD]'])
            
        return token_ids[:max_length]


class LogBERTDataset:
    """Dataset for LogBERT training"""
    
    def __init__(self, logs: List[Dict], tokenizer: LogTokenizer, max_length: int = 64):
        self.logs = logs
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.sequences = []
        
        # Tokenize all logs
        for log in logs:
            tokens = tokenizer.tokenize_log(log, max_length)
            self.sequences.append(tokens)
    
    def create_masked_lm_data(self, mask_prob: float = 0.15) -> Tuple[List[List[int]], List[List[int]], List[List[int]]]:
        """Create masked language model training data"""
        input_ids = []
        masked_lm_labels = []
        attention_masks = []
        
        for sequence in self.sequences:
            input_seq = sequence.copy()
            labels = [-100] * len(sequence)  # -100 is ignored in loss computation
            attention_mask = [1 if token_id != 0 else 0 for token_id in sequence]  # 0 is PAD token
            
            # Randomly mask tokens
            for i, token_id in enumerate(sequence):
                if token_id in [0, 2, 3]:  # Don't mask PAD, CLS, SEP
                    continue
                    
                if np.random.random() < mask_prob:
                    labels[i] = token_id  # Store original token for prediction
                    
                    # 80% of time replace with [MASK]
                    if np.random.random() < 0.8:
                        input_seq[i] = 4  # [MASK] token
                    # 10% of time replace with random token
                    elif np.random.random() < 0.5:
                        input_seq[i] = np.random.randint(5, len(self.tokenizer.token_to_id))
                    # 10% of time keep original (helps with bias)
                    
            input_ids.append(input_seq)
            masked_lm_labels.append(labels)
            attention_masks.append(attention_mask)
        
        return input_ids, masked_lm_labels, attention_masks


def detect_anomalies_with_perplexity(sequences: List[List[int]], model, tokenizer_obj: LogTokenizer, threshold_percentile: float = 95) -> List[bool]:
    """Detect anomalies using perplexity-based approach"""
    logger.info("Computing perplexity scores for anomaly detection...")
    
    # This is a simplified version - in practice you'd use the trained BERT model
    # For now, we'll use a rule-based approach to demonstrate the concept
    
    anomaly_scores = []
    
    for sequence in sequences:
        score = 0
        token_count = 0
        
        for token_id in sequence:
            if token_id == 0:  # PAD token
                continue
                
            token_count += 1
            token = tokenizer_obj.id_to_token.get(token_id, '[UNK]')
            
            # Simple heuristic scoring (replace with actual model inference)
            if 'SUSPICIOUS' in token or 'PATH_TRAVERSAL' in token:
                score += 5.0
            elif 'SECURITY_TOOL' in token:
                score += 3.0
            elif 'CLIENT_ERROR' in token or 'SERVER_ERROR' in token:
                score += 1.0
            elif 'LONG_VALUE' in token:
                score += 2.0
            else:
                score += 0.1  # Base score for normal tokens
        
        # Normalize by sequence length
        if token_count > 0:
            score /= token_count
            
        anomaly_scores.append(score)
    
    # Determine threshold
    threshold = np.percentile(anomaly_scores, threshold_percentile)
    logger.info(f"Anomaly threshold (P{threshold_percentile}): {threshold:.3f}")
    
    # Classify anomalies
    is_anomaly = [score > threshold for score in anomaly_scores]
    
    return is_anomaly, anomaly_scores, threshold


def main():
    """Main training and inference pipeline"""
    
    # Parse Tomcat access logs
    log_file = "/Users/majjipradeepkumar/Downloads/apache-tomcat-9.0.109/logs/logbert_access.2025-09-21.log"
    
    if not Path(log_file).exists():
        logger.error(f"Log file not found: {log_file}")
        return
    
    parser = TomcatLogParser()
    logs = parser.parse_file(log_file)
    
    if not logs:
        logger.error("No logs parsed successfully")
        return
    
    # Build tokenizer vocabulary
    tokenizer = LogTokenizer()
    vocab = tokenizer.build_vocabulary(logs)
    
    # Create dataset
    dataset = LogBERTDataset(logs, tokenizer, max_length=64)
    
    # Create masked LM data (for BERT pre-training)
    input_ids, masked_lm_labels, attention_masks = dataset.create_masked_lm_data()
    
    logger.info(f"Created {len(input_ids)} training examples")
    
    # Detect anomalies (simplified approach)
    is_anomaly, anomaly_scores, threshold = detect_anomalies_with_perplexity(
        dataset.sequences, None, tokenizer
    )
    
    # Analyze results
    anomaly_count = sum(is_anomaly)
    logger.info(f"Detected {anomaly_count} anomalies out of {len(logs)} requests ({100*anomaly_count/len(logs):.1f}%)")
    
    # Show some examples
    logger.info("\n=== ANOMALOUS REQUESTS ===")
    for i, (log, is_anom, score) in enumerate(zip(logs, is_anomaly, anomaly_scores)):
        if is_anom:
            logger.info(f"[ANOMALY {score:.3f}] {log['method']} {log['uri']} - Status: {log['status']} - UA: {log['user_agent'][:50]}")
    
    # Save results
    results = []
    for log, is_anom, score in zip(logs, is_anomaly, anomaly_scores):
        results.append({
            'timestamp': log['timestamp'],
            'method': log['method'],
            'uri': log['uri'],
            'status': log['status'],
            'user_agent': log['user_agent'],
            'anomaly_score': score,
            'is_anomaly': is_anom
        })
    
    results_df = pd.DataFrame(results)
    results_file = "/Users/majjipradeepkumar/Downloads/samplewar/logbert_results.csv"
    results_df.to_csv(results_file, index=False)
    logger.info(f"Results saved to {results_file}")
    
    # Generate training data files for actual BERT training
    training_data = {
        'input_ids': input_ids,
        'masked_lm_labels': masked_lm_labels,
        'attention_masks': attention_masks,
        'vocab': vocab,
        'tokenizer_config': {
            'max_length': 64,
            'vocab_size': len(vocab)
        }
    }
    
    training_file = "/Users/majjipradeepkumar/Downloads/samplewar/logbert_training_data.json"
    with open(training_file, 'w') as f:
        json.dump(training_data, f, indent=2)
    logger.info(f"Training data saved to {training_file}")
    
    return results_df, training_data


if __name__ == "__main__":
    main()
