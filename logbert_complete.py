#!/usr/bin/env python3
"""
LogBERT: Complete Implementation for Tomcat Access Log Anomaly Detection
Uses transformer architecture with hypersphere training approach
"""

import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import re
import json
from typing import List, Dict, Tuple
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from transformers import BertTokenizer, BertConfig, BertModel
import warnings
warnings.filterwarnings('ignore')

class LogBERTTokenizer:
    """Custom tokenizer for log entries optimized for anomaly detection"""
    
    def __init__(self):
        self.vocab = {}
        self.token_to_id = {}
        self.id_to_token = {}
        self.max_length = 128
        
        # Initialize with special tokens
        special_tokens = ['[PAD]', '[UNK]', '[CLS]', '[SEP]', '[MASK]']
        for i, token in enumerate(special_tokens):
            self.token_to_id[token] = i
            self.id_to_token[i] = token
        
        self.vocab_size = len(special_tokens)
    
    def build_vocab_from_logs(self, log_entries: List[Dict]):
        """Build vocabulary from log entries"""
        print("Building vocabulary from log entries...")
        
        tokens = set()
        for entry in log_entries:
            entry_tokens = self.extract_log_tokens(entry)
            tokens.update(entry_tokens)
        
        # Add tokens to vocabulary
        for token in sorted(tokens):
            if token not in self.token_to_id:
                self.token_to_id[token] = self.vocab_size
                self.id_to_token[self.vocab_size] = token
                self.vocab_size += 1
        
        print(f"Vocabulary built with {self.vocab_size} tokens")
    
    def extract_log_tokens(self, log_entry: Dict) -> List[str]:
        """Extract meaningful tokens from log entry for anomaly detection"""
        tokens = []
        
        # Parse request
        request = log_entry.get('request', '')
        if ' ' in request:
            parts = request.split(' ')
            if len(parts) >= 3:
                method, uri, protocol = parts[0], parts[1], parts[2]
                tokens.append(f'METHOD_{method}')
                tokens.append(f'PROTOCOL_{protocol}')
                
                # Parse URI components
                if '?' in uri:
                    path, query = uri.split('?', 1)
                else:
                    path, query = uri, ''
                
                # Path segments
                path_segments = [seg for seg in path.split('/') if seg]
                for segment in path_segments[:5]:  # Limit to first 5 segments
                    tokens.append(f'PATH_{segment}')
                
                # Query analysis for attack patterns
                if query:
                    query_lower = query.lower()
                    # SQL Injection indicators
                    sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', 'or+', 'and+', "'", '"', ';']
                    for pattern in sql_patterns:
                        if pattern in query_lower:
                            tokens.append(f'SQL_{pattern.upper().replace("+", "_")}')
                    
                    # XSS indicators
                    xss_patterns = ['<script', '<img', 'javascript:', 'alert(', 'onerror=', 'onload=']
                    for pattern in xss_patterns:
                        if pattern in query_lower:
                            tokens.append('XSS_DETECTED')
                    
                    # Path traversal indicators
                    if '../' in query or '.\\\\' in query:
                        tokens.append('PATH_TRAVERSAL')
                    
                    # Long parameter values (potential overflow)
                    if len(query) > 200:
                        tokens.append('LONG_QUERY')
        
        # Status code analysis
        status = log_entry.get('status', 200)
        tokens.append(f'STATUS_{status//100}XX')  # 2XX, 4XX, 5XX, etc.
        
        # User agent analysis
        user_agent = log_entry.get('user_agent', '').lower()
        
        # Security tool indicators
        security_tools = ['sqlmap', 'nikto', 'nessus', 'burp', 'nmap', 'masscan', 'zap']
        for tool in security_tools:
            if tool in user_agent:
                tokens.append(f'TOOL_{tool.upper()}')
        
        # Browser indicators
        browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera']
        for browser in browsers:
            if browser in user_agent:
                tokens.append(f'BROWSER_{browser.upper()}')
                break
        else:
            if 'curl' in user_agent:
                tokens.append('TOOL_CURL')
            elif user_agent == '-':
                tokens.append('UA_MISSING')
            else:
                tokens.append('UA_OTHER')
        
        # Response time indicators (if available)
        response_time = log_entry.get('response_time', 0)
        if response_time > 5000:
            tokens.append('SLOW_RESPONSE')
        elif response_time > 1000:
            tokens.append('MEDIUM_RESPONSE')
        
        return tokens
    
    def tokenize(self, log_entry: Dict) -> List[int]:
        """Convert log entry to token IDs"""
        tokens = self.extract_log_tokens(log_entry)
        
        # Add special tokens
        token_ids = [self.token_to_id['[CLS]']]
        
        for token in tokens[:self.max_length-2]:  # Reserve space for CLS and SEP
            token_id = self.token_to_id.get(token, self.token_to_id['[UNK]'])
            token_ids.append(token_id)
        
        token_ids.append(self.token_to_id['[SEP]'])
        
        # Pad to max length
        while len(token_ids) < self.max_length:
            token_ids.append(self.token_to_id['[PAD]'])
        
        return token_ids[:self.max_length]

class LogBERTModel(nn.Module):
    """LogBERT model for anomaly detection using hypersphere approach"""
    
    def __init__(self, vocab_size: int, hidden_size: int = 128, num_layers: int = 6, num_heads: int = 8):
        super().__init__()
        
        config = BertConfig(
            vocab_size=vocab_size,
            hidden_size=hidden_size,
            num_attention_heads=num_heads,
            num_hidden_layers=num_layers,
            intermediate_size=hidden_size * 4,
            max_position_embeddings=128,
            hidden_dropout_prob=0.1,
            attention_probs_dropout_prob=0.1,
        )
        
        self.bert = BertModel(config)
        self.dropout = nn.Dropout(0.1)
        
        # Hypersphere projection
        self.projection = nn.Linear(hidden_size, hidden_size)
        
        # Learnable center and radius for hypersphere
        self.register_parameter('center', nn.Parameter(torch.randn(hidden_size)))
        self.register_parameter('radius', nn.Parameter(torch.tensor(1.0)))
        
    def forward(self, input_ids, attention_mask=None):
        # Get BERT representations
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        
        # Use [CLS] token representation
        cls_output = outputs.pooler_output
        cls_output = self.dropout(cls_output)
        
        # Project to hypersphere space
        projected = self.projection(cls_output)
        projected = F.normalize(projected, p=2, dim=1)  # L2 normalize
        
        # Compute distances from center
        center_norm = F.normalize(self.center, p=2, dim=0)
        distances = torch.norm(projected - center_norm, dim=1)
        
        return {
            'projected': projected,
            'distances': distances,
            'radius': self.radius
        }

def parse_tomcat_logs(log_file: str) -> List[Dict]:
    """Parse Tomcat access logs into structured format"""
    print(f"Parsing log file: {log_file}")
    
    # Enhanced regex for our log format
    log_pattern = re.compile(
        r'(?P<ip>[^\\s]+)\\s+'
        r'(?P<identd>[^\\s]+)\\s+'
        r'(?P<user>[^\\s]+)\\s+'
        r'\\[(?P<timestamp>[^\\]]+)\\]\\s+'
        r'"(?P<request>[^"]*)"\\s+'
        r'(?P<status>\\d+)\\s+'
        r'(?P<bytes>[^\\s]+)\\s+'
        r'"(?P<referer>[^"]*)"\\s+'
        r'"(?P<user_agent>[^"]*)".*'
    )
    
    log_entries = []
    
    with open(log_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            match = log_pattern.match(line)
            
            if match:
                data = match.groupdict()
                
                # Convert status to int
                try:
                    data['status'] = int(data['status'])
                except:
                    data['status'] = 200
                    
                # Extract response time if available (simplified)
                response_time_match = re.search(r'(\\d+)\\.(\\d+)$', line)
                if response_time_match:
                    data['response_time'] = int(float(response_time_match.group(0)) * 1000)
                else:
                    data['response_time'] = 0
                
                log_entries.append(data)
            else:
                print(f"Failed to parse line {line_num}: {line[:100]}...")
    
    print(f"Parsed {len(log_entries)} log entries")
    return log_entries

def label_anomalies(log_entries: List[Dict]) -> List[int]:
    """Label anomalies using rule-based approach for training"""
    labels = []
    
    for entry in log_entries:
        is_anomaly = False
        
        request = entry.get('request', '').lower()
        user_agent = entry.get('user_agent', '').lower()
        status = entry.get('status', 200)
        
        # SQL Injection patterns
        sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', "'", 'or ', 'and ']
        if any(pattern in request for pattern in sql_patterns):
            is_anomaly = True
        
        # XSS patterns
        xss_patterns = ['<script', '<img', 'alert(', 'onerror=', 'javascript:']
        if any(pattern in request for pattern in xss_patterns):
            is_anomaly = True
        
        # Path traversal
        if '../' in request or '.\\\\' in request:
            is_anomaly = True
        
        # Security tools
        security_tools = ['sqlmap', 'nikto', 'nessus', 'burp', 'nmap']
        if any(tool in user_agent for tool in security_tools):
            is_anomaly = True
        
        # Suspicious status codes (can indicate reconnaissance)
        if status in [400, 401, 403, 404, 500, 502, 503]:
            # Only flag as anomaly if combined with other indicators
            if len(request) > 100 or any(char in request for char in ['<', '>', '"', "'"]):
                is_anomaly = True
        
        labels.append(1 if is_anomaly else 0)
    
    return labels

def train_logbert(log_entries: List[Dict], labels: List[int], epochs: int = 10):
    """Train LogBERT model"""
    print("Starting LogBERT training...")
    
    # Initialize tokenizer and build vocabulary
    tokenizer = LogBERTTokenizer()
    tokenizer.build_vocab_from_logs(log_entries)
    
    # Tokenize all entries
    tokenized_data = []
    for entry in log_entries:
        tokens = tokenizer.tokenize(entry)
        tokenized_data.append(tokens)
    
    # Convert to tensors
    input_ids = torch.tensor(tokenized_data)
    attention_masks = (input_ids != 0).long()  # Attention mask (0 for padding)
    labels_tensor = torch.tensor(labels)
    
    # Split data
    train_ids, val_ids, train_masks, val_masks, train_labels, val_labels = train_test_split(
        input_ids, attention_masks, labels_tensor, test_size=0.2, random_state=42, stratify=labels_tensor
    )
    
    # Initialize model
    model = LogBERTModel(vocab_size=tokenizer.vocab_size)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4, weight_decay=0.01)
    
    # Training loop
    model.train()
    train_losses = []
    
    batch_size = 16
    for epoch in range(epochs):
        total_loss = 0
        num_batches = 0
        
        # Mini-batch training
        for i in range(0, len(train_ids), batch_size):
            batch_ids = train_ids[i:i+batch_size]
            batch_masks = train_masks[i:i+batch_size]
            batch_labels = train_labels[i:i+batch_size]
            
            optimizer.zero_grad()
            
            outputs = model(batch_ids, batch_masks)
            distances = outputs['distances']
            radius = outputs['radius']
            
            # Hypersphere loss: minimize distance for normal samples, maximize for anomalies
            normal_mask = (batch_labels == 0)
            anomaly_mask = (batch_labels == 1)
            
            loss = 0
            if normal_mask.sum() > 0:
                normal_loss = torch.mean(distances[normal_mask])  # Pull normal samples to center
                loss += normal_loss
            
            if anomaly_mask.sum() > 0:
                anomaly_loss = torch.mean(torch.clamp(radius - distances[anomaly_mask], min=0))  # Push anomalies outside radius
                loss += anomaly_loss
            
            # Regularization to prevent radius from growing too large
            loss += 0.01 * (radius ** 2)
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            num_batches += 1
        
        avg_loss = total_loss / num_batches if num_batches > 0 else 0
        train_losses.append(avg_loss)
        
        print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}, Radius: {radius.item():.4f}")
    
    return model, tokenizer, train_losses

def evaluate_model(model, tokenizer, log_entries: List[Dict], labels: List[int]):
    """Evaluate LogBERT model"""
    model.eval()
    
    # Tokenize data
    tokenized_data = [tokenizer.tokenize(entry) for entry in log_entries]
    input_ids = torch.tensor(tokenized_data)
    attention_masks = (input_ids != 0).long()
    
    with torch.no_grad():
        outputs = model(input_ids, attention_masks)
        distances = outputs['distances'].numpy()
        radius = outputs['radius'].item()
    
    # Determine threshold (use radius as threshold)
    threshold = radius
    predictions = (distances > threshold).astype(int)
    
    # Calculate metrics
    print(f"\\n=== LogBERT Evaluation Results ===")
    print(f"Threshold (Radius): {threshold:.4f}")
    print(f"True Positives: {sum((predictions == 1) & (np.array(labels) == 1))}")
    print(f"False Positives: {sum((predictions == 1) & (np.array(labels) == 0))}")
    print(f"True Negatives: {sum((predictions == 0) & (np.array(labels) == 0))}")
    print(f"False Negatives: {sum((predictions == 0) & (np.array(labels) == 1))}")
    
    # Classification report
    print(f"\\n{classification_report(labels, predictions, target_names=['Normal', 'Anomaly'])}")
    
    return predictions, distances, threshold

def visualize_results(distances, labels, predictions, threshold):
    """Create visualizations"""
    plt.figure(figsize=(15, 5))
    
    # Distance distribution
    plt.subplot(1, 3, 1)
    normal_distances = distances[np.array(labels) == 0]
    anomaly_distances = distances[np.array(labels) == 1]
    
    plt.hist(normal_distances, bins=30, alpha=0.7, label='Normal', density=True)
    plt.hist(anomaly_distances, bins=30, alpha=0.7, label='Anomaly', density=True)
    plt.axvline(threshold, color='red', linestyle='--', label='Threshold')
    plt.xlabel('Distance from Center')
    plt.ylabel('Density')
    plt.title('Distance Distribution')
    plt.legend()
    
    # Confusion matrix
    plt.subplot(1, 3, 2)
    cm = confusion_matrix(labels, predictions)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Normal', 'Anomaly'], yticklabels=['Normal', 'Anomaly'])
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    
    # Scatter plot
    plt.subplot(1, 3, 3)
    normal_idx = np.where(np.array(labels) == 0)[0]
    anomaly_idx = np.where(np.array(labels) == 1)[0]
    
    plt.scatter(normal_idx, distances[normal_idx], alpha=0.6, s=20, label='Normal', c='blue')
    plt.scatter(anomaly_idx, distances[anomaly_idx], alpha=0.6, s=20, label='Anomaly', c='red')
    plt.axhline(threshold, color='red', linestyle='--', label='Threshold')
    plt.xlabel('Sample Index')
    plt.ylabel('Distance from Center')
    plt.title('LogBERT Anomaly Detection')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig('/Users/majjipradeepkumar/Downloads/samplewar/logbert_complete_results.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    print("Visualization saved to logbert_complete_results.png")

def main():
    """Main execution function"""
    print("=== LogBERT: Log Anomaly Detection via BERT ===")
    
    # Parse logs
    log_file = "/Users/majjipradeepkumar/Downloads/apache-tomcat-9.0.109/logs/logbert_access.2025-09-21.log"
    log_entries = parse_tomcat_logs(log_file)
    
    if not log_entries:
        print("No log entries found!")
        return
    
    # Label anomalies
    labels = label_anomalies(log_entries)
    
    print(f"Dataset: {len(log_entries)} requests")
    print(f"Normal: {labels.count(0)} ({100*labels.count(0)/len(labels):.1f}%)")
    print(f"Anomalies: {labels.count(1)} ({100*labels.count(1)/len(labels):.1f}%)")
    
    # Train model
    model, tokenizer, losses = train_logbert(log_entries, labels, epochs=15)
    
    # Evaluate model
    predictions, distances, threshold = evaluate_model(model, tokenizer, log_entries, labels)
    
    # Save results
    results_df = pd.DataFrame({
        'timestamp': [entry['timestamp'] for entry in log_entries],
        'request': [entry['request'] for entry in log_entries],
        'status': [entry['status'] for entry in log_entries],
        'user_agent': [entry['user_agent'] for entry in log_entries],
        'true_label': labels,
        'predicted_label': predictions,
        'anomaly_score': distances,
        'is_correct': (np.array(labels) == predictions).astype(int)
    })
    
    results_df.to_csv('/Users/majjipradeepkumar/Downloads/samplewar/logbert_final_results.csv', index=False)
    print(f"\\nResults saved to logbert_final_results.csv")
    
    # Show top anomalies
    print(f"\\n=== TOP ANOMALIES DETECTED ===")
    anomaly_results = results_df[results_df['predicted_label'] == 1].sort_values('anomaly_score', ascending=False)
    
    for idx, row in anomaly_results.head(10).iterrows():
        print(f"[Score: {row['anomaly_score']:.3f}] {row['request']} | {row['user_agent'][:50]}")
    
    # Visualize results
    visualize_results(distances, labels, predictions, threshold)
    
    # Save model
    torch.save({
        'model_state_dict': model.state_dict(),
        'tokenizer': tokenizer,
        'threshold': threshold
    }, '/Users/majjipradeepkumar/Downloads/samplewar/logbert_trained_model.pth')
    
    print(f"\\nLogBERT model saved to logbert_trained_model.pth")
    print("Training completed successfully!")

if __name__ == "__main__":
    main()
