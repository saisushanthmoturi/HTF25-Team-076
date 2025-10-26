#!/usr/bin/env python3
"""
LogBERT: Simplified Implementation for Tomcat Log Anomaly Detection
Demonstrates the core concepts with working code
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import pandas as pd
import re
from typing import List, Dict
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt

class SimpleLogTokenizer:
    """Simplified tokenizer for log entries"""
    
    def __init__(self):
        self.vocab = {'[PAD]': 0, '[UNK]': 1, '[CLS]': 2, '[SEP]': 3}
        self.vocab_size = 4
        self.max_length = 64
    
    def add_tokens(self, tokens):
        """Add new tokens to vocabulary"""
        for token in tokens:
            if token not in self.vocab:
                self.vocab[token] = self.vocab_size
                self.vocab_size += 1
    
    def extract_features(self, log_entry):
        """Extract features from log entry"""
        features = []
        
        request = log_entry.get('request', '')
        user_agent = log_entry.get('user_agent', '').lower()
        status = log_entry.get('status', 200)
        
        # HTTP method
        if request.startswith('GET'):
            features.append('METHOD_GET')
        elif request.startswith('POST'):
            features.append('METHOD_POST')
        elif request.startswith('PUT'):
            features.append('METHOD_PUT')
        elif request.startswith('DELETE'):
            features.append('METHOD_DELETE')
        else:
            features.append('METHOD_OTHER')
        
        # Path analysis
        if '/admin' in request.lower():
            features.append('PATH_ADMIN')
        if '/api' in request.lower():
            features.append('PATH_API')
        if '/login' in request.lower():
            features.append('PATH_LOGIN')
        
        # Attack patterns
        request_lower = request.lower()
        if any(pattern in request_lower for pattern in ['union', 'select', 'drop', "'"]):
            features.append('SQL_INJECTION')
        if any(pattern in request for pattern in ['<script', 'alert(', 'onerror']):
            features.append('XSS_ATTACK')
        if '../' in request:
            features.append('PATH_TRAVERSAL')
        if len(request) > 200:
            features.append('LONG_REQUEST')
        
        # Status codes
        if 200 <= status < 300:
            features.append('STATUS_SUCCESS')
        elif 400 <= status < 500:
            features.append('STATUS_CLIENT_ERROR')
        elif status >= 500:
            features.append('STATUS_SERVER_ERROR')
        
        # User agent analysis
        if 'sqlmap' in user_agent:
            features.append('TOOL_SQLMAP')
        elif 'nikto' in user_agent:
            features.append('TOOL_NIKTO')
        elif 'curl' in user_agent:
            features.append('TOOL_CURL')
        elif user_agent == '-':
            features.append('UA_MISSING')
        elif any(browser in user_agent for browser in ['chrome', 'firefox', 'safari']):
            features.append('UA_BROWSER')
        else:
            features.append('UA_OTHER')
        
        return features
    
    def tokenize(self, log_entry):
        """Convert log entry to token IDs"""
        features = self.extract_features(log_entry)
        
        # Build sequence
        tokens = [self.vocab['[CLS]']]
        
        for feature in features[:self.max_length-2]:
            token_id = self.vocab.get(feature, self.vocab['[UNK]'])
            tokens.append(token_id)
        
        tokens.append(self.vocab['[SEP]'])
        
        # Pad to max length
        while len(tokens) < self.max_length:
            tokens.append(self.vocab['[PAD]'])
        
        return tokens[:self.max_length]

class SimpleLogBERT(nn.Module):
    """Simplified BERT model for log anomaly detection"""
    
    def __init__(self, vocab_size, embed_dim=64, hidden_dim=128):
        super().__init__()
        
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.positional_encoding = nn.Embedding(64, embed_dim)  # max_length = 64
        
        # Simplified transformer layers
        self.attention = nn.MultiheadAttention(embed_dim, num_heads=4, batch_first=True)
        self.norm1 = nn.LayerNorm(embed_dim)
        self.ff = nn.Sequential(
            nn.Linear(embed_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, embed_dim)
        )
        self.norm2 = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(0.1)
        
        # Anomaly detection head
        self.anomaly_head = nn.Linear(embed_dim, 1)
        
    def forward(self, input_ids):
        seq_len = input_ids.size(1)
        
        # Embeddings
        token_embeds = self.embedding(input_ids)
        pos_ids = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).repeat(input_ids.size(0), 1)
        pos_embeds = self.positional_encoding(pos_ids)
        
        x = token_embeds + pos_embeds
        x = self.dropout(x)
        
        # Simplified transformer block
        attn_out, _ = self.attention(x, x, x)
        x = self.norm1(x + attn_out)
        
        ff_out = self.ff(x)
        x = self.norm2(x + ff_out)
        
        # Use [CLS] token (first token) for classification
        cls_output = x[:, 0, :]
        anomaly_score = self.anomaly_head(cls_output)
        
        return anomaly_score

def parse_logs(log_file):
    """Parse Tomcat logs"""
    print(f"Parsing {log_file}...")
    
    pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] \"([^\"]+)\" (\d+) (\S+) \"([^\"]*)\" \"([^\"]*)'
    
    logs = []
    with open(log_file, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                logs.append({
                    'ip': match.group(1),
                    'timestamp': match.group(4),
                    'request': match.group(5),
                    'status': int(match.group(6)),
                    'user_agent': match.group(9)
                })
    
    print(f"Parsed {len(logs)} log entries")
    return logs

def create_labels(logs):
    """Create ground truth labels for anomaly detection"""
    labels = []
    
    for log in logs:
        is_anomaly = False
        
        request = log['request'].lower()
        user_agent = log['user_agent'].lower()
        
        # Rule-based anomaly detection for ground truth
        if any(pattern in request for pattern in ['union', 'select', "'", '<script', 'alert']):
            is_anomaly = True
        if '../' in request:
            is_anomaly = True
        if any(tool in user_agent for tool in ['sqlmap', 'nikto', 'nessus']):
            is_anomaly = True
        if len(request) > 300:
            is_anomaly = True
        
        labels.append(1 if is_anomaly else 0)
    
    return labels

def train_model(logs, labels, epochs=20):
    """Train the LogBERT model"""
    print("Training LogBERT model...")
    
    # Initialize tokenizer
    tokenizer = SimpleLogTokenizer()
    
    # Build vocabulary from all features
    all_features = []
    for log in logs:
        features = tokenizer.extract_features(log)
        all_features.extend(features)
    
    tokenizer.add_tokens(set(all_features))
    
    # Tokenize all logs
    tokenized = [tokenizer.tokenize(log) for log in logs]
    
    # Convert to tensors
    X = torch.tensor(tokenized, dtype=torch.long)
    y = torch.tensor(labels, dtype=torch.float).unsqueeze(1)
    
    # Split data (80/20)
    split_idx = int(0.8 * len(X))
    X_train, X_val = X[:split_idx], X[split_idx:]
    y_train, y_val = y[:split_idx], y[split_idx:]
    
    # Initialize model
    model = SimpleLogBERT(tokenizer.vocab_size)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCEWithLogitsLoss()
    
    # Training loop
    model.train()
    for epoch in range(epochs):
        # Forward pass
        outputs = model(X_train)
        loss = criterion(outputs, y_train)
        
        # Backward pass
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        # Validation
        if epoch % 5 == 0:
            model.eval()
            with torch.no_grad():
                val_outputs = model(X_val)
                val_loss = criterion(val_outputs, y_val)
                val_preds = (torch.sigmoid(val_outputs) > 0.5).float()
                val_acc = (val_preds == y_val).float().mean()
            
            print(f"Epoch {epoch:2d}/{epochs} | Train Loss: {loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")
            model.train()
    
    return model, tokenizer

def evaluate_model(model, tokenizer, logs, labels):
    """Evaluate the trained model"""
    print("\\nEvaluating model...")
    
    # Tokenize logs
    tokenized = [tokenizer.tokenize(log) for log in logs]
    X = torch.tensor(tokenized, dtype=torch.long)
    
    # Get predictions
    model.eval()
    with torch.no_grad():
        outputs = model(X)
        probabilities = torch.sigmoid(outputs).numpy().flatten()
        predictions = (probabilities > 0.5).astype(int)
    
    # Print results
    print("\\n=== LogBERT Evaluation Results ===")
    print(classification_report(labels, predictions, target_names=['Normal', 'Anomaly']))
    
    # Show top anomalies
    print("\\n=== TOP DETECTED ANOMALIES ===")
    anomaly_indices = np.argsort(probabilities)[::-1]
    
    for i, idx in enumerate(anomaly_indices[:10]):
        if predictions[idx] == 1:  # Only show predicted anomalies
            log = logs[idx]
            print(f"{i+1:2d}. [Score: {probabilities[idx]:.3f}] {log['request'][:80]} | {log['user_agent'][:40]}")
    
    return predictions, probabilities

def visualize_results(labels, predictions, probabilities):
    """Create visualizations"""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    
    # Score distribution
    normal_scores = probabilities[np.array(labels) == 0]
    anomaly_scores = probabilities[np.array(labels) == 1]
    
    axes[0].hist(normal_scores, bins=20, alpha=0.7, label='Normal', density=True)
    axes[0].hist(anomaly_scores, bins=20, alpha=0.7, label='Anomaly', density=True)
    axes[0].axvline(0.5, color='red', linestyle='--', label='Threshold')
    axes[0].set_xlabel('Anomaly Score')
    axes[0].set_ylabel('Density')
    axes[0].set_title('LogBERT Score Distribution')
    axes[0].legend()
    
    # Timeline plot
    axes[1].scatter(range(len(probabilities)), probabilities, 
                   c=['red' if l == 1 else 'blue' for l in labels], 
                   alpha=0.6, s=10)
    axes[1].axhline(0.5, color='red', linestyle='--', label='Threshold')
    axes[1].set_xlabel('Request Index')
    axes[1].set_ylabel('Anomaly Score')
    axes[1].set_title('Anomaly Detection Timeline')
    axes[1].legend(['Normal', 'Anomaly', 'Threshold'])
    
    plt.tight_layout()
    plt.savefig('/Users/majjipradeepkumar/Downloads/samplewar/logbert_simple_results.png', dpi=300)
    print("\\nVisualization saved to logbert_simple_results.png")
    plt.show()

def main():
    """Main execution function"""
    print("=== LogBERT: Simplified Log Anomaly Detection ===")
    
    # Parse logs
    log_file = "/Users/majjipradeepkumar/Downloads/apache-tomcat-9.0.109/logs/logbert_access.2025-09-21.log"
    logs = parse_logs(log_file)
    
    if not logs:
        print("No logs found!")
        return
    
    # Create labels
    labels = create_labels(logs)
    
    print(f"\\nDataset Summary:")
    print(f"Total requests: {len(logs)}")
    print(f"Normal: {labels.count(0)} ({100*labels.count(0)/len(labels):.1f}%)")
    print(f"Anomalies: {labels.count(1)} ({100*labels.count(1)/len(labels):.1f}%)")
    
    # Train model
    model, tokenizer = train_model(logs, labels)
    
    # Evaluate model
    predictions, probabilities = evaluate_model(model, tokenizer, logs, labels)
    
    # Save results
    results_df = pd.DataFrame({
        'timestamp': [log['timestamp'] for log in logs],
        'request': [log['request'] for log in logs],
        'user_agent': [log['user_agent'] for log in logs],
        'status': [log['status'] for log in logs],
        'true_label': labels,
        'predicted_label': predictions,
        'anomaly_score': probabilities
    })
    
    results_df.to_csv('/Users/majjipradeepkumar/Downloads/samplewar/logbert_simple_results.csv', index=False)
    print(f"\\nResults saved to logbert_simple_results.csv")
    
    # Visualize
    visualize_results(labels, predictions, probabilities)
    
    # Save model
    torch.save({
        'model_state_dict': model.state_dict(),
        'tokenizer_vocab': tokenizer.vocab,
        'vocab_size': tokenizer.vocab_size
    }, '/Users/majjipradeepkumar/Downloads/samplewar/logbert_simple_model.pth')
    
    print("\\nLogBERT training completed successfully!")
    print("Model saved to logbert_simple_model.pth")

if __name__ == "__main__":
    main()
