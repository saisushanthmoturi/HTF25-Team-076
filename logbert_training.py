#!/usr/bin/env python3
"""
LogBERT Training Script
Trains a BERT model for log anomaly detection using the hypersphere approach
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from transformers import BertModel, BertConfig, BertTokenizer, AdamW
import numpy as np
import json
import logging
from typing import List, Dict, Tuple
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LogBERTModel(nn.Module):
    """BERT-based model for log anomaly detection using hypersphere approach"""
    
    def __init__(self, vocab_size: int, hidden_size: int = 128, num_attention_heads: int = 4, 
                 num_hidden_layers: int = 4, max_position_embeddings: int = 64):
        super().__init__()
        
        config = BertConfig(
            vocab_size=vocab_size,
            hidden_size=hidden_size,
            num_attention_heads=num_attention_heads,
            num_hidden_layers=num_hidden_layers,
            max_position_embeddings=max_position_embeddings,
            intermediate_size=hidden_size * 4,
            hidden_dropout_prob=0.1,
            attention_probs_dropout_prob=0.1,
        )
        
        self.bert = BertModel(config)
        self.cls_head = nn.Linear(hidden_size, hidden_size)  # For hypersphere center
        self.lm_head = nn.Linear(hidden_size, vocab_size)    # For masked LM
        
        # Hypersphere parameters
        self.center = nn.Parameter(torch.zeros(hidden_size))
        self.radius = nn.Parameter(torch.tensor(1.0))
        
    def forward(self, input_ids, attention_mask=None, masked_lm_labels=None):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        sequence_output = outputs.last_hidden_state
        pooled_output = outputs.pooler_output
        
        # Masked LM head
        lm_logits = self.lm_head(sequence_output)
        
        # Hypersphere projection
        projected = self.cls_head(pooled_output)
        
        # Compute distance from center
        distances = torch.norm(projected - self.center.unsqueeze(0), dim=1)
        
        loss = None
        if masked_lm_labels is not None:
            loss_fct = nn.CrossEntropyLoss()
            # Only compute loss on masked tokens
            active_loss = masked_lm_labels.view(-1) != -100
            active_logits = lm_logits.view(-1, lm_logits.size(-1))
            active_labels = torch.where(
                active_loss, 
                masked_lm_labels.view(-1), 
                torch.tensor(loss_fct.ignore_index).type_as(masked_lm_labels)
            )
            lm_loss = loss_fct(active_logits, active_labels)
            
            # Hypersphere loss - encourage normal logs to be within radius
            hypersphere_loss = torch.mean(F.relu(distances - self.radius))
            
            loss = lm_loss + 0.1 * hypersphere_loss
        
        return {
            'loss': loss,
            'lm_logits': lm_logits,
            'distances': distances,
            'projected': projected
        }


class LogDataset(Dataset):
    """PyTorch dataset for log data"""
    
    def __init__(self, input_ids: List[List[int]], attention_masks: List[List[int]], 
                 masked_lm_labels: List[List[int]]):
        self.input_ids = torch.tensor(input_ids)
        self.attention_masks = torch.tensor(attention_masks) 
        self.masked_lm_labels = torch.tensor(masked_lm_labels)
        
    def __len__(self):
        return len(self.input_ids)
    
    def __getitem__(self, idx):
        return {
            'input_ids': self.input_ids[idx],
            'attention_mask': self.attention_masks[idx],
            'masked_lm_labels': self.masked_lm_labels[idx]
        }


def train_logbert_model(training_data: Dict, epochs: int = 10, batch_size: int = 16, 
                       learning_rate: float = 5e-4, device: str = 'cpu'):
    """Train the LogBERT model"""
    logger.info("Starting LogBERT model training...")
    
    vocab_size = training_data['tokenizer_config']['vocab_size']
    max_length = training_data['tokenizer_config']['max_length']
    
    # Create model
    model = LogBERTModel(vocab_size=vocab_size, max_position_embeddings=max_length)
    model.to(device)
    
    # Create dataset
    dataset = LogDataset(
        training_data['input_ids'],
        training_data['attention_masks'], 
        training_data['masked_lm_labels']
    )
    
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    # Optimizer
    optimizer = AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    
    # Training loop
    model.train()
    losses = []
    
    for epoch in range(epochs):
        total_loss = 0
        num_batches = 0
        
        for batch in dataloader:
            optimizer.zero_grad()
            
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            masked_lm_labels = batch['masked_lm_labels'].to(device)
            
            outputs = model(input_ids, attention_mask, masked_lm_labels)
            loss = outputs['loss']
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            num_batches += 1
        
        avg_loss = total_loss / num_batches if num_batches > 0 else 0
        losses.append(avg_loss)
        logger.info(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")
    
    logger.info("Training completed!")
    
    # Save model
    model_path = "/Users/majjipradeepkumar/Downloads/samplewar/logbert_model.pth"
    torch.save({
        'model_state_dict': model.state_dict(),
        'vocab': training_data['vocab'],
        'config': training_data['tokenizer_config'],
        'center': model.center.detach().cpu().numpy(),
        'radius': model.radius.item()
    }, model_path)
    logger.info(f"Model saved to {model_path}")
    
    return model, losses


def detect_anomalies_with_hypersphere(model: LogBERTModel, dataset: LogDataset, 
                                     device: str = 'cpu', threshold_percentile: float = 95):
    """Detect anomalies using the trained hypersphere model"""
    logger.info("Detecting anomalies with hypersphere approach...")
    
    model.eval()
    dataloader = DataLoader(dataset, batch_size=32, shuffle=False)
    
    all_distances = []
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            
            outputs = model(input_ids, attention_mask)
            distances = outputs['distances'].cpu().numpy()
            all_distances.extend(distances)
    
    all_distances = np.array(all_distances)
    
    # Determine threshold based on percentile
    threshold = np.percentile(all_distances, threshold_percentile)
    is_anomaly = all_distances > threshold
    
    logger.info(f"Anomaly threshold (P{threshold_percentile}): {threshold:.4f}")
    logger.info(f"Detected {sum(is_anomaly)} anomalies out of {len(all_distances)} samples")
    
    return is_anomaly, all_distances, threshold


def visualize_results(distances: np.ndarray, is_anomaly: np.ndarray, threshold: float):
    """Visualize anomaly detection results"""
    plt.figure(figsize=(12, 5))
    
    # Distance distribution
    plt.subplot(1, 2, 1)
    plt.hist(distances[~is_anomaly], bins=50, alpha=0.7, label='Normal', density=True)
    plt.hist(distances[is_anomaly], bins=50, alpha=0.7, label='Anomaly', density=True)
    plt.axvline(threshold, color='red', linestyle='--', label='Threshold')
    plt.xlabel('Distance from Hypersphere Center')
    plt.ylabel('Density')
    plt.title('Distance Distribution')
    plt.legend()
    
    # Scatter plot
    plt.subplot(1, 2, 2)
    normal_idx = np.where(~is_anomaly)[0]
    anomaly_idx = np.where(is_anomaly)[0]
    
    plt.scatter(normal_idx, distances[~is_anomaly], alpha=0.6, s=10, label='Normal')
    plt.scatter(anomaly_idx, distances[is_anomaly], alpha=0.6, s=10, label='Anomaly')
    plt.axhline(threshold, color='red', linestyle='--', label='Threshold')
    plt.xlabel('Sample Index')
    plt.ylabel('Distance from Center')
    plt.title('Anomaly Detection Results')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig('/Users/majjipradeepkumar/Downloads/samplewar/logbert_anomaly_visualization.png')
    logger.info("Visualization saved to logbert_anomaly_visualization.png")
    plt.show()


def create_training_script():
    """Create a complete training script"""
    
    script_content = '''#!/usr/bin/env python3
"""
Complete LogBERT Training and Inference Pipeline
Run this script to train LogBERT on your Tomcat access logs
"""

# Installation requirements:
# pip install torch transformers scikit-learn matplotlib seaborn pandas numpy

import sys
import os
sys.path.append('/Users/majjipradeepkumar/Downloads/samplewar')

from logbert_model import main as parse_logs
from logbert_training import train_logbert_model, detect_anomalies_with_hypersphere, visualize_results, LogDataset
import json
import torch

def run_complete_pipeline():
    """Run the complete LogBERT pipeline"""
    
    print("=== LogBERT: Log Anomaly Detection via BERT ===")
    print("Step 1: Parsing Tomcat access logs...")
    
    # Parse logs and create training data
    results_df, training_data = parse_logs()
    
    print("Step 2: Training LogBERT model...")
    
    # Set device
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"Using device: {device}")
    
    # Train model
    model, losses = train_logbert_model(
        training_data, 
        epochs=20, 
        batch_size=8,
        learning_rate=1e-4,
        device=device
    )
    
    print("Step 3: Detecting anomalies...")
    
    # Create inference dataset (without labels for pure inference)
    inference_dataset = LogDataset(
        training_data['input_ids'],
        training_data['attention_masks'],
        [[-100] * len(seq) for seq in training_data['input_ids']]  # No labels for inference
    )
    
    # Detect anomalies
    is_anomaly, distances, threshold = detect_anomalies_with_hypersphere(
        model, inference_dataset, device=device, threshold_percentile=90
    )
    
    print("Step 4: Analyzing results...")
    
    # Add anomaly results to dataframe
    results_df['bert_anomaly_score'] = distances
    results_df['bert_is_anomaly'] = is_anomaly
    
    # Print some anomalous examples
    print("\\n=== TOP ANOMALIES DETECTED BY LogBERT ===")
    anomaly_results = results_df[results_df['bert_is_anomaly']].sort_values('bert_anomaly_score', ascending=False)
    
    for _, row in anomaly_results.head(10).iterrows():
        print(f"[SCORE: {row['bert_anomaly_score']:.3f}] {row['method']} {row['uri']} - Status: {row['status']}")
    
    # Save enhanced results
    results_df.to_csv('/Users/majjipradeepkumar/Downloads/samplewar/logbert_enhanced_results.csv', index=False)
    print("\\nEnhanced results saved to logbert_enhanced_results.csv")
    
    # Create visualization
    visualize_results(distances, is_anomaly, threshold)
    
    # Summary stats
    total_requests = len(results_df)
    anomalies_detected = sum(is_anomaly)
    print(f"\\n=== SUMMARY ===")
    print(f"Total requests analyzed: {total_requests}")
    print(f"Anomalies detected: {anomalies_detected} ({100*anomalies_detected/total_requests:.1f}%)")
    print(f"Threshold used: {threshold:.4f}")
    
    return results_df

if __name__ == "__main__":
    results = run_complete_pipeline()
'''
    
    with open('/Users/majjipradeepkumar/Downloads/samplewar/run_logbert_training.py', 'w') as f:
        f.write(script_content)


if __name__ == "__main__":
    create_training_script()
    logger.info("LogBERT training modules created successfully!")
