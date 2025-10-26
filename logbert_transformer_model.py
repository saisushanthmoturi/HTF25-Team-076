"""
LogBERT-style Transformer Model for WAF Anomaly Detection
=========================================================
Implements a BERT-like encoder trained on log sequences for anomaly detection.
Uses masked token prediction + hypersphere compactness loss.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
import numpy as np
import json
import pickle
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import math
import logging
from sklearn.metrics import roc_auc_score, precision_recall_curve
from transformers import BertTokenizer, BertModel, BertConfig
from transformers.models.bert.modeling_bert import BertEncoder
import warnings

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ModelConfig:
    """Configuration for the LogBERT model"""
    vocab_size: int = 10000
    hidden_size: int = 256
    num_attention_heads: int = 8
    num_hidden_layers: int = 4
    intermediate_size: int = 1024
    max_position_embeddings: int = 128
    dropout: float = 0.1
    mask_token_id: int = 1
    pad_token_id: int = 0
    cls_token_id: int = 2
    sep_token_id: int = 3

class LogSequenceDataset(Dataset):
    """Dataset for log sequences"""
    
    def __init__(self, sequences: List[List[int]], tokenizer, max_length: int = 64, mask_prob: float = 0.15):
        self.sequences = sequences
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.mask_prob = mask_prob
        self.vocab_size = tokenizer.vocab_size
        
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        sequence = self.sequences[idx]
        
        # Truncate or pad sequence
        if len(sequence) > self.max_length - 2:  # Leave room for [CLS] and [SEP]
            sequence = sequence[:self.max_length - 2]
        
        # Add [CLS] and [SEP] tokens
        sequence = [self.tokenizer.cls_token_id] + sequence + [self.tokenizer.sep_token_id]
        
        # Pad sequence
        while len(sequence) < self.max_length:
            sequence.append(self.tokenizer.pad_token_id)
        
        # Create attention mask
        attention_mask = [1 if token != self.tokenizer.pad_token_id else 0 for token in sequence]
        
        # Create masked sequence for MLM
        masked_sequence, mlm_labels = self._create_masked_sequence(sequence)
        
        return {
            'input_ids': torch.tensor(masked_sequence, dtype=torch.long),
            'attention_mask': torch.tensor(attention_mask, dtype=torch.long),
            'labels': torch.tensor(mlm_labels, dtype=torch.long),
            'original_sequence': torch.tensor(sequence, dtype=torch.long)
        }
    
    def _create_masked_sequence(self, sequence: List[int]) -> Tuple[List[int], List[int]]:
        """Create masked sequence for MLM training"""
        masked_sequence = sequence.copy()
        labels = [-100] * len(sequence)  # -100 is ignored in loss computation
        
        for i, token in enumerate(sequence):
            if token in [self.tokenizer.cls_token_id, self.tokenizer.sep_token_id, self.tokenizer.pad_token_id]:
                continue
                
            if np.random.random() < self.mask_prob:
                labels[i] = token  # Store original token for loss
                
                # 80% of the time, replace with [MASK]
                if np.random.random() < 0.8:
                    masked_sequence[i] = self.tokenizer.mask_token_id
                # 10% of the time, replace with random token
                elif np.random.random() < 0.5:
                    masked_sequence[i] = np.random.randint(4, self.vocab_size)
                # 10% of the time, keep original token
        
        return masked_sequence, labels

class LogTokenizer:
    """Custom tokenizer for log sequences"""
    
    def __init__(self):
        self.vocab = {}
        self.reverse_vocab = {}
        self.vocab_size = 0
        
        # Special tokens
        self.pad_token = '[PAD]'
        self.mask_token = '[MASK]'
        self.cls_token = '[CLS]'
        self.sep_token = '[SEP]'
        self.unk_token = '[UNK]'
        
        # Initialize special tokens
        self._init_special_tokens()
    
    def _init_special_tokens(self):
        """Initialize special tokens"""
        special_tokens = [
            self.pad_token,
            self.mask_token, 
            self.cls_token,
            self.sep_token,
            self.unk_token
        ]
        
        for token in special_tokens:
            self._add_token(token)
        
        # Store special token IDs
        self.pad_token_id = self.vocab[self.pad_token]
        self.mask_token_id = self.vocab[self.mask_token]
        self.cls_token_id = self.vocab[self.cls_token]
        self.sep_token_id = self.vocab[self.sep_token]
        self.unk_token_id = self.vocab[self.unk_token]
    
    def _add_token(self, token: str) -> int:
        """Add token to vocabulary"""
        if token not in self.vocab:
            self.vocab[token] = self.vocab_size
            self.reverse_vocab[self.vocab_size] = token
            self.vocab_size += 1
        return self.vocab[token]
    
    def fit(self, token_sequences: List[List[str]]):
        """Build vocabulary from token sequences"""
        logger.info("Building vocabulary from token sequences...")
        
        for sequence in token_sequences:
            for token in sequence:
                self._add_token(token)
        
        logger.info(f"Built vocabulary with {self.vocab_size} tokens")
    
    def encode(self, tokens: List[str]) -> List[int]:
        """Convert tokens to IDs"""
        return [self.vocab.get(token, self.unk_token_id) for token in tokens]
    
    def decode(self, ids: List[int]) -> List[str]:
        """Convert IDs to tokens"""
        return [self.reverse_vocab.get(id, self.unk_token) for id in ids]
    
    def save(self, path: str):
        """Save tokenizer"""
        with open(path, 'wb') as f:
            pickle.dump({
                'vocab': self.vocab,
                'reverse_vocab': self.reverse_vocab,
                'vocab_size': self.vocab_size
            }, f)
    
    def load(self, path: str):
        """Load tokenizer"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.vocab = data['vocab']
            self.reverse_vocab = data['reverse_vocab'] 
            self.vocab_size = data['vocab_size']

class LogBERTModel(nn.Module):
    """LogBERT model for log anomaly detection"""
    
    def __init__(self, config: ModelConfig):
        super().__init__()
        self.config = config
        
        # Embedding layers
        self.token_embeddings = nn.Embedding(config.vocab_size, config.hidden_size, padding_idx=config.pad_token_id)
        self.position_embeddings = nn.Embedding(config.max_position_embeddings, config.hidden_size)
        self.layer_norm = nn.LayerNorm(config.hidden_size)
        self.dropout = nn.Dropout(config.dropout)
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.hidden_size,
            nhead=config.num_attention_heads,
            dim_feedforward=config.intermediate_size,
            dropout=config.dropout,
            batch_first=True
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=config.num_hidden_layers)
        
        # MLM head for masked language modeling
        self.mlm_head = nn.Linear(config.hidden_size, config.vocab_size)
        
        # Hypersphere center for compactness loss
        self.register_buffer('hypersphere_center', torch.zeros(config.hidden_size))
        self.center_momentum = 0.99
        
        # Initialize weights
        self.apply(self._init_weights)
    
    def _init_weights(self, module):
        """Initialize model weights"""
        if isinstance(module, nn.Linear):
            torch.nn.init.normal_(module.weight, mean=0.0, std=0.02)
            if module.bias is not None:
                torch.nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            torch.nn.init.normal_(module.weight, mean=0.0, std=0.02)
        elif isinstance(module, nn.LayerNorm):
            torch.nn.init.zeros_(module.bias)
            torch.nn.init.ones_(module.weight)
    
    def get_embeddings(self, input_ids, attention_mask=None):
        """Get contextualized embeddings"""
        batch_size, seq_len = input_ids.shape
        
        # Create position IDs
        position_ids = torch.arange(seq_len, dtype=torch.long, device=input_ids.device)
        position_ids = position_ids.unsqueeze(0).expand(batch_size, -1)
        
        # Get embeddings
        token_embeds = self.token_embeddings(input_ids)
        pos_embeds = self.position_embeddings(position_ids)
        
        embeddings = token_embeds + pos_embeds
        embeddings = self.layer_norm(embeddings)
        embeddings = self.dropout(embeddings)
        
        # Create attention mask for transformer
        if attention_mask is not None:
            # Convert attention mask to transformer format
            extended_attention_mask = attention_mask.unsqueeze(1).unsqueeze(2)
            extended_attention_mask = extended_attention_mask.float()
            extended_attention_mask = (1.0 - extended_attention_mask) * -10000.0
            key_padding_mask = (attention_mask == 0)
        else:
            extended_attention_mask = None
            key_padding_mask = None
        
        # Apply transformer encoder
        encoded = self.encoder(embeddings, src_key_padding_mask=key_padding_mask)
        
        return encoded
    
    def forward(self, input_ids, attention_mask=None, labels=None):
        """Forward pass"""
        # Get contextualized embeddings
        encoded = self.get_embeddings(input_ids, attention_mask)
        
        # MLM predictions
        mlm_logits = self.mlm_head(encoded)
        
        # Get [CLS] representation for hypersphere loss
        cls_representation = encoded[:, 0]  # [CLS] token representation
        
        outputs = {
            'logits': mlm_logits,
            'hidden_states': encoded,
            'cls_representation': cls_representation
        }
        
        if labels is not None:
            # MLM loss
            loss_fct = nn.CrossEntropyLoss(ignore_index=-100)
            mlm_loss = loss_fct(mlm_logits.view(-1, self.config.vocab_size), labels.view(-1))
            
            # Hypersphere compactness loss
            center_loss = self._compute_center_loss(cls_representation)
            
            # Combined loss
            total_loss = mlm_loss + 0.1 * center_loss
            
            outputs.update({
                'loss': total_loss,
                'mlm_loss': mlm_loss,
                'center_loss': center_loss
            })
        
        return outputs
    
    def _compute_center_loss(self, representations):
        """Compute hypersphere center loss for compactness"""
        batch_size = representations.shape[0]
        
        if self.training:
            # Update center with momentum
            batch_center = representations.mean(dim=0)
            self.hypersphere_center = (
                self.center_momentum * self.hypersphere_center + 
                (1 - self.center_momentum) * batch_center.detach()
            )
        
        # Compute distances to center
        distances = torch.norm(representations - self.hypersphere_center, dim=1)
        center_loss = distances.mean()
        
        return center_loss
    
    def compute_anomaly_score(self, input_ids, attention_mask=None):
        """Compute anomaly score for a sequence"""
        self.eval()
        with torch.no_grad():
            outputs = self.forward(input_ids, attention_mask)
            
            # Distance-based score (hypersphere approach)
            cls_repr = outputs['cls_representation']
            distances = torch.norm(cls_repr - self.hypersphere_center, dim=1)
            
            # Normalize scores to [0, 1]
            scores = torch.sigmoid(distances - distances.mean())
            
            return scores

class LogBERTTrainer:
    """Trainer for LogBERT model"""
    
    def __init__(self, model, tokenizer, device='cuda' if torch.cuda.is_available() else 'cpu'):
        self.model = model.to(device)
        self.tokenizer = tokenizer
        self.device = device
        self.training_history = []
    
    def train_epoch(self, dataloader, optimizer, scheduler=None):
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        total_mlm_loss = 0
        total_center_loss = 0
        
        for batch_idx, batch in enumerate(dataloader):
            # Move batch to device
            batch = {k: v.to(self.device) for k, v in batch.items()}
            
            # Forward pass
            outputs = self.model(**batch)
            
            # Backward pass
            optimizer.zero_grad()
            outputs['loss'].backward()
            
            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            
            optimizer.step()
            
            if scheduler:
                scheduler.step()
            
            # Accumulate losses
            total_loss += outputs['loss'].item()
            total_mlm_loss += outputs['mlm_loss'].item()
            total_center_loss += outputs['center_loss'].item()
            
            if batch_idx % 100 == 0:
                logger.info(f"Batch {batch_idx}: Loss={outputs['loss'].item():.4f}")
        
        avg_loss = total_loss / len(dataloader)
        avg_mlm_loss = total_mlm_loss / len(dataloader)
        avg_center_loss = total_center_loss / len(dataloader)
        
        return {
            'loss': avg_loss,
            'mlm_loss': avg_mlm_loss,
            'center_loss': avg_center_loss
        }
    
    def evaluate(self, dataloader):
        """Evaluate model"""
        self.model.eval()
        total_loss = 0
        all_scores = []
        
        with torch.no_grad():
            for batch in dataloader:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                
                outputs = self.model(**batch)
                total_loss += outputs['loss'].item()
                
                # Compute anomaly scores
                scores = self.model.compute_anomaly_score(
                    batch['input_ids'], 
                    batch['attention_mask']
                )
                all_scores.extend(scores.cpu().numpy())
        
        avg_loss = total_loss / len(dataloader)
        avg_score = np.mean(all_scores)
        
        return {
            'loss': avg_loss,
            'avg_anomaly_score': avg_score,
            'anomaly_scores': all_scores
        }
    
    def fit(self, train_dataloader, val_dataloader=None, epochs=10, lr=1e-4):
        """Train the model"""
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=0.01)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
        
        logger.info(f"Starting training for {epochs} epochs...")
        
        best_val_loss = float('inf')
        
        for epoch in range(epochs):
            logger.info(f"Epoch {epoch + 1}/{epochs}")
            
            # Training
            train_metrics = self.train_epoch(train_dataloader, optimizer, scheduler)
            
            logger.info(f"Train Loss: {train_metrics['loss']:.4f}, "
                       f"MLM Loss: {train_metrics['mlm_loss']:.4f}, "
                       f"Center Loss: {train_metrics['center_loss']:.4f}")
            
            # Validation
            if val_dataloader:
                val_metrics = self.evaluate(val_dataloader)
                logger.info(f"Val Loss: {val_metrics['loss']:.4f}, "
                           f"Avg Anomaly Score: {val_metrics['avg_anomaly_score']:.4f}")
                
                # Save best model
                if val_metrics['loss'] < best_val_loss:
                    best_val_loss = val_metrics['loss']
                    self.save_model('best_model.pt')
                    logger.info("Saved new best model")
            
            # Save training history
            history_entry = {
                'epoch': epoch + 1,
                'train_loss': train_metrics['loss'],
                'train_mlm_loss': train_metrics['mlm_loss'],
                'train_center_loss': train_metrics['center_loss']
            }
            
            if val_dataloader:
                history_entry.update({
                    'val_loss': val_metrics['loss'],
                    'val_avg_score': val_metrics['avg_anomaly_score']
                })
            
            self.training_history.append(history_entry)
        
        logger.info("Training completed!")
        return self.training_history
    
    def save_model(self, path: str):
        """Save model checkpoint"""
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'config': self.model.config,
            'hypersphere_center': self.model.hypersphere_center,
            'training_history': self.training_history
        }
        torch.save(checkpoint, path)
    
    def load_model(self, path: str):
        """Load model checkpoint"""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.hypersphere_center = checkpoint['hypersphere_center']
        self.training_history = checkpoint.get('training_history', [])

def create_model_and_tokenizer(token_sequences: List[List[str]]) -> Tuple[LogBERTModel, LogTokenizer]:
    """Create and initialize model and tokenizer"""
    # Create tokenizer
    tokenizer = LogTokenizer()
    tokenizer.fit(token_sequences)
    
    # Create model config
    config = ModelConfig(
        vocab_size=tokenizer.vocab_size,
        hidden_size=256,
        num_attention_heads=8,
        num_hidden_layers=4,
        max_position_embeddings=128
    )
    
    # Update config with tokenizer special token IDs
    config.pad_token_id = tokenizer.pad_token_id
    config.mask_token_id = tokenizer.mask_token_id
    config.cls_token_id = tokenizer.cls_token_id
    config.sep_token_id = tokenizer.sep_token_id
    
    # Create model
    model = LogBERTModel(config)
    
    return model, tokenizer

if __name__ == "__main__":
    # Example usage
    sample_sequences = [
        ['<METHOD_GET>', '<PATH_/ecommerce/products>', '<STATUS_success>', '<PARAM_category>'],
        ['<METHOD_POST>', '<PATH_/rest-api/api/tasks>', '<STATUS_success>'],
        ['<METHOD_GET>', '<PATH_/ecommerce/product/<ID>>', '<STATUS_success>'],
        ['<METHOD_DELETE>', '<PATH_/rest-api/api/task/<ID>>', '<STATUS_success>'],
    ]
    
    # Create model and tokenizer
    model, tokenizer = create_model_and_tokenizer(sample_sequences)
    
    print(f"Created model with vocab size: {tokenizer.vocab_size}")
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Create sample dataset
    encoded_sequences = [tokenizer.encode(seq) for seq in sample_sequences]
    dataset = LogSequenceDataset(encoded_sequences, tokenizer)
    dataloader = DataLoader(dataset, batch_size=2, shuffle=True)
    
    # Test training
    trainer = LogBERTTrainer(model, tokenizer)
    
    # Run a quick test
    sample_batch = next(iter(dataloader))
    outputs = model(**sample_batch)
    print(f"Sample loss: {outputs['loss'].item():.4f}")
    
    # Compute anomaly scores
    scores = model.compute_anomaly_score(sample_batch['input_ids'], sample_batch['attention_mask'])
    print(f"Anomaly scores: {scores.tolist()}")
