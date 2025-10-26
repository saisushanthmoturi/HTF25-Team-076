"""
Incremental Learning with LoRA for WAF Model Updates
===================================================
Implements parameter-efficient fine-tuning using LoRA (Low-Rank Adaptation)
for continuous model updates on new benign traffic without catastrophic forgetting.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple
import numpy as np
import logging
import json
import os
from dataclasses import dataclass
from torch.utils.data import DataLoader
import time
from collections import deque

from logbert_transformer_model import LogBERTModel, LogTokenizer, LogSequenceDataset
from log_parser_normalizer import AccessLogParser

logger = logging.getLogger(__name__)

@dataclass
class LoRAConfig:
    """Configuration for LoRA adaptation"""
    rank: int = 8  # Low-rank dimension
    alpha: float = 16.0  # Scaling factor  
    dropout: float = 0.1
    target_modules: List[str] = None  # Which modules to adapt
    
    def __post_init__(self):
        if self.target_modules is None:
            self.target_modules = ["query", "key", "value", "dense"]

class LoRALayer(nn.Module):
    """LoRA adaptation layer"""
    
    def __init__(self, in_features: int, out_features: int, rank: int, alpha: float, dropout: float = 0.1):
        super().__init__()
        self.rank = rank
        self.alpha = alpha
        self.dropout = nn.Dropout(dropout)
        
        # Low-rank matrices
        self.lora_A = nn.Parameter(torch.randn(rank, in_features) * 0.01)
        self.lora_B = nn.Parameter(torch.zeros(out_features, rank))
        
        self.scaling = alpha / rank
        
    def forward(self, x):
        """Forward pass through LoRA adaptation"""
        # x shape: (..., in_features)
        result = x @ self.lora_A.T  # (..., rank)
        result = self.dropout(result)
        result = result @ self.lora_B.T  # (..., out_features)
        return result * self.scaling

class LoRALinear(nn.Module):
    """Linear layer with LoRA adaptation"""
    
    def __init__(self, original_layer: nn.Linear, rank: int, alpha: float, dropout: float = 0.1):
        super().__init__()
        self.original_layer = original_layer
        self.lora = LoRALayer(
            in_features=original_layer.in_features,
            out_features=original_layer.out_features, 
            rank=rank,
            alpha=alpha,
            dropout=dropout
        )
        
        # Freeze original weights
        for param in self.original_layer.parameters():
            param.requires_grad = False
    
    def forward(self, x):
        """Forward pass with LoRA adaptation"""
        original_output = self.original_layer(x)
        lora_output = self.lora(x)
        return original_output + lora_output

class LoRAModel(nn.Module):
    """LogBERT model with LoRA adaptations"""
    
    def __init__(self, base_model: LogBERTModel, lora_config: LoRAConfig):
        super().__init__()
        self.base_model = base_model
        self.lora_config = lora_config
        
        # Freeze base model
        for param in self.base_model.parameters():
            param.requires_grad = False
        
        # Add LoRA layers to target modules
        self._add_lora_layers()
        
        # Keep track of LoRA parameters
        self.lora_layers = {}
        for name, module in self.named_modules():
            if isinstance(module, LoRALinear):
                self.lora_layers[name] = module
        
        logger.info(f"Added LoRA to {len(self.lora_layers)} layers")
    
    def _add_lora_layers(self):
        """Add LoRA layers to target modules"""
        for name, module in self.base_model.named_modules():
            if isinstance(module, nn.Linear):
                # Check if this is a target module
                should_adapt = any(target in name for target in self.lora_config.target_modules)
                
                if should_adapt:
                    # Replace with LoRA version
                    parent_module = self.base_model
                    name_parts = name.split('.')
                    
                    # Navigate to parent
                    for part in name_parts[:-1]:
                        parent_module = getattr(parent_module, part)
                    
                    # Replace the layer
                    lora_layer = LoRALinear(
                        original_layer=module,
                        rank=self.lora_config.rank,
                        alpha=self.lora_config.alpha,
                        dropout=self.lora_config.dropout
                    )
                    
                    setattr(parent_module, name_parts[-1], lora_layer)
                    logger.debug(f"Added LoRA to {name}")
    
    def forward(self, *args, **kwargs):
        """Forward pass through base model with LoRA"""
        return self.base_model(*args, **kwargs)
    
    def compute_anomaly_score(self, *args, **kwargs):
        """Compute anomaly score"""
        return self.base_model.compute_anomaly_score(*args, **kwargs)
    
    def get_lora_state_dict(self):
        """Get only LoRA parameters"""
        lora_state = {}
        for name, module in self.named_modules():
            if isinstance(module, LoRALinear):
                lora_state[f"{name}.lora_A"] = module.lora.lora_A
                lora_state[f"{name}.lora_B"] = module.lora.lora_B
        return lora_state
    
    def load_lora_state_dict(self, state_dict):
        """Load only LoRA parameters"""
        for name, param in state_dict.items():
            if 'lora_A' in name or 'lora_B' in name:
                # Find the corresponding module
                module_path = name.replace('.lora_A', '').replace('.lora_B', '')
                try:
                    module = self
                    for part in module_path.split('.'):
                        module = getattr(module, part)
                    
                    if 'lora_A' in name:
                        module.lora.lora_A.data = param
                    elif 'lora_B' in name:
                        module.lora.lora_B.data = param
                        
                except AttributeError:
                    logger.warning(f"Could not load parameter {name}")

class IncrementalLearner:
    """Handles incremental learning with LoRA"""
    
    def __init__(self, base_model: LogBERTModel, tokenizer: LogTokenizer, lora_config: LoRAConfig = None):
        self.base_model = base_model
        self.tokenizer = tokenizer
        self.lora_config = lora_config or LoRAConfig()
        
        # Create LoRA model
        self.lora_model = LoRAModel(base_model, self.lora_config)
        
        # Replay buffer for preventing catastrophic forgetting
        self.replay_buffer = deque(maxlen=1000)
        
        # Update history
        self.update_history = []
        
        # Device
        self.device = next(base_model.parameters()).device
        self.lora_model = self.lora_model.to(self.device)
        
        logger.info("Incremental learner initialized")
    
    def add_benign_data(self, token_sequences: List[List[str]], max_samples: int = 100):
        """Add new benign data to replay buffer"""
        # Convert to encoded sequences
        encoded_sequences = [self.tokenizer.encode(seq) for seq in token_sequences]
        
        # Add to replay buffer
        for seq in encoded_sequences[-max_samples:]:  # Take most recent samples
            self.replay_buffer.append(seq)
        
        logger.info(f"Added {min(len(encoded_sequences), max_samples)} samples to replay buffer")
    
    def incremental_update(self, new_sequences: List[List[str]], epochs: int = 3, lr: float = 1e-5):
        """Perform incremental update with LoRA"""
        start_time = time.time()
        
        try:
            # Encode new sequences
            new_encoded = [self.tokenizer.encode(seq) for seq in new_sequences]
            
            # Combine with replay buffer samples
            replay_samples = list(self.replay_buffer)
            all_sequences = new_encoded + replay_samples
            
            if not all_sequences:
                logger.warning("No sequences to update on")
                return False
            
            # Create dataset
            dataset = LogSequenceDataset(
                sequences=all_sequences,
                tokenizer=self.tokenizer,
                max_length=64,
                mask_prob=0.15
            )
            
            # Create dataloader
            dataloader = DataLoader(dataset, batch_size=8, shuffle=True)
            
            # Setup optimizer for LoRA parameters only
            lora_params = []
            for module in self.lora_model.modules():
                if isinstance(module, LoRALinear):
                    lora_params.extend([module.lora.lora_A, module.lora.lora_B])
            
            optimizer = torch.optim.AdamW(lora_params, lr=lr, weight_decay=0.01)
            
            logger.info(f"Starting incremental update with {len(all_sequences)} sequences")
            logger.info(f"LoRA parameters: {sum(p.numel() for p in lora_params):,}")
            
            # Training loop
            self.lora_model.train()
            total_loss = 0
            num_batches = 0
            
            for epoch in range(epochs):
                epoch_loss = 0
                epoch_batches = 0
                
                for batch in dataloader:
                    # Move to device
                    batch = {k: v.to(self.device) for k, v in batch.items()}
                    
                    # Forward pass
                    optimizer.zero_grad()
                    outputs = self.lora_model(**batch)
                    loss = outputs['loss']
                    
                    # Backward pass
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(lora_params, max_norm=1.0)
                    optimizer.step()
                    
                    epoch_loss += loss.item()
                    epoch_batches += 1
                
                avg_epoch_loss = epoch_loss / epoch_batches if epoch_batches > 0 else 0
                logger.info(f"Epoch {epoch + 1}/{epochs}: Loss = {avg_epoch_loss:.4f}")
                
                total_loss += epoch_loss
                num_batches += epoch_batches
            
            # Update metrics
            avg_loss = total_loss / num_batches if num_batches > 0 else 0
            duration = time.time() - start_time
            
            # Save update history
            update_record = {
                'timestamp': time.time(),
                'new_samples': len(new_encoded),
                'replay_samples': len(replay_samples),
                'epochs': epochs,
                'final_loss': avg_loss,
                'duration_seconds': duration,
                'lora_params': sum(p.numel() for p in lora_params)
            }
            self.update_history.append(update_record)
            
            logger.info(f"✅ Incremental update completed in {duration:.2f}s")
            logger.info(f"   Average loss: {avg_loss:.4f}")
            logger.info(f"   New samples: {len(new_encoded)}")
            logger.info(f"   Replay samples: {len(replay_samples)}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Incremental update failed: {e}")
            return False
    
    def save_lora_checkpoint(self, path: str):
        """Save LoRA adaptation weights"""
        checkpoint = {
            'lora_state_dict': self.lora_model.get_lora_state_dict(),
            'lora_config': {
                'rank': self.lora_config.rank,
                'alpha': self.lora_config.alpha,
                'dropout': self.lora_config.dropout,
                'target_modules': self.lora_config.target_modules
            },
            'replay_buffer': list(self.replay_buffer),
            'update_history': self.update_history,
            'timestamp': time.time()
        }
        
        torch.save(checkpoint, path)
        logger.info(f"Saved LoRA checkpoint to {path}")
    
    def load_lora_checkpoint(self, path: str):
        """Load LoRA adaptation weights"""
        checkpoint = torch.load(path, map_location=self.device)
        
        # Load LoRA weights
        self.lora_model.load_lora_state_dict(checkpoint['lora_state_dict'])
        
        # Restore replay buffer and history
        self.replay_buffer.extend(checkpoint.get('replay_buffer', []))
        self.update_history = checkpoint.get('update_history', [])
        
        logger.info(f"Loaded LoRA checkpoint from {path}")
        logger.info(f"Replay buffer size: {len(self.replay_buffer)}")
        logger.info(f"Update history: {len(self.update_history)} updates")
    
    def get_model_for_inference(self):
        """Get model for inference (base + LoRA)"""
        return self.lora_model
    
    def evaluate_drift(self, validation_sequences: List[List[str]]) -> Dict[str, float]:
        """Evaluate model drift on validation data"""
        if not validation_sequences:
            return {}
        
        try:
            # Encode sequences
            encoded_seqs = [self.tokenizer.encode(seq) for seq in validation_sequences]
            
            # Create dataset
            dataset = LogSequenceDataset(encoded_seqs, self.tokenizer, max_length=64)
            dataloader = DataLoader(dataset, batch_size=16, shuffle=False)
            
            # Evaluate both models
            models = {
                'base': self.base_model,
                'lora': self.lora_model
            }
            
            results = {}
            
            for model_name, model in models.items():
                model.eval()
                total_loss = 0
                anomaly_scores = []
                num_batches = 0
                
                with torch.no_grad():
                    for batch in dataloader:
                        batch = {k: v.to(self.device) for k, v in batch.items()}
                        
                        outputs = model(**batch)
                        total_loss += outputs['loss'].item()
                        
                        scores = model.compute_anomaly_score(
                            batch['input_ids'], 
                            batch['attention_mask']
                        )
                        anomaly_scores.extend(scores.cpu().numpy())
                        num_batches += 1
                
                results[model_name] = {
                    'avg_loss': total_loss / num_batches if num_batches > 0 else 0,
                    'avg_anomaly_score': np.mean(anomaly_scores),
                    'std_anomaly_score': np.std(anomaly_scores)
                }
            
            # Calculate drift metrics
            base_scores = results['base']['avg_anomaly_score']
            lora_scores = results['lora']['avg_anomaly_score']
            
            drift_metrics = {
                'score_drift': abs(lora_scores - base_scores),
                'loss_improvement': results['base']['avg_loss'] - results['lora']['avg_loss'],
                'base_model_loss': results['base']['avg_loss'],
                'lora_model_loss': results['lora']['avg_loss']
            }
            
            return drift_metrics
            
        except Exception as e:
            logger.error(f"Drift evaluation failed: {e}")
            return {}

class IncrementalUpdateService:
    """Service for handling incremental model updates"""
    
    def __init__(self, model_path: str, tokenizer_path: str, lora_config: LoRAConfig = None):
        # Load base model and tokenizer
        self.tokenizer = LogTokenizer()
        self.tokenizer.load(tokenizer_path)
        
        checkpoint = torch.load(model_path)
        self.base_model = LogBERTModel(checkpoint['config'])
        self.base_model.load_state_dict(checkpoint['model_state_dict'])
        self.base_model.hypersphere_center = checkpoint['hypersphere_center']
        
        # Setup incremental learner
        self.learner = IncrementalLearner(
            base_model=self.base_model,
            tokenizer=self.tokenizer,
            lora_config=lora_config
        )
        
        # Log parser for processing new data
        self.parser = AccessLogParser()
        
        logger.info("Incremental update service initialized")
    
    def process_new_logs(self, log_lines: List[str]) -> List[List[str]]:
        """Process new log lines into token sequences"""
        sequences = []
        
        for line in log_lines:
            event = self.parser.process_log_line(line)
            if event and hasattr(event, 'normalized_tokens'):
                sequences.append(event.normalized_tokens)
        
        return sequences
    
    def update_model(self, log_lines: List[str], epochs: int = 3) -> bool:
        """Update model with new log data"""
        # Process logs to token sequences
        token_sequences = self.process_new_logs(log_lines)
        
        if not token_sequences:
            logger.warning("No valid sequences from log lines")
            return False
        
        # Add to replay buffer
        self.learner.add_benign_data(token_sequences)
        
        # Perform incremental update
        success = self.learner.incremental_update(token_sequences, epochs=epochs)
        
        if success:
            # Save updated LoRA weights
            checkpoint_path = f"./models/lora_checkpoint_{int(time.time())}.pt"
            self.learner.save_lora_checkpoint(checkpoint_path)
        
        return success
    
    def get_model_for_inference(self):
        """Get updated model for inference"""
        return self.learner.get_model_for_inference()

if __name__ == "__main__":
    # Example usage
    from logbert_transformer_model import create_model_and_tokenizer
    
    # Create sample data
    sample_sequences = [
        ['<METHOD_GET>', '<PATH_/ecommerce/products>', '<STATUS_success>'],
        ['<METHOD_POST>', '<PATH_/rest-api/api/tasks>', '<STATUS_success>'],
    ]
    
    # Create base model
    model, tokenizer = create_model_and_tokenizer(sample_sequences)
    
    # Create incremental learner
    lora_config = LoRAConfig(rank=4, alpha=8.0)
    learner = IncrementalLearner(model, tokenizer, lora_config)
    
    # Test incremental update
    new_sequences = [
        ['<METHOD_PUT>', '<PATH_/ecommerce/product/<ID>>', '<STATUS_success>'],
        ['<METHOD_DELETE>', '<PATH_/rest-api/api/task/<ID>>', '<STATUS_success>'],
    ]
    
    success = learner.incremental_update(new_sequences, epochs=2)
    print(f"Incremental update: {'Success' if success else 'Failed'}")
    
    # Save and load checkpoint
    learner.save_lora_checkpoint('./test_lora_checkpoint.pt')
    
    print(f"LoRA parameters: {sum(p.numel() for p in learner.lora_model.modules() if isinstance(p, LoRALinear))}")
    print(f"Update history: {len(learner.update_history)} updates")
