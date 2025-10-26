"""
WAF Training Pipeline
====================
Complete pipeline for training the Transformer-based WAF system:
1. Generate benign traffic
2. Parse and normalize logs
3. Train LogBERT model
4. Export for production inference
"""

import os
import sys
import json
import pandas as pd
import numpy as np
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict
import subprocess
import time
import torch
from torch.utils.data import DataLoader, random_split

# Import our components
from benign_traffic_generator import generate_benign_traffic
from log_parser_normalizer import AccessLogParser, LogNormalizer, create_drain_config
from logbert_transformer_model import (
    LogBERTModel, LogTokenizer, LogSequenceDataset, 
    LogBERTTrainer, ModelConfig, create_model_and_tokenizer
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('waf_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WAFTrainingPipeline:
    """Complete training pipeline for WAF system"""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.setup_directories()
        
        # Components
        self.parser = None
        self.tokenizer = None
        self.model = None
        self.trainer = None
        
        logger.info("WAF Training Pipeline initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration"""
        default_config = {
            "data": {
                "log_paths": [
                    "/Users/majjipradeepkumar/Downloads/apache-tomcat-9.0.109/logs/localhost_access_log.txt"
                ],
                "output_dir": "./waf_training_data",
                "synthetic_traffic": True,
                "traffic_duration_minutes": 30,
                "concurrent_users": 50
            },
            "model": {
                "hidden_size": 256,
                "num_attention_heads": 8,
                "num_hidden_layers": 4,
                "max_position_embeddings": 128,
                "sequence_length": 64,
                "mask_probability": 0.15
            },
            "training": {
                "batch_size": 16,
                "epochs": 10,
                "learning_rate": 1e-4,
                "validation_split": 0.2,
                "early_stopping_patience": 3
            },
            "inference": {
                "anomaly_threshold": 0.7,
                "export_onnx": True,
                "model_save_path": "./models"
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                # Merge configs
                for key, value in user_config.items():
                    if key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
        
        return default_config
    
    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.config["data"]["output_dir"],
            self.config["inference"]["model_save_path"],
            "./logs",
            "./exports"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def step1_generate_traffic(self):
        """Step 1: Generate benign traffic"""
        logger.info("🚀 Step 1: Generating benign traffic...")
        
        if not self.config["data"]["synthetic_traffic"]:
            logger.info("Skipping traffic generation (using existing logs)")
            return
        
        try:
            # Check if applications are running
            self._check_applications_running()
            
            # Generate traffic
            stats = generate_benign_traffic(
                duration_minutes=self.config["data"]["traffic_duration_minutes"],
                users=self.config["data"]["concurrent_users"],
                spawn_rate=5
            )
            
            logger.info(f"✅ Generated {stats.total.num_requests} requests")
            
            # Wait a moment for logs to be written
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"❌ Traffic generation failed: {e}")
            raise
    
    def step2_parse_logs(self):
        """Step 2: Parse and normalize access logs"""
        logger.info("📝 Step 2: Parsing and normalizing logs...")
        
        try:
            # Create Drain config
            create_drain_config()
            
            # Initialize parser
            self.parser = AccessLogParser()
            
            # Process all log files
            all_events = []
            for log_path in self.config["data"]["log_paths"]:
                if os.path.exists(log_path):
                    logger.info(f"Processing {log_path}")
                    events = self.parser.process_log_file(log_path)
                    all_events.extend(events)
                else:
                    logger.warning(f"Log file not found: {log_path}")
            
            if not all_events:
                raise ValueError("No log events processed")
            
            # Save processed events
            output_path = os.path.join(self.config["data"]["output_dir"], "processed_events.csv")
            self.parser.save_events(all_events, output_path)
            
            logger.info(f"✅ Processed {len(all_events)} log events")
            return all_events
            
        except Exception as e:
            logger.error(f"❌ Log parsing failed: {e}")
            raise
    
    def step3_prepare_sequences(self, events: List):
        """Step 3: Prepare token sequences for training"""
        logger.info("🔤 Step 3: Preparing token sequences...")
        
        try:
            # Extract token sequences from events
            token_sequences = []
            for event in events:
                if hasattr(event, 'normalized_tokens') and event.normalized_tokens:
                    token_sequences.append(event.normalized_tokens)
            
            if not token_sequences:
                raise ValueError("No token sequences extracted")
            
            logger.info(f"✅ Extracted {len(token_sequences)} token sequences")
            
            # Save sequences
            sequences_path = os.path.join(self.config["data"]["output_dir"], "token_sequences.json")
            with open(sequences_path, 'w') as f:
                json.dump(token_sequences, f, indent=2)
            
            return token_sequences
            
        except Exception as e:
            logger.error(f"❌ Sequence preparation failed: {e}")
            raise
    
    def step4_train_model(self, token_sequences: List[List[str]]):
        """Step 4: Train LogBERT model"""
        logger.info("🧠 Step 4: Training LogBERT model...")
        
        try:
            # Create model and tokenizer
            self.model, self.tokenizer = create_model_and_tokenizer(token_sequences)
            
            # Update model config from pipeline config
            model_config = self.config["model"]
            self.model.config.hidden_size = model_config.get("hidden_size", 256)
            self.model.config.num_attention_heads = model_config.get("num_attention_heads", 8)
            self.model.config.num_hidden_layers = model_config.get("num_hidden_layers", 4)
            
            # Recreate model with updated config
            self.model = LogBERTModel(self.model.config)
            
            logger.info(f"Model created: {sum(p.numel() for p in self.model.parameters()):,} parameters")
            
            # Prepare training data
            encoded_sequences = [self.tokenizer.encode(seq) for seq in token_sequences]
            
            # Create dataset
            dataset = LogSequenceDataset(
                sequences=encoded_sequences,
                tokenizer=self.tokenizer,
                max_length=self.config["model"]["sequence_length"],
                mask_prob=self.config["model"]["mask_probability"]
            )
            
            # Split dataset
            train_size = int(len(dataset) * (1 - self.config["training"]["validation_split"]))
            val_size = len(dataset) - train_size
            train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
            
            # Create data loaders
            train_loader = DataLoader(
                train_dataset, 
                batch_size=self.config["training"]["batch_size"],
                shuffle=True,
                num_workers=0  # Set to 0 to avoid multiprocessing issues
            )
            
            val_loader = DataLoader(
                val_dataset,
                batch_size=self.config["training"]["batch_size"],
                shuffle=False,
                num_workers=0
            )
            
            logger.info(f"Training set: {len(train_dataset)} samples")
            logger.info(f"Validation set: {len(val_dataset)} samples")
            
            # Initialize trainer
            self.trainer = LogBERTTrainer(self.model, self.tokenizer)
            
            # Train model
            training_config = self.config["training"]
            history = self.trainer.fit(
                train_dataloader=train_loader,
                val_dataloader=val_loader,
                epochs=training_config["epochs"],
                lr=training_config["learning_rate"]
            )
            
            logger.info("✅ Model training completed")
            return history
            
        except Exception as e:
            logger.error(f"❌ Model training failed: {e}")
            raise
    
    def step5_export_model(self):
        """Step 5: Export model for production"""
        logger.info("📦 Step 5: Exporting model for production...")
        
        try:
            model_dir = self.config["inference"]["model_save_path"]
            
            # Save PyTorch model
            model_path = os.path.join(model_dir, "logbert_model.pt")
            self.trainer.save_model(model_path)
            logger.info(f"Saved PyTorch model to {model_path}")
            
            # Save tokenizer
            tokenizer_path = os.path.join(model_dir, "tokenizer.pkl")
            self.tokenizer.save(tokenizer_path)
            logger.info(f"Saved tokenizer to {tokenizer_path}")
            
            # Export to ONNX if requested
            if self.config["inference"]["export_onnx"]:
                onnx_path = os.path.join(model_dir, "logbert_model.onnx")
                self._export_onnx(onnx_path)
                logger.info(f"Exported ONNX model to {onnx_path}")
            
            # Save model config
            config_path = os.path.join(model_dir, "model_config.json")
            with open(config_path, 'w') as f:
                json.dump({
                    "vocab_size": self.tokenizer.vocab_size,
                    "hidden_size": self.model.config.hidden_size,
                    "num_attention_heads": self.model.config.num_attention_heads,
                    "num_hidden_layers": self.model.config.num_hidden_layers,
                    "max_position_embeddings": self.model.config.max_position_embeddings,
                    "anomaly_threshold": self.config["inference"]["anomaly_threshold"]
                }, f, indent=2)
            
            logger.info("✅ Model export completed")
            
        except Exception as e:
            logger.error(f"❌ Model export failed: {e}")
            raise
    
    def _export_onnx(self, onnx_path: str):
        """Export model to ONNX format"""
        try:
            # Create dummy input
            batch_size = 1
            seq_len = self.config["model"]["sequence_length"]
            
            dummy_input_ids = torch.randint(0, self.tokenizer.vocab_size, (batch_size, seq_len))
            dummy_attention_mask = torch.ones(batch_size, seq_len)
            
            # Export model
            torch.onnx.export(
                self.model,
                (dummy_input_ids, dummy_attention_mask),
                onnx_path,
                export_params=True,
                opset_version=11,
                do_constant_folding=True,
                input_names=['input_ids', 'attention_mask'],
                output_names=['anomaly_scores'],
                dynamic_axes={
                    'input_ids': {0: 'batch_size'},
                    'attention_mask': {0: 'batch_size'},
                    'anomaly_scores': {0: 'batch_size'}
                }
            )
            
        except Exception as e:
            logger.warning(f"ONNX export failed: {e}")
    
    def _check_applications_running(self):
        """Check if web applications are running"""
        import requests
        
        apps = [
            ("E-commerce", "http://localhost:8080/ecommerce/"),
            ("REST API", "http://localhost:8080/rest-api/")
        ]
        
        for name, url in apps:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    logger.info(f"✅ {name} application is running")
                else:
                    logger.warning(f"⚠️ {name} application returned {response.status_code}")
            except Exception as e:
                logger.warning(f"⚠️ {name} application not accessible: {e}")
    
    def run_full_pipeline(self):
        """Run the complete training pipeline"""
        start_time = time.time()
        logger.info("🎯 Starting WAF Training Pipeline")
        
        try:
            # Step 1: Generate benign traffic
            self.step1_generate_traffic()
            
            # Step 2: Parse and normalize logs
            events = self.step2_parse_logs()
            
            # Step 3: Prepare token sequences
            token_sequences = self.step3_prepare_sequences(events)
            
            # Step 4: Train model
            history = self.step4_train_model(token_sequences)
            
            # Step 5: Export model
            self.step5_export_model()
            
            # Complete
            duration = time.time() - start_time
            logger.info(f"🎉 Pipeline completed successfully in {duration:.2f} seconds")
            
            # Print summary
            self._print_summary(len(events), len(token_sequences), history)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Pipeline failed: {e}")
            return False
    
    def _print_summary(self, num_events: int, num_sequences: int, history: List[Dict]):
        """Print training summary"""
        print("\n" + "="*60)
        print("🛡️  WAF TRAINING PIPELINE SUMMARY")
        print("="*60)
        print(f"📊 Log Events Processed: {num_events:,}")
        print(f"🔤 Token Sequences: {num_sequences:,}")
        print(f"🧠 Model Parameters: {sum(p.numel() for p in self.model.parameters()):,}")
        print(f"📚 Vocabulary Size: {self.tokenizer.vocab_size:,}")
        
        if history:
            final_metrics = history[-1]
            print(f"\n📈 Training Results:")
            print(f"   Final Training Loss: {final_metrics.get('train_loss', 0):.4f}")
            print(f"   Final Validation Loss: {final_metrics.get('val_loss', 0):.4f}")
            print(f"   Epochs Completed: {len(history)}")
        
        print(f"\n📦 Model Artifacts:")
        print(f"   PyTorch Model: ./models/logbert_model.pt")
        print(f"   Tokenizer: ./models/tokenizer.pkl")
        print(f"   Model Config: ./models/model_config.json")
        
        print(f"\n🚀 Next Steps:")
        print(f"   1. Start inference service: python waf_inference_service.py")
        print(f"   2. Configure Nginx integration")
        print(f"   3. Test with malicious requests")
        print("="*60)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="WAF Training Pipeline")
    parser.add_argument("--config", type=str, help="Configuration file path")
    parser.add_argument("--skip-traffic", action="store_true", help="Skip traffic generation")
    parser.add_argument("--dry-run", action="store_true", help="Dry run without training")
    
    args = parser.parse_args()
    
    # Create pipeline
    pipeline = WAFTrainingPipeline(args.config)
    
    # Override config if needed
    if args.skip_traffic:
        pipeline.config["data"]["synthetic_traffic"] = False
    
    if args.dry_run:
        logger.info("Dry run mode - training pipeline setup verified")
        return
    
    # Run pipeline
    success = pipeline.run_full_pipeline()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
