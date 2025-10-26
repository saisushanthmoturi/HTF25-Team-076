#!/usr/bin/env python3
"""
Advanced Multi-Model Ensemble System
====================================
Combines multiple ML models for superior anomaly detection accuracy
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import joblib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import logging
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class AdvancedAutoEncoder(nn.Module):
    """Deep Autoencoder for anomaly detection"""
    
    def __init__(self, input_dim: int, hidden_dims: List[int] = [64, 32, 16]):
        super(AdvancedAutoEncoder, self).__init__()
        
        # Encoder
        encoder_layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.1)
            ])
            prev_dim = hidden_dim
        
        # Bottleneck
        encoder_layers.append(nn.Linear(prev_dim, hidden_dims[-1] // 2))
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Decoder
        decoder_layers = []
        hidden_dims_rev = [hidden_dims[-1] // 2] + hidden_dims[::-1] + [input_dim]
        
        for i in range(len(hidden_dims_rev) - 1):
            decoder_layers.extend([
                nn.Linear(hidden_dims_rev[i], hidden_dims_rev[i + 1]),
                nn.ReLU() if i < len(hidden_dims_rev) - 2 else nn.Identity()
            ])
            if i < len(hidden_dims_rev) - 2:
                decoder_layers.append(nn.Dropout(0.1))
        
        self.decoder = nn.Sequential(*decoder_layers)
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        return self.encoder(x)

class AdvancedEnsembleDetector:
    """Advanced ensemble anomaly detector using multiple ML models"""
    
    def __init__(self, model_dir: str = "models/ensemble"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize autoencoder components
        self.autoencoder = None
        self.autoencoder_optimizer = None
        self.autoencoder_loss_fn = None
        
        # Initialize models
        self.models = {
            'isolation_forest': IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=200,
                max_samples='auto',
                bootstrap=True
            ),
            'one_class_svm': OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=0.1
            ),
            'local_outlier_factor': LocalOutlierFactor(
                n_neighbors=20,
                contamination=0.1,
                novelty=True
            ),
            'autoencoder': None  # Will be initialized after seeing data
        }
        
        # Scalers for different models
        self.scalers = {
            'standard': StandardScaler(),
            'robust': RobustScaler()
        }
        
        # PCA for dimensionality reduction
        self.pca = PCA(n_components=0.95)
        
        # Model weights for ensemble voting
        self.model_weights = {
            'isolation_forest': 0.3,
            'one_class_svm': 0.25,
            'local_outlier_factor': 0.25,
            'autoencoder': 0.2
        }
        
        # Performance tracking
        self.performance_history = {
            'accuracy': [],
            'precision': [],
            'recall': [],
            'f1_score': [],
            'timestamps': []
        }
        
        # Feature importance tracking
        self.feature_importance = {}
        
        # Training status
        self.is_trained = False
        self.last_training_time = None
        self.training_samples_count = 0

    def prepare_features(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Advanced feature preparation with multiple scaling strategies"""
        
        # Extract numerical features
        numerical_features = data.select_dtypes(include=[np.number]).values
        
        # Apply robust scaling for outlier resistance
        scaled_features_robust = self.scalers['robust'].fit_transform(numerical_features)
        
        # Apply standard scaling for normal distribution assumption
        scaled_features_standard = self.scalers['standard'].fit_transform(numerical_features)
        
        # Apply PCA for dimensionality reduction
        pca_features = self.pca.fit_transform(scaled_features_standard)
        
        return scaled_features_robust, pca_features

    def initialize_autoencoder(self, input_dim: int):
        """Initialize autoencoder based on input dimensions"""
        self.autoencoder = AdvancedAutoEncoder(input_dim)
        self.autoencoder_optimizer = optim.Adam(self.autoencoder.parameters(), lr=0.001)
        self.autoencoder_loss_fn = nn.MSELoss()
        
        # Add to models dict
        self.models['autoencoder'] = self.autoencoder

    def train_autoencoder(self, data: np.ndarray, epochs: int = 100, batch_size: int = 32):
        """Train the autoencoder component"""
        if self.autoencoder is None:
            self.initialize_autoencoder(data.shape[1])
        
        # Prepare data
        tensor_data = torch.FloatTensor(data)
        dataset = TensorDataset(tensor_data, tensor_data)  # Autoencoder: input = target
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        # Training loop
        self.autoencoder.train()
        for epoch in range(epochs):
            epoch_loss = 0.0
            
            for batch_data, _ in dataloader:
                self.autoencoder_optimizer.zero_grad()
                reconstructed = self.autoencoder(batch_data)
                loss = self.autoencoder_loss_fn(reconstructed, batch_data)
                loss.backward()
                self.autoencoder_optimizer.step()
                epoch_loss += loss.item()
            
            if epoch % 20 == 0:
                avg_loss = epoch_loss / len(dataloader)
                self.logger.info(f"Autoencoder Epoch {epoch}/{epochs}, Loss: {avg_loss:.4f}")

    def fit(self, data: pd.DataFrame, normal_samples_only: bool = True):
        """Train all ensemble models"""
        try:
            self.logger.info("Starting advanced ensemble model training...")
            
            # Prepare features
            robust_features, pca_features = self.prepare_features(data)
            
            # Initialize autoencoder first
            if self.autoencoder is None:
                self.initialize_autoencoder(pca_features.shape[1])
            
            # Train traditional ML models
            self.models['isolation_forest'].fit(robust_features)
            self.models['one_class_svm'].fit(robust_features)
            self.models['local_outlier_factor'].fit(robust_features)
            
            # Train autoencoder
            self.train_autoencoder(pca_features, epochs=50)  # Reduce epochs for demo
            
            # Update training status
            self.is_trained = True
            self.last_training_time = datetime.now()
            self.training_samples_count = len(data)
            
            # Calculate and store feature importance
            self._calculate_feature_importance(data, robust_features)
            
            # Save models
            self.save_models()
            
            self.logger.info(f"Ensemble training completed with {len(data)} samples")
            
        except Exception as e:
            self.logger.error(f"Error training ensemble models: {e}")
            raise

    def _calculate_feature_importance(self, original_data: pd.DataFrame, features: np.ndarray):
        """Calculate feature importance from ensemble models"""
        try:
            # Get feature names
            feature_names = original_data.select_dtypes(include=[np.number]).columns.tolist()
            
            # Isolation Forest feature importance (based on path lengths)
            if hasattr(self.models['isolation_forest'], 'score_samples'):
                scores = self.models['isolation_forest'].score_samples(features)
                # Simple importance based on variance in scores
                importance_scores = np.var(scores.reshape(-1, 1) * features, axis=0)
                
                self.feature_importance = {
                    name: float(score) for name, score in zip(feature_names, importance_scores)
                }
                
                # Normalize importance scores
                total_importance = sum(self.feature_importance.values())
                if total_importance > 0:
                    self.feature_importance = {
                        k: v / total_importance for k, v in self.feature_importance.items()
                    }
            
        except Exception as e:
            self.logger.error(f"Error calculating feature importance: {e}")

    def predict(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """Make predictions using ensemble voting"""
        if not self.is_trained:
            raise ValueError("Models must be trained before making predictions")
        
        try:
            # Prepare features using the same scalers and PCA from training
            numerical_features = data.select_dtypes(include=[np.number]).values
            robust_features = self.scalers['robust'].transform(numerical_features)
            standard_features = self.scalers['standard'].transform(numerical_features)
            pca_features = self.pca.transform(standard_features)
            
            # Get predictions from each model
            predictions = {}
            prediction_scores = {}
            
            # Traditional ML models
            predictions['isolation_forest'] = self.models['isolation_forest'].predict(robust_features)
            prediction_scores['isolation_forest'] = self.models['isolation_forest'].score_samples(robust_features)
            
            predictions['one_class_svm'] = self.models['one_class_svm'].predict(robust_features)
            prediction_scores['one_class_svm'] = self.models['one_class_svm'].score_samples(robust_features)
            
            predictions['local_outlier_factor'] = self.models['local_outlier_factor'].predict(robust_features)
            prediction_scores['local_outlier_factor'] = self.models['local_outlier_factor'].score_samples(robust_features)
            
            # Autoencoder predictions
            if self.autoencoder is not None:
                with torch.no_grad():
                    self.autoencoder.eval()
                    tensor_data = torch.FloatTensor(pca_features)
                    reconstructed = self.autoencoder(tensor_data)
                    reconstruction_errors = torch.mean((tensor_data - reconstructed) ** 2, dim=1).numpy()
                    
                    # Convert reconstruction errors to predictions (-1 for anomaly, 1 for normal)
                    threshold = np.percentile(reconstruction_errors, 90)  # Top 10% as anomalies
                    predictions['autoencoder'] = np.where(reconstruction_errors > threshold, -1, 1)
                    prediction_scores['autoencoder'] = -reconstruction_errors  # Negative for consistency
            
            # Ensemble voting
            ensemble_predictions = self._ensemble_vote(predictions)
            ensemble_scores = self._ensemble_score(prediction_scores)
            
            # Additional metrics
            model_agreement = self._calculate_model_agreement(predictions)
            confidence_scores = self._calculate_confidence(prediction_scores, ensemble_scores)
            
            detailed_results = {
                'individual_predictions': predictions,
                'individual_scores': prediction_scores,
                'model_agreement': model_agreement,
                'confidence_scores': confidence_scores,
                'feature_importance': self.feature_importance
            }
            
            return ensemble_predictions, ensemble_scores, detailed_results
            
        except Exception as e:
            self.logger.error(f"Error making ensemble predictions: {e}")
            raise

    def _ensemble_vote(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Combine predictions using weighted voting"""
        total_votes = np.zeros(len(list(predictions.values())[0]))
        
        for model_name, preds in predictions.items():
            weight = self.model_weights.get(model_name, 0.25)
            # Convert -1/1 to 0/1 for voting
            binary_preds = (preds == -1).astype(int)
            total_votes += weight * binary_preds
        
        # Final prediction: -1 if weighted vote > 0.5, else 1
        return np.where(total_votes > 0.5, -1, 1)

    def _ensemble_score(self, scores: Dict[str, np.ndarray]) -> np.ndarray:
        """Combine scores using weighted averaging"""
        total_scores = np.zeros(len(list(scores.values())[0]))
        
        for model_name, score_array in scores.items():
            weight = self.model_weights.get(model_name, 0.25)
            # Normalize scores to [0, 1] range
            normalized_scores = (score_array - score_array.min()) / (score_array.max() - score_array.min())
            total_scores += weight * normalized_scores
        
        return total_scores

    def _calculate_model_agreement(self, predictions: Dict[str, np.ndarray]) -> float:
        """Calculate agreement between models"""
        pred_matrix = np.array(list(predictions.values()))
        
        # Count agreements for each sample
        agreements = []
        for i in range(pred_matrix.shape[1]):
            sample_preds = pred_matrix[:, i]
            agreement = np.sum(sample_preds == sample_preds[0]) / len(sample_preds)
            agreements.append(agreement)
        
        return np.mean(agreements)

    def _calculate_confidence(self, individual_scores: Dict[str, np.ndarray], 
                            ensemble_scores: np.ndarray) -> np.ndarray:
        """Calculate prediction confidence based on score consistency"""
        score_matrix = np.array(list(individual_scores.values()))
        
        # Calculate coefficient of variation for each sample
        confidence_scores = []
        for i in range(score_matrix.shape[1]):
            sample_scores = score_matrix[:, i]
            cv = np.std(sample_scores) / (np.mean(np.abs(sample_scores)) + 1e-8)
            confidence = 1.0 / (1.0 + cv)  # Lower variation = higher confidence
            confidence_scores.append(confidence)
        
        return np.array(confidence_scores)

    def update_model_weights(self, performance_feedback: Dict[str, float]):
        """Update model weights based on performance feedback"""
        try:
            for model_name, performance in performance_feedback.items():
                if model_name in self.model_weights:
                    # Adjust weight based on performance (0.0 to 1.0)
                    self.model_weights[model_name] *= (0.5 + performance)
            
            # Normalize weights
            total_weight = sum(self.model_weights.values())
            self.model_weights = {
                k: v / total_weight for k, v in self.model_weights.items()
            }
            
            self.logger.info(f"Updated model weights: {self.model_weights}")
            
        except Exception as e:
            self.logger.error(f"Error updating model weights: {e}")

    def get_performance_summary(self) -> Dict:
        """Get performance summary of the ensemble"""
        return {
            'is_trained': self.is_trained,
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'training_samples_count': self.training_samples_count,
            'model_weights': self.model_weights,
            'feature_importance': self.feature_importance,
            'performance_history': self.performance_history
        }

    def save_models(self):
        """Save all trained models"""
        try:
            # Save traditional ML models
            joblib.dump(self.models['isolation_forest'], 
                       self.model_dir / 'isolation_forest.pkl')
            joblib.dump(self.models['one_class_svm'], 
                       self.model_dir / 'one_class_svm.pkl')
            joblib.dump(self.models['local_outlier_factor'], 
                       self.model_dir / 'local_outlier_factor.pkl')
            
            # Save scalers and PCA
            joblib.dump(self.scalers, self.model_dir / 'scalers.pkl')
            joblib.dump(self.pca, self.model_dir / 'pca.pkl')
            
            # Save autoencoder
            if self.autoencoder is not None:
                torch.save(self.autoencoder.state_dict(), 
                          self.model_dir / 'autoencoder.pth')
            
            # Save metadata
            metadata = {
                'model_weights': self.model_weights,
                'feature_importance': self.feature_importance,
                'training_samples_count': self.training_samples_count,
                'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None
            }
            
            with open(self.model_dir / 'ensemble_metadata.json', 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info("All ensemble models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")

    def load_models(self):
        """Load all trained models"""
        try:
            # Load traditional ML models
            self.models['isolation_forest'] = joblib.load(
                self.model_dir / 'isolation_forest.pkl')
            self.models['one_class_svm'] = joblib.load(
                self.model_dir / 'one_class_svm.pkl')
            self.models['local_outlier_factor'] = joblib.load(
                self.model_dir / 'local_outlier_factor.pkl')
            
            # Load scalers and PCA
            self.scalers = joblib.load(self.model_dir / 'scalers.pkl')
            self.pca = joblib.load(self.model_dir / 'pca.pkl')
            
            # Load autoencoder
            autoencoder_path = self.model_dir / 'autoencoder.pth'
            if autoencoder_path.exists():
                # We need to know the input dimension to recreate the model
                # For now, we'll recreate with a standard dimension
                self.initialize_autoencoder(self.pca.n_components_)
                self.autoencoder.load_state_dict(torch.load(autoencoder_path))
            
            # Load metadata
            metadata_path = self.model_dir / 'ensemble_metadata.json'
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    self.model_weights = metadata.get('model_weights', self.model_weights)
                    self.feature_importance = metadata.get('feature_importance', {})
                    self.training_samples_count = metadata.get('training_samples_count', 0)
                    
                    last_training = metadata.get('last_training_time')
                    if last_training:
                        self.last_training_time = datetime.fromisoformat(last_training)
            
            self.is_trained = True
            self.logger.info("All ensemble models loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")

# Example usage and testing
def main():
    """Test the advanced ensemble detector"""
    print("🤖 Advanced Multi-Model Ensemble Detector")
    print("=" * 50)
    
    # Create sample data
    np.random.seed(42)
    n_samples = 1000
    n_features = 20
    
    # Normal data
    normal_data = np.random.normal(0, 1, (int(n_samples * 0.9), n_features))
    
    # Anomalous data
    anomaly_data = np.random.normal(3, 1.5, (int(n_samples * 0.1), n_features))
    
    # Combine data
    all_data = np.vstack([normal_data, anomaly_data])
    labels = np.hstack([np.ones(len(normal_data)), -np.ones(len(anomaly_data))])
    
    # Create DataFrame
    feature_names = [f'feature_{i}' for i in range(n_features)]
    df = pd.DataFrame(all_data, columns=feature_names)
    
    # Initialize detector
    detector = AdvancedEnsembleDetector()
    
    # Train on normal data only
    normal_df = df[labels == 1]
    print(f"Training on {len(normal_df)} normal samples...")
    detector.fit(normal_df)
    
    # Make predictions on all data
    print("Making predictions...")
    predictions, scores, detailed_results = detector.predict(df)
    
    # Evaluate performance
    accuracy = np.mean(predictions == labels)
    anomalies_detected = np.sum(predictions == -1)
    true_anomalies = np.sum(labels == -1)
    
    print(f"\n📊 Performance Results:")
    print(f"   Overall Accuracy: {accuracy:.3f}")
    print(f"   Anomalies Detected: {anomalies_detected}/{len(df)}")
    print(f"   True Anomalies: {true_anomalies}")
    print(f"   Model Agreement: {detailed_results['model_agreement']:.3f}")
    
    # Show individual model predictions
    print(f"\n🔍 Individual Model Results:")
    for model_name, preds in detailed_results['individual_predictions'].items():
        model_accuracy = np.mean(preds == labels)
        anomalies_found = np.sum(preds == -1)
        print(f"   {model_name}: Accuracy {model_accuracy:.3f}, Anomalies {anomalies_found}")
    
    # Show feature importance
    print(f"\n📈 Top Feature Importance:")
    importance_items = sorted(detailed_results['feature_importance'].items(), 
                            key=lambda x: x[1], reverse=True)
    for feature, importance in importance_items[:5]:
        print(f"   {feature}: {importance:.4f}")
    
    # Performance summary
    print(f"\n⚙️ System Summary:")
    summary = detector.get_performance_summary()
    print(f"   Training Samples: {summary['training_samples_count']}")
    print(f"   Model Weights: {summary['model_weights']}")

if __name__ == "__main__":
    main()
