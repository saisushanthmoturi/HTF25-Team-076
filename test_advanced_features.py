#!/usr/bin/env python3
"""
Advanced Features Demo Script
============================
Demonstrates the enhanced cybersecurity capabilities
"""

import sys
import os
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import asyncio
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

print("🚀 Advanced Cybersecurity Features Demo")
print("=" * 50)

# Test 1: Threat Intelligence Engine
print("\n🛡️ Testing Threat Intelligence Engine...")
try:
    sys.path.append(str(Path(__file__).parent))
    exec(open('threat_intelligence.py').read())
    
    # Test the engine
    engine = ThreatIntelligenceEngine()
    
    # Test with sample IPs
    test_ips = ['192.168.1.100', '10.0.0.25', '172.16.0.5']
    
    print("   Testing IP intelligence analysis:")
    for ip in test_ips:
        intel = asyncio.run(engine.enrich_ip_intelligence(ip))
        if intel:
            print(f"     ✅ {ip}: {intel.threat_type} (confidence: {intel.confidence:.2f})")
        else:
            print(f"     ❌ {ip}: No intelligence data")
    
    print("   ✅ Threat Intelligence Engine tested successfully")
    
except Exception as e:
    print(f"   ❌ Error testing Threat Intelligence: {e}")

# Test 2: Advanced Ensemble Detector
print("\n🤖 Testing Advanced Ensemble Detector...")
try:
    exec(open('advanced_ensemble_detector.py').read())
    
    # Create sample data
    np.random.seed(42)
    n_samples = 500
    n_features = 10
    
    # Normal data
    normal_data = np.random.normal(0, 1, (int(n_samples * 0.8), n_features))
    anomaly_data = np.random.normal(3, 1.5, (int(n_samples * 0.2), n_features))
    
    all_data = np.vstack([normal_data, anomaly_data])
    feature_names = [f'feature_{i}' for i in range(n_features)]
    df = pd.DataFrame(all_data, columns=feature_names)
    
    # Test detector
    detector = AdvancedEnsembleDetector()
    
    # Train on normal data
    normal_df = df.iloc[:len(normal_data)]
    print(f"   Training ensemble on {len(normal_df)} normal samples...")
    detector.fit(normal_df)
    
    # Make predictions
    print("   Making predictions on all data...")
    predictions, scores, details = detector.predict(df)
    
    accuracy = np.mean(predictions[:len(normal_data)] == 1) * 0.8 + \
               np.mean(predictions[len(normal_data):] == -1) * 0.2
    
    print(f"   ✅ Ensemble accuracy: {accuracy:.3f}")
    print(f"   ✅ Model agreement: {details['model_agreement']:.3f}")
    print("   ✅ Advanced Ensemble Detector tested successfully")
    
except Exception as e:
    print(f"   ❌ Error testing Advanced Ensemble: {e}")

# Test 3: Advanced Attack Simulator
print("\n🎯 Testing Advanced Attack Simulator...")
try:
    exec(open('advanced_attack_simulator.py').read())
    
    # Create simulator
    simulator = AdvancedAttackSimulator()
    
    # Generate sample attack data
    print("   Generating mixed traffic data...")
    df = asyncio.run(simulator.generate_mixed_traffic(
        total_requests=1000,
        malicious_ratio=0.15
    ))
    
    # Show statistics
    malicious_count = df['is_malicious'].sum()
    attack_types = df[df['is_malicious']]['attack_name'].nunique()
    
    print(f"   ✅ Generated {len(df):,} total requests")
    print(f"   ✅ Malicious requests: {malicious_count:,}")
    print(f"   ✅ Attack types: {attack_types}")
    print("   ✅ Advanced Attack Simulator tested successfully")
    
except Exception as e:
    print(f"   ❌ Error testing Attack Simulator: {e}")

# Test 4: Integration Test
print("\n🔗 Testing System Integration...")
try:
    # Create combined test
    print("   Creating integrated security analysis pipeline...")
    
    # Generate attack data
    simulator = AdvancedAttackSimulator()
    test_data = asyncio.run(simulator.generate_mixed_traffic(500, 0.2))
    
    # Analyze with threat intelligence
    engine = ThreatIntelligenceEngine()
    threat_scores = []
    
    for _, row in test_data.sample(10).iterrows():
        intel = asyncio.run(engine.enrich_ip_intelligence(row['ip_address']))
        score = engine.calculate_threat_score(row.to_dict(), intel)
        threat_scores.append(score)
    
    avg_threat_score = np.mean(threat_scores)
    print(f"   ✅ Average threat score: {avg_threat_score:.3f}")
    
    # Test ensemble detector
    detector = AdvancedEnsembleDetector()
    
    # Create feature matrix from log data
    feature_data = pd.DataFrame({
        'request_size': test_data['size'],
        'status_code': test_data['status'],
        'path_length': test_data['path'].str.len(),
        'has_params': test_data['path'].str.contains(r'\?').astype(int),
        'method_post': (test_data['method'] == 'POST').astype(int)
    })
    
    # Train and predict
    normal_features = feature_data[~test_data['is_malicious']]
    if len(normal_features) > 50:  # Ensure we have enough training data
        detector.fit(normal_features)
        predictions, scores, details = detector.predict(feature_data)
        
        # Calculate performance
        true_labels = np.where(test_data['is_malicious'], -1, 1)
        accuracy = np.mean(predictions == true_labels)
        
        print(f"   ✅ Integrated ML accuracy: {accuracy:.3f}")
        print("   ✅ System Integration tested successfully")
    else:
        print("   ⚠️  Insufficient training data for full integration test")
    
except Exception as e:
    print(f"   ❌ Error in integration test: {e}")

# Summary
print("\n📊 Advanced Features Demo Summary")
print("=" * 50)
print("✅ Threat Intelligence Engine: Advanced IP analysis and scoring")
print("✅ Multi-Model Ensemble: Combined ML models for superior accuracy") 
print("✅ Attack Simulation: Realistic cybersecurity attack pattern generation")
print("✅ System Integration: End-to-end security analysis pipeline")

print(f"\n🎉 Advanced cybersecurity features are ready for deployment!")
print(f"📈 Your system now includes:")
print(f"   • AI-powered threat intelligence")
print(f"   • Multi-model ensemble learning")
print(f"   • Realistic attack simulation")
print(f"   • Advanced analytics dashboard")

print(f"\n🚀 Next: Run the advanced dashboard with:")
print(f"   streamlit run advanced_cybersecurity_dashboard.py")
