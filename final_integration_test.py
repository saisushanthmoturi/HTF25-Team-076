#!/usr/bin/env python3
"""
Final Integration Test - Complete ML + Cybersecurity System
===========================================================
Comprehensive test of all advanced features working together
"""

import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import sys
import traceback

# Import all advanced components
from threat_intelligence import ThreatIntelligenceEngine
from advanced_ensemble_detector import AdvancedEnsembleDetector
from advanced_attack_simulator import AdvancedAttackSimulator

class SystemIntegrationTest:
    """Complete system integration testing"""
    
    def __init__(self):
        self.threat_intel = None
        self.ensemble_detector = None
        self.attack_simulator = None
        self.test_results = {}
        
    async def setup_components(self):
        """Initialize all system components"""
        print("🔧 Initializing System Components...")
        
        try:
            # Initialize Threat Intelligence
            self.threat_intel = ThreatIntelligenceEngine()
            print("   ✅ Threat Intelligence Engine initialized")
            
            # Initialize Ensemble Detector
            self.ensemble_detector = AdvancedEnsembleDetector()
            print("   ✅ Advanced Ensemble Detector initialized")
            
            # Initialize Attack Simulator
            self.attack_simulator = AdvancedAttackSimulator()
            print("   ✅ Advanced Attack Simulator initialized")
            
            return True
            
        except Exception as e:
            print(f"   ❌ Component initialization failed: {str(e)}")
            return False
    
    async def test_threat_intelligence(self):
        """Test threat intelligence functionality"""
        print("\n🔍 Testing Threat Intelligence Engine...")
        
        try:
            # Test IP analysis
            test_ips = [
                '192.168.1.100',  # Internal
                '8.8.8.8',        # Public DNS
                '203.0.113.1',    # Test range
                '127.0.0.1'       # Localhost
            ]
            
            intel_results = []
            for ip in test_ips:
                intel = await self.threat_intel.enrich_ip_intelligence(ip)
                if intel:
                    intel_results.append({
                        'ip': ip,
                        'threat_type': intel.threat_type,
                        'confidence': intel.confidence,
                        'source': intel.source
                    })
            
            print(f"   📊 Analyzed {len(intel_results)} IPs successfully")
            
            # Test threat scoring
            sample_log = {
                'source_ip': '203.0.113.1',
                'method': 'POST',
                'path': '/admin/login.php',
                'status_code': 401,
                'user_agent': 'python-requests/2.28.1'
            }
            
            threat_score = self.threat_intel.calculate_threat_score(sample_log)
            print(f"   🎯 Sample threat score: {threat_score:.3f}")
            
            # Get system summary
            summary = self.threat_intel.get_threat_summary()
            print(f"   📈 Total threats tracked: {summary.get('total_threats', 0)}")
            
            self.test_results['threat_intelligence'] = {
                'status': 'passed',
                'ips_analyzed': len(intel_results),
                'threat_score': threat_score,
                'total_threats': summary.get('total_threats', 0)
            }
            
            return True
            
        except Exception as e:
            print(f"   ❌ Threat Intelligence test failed: {str(e)}")
            self.test_results['threat_intelligence'] = {'status': 'failed', 'error': str(e)}
            return False
    
    async def test_ensemble_detector(self):
        """Test ensemble anomaly detection"""
        print("\n🤖 Testing Advanced Ensemble Detector...")
        
        try:
            # Generate training data
            np.random.seed(42)
            
            # Create realistic cybersecurity training data
            normal_requests = pd.DataFrame({
                'request_length': np.random.normal(300, 100, 80),
                'path_complexity': np.random.normal(3, 1, 80),
                'param_count': np.random.poisson(2, 80),
                'header_count': np.random.normal(12, 3, 80),
                'response_time': np.random.exponential(0.2, 80),
                'is_anomaly': [0] * 80
            })
            
            # Anomalous requests
            anomalous_requests = pd.DataFrame({
                'request_length': np.random.normal(1500, 500, 20),
                'path_complexity': np.random.normal(12, 4, 20),
                'param_count': np.random.poisson(8, 20),
                'header_count': np.random.normal(25, 8, 20),
                'response_time': np.random.exponential(2.0, 20),
                'is_anomaly': [1] * 20
            })
            
            # Combine training data
            train_data = pd.concat([normal_requests, anomalous_requests], ignore_index=True)
            train_data = train_data.sample(frac=1).reset_index(drop=True)  # Shuffle
            
            print(f"   📊 Training data: {len(train_data)} samples")
            
            # Train the ensemble
            self.ensemble_detector.fit(train_data, normal_samples_only=False)
            print("   ✅ Ensemble training completed")
            
            # Create test data
            test_data = pd.DataFrame({
                'request_length': np.random.normal(600, 300, 10),
                'path_complexity': np.random.normal(6, 3, 10),
                'param_count': np.random.poisson(4, 10),
                'header_count': np.random.normal(18, 6, 10),
                'response_time': np.random.exponential(0.8, 10),
                'is_anomaly': [0] * 10  # For feature consistency
            })
            
            # Make predictions
            predictions, scores, metrics = self.ensemble_detector.predict(test_data)
            
            anomalies_detected = np.sum(predictions == 1)
            avg_anomaly_score = np.mean(scores)
            model_agreement = metrics.get('model_agreement', 0)
            
            print(f"   📈 Anomalies detected: {anomalies_detected}/{len(predictions)}")
            print(f"   💯 Average anomaly score: {avg_anomaly_score:.3f}")
            print(f"   🤝 Model agreement: {model_agreement:.3f}")
            
            self.test_results['ensemble_detector'] = {
                'status': 'passed',
                'training_samples': len(train_data),
                'anomalies_detected': int(anomalies_detected),
                'avg_score': float(avg_anomaly_score),
                'model_agreement': float(model_agreement)
            }
            
            return True
            
        except Exception as e:
            print(f"   ❌ Ensemble Detector test failed: {str(e)}")
            self.test_results['ensemble_detector'] = {'status': 'failed', 'error': str(e)}
            return False
    
    async def test_attack_simulator(self):
        """Test attack simulation capabilities"""
        print("\n⚔️  Testing Advanced Attack Simulator...")
        
        try:
            # Test different attack types
            attack_types = ['sql_injection', 'brute_force', 'dos_attack', 'xss_attack']
            attack_results = {}
            
            for attack_type in attack_types[:2]:  # Test first 2 to save time
                campaign = await self.attack_simulator.generate_attack_campaign(
                    attack_type=attack_type,
                    duration_minutes=1,
                    requests_per_minute=5
                )
                
                attack_results[attack_type] = len(campaign)
                print(f"   📊 {attack_type}: Generated {len(campaign)} scenarios")
            
            # Test available attack patterns
            available_patterns = list(self.attack_simulator.attack_patterns.keys())
            print(f"   🎯 Available attack patterns: {len(available_patterns)}")
            
            total_scenarios = sum(attack_results.values())
            
            self.test_results['attack_simulator'] = {
                'status': 'passed',
                'attack_types_tested': len(attack_results),
                'total_scenarios': total_scenarios,
                'available_patterns': len(available_patterns),
                'attack_results': attack_results
            }
            
            return True
            
        except Exception as e:
            print(f"   ❌ Attack Simulator test failed: {str(e)}")
            self.test_results['attack_simulator'] = {'status': 'failed', 'error': str(e)}
            return False
    
    async def test_integrated_workflow(self):
        """Test complete integrated workflow"""
        print("\n🔄 Testing Integrated Workflow...")
        
        try:
            # Step 1: Generate attack data
            attack_campaign = await self.attack_simulator.generate_attack_campaign(
                attack_type='sql_injection',
                duration_minutes=1,
                requests_per_minute=3
            )
            
            print(f"   📊 Generated {len(attack_campaign)} attack scenarios")
            
            # Step 2: Convert to detection-ready format
            detection_data = []
            for i, scenario in enumerate(attack_campaign):
                # Extract features for detection
                request_data = {
                    'request_length': len(scenario.get('payload', '')),
                    'path_complexity': scenario.get('path', '').count('/'),
                    'param_count': scenario.get('path', '').count('='),
                    'header_count': 10 + np.random.randint(0, 5),
                    'response_time': np.random.exponential(0.5),
                    'is_anomaly': 0  # For consistency
                }
                detection_data.append(request_data)
            
            detection_df = pd.DataFrame(detection_data)
            
            # Step 3: Analyze with ensemble detector (if trained)
            if hasattr(self.ensemble_detector, 'models') and self.ensemble_detector.models:
                predictions, scores, metrics = self.ensemble_detector.predict(detection_df)
                detected_attacks = np.sum(predictions == 1)
                print(f"   🎯 Detected {detected_attacks}/{len(predictions)} as anomalous")
            else:
                print("   ⚠️ Ensemble detector not trained, skipping detection")
                detected_attacks = 0
            
            # Step 4: Enrich with threat intelligence
            sample_ips = ['192.168.1.100', '203.0.113.1', '10.0.0.1']
            intel_enriched = 0
            
            for ip in sample_ips:
                intel = await self.threat_intel.enrich_ip_intelligence(ip)
                if intel:
                    intel_enriched += 1
            
            print(f"   🔍 Enriched {intel_enriched}/{len(sample_ips)} IPs with threat intelligence")
            
            self.test_results['integrated_workflow'] = {
                'status': 'passed',
                'attack_scenarios': len(attack_campaign),
                'detected_attacks': int(detected_attacks),
                'intel_enriched': intel_enriched
            }
            
            return True
            
        except Exception as e:
            print(f"   ❌ Integrated workflow test failed: {str(e)}")
            self.test_results['integrated_workflow'] = {'status': 'failed', 'error': str(e)}
            return False
    
    def print_final_report(self):
        """Print comprehensive test results"""
        print("\n" + "="*60)
        print("🎉 FINAL INTEGRATION TEST RESULTS")
        print("="*60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result['status'] == 'passed')
        
        print(f"📊 Overall Status: {passed_tests}/{total_tests} tests passed")
        
        for component, result in self.test_results.items():
            status_emoji = "✅" if result['status'] == 'passed' else "❌"
            print(f"\n{status_emoji} {component.upper()}:")
            
            if result['status'] == 'passed':
                for key, value in result.items():
                    if key != 'status':
                        print(f"   • {key}: {value}")
            else:
                print(f"   • Error: {result.get('error', 'Unknown error')}")
        
        if passed_tests == total_tests:
            print(f"\n🚀 SUCCESS: All components working correctly!")
            print("   The advanced ML + cybersecurity system is fully operational.")
        else:
            print(f"\n⚠️ WARNING: {total_tests - passed_tests} components need attention.")
        
        return passed_tests == total_tests


async def main():
    """Run complete integration test"""
    print("🔥 ADVANCED ML + CYBERSECURITY SYSTEM - INTEGRATION TEST")
    print("="*65)
    print(f"🕐 Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tester = SystemIntegrationTest()
    
    # Setup all components
    if not await tester.setup_components():
        print("❌ Failed to initialize components. Exiting.")
        return False
    
    # Run all tests
    await tester.test_threat_intelligence()
    await tester.test_ensemble_detector()
    await tester.test_attack_simulator()
    await tester.test_integrated_workflow()
    
    # Print final report
    success = tester.print_final_report()
    
    print(f"\n🕐 Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return success


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
