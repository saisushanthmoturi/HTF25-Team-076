#!/usr/bin/env python3
"""
Attack Prevention Ratio Testing Script
=====================================
Tests various attack types and calculates prevention ratios
"""

import requests
import json
import time
from typing import Dict, List, Tuple
import statistics

class AttackPreventionTester:
    def __init__(self, waf_url: str = "http://localhost:8000"):
        self.waf_url = waf_url
        self.results = {
            'total_tests': 0,
            'attacks_blocked': 0,
            'attacks_missed': 0,
            'false_positives': 0,
            'legitimate_blocked': 0,
            'by_category': {}
        }
    
    def test_attack(self, ip: str, method: str, path: str, query_params: dict, 
                   expected_block: bool, attack_type: str) -> Tuple[bool, float, dict]:
        """Test a single attack and return (blocked, score, response)"""
        payload = {
            "ip": ip,
            "method": method,
            "path": path,
            "query_params": query_params
        }
        
        try:
            response = requests.post(f"{self.waf_url}/detect", 
                                   json=payload, timeout=5)
            if response.status_code == 200:
                result = response.json()
                is_blocked = result.get('is_anomalous', False)
                score = result.get('anomaly_score', 0.0)
                return is_blocked, score, result
            else:
                return False, 0.0, {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return False, 0.0, {"error": str(e)}
    
    def run_sql_injection_tests(self):
        """Test SQL injection attacks"""
        print("🧪 Testing SQL Injection Attacks...")
        sql_attacks = [
            ("' OR 1=1--", True, "Basic OR injection"),
            ("'; DROP TABLE users;--", True, "DROP table attack"),
            ("' UNION SELECT * FROM users--", True, "UNION injection"),
            ("admin'/*", True, "Comment injection"),
            ("1' AND (SELECT COUNT(*) FROM users) > 0--", True, "Subquery injection"),
            ("'; INSERT INTO users VALUES('hacker','pass');--", True, "INSERT injection")
        ]
        
        category_results = []
        for payload, should_block, description in sql_attacks:
            blocked, score, response = self.test_attack(
                "192.168.1.100", "GET", "/search", 
                {"q": payload}, should_block, "SQL Injection"
            )
            
            category_results.append({
                'payload': payload,
                'description': description,
                'expected_block': should_block,
                'actual_block': blocked,
                'score': score,
                'correct': blocked == should_block
            })
            
            print(f"   {description}: {'✅ BLOCKED' if blocked else '❌ ALLOWED'} (Score: {score:.3f})")
        
        self.results['by_category']['SQL Injection'] = category_results
        return category_results
    
    def run_xss_tests(self):
        """Test XSS attacks"""
        print("\n🧪 Testing XSS Attacks...")
        xss_attacks = [
            ("<script>alert('xss')</script>", True, "Basic script injection"),
            ("javascript:alert(1)", True, "JavaScript protocol"),
            ("<img src=x onerror=alert(1)>", True, "Event handler injection"),
            ("<svg onload=alert(1)>", True, "SVG injection"),
            ("'><script>alert(document.cookie)</script>", True, "Cookie stealing"),
            ("<iframe src=javascript:alert(1)>", True, "Iframe injection")
        ]
        
        category_results = []
        for payload, should_block, description in xss_attacks:
            blocked, score, response = self.test_attack(
                "192.168.1.101", "POST", "/comment", 
                {"content": payload}, should_block, "XSS"
            )
            
            category_results.append({
                'payload': payload,
                'description': description,
                'expected_block': should_block,
                'actual_block': blocked,
                'score': score,
                'correct': blocked == should_block
            })
            
            print(f"   {description}: {'✅ BLOCKED' if blocked else '❌ ALLOWED'} (Score: {score:.3f})")
        
        self.results['by_category']['XSS'] = category_results
        return category_results
    
    def run_path_traversal_tests(self):
        """Test path traversal attacks"""
        print("\n🧪 Testing Path Traversal Attacks...")
        path_attacks = [
            ("../../../etc/passwd", True, "Basic path traversal"),
            ("..\\..\\..\\windows\\system32\\config", True, "Windows path traversal"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", True, "URL encoded traversal"),
            ("....//....//....//etc/passwd", True, "Double dot traversal"),
            ("/var/www/../../etc/passwd", True, "Absolute path traversal"),
            ("file:///etc/passwd", True, "File protocol traversal")
        ]
        
        category_results = []
        for path, should_block, description in path_attacks:
            blocked, score, response = self.test_attack(
                "192.168.1.102", "GET", path, 
                {}, should_block, "Path Traversal"
            )
            
            category_results.append({
                'payload': path,
                'description': description,
                'expected_block': should_block,
                'actual_block': blocked,
                'score': score,
                'correct': blocked == should_block
            })
            
            print(f"   {description}: {'✅ BLOCKED' if blocked else '❌ ALLOWED'} (Score: {score:.3f})")
        
        self.results['by_category']['Path Traversal'] = category_results
        return category_results
    
    def run_legitimate_tests(self):
        """Test legitimate requests"""
        print("\n🧪 Testing Legitimate Requests...")
        legitimate_requests = [
            ("/", {}, "Homepage"),
            ("/products", {"category": "electronics"}, "Product search"),
            ("/api/users", {"limit": "10"}, "API call"),
            ("/login", {"username": "john.doe"}, "Login form"),
            ("/search", {"q": "laptop computers"}, "Normal search"),
            ("/contact", {"message": "Hello world"}, "Contact form")
        ]
        
        category_results = []
        for path, params, description in legitimate_requests:
            blocked, score, response = self.test_attack(
                "192.168.1.200", "GET", path, 
                params, False, "Legitimate"
            )
            
            category_results.append({
                'payload': f"{path}?{params}",
                'description': description,
                'expected_block': False,
                'actual_block': blocked,
                'score': score,
                'correct': blocked == False
            })
            
            print(f"   {description}: {'✅ ALLOWED' if not blocked else '❌ BLOCKED'} (Score: {score:.3f})")
        
        self.results['by_category']['Legitimate'] = category_results
        return category_results
    
    def calculate_prevention_ratios(self):
        """Calculate comprehensive prevention statistics"""
        print("\n" + "="*60)
        print("📊 ATTACK PREVENTION ANALYSIS")
        print("="*60)
        
        total_attacks = 0
        total_blocked = 0
        total_legitimate = 0
        legitimate_false_positives = 0
        
        # Calculate by category
        for category, tests in self.results['by_category'].items():
            category_total = len(tests)
            category_correct = sum(1 for test in tests if test['correct'])
            category_accuracy = (category_correct / category_total) * 100 if category_total > 0 else 0
            
            if category == 'Legitimate':
                total_legitimate += category_total
                legitimate_false_positives += sum(1 for test in tests if test['actual_block'])
                print(f"\n🔍 {category} Requests:")
                print(f"   Total: {category_total}")
                print(f"   False Positives: {legitimate_false_positives}")
                print(f"   Accuracy: {category_accuracy:.1f}%")
            else:
                category_blocked = sum(1 for test in tests if test['actual_block'])
                total_attacks += category_total
                total_blocked += category_blocked
                prevention_rate = (category_blocked / category_total) * 100 if category_total > 0 else 0
                
                print(f"\n🚨 {category} Attacks:")
                print(f"   Total: {category_total}")
                print(f"   Blocked: {category_blocked}")
                print(f"   Prevention Rate: {prevention_rate:.1f}%")
        
        # Overall statistics
        overall_prevention_rate = (total_blocked / total_attacks) * 100 if total_attacks > 0 else 0
        false_positive_rate = (legitimate_false_positives / total_legitimate) * 100 if total_legitimate > 0 else 0
        
        print(f"\n🎯 OVERALL STATISTICS:")
        print(f"   Total Attack Tests: {total_attacks}")
        print(f"   Attacks Prevented: {total_blocked}")
        print(f"   Attack Prevention Rate: {overall_prevention_rate:.1f}%")
        print(f"   False Positive Rate: {false_positive_rate:.1f}%")
        
        # Calculate accuracy and precision
        all_tests = []
        for tests in self.results['by_category'].values():
            all_tests.extend(tests)
        
        total_tests = len(all_tests)
        correct_predictions = sum(1 for test in all_tests if test['correct'])
        overall_accuracy = (correct_predictions / total_tests) * 100 if total_tests > 0 else 0
        
        print(f"   Overall Accuracy: {overall_accuracy:.1f}%")
        print(f"   Total Tests Run: {total_tests}")
        
        return {
            'attack_prevention_rate': overall_prevention_rate,
            'false_positive_rate': false_positive_rate,
            'overall_accuracy': overall_accuracy,
            'total_attacks': total_attacks,
            'attacks_blocked': total_blocked,
            'legitimate_requests': total_legitimate,
            'false_positives': legitimate_false_positives
        }
    
    def run_comprehensive_test(self):
        """Run all tests and return results"""
        print("🛡️" * 30)
        print("  WAF ATTACK PREVENTION TEST")
        print("🛡️" * 30)
        
        # Run all test categories
        self.run_sql_injection_tests()
        self.run_xss_tests()
        self.run_path_traversal_tests()
        self.run_legitimate_tests()
        
        # Calculate and display results
        stats = self.calculate_prevention_ratios()
        
        print("\n" + "="*60)
        print("✅ ATTACK PREVENTION TEST COMPLETE!")
        print("="*60)
        
        return stats

if __name__ == "__main__":
    tester = AttackPreventionTester()
    results = tester.run_comprehensive_test()
