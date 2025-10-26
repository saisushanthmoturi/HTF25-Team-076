#!/usr/bin/env python3
"""
WAF Comprehensive Test Suite
===========================
Tests various attack patterns and edge cases to validate WAF detection capabilities.
"""

import requests
import json
import time
from datetime import datetime

class WAFTester:
    """Comprehensive WAF testing suite"""
    
    def __init__(self, waf_endpoint="http://localhost:8000"):
        self.waf_endpoint = waf_endpoint
        self.test_results = []
    
    def test_request(self, name, request_data, expected_anomalous=False):
        """Test a single request and record results"""
        print(f"\n🧪 Testing: {name}")
        print(f"   Path: {request_data['path']}")
        if request_data.get('query_params'):
            print(f"   Params: {request_data['query_params']}")
        
        try:
            start_time = time.time()
            response = requests.post(
                f"{self.waf_endpoint}/detect",
                json=request_data,
                timeout=10
            )
            end_time = time.time()
            
            if response.status_code == 200:
                result = response.json()
                
                # Record result
                test_result = {
                    "name": name,
                    "request": request_data,
                    "response": result,
                    "expected_anomalous": expected_anomalous,
                    "actual_anomalous": result.get("is_anomalous", False),
                    "score": result.get("anomaly_score", 0),
                    "response_time": (end_time - start_time) * 1000,
                    "passed": (result.get("is_anomalous", False) == expected_anomalous)
                }
                
                self.test_results.append(test_result)
                
                # Print result
                status = "🚨 ANOMALOUS" if result.get("is_anomalous") else "✅ NORMAL"
                score = result.get("anomaly_score", 0)
                confidence = result.get("confidence", 0)
                response_time = result.get("processing_time_ms", 0)
                
                print(f"   Result: {status}")
                print(f"   Score: {score:.3f}")
                print(f"   Confidence: {confidence:.3f}")
                print(f"   Response Time: {response_time:.1f}ms")
                
                # Check if test passed
                if test_result["passed"]:
                    print(f"   ✅ Test PASSED")
                else:
                    expected_str = "anomalous" if expected_anomalous else "normal"
                    actual_str = "anomalous" if result.get("is_anomalous") else "normal"
                    print(f"   ❌ Test FAILED: Expected {expected_str}, got {actual_str}")
                
            else:
                print(f"   ❌ HTTP Error: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
    
    def run_sql_injection_tests(self):
        """Test SQL injection detection"""
        print(f"\n{'='*60}")
        print("🗄️  SQL INJECTION TESTS")
        print(f"{'='*60}")
        
        sql_tests = [
            ("Basic SQL Injection", {
                "ip": "192.168.1.100",
                "method": "GET",
                "path": "/users",
                "query_params": {"id": "1' OR '1'='1"}
            }, True),
            
            ("Union-based SQL Injection", {
                "ip": "192.168.1.101", 
                "method": "GET",
                "path": "/products",
                "query_params": {"category": "electronics' UNION SELECT * FROM users--"}
            }, True),
            
            ("Time-based SQL Injection", {
                "ip": "192.168.1.102",
                "method": "POST", 
                "path": "/login",
                "query_params": {"username": "admin'; WAITFOR DELAY '00:00:05'--"}
            }, True),
            
            ("Normal SQL-like Query", {
                "ip": "192.168.1.103",
                "method": "GET",
                "path": "/search",
                "query_params": {"q": "SELECT laptops under 1000"}
            }, False)
        ]
        
        for name, request_data, expected in sql_tests:
            self.test_request(name, request_data, expected)
    
    def run_xss_tests(self):
        """Test XSS detection"""
        print(f"\n{'='*60}")
        print("🎭 CROSS-SITE SCRIPTING (XSS) TESTS")
        print(f"{'='*60}")
        
        xss_tests = [
            ("Basic Script Injection", {
                "ip": "192.168.1.110",
                "method": "GET", 
                "path": "/search",
                "query_params": {"q": "<script>alert('xss')</script>"}
            }, True),
            
            ("Event Handler XSS", {
                "ip": "192.168.1.111",
                "method": "GET",
                "path": "/profile",
                "query_params": {"name": "<img src=x onerror=alert('xss')>"}
            }, True),
            
            ("JavaScript URL", {
                "ip": "192.168.1.112", 
                "method": "GET",
                "path": "/redirect",
                "query_params": {"url": "javascript:alert('xss')"}
            }, True),
            
            ("Normal HTML-like Content", {
                "ip": "192.168.1.113",
                "method": "GET",
                "path": "/search", 
                "query_params": {"q": "HTML tutorial script tags"}
            }, False)
        ]
        
        for name, request_data, expected in xss_tests:
            self.test_request(name, request_data, expected)
    
    def run_path_traversal_tests(self):
        """Test path traversal detection"""
        print(f"\n{'='*60}")
        print("📁 PATH TRAVERSAL TESTS")
        print(f"{'='*60}")
        
        traversal_tests = [
            ("Unix Path Traversal", {
                "ip": "192.168.1.120",
                "method": "GET",
                "path": "/../../../etc/passwd",
                "query_params": {}
            }, True),
            
            ("Windows Path Traversal", {
                "ip": "192.168.1.121",
                "method": "GET", 
                "path": "/..\\..\\..\\windows\\system32\\config\\sam",
                "query_params": {}
            }, True),
            
            ("Encoded Path Traversal", {
                "ip": "192.168.1.122",
                "method": "GET",
                "path": "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "query_params": {}
            }, True),
            
            ("Normal File Access", {
                "ip": "192.168.1.123",
                "method": "GET",
                "path": "/docs/manual.pdf",
                "query_params": {}
            }, False)
        ]
        
        for name, request_data, expected in traversal_tests:
            self.test_request(name, request_data, expected)
    
    def run_admin_access_tests(self):
        """Test admin path detection"""
        print(f"\n{'='*60}")
        print("👑 ADMIN ACCESS TESTS") 
        print(f"{'='*60}")
        
        admin_tests = [
            ("Admin Panel Access", {
                "ip": "192.168.1.130",
                "method": "GET",
                "path": "/admin/",
                "query_params": {}
            }, True),
            
            ("WordPress Admin", {
                "ip": "192.168.1.131",
                "method": "GET",
                "path": "/wp-admin/admin.php",
                "query_params": {}
            }, True),
            
            ("phpMyAdmin Access", {
                "ip": "192.168.1.132",
                "method": "GET", 
                "path": "/phpmyadmin/index.php",
                "query_params": {}
            }, True),
            
            ("Normal Admin Content", {
                "ip": "192.168.1.133",
                "method": "GET",
                "path": "/about/administration-team",
                "query_params": {}
            }, False)
        ]
        
        for name, request_data, expected in admin_tests:
            self.test_request(name, request_data, expected)
    
    def run_normal_traffic_tests(self):
        """Test normal traffic patterns"""
        print(f"\n{'='*60}")
        print("✅ NORMAL TRAFFIC TESTS")
        print(f"{'='*60}")
        
        normal_tests = [
            ("Homepage Access", {
                "ip": "192.168.1.200",
                "method": "GET",
                "path": "/",
                "query_params": {}
            }, False),
            
            ("Product Browsing", {
                "ip": "192.168.1.201",
                "method": "GET",
                "path": "/products",
                "query_params": {"category": "electronics", "page": "1"}
            }, False),
            
            ("API Call", {
                "ip": "192.168.1.202",
                "method": "GET", 
                "path": "/api/tasks",
                "query_params": {"limit": "10"}
            }, False),
            
            ("Search Query", {
                "ip": "192.168.1.203",
                "method": "GET",
                "path": "/search",
                "query_params": {"q": "laptop computer"}
            }, False)
        ]
        
        for name, request_data, expected in normal_tests:
            self.test_request(name, request_data, expected)
    
    def print_summary(self):
        """Print test summary"""
        print(f"\n{'='*60}")
        print("📊 TEST SUMMARY")
        print(f"{'='*60}")
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r["passed"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests} ✅")
        print(f"Failed: {failed_tests} ❌")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        # Performance stats
        avg_response_time = sum(r["response_time"] for r in self.test_results) / total_tests
        max_response_time = max(r["response_time"] for r in self.test_results)
        
        print(f"\nPerformance:")
        print(f"Average Response Time: {avg_response_time:.1f}ms")
        print(f"Max Response Time: {max_response_time:.1f}ms")
        
        # Attack detection stats
        anomalous_results = [r for r in self.test_results if r["expected_anomalous"]]
        normal_results = [r for r in self.test_results if not r["expected_anomalous"]]
        
        if anomalous_results:
            correctly_detected = sum(1 for r in anomalous_results if r["actual_anomalous"])
            detection_rate = (correctly_detected / len(anomalous_results)) * 100
            print(f"\nAttack Detection Rate: {detection_rate:.1f}%")
        
        if normal_results:
            false_positives = sum(1 for r in normal_results if r["actual_anomalous"])
            false_positive_rate = (false_positives / len(normal_results)) * 100
            print(f"False Positive Rate: {false_positive_rate:.1f}%")
        
        # Failed tests details
        if failed_tests > 0:
            print(f"\n❌ Failed Tests:")
            for result in self.test_results:
                if not result["passed"]:
                    expected = "anomalous" if result["expected_anomalous"] else "normal"
                    actual = "anomalous" if result["actual_anomalous"] else "normal"
                    print(f"   • {result['name']}: Expected {expected}, got {actual} (Score: {result['score']:.3f})")
    
    def run_all_tests(self):
        """Run all test suites"""
        print("🛡️ WAF COMPREHENSIVE TEST SUITE")
        print(f"Testing endpoint: {self.waf_endpoint}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Check WAF service health
        try:
            response = requests.get(f"{self.waf_endpoint}/health", timeout=5)
            if response.status_code == 200:
                print(f"✅ WAF service is healthy")
            else:
                print(f"⚠️ WAF service status: {response.status_code}")
                return
        except Exception as e:
            print(f"❌ Cannot connect to WAF service: {e}")
            return
        
        # Run test suites
        self.run_sql_injection_tests()
        self.run_xss_tests()
        self.run_path_traversal_tests()
        self.run_admin_access_tests()
        self.run_normal_traffic_tests()
        
        # Print summary
        self.print_summary()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="WAF Comprehensive Test Suite")
    parser.add_argument("--waf-endpoint", default="http://localhost:8000", 
                       help="WAF service endpoint")
    
    args = parser.parse_args()
    
    tester = WAFTester(waf_endpoint=args.waf_endpoint)
    tester.run_all_tests()

if __name__ == "__main__":
    main()
