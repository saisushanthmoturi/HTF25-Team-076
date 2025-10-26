#!/usr/bin/env python3
"""
WAF Performance Test Suite
==========================
Comprehensive performance testing for the Transformer-based WAF system
"""

import asyncio
import aiohttp
import time
import json
import statistics
from typing import List, Dict, Any
import concurrent.futures
import threading
from dataclasses import dataclass

@dataclass
class TestResult:
    """Test result data class"""
    response_time: float
    status_code: int
    anomaly_score: float
    is_anomalous: bool
    success: bool = True
    error: str = ""

class WAFPerformanceTester:
    """Comprehensive WAF performance testing"""
    
    def __init__(self, waf_url: str = "http://localhost:8000"):
        self.waf_url = waf_url
        self.results: List[TestResult] = []
        
    async def test_single_request(self, session: aiohttp.ClientSession, test_data: Dict[str, Any]) -> TestResult:
        """Test a single request"""
        start_time = time.time()
        
        try:
            async with session.post(f"{self.waf_url}/detect", json=test_data) as response:
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # Convert to ms
                
                if response.status == 200:
                    result_data = await response.json()
                    return TestResult(
                        response_time=response_time,
                        status_code=response.status,
                        anomaly_score=result_data.get('anomaly_score', 0),
                        is_anomalous=result_data.get('is_anomalous', False)
                    )
                else:
                    return TestResult(
                        response_time=response_time,
                        status_code=response.status,
                        anomaly_score=0,
                        is_anomalous=False,
                        success=False,
                        error=f"HTTP {response.status}"
                    )
                    
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            return TestResult(
                response_time=response_time,
                status_code=0,
                anomaly_score=0,
                is_anomalous=False,
                success=False,
                error=str(e)
            )
    
    async def run_concurrent_test(self, test_requests: List[Dict[str, Any]], concurrent_users: int = 50) -> List[TestResult]:
        """Run concurrent performance test"""
        print(f"🚀 Running concurrent test with {concurrent_users} users and {len(test_requests)} requests...")
        
        connector = aiohttp.TCPConnector(limit=100)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create tasks for concurrent execution
            tasks = []
            for i in range(len(test_requests)):
                request_data = test_requests[i % len(test_requests)]
                task = asyncio.create_task(self.test_single_request(session, request_data))
                tasks.append(task)
            
            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and convert to TestResult objects
            valid_results = []
            for result in results:
                if isinstance(result, TestResult):
                    valid_results.append(result)
                elif isinstance(result, Exception):
                    print(f"❌ Exception during test: {result}")
            
            return valid_results
    
    def generate_test_data(self) -> List[Dict[str, Any]]:
        """Generate comprehensive test data"""
        test_requests = []
        
        # Normal requests
        normal_requests = [
            {"ip": "192.168.1.100", "method": "GET", "path": "/", "query_params": {}},
            {"ip": "192.168.1.101", "method": "GET", "path": "/products", "query_params": {}},
            {"ip": "192.168.1.102", "method": "POST", "path": "/api/users", "query_params": {}},
            {"ip": "192.168.1.103", "method": "GET", "path": "/search", "query_params": {"q": "laptop"}},
            {"ip": "192.168.1.104", "method": "PUT", "path": "/api/items/1", "query_params": {}},
        ]
        
        # Attack requests
        attack_requests = [
            {"ip": "192.168.1.200", "method": "GET", "path": "/admin/../../../etc/passwd", "query_params": {}},
            {"ip": "192.168.1.201", "method": "POST", "path": "/login", "query_params": {"user": "admin", "pass": "' OR 1=1--"}},
            {"ip": "192.168.1.202", "method": "GET", "path": "/search", "query_params": {"q": "<script>alert('xss')</script>"}},
            {"ip": "192.168.1.203", "method": "GET", "path": "/admin/config", "query_params": {}},
            {"ip": "192.168.1.204", "method": "POST", "path": "/upload", "query_params": {"file": "../../../../etc/passwd"}},
        ]
        
        # Mix normal and attack requests (80% normal, 20% attacks)
        for _ in range(400):  # 400 normal requests
            test_requests.append(normal_requests[_ % len(normal_requests)])
        
        for _ in range(100):  # 100 attack requests
            test_requests.append(attack_requests[_ % len(attack_requests)])
        
        return test_requests
    
    def analyze_results(self, results: List[TestResult]) -> Dict[str, Any]:
        """Analyze test results and generate performance metrics"""
        if not results:
            return {"error": "No results to analyze"}
        
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]
        
        if not successful_results:
            return {"error": "No successful requests"}
        
        response_times = [r.response_time for r in successful_results]
        anomaly_scores = [r.anomaly_score for r in successful_results]
        anomalous_requests = [r for r in successful_results if r.is_anomalous]
        
        analysis = {
            "total_requests": len(results),
            "successful_requests": len(successful_results),
            "failed_requests": len(failed_results),
            "success_rate": len(successful_results) / len(results) * 100,
            
            # Response time metrics
            "response_time": {
                "mean": statistics.mean(response_times),
                "median": statistics.median(response_times),
                "min": min(response_times),
                "max": max(response_times),
                "p95": statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times),
                "p99": statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else max(response_times),
                "std": statistics.stdev(response_times) if len(response_times) > 1 else 0
            },
            
            # Throughput metrics
            "throughput": {
                "requests_per_second": len(successful_results) / (max(response_times) / 1000) if response_times else 0,
                "avg_requests_per_second": 1000 / statistics.mean(response_times) if response_times else 0
            },
            
            # Security metrics
            "security": {
                "anomalies_detected": len(anomalous_requests),
                "detection_rate": len(anomalous_requests) / len(successful_results) * 100,
                "avg_anomaly_score": statistics.mean(anomaly_scores),
                "max_anomaly_score": max(anomaly_scores) if anomaly_scores else 0,
                "min_anomaly_score": min(anomaly_scores) if anomaly_scores else 0
            },
            
            # Error analysis
            "errors": {
                "error_rate": len(failed_results) / len(results) * 100,
                "error_types": {}
            }
        }
        
        # Analyze error types
        for result in failed_results:
            error_type = result.error or f"HTTP_{result.status_code}"
            if error_type in analysis["errors"]["error_types"]:
                analysis["errors"]["error_types"][error_type] += 1
            else:
                analysis["errors"]["error_types"][error_type] = 1
        
        return analysis
    
    def print_results(self, analysis: Dict[str, Any]):
        """Print formatted test results"""
        print("\n" + "="*70)
        print("🛡️  WAF PERFORMANCE TEST RESULTS")
        print("="*70)
        
        print(f"\n📊 REQUEST SUMMARY")
        print(f"   Total Requests: {analysis['total_requests']:,}")
        print(f"   Successful: {analysis['successful_requests']:,} ({analysis['success_rate']:.1f}%)")
        print(f"   Failed: {analysis['failed_requests']:,} ({analysis['errors']['error_rate']:.1f}%)")
        
        rt = analysis['response_time']
        print(f"\n⚡ RESPONSE TIME METRICS")
        print(f"   Mean: {rt['mean']:.2f}ms")
        print(f"   Median: {rt['median']:.2f}ms")
        print(f"   P95: {rt['p95']:.2f}ms")
        print(f"   P99: {rt['p99']:.2f}ms")
        print(f"   Min/Max: {rt['min']:.2f}ms / {rt['max']:.2f}ms")
        print(f"   Std Dev: {rt['std']:.2f}ms")
        
        tp = analysis['throughput']
        print(f"\n🚀 THROUGHPUT METRICS")
        print(f"   Peak RPS: {tp['requests_per_second']:.1f}")
        print(f"   Average RPS: {tp['avg_requests_per_second']:.1f}")
        
        sec = analysis['security']
        print(f"\n🛡️  SECURITY METRICS")
        print(f"   Anomalies Detected: {sec['anomalies_detected']}")
        print(f"   Detection Rate: {sec['detection_rate']:.1f}%")
        print(f"   Avg Anomaly Score: {sec['avg_anomaly_score']:.3f}")
        print(f"   Score Range: {sec['min_anomaly_score']:.3f} - {sec['max_anomaly_score']:.3f}")
        
        if analysis['errors']['error_types']:
            print(f"\n❌ ERROR ANALYSIS")
            for error_type, count in analysis['errors']['error_types'].items():
                print(f"   {error_type}: {count}")
        
        print("\n" + "="*70)

async def main():
    """Main test execution"""
    print("🛡️  WAF Performance Test Suite")
    print("="*40)
    
    # Initialize tester
    tester = WAFPerformanceTester()
    
    # Generate test data
    test_data = tester.generate_test_data()
    print(f"📝 Generated {len(test_data)} test requests")
    
    # Test WAF service availability
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{tester.waf_url}/health") as response:
                if response.status != 200:
                    print("❌ WAF service not available")
                    return
                print("✅ WAF service is healthy")
    except Exception as e:
        print(f"❌ Cannot connect to WAF service: {e}")
        return
    
    # Run performance tests
    start_time = time.time()
    results = await tester.run_concurrent_test(test_data, concurrent_users=50)
    end_time = time.time()
    
    print(f"⏱️  Test completed in {end_time - start_time:.2f} seconds")
    
    # Analyze and print results
    analysis = tester.analyze_results(results)
    tester.print_results(analysis)
    
    # Save results to file
    with open("waf_performance_results.json", "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"\n💾 Results saved to waf_performance_results.json")

if __name__ == "__main__":
    asyncio.run(main())
