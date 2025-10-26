"""
Benign Traffic Generator for WAF Training
=========================================
Generates diverse, realistic HTTP traffic for the 3 WAR applications
to create training data for the Transformer-based anomaly detector.
"""

import random
import json
import time
from locust import HttpUser, TaskSet, task, between
from locust.env import Environment
from locust.stats import stats_printer, stats_history
from locust.log import setup_logging
import requests
import uuid

class EcommerceUser(HttpUser):
    """Simulate realistic e-commerce user behavior"""
    
    wait_time = between(1, 3)
    host = "http://localhost:8080"
    
    def on_start(self):
        """Initialize user session"""
        self.session_id = str(uuid.uuid4())
        self.user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ])
        
    @task(5)
    def browse_homepage(self):
        """Visit homepage - most common action"""
        self.client.get("/ecommerce/", 
                       headers={"User-Agent": self.user_agent})
    
    @task(4) 
    def browse_products(self):
        """Browse product catalog"""
        endpoints = [
            "/ecommerce/products",
            "/ecommerce/products?category=electronics", 
            "/ecommerce/products?category=books&sort=price",
            f"/ecommerce/products/{random.randint(1, 100)}"
        ]
        self.client.get(random.choice(endpoints),
                       headers={"User-Agent": self.user_agent})
    
    @task(3)
    def search_products(self):
        """Search functionality"""
        search_terms = [
            "laptop", "book", "phone", "camera", "headphones",
            "tablet", "monitor", "keyboard", "mouse", "speaker"
        ]
        query = random.choice(search_terms)
        self.client.get(f"/ecommerce/search?q={query}",
                       headers={"User-Agent": self.user_agent})
        
    @task(2)
    def add_to_cart(self):
        """Add items to cart"""
        product_data = {
            "productId": random.randint(1, 50),
            "quantity": random.randint(1, 3)
        }
        self.client.post("/ecommerce/cart",
                        json=product_data,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": self.user_agent
                        })
    
    @task(1)
    def user_operations(self):
        """User account operations"""
        if random.choice([True, False]):
            # GET users
            self.client.get("/ecommerce/users",
                           headers={"User-Agent": self.user_agent})
        else:
            # Create user
            user_data = {
                "username": f"user_{random.randint(1000, 9999)}",
                "email": f"user{random.randint(1, 1000)}@example.com"
            }
            self.client.post("/ecommerce/users",
                            json=user_data,
                            headers={
                                "Content-Type": "application/json",
                                "User-Agent": self.user_agent
                            })

class RestApiUser(HttpUser):
    """Simulate API client behavior"""
    
    wait_time = between(0.5, 2)
    host = "http://localhost:8080"
    
    def on_start(self):
        self.api_key = f"api_key_{uuid.uuid4().hex[:8]}"
        self.auth_token = f"Bearer token_{uuid.uuid4().hex[:16]}"
    
    @task(4)
    def get_tasks(self):
        """Fetch tasks - most common API call"""
        params = random.choice([
            {},
            {"status": "active"},
            {"limit": "10", "offset": "0"},
            {"sort": "created_date", "order": "desc"}
        ])
        self.client.get("/rest-api/api/tasks",
                       params=params,
                       headers={"Authorization": self.auth_token})
    
    @task(3)
    def get_users(self):
        """User API operations"""
        self.client.get("/rest-api/api/users",
                       headers={"X-API-Key": self.api_key})
                       
    @task(3)
    def get_projects(self):
        """Project API operations"""
        self.client.get("/rest-api/api/projects",
                       headers={"Authorization": self.auth_token})
    
    @task(2)
    def create_task(self):
        """Create new task"""
        task_data = {
            "title": f"Task {random.randint(1, 1000)}",
            "description": f"Description for task {uuid.uuid4().hex[:8]}",
            "priority": random.choice(["low", "medium", "high"]),
            "status": "active"
        }
        self.client.post("/rest-api/api/tasks",
                        json=task_data,
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": self.auth_token
                        })
    
    @task(2)
    def get_analytics(self):
        """Analytics endpoints"""
        endpoints = [
            "/rest-api/api/analytics",
            "/rest-api/api/analytics/api-usage",
            "/rest-api/api/analytics/real-time"
        ]
        self.client.get(random.choice(endpoints),
                       headers={"Authorization": self.auth_token})
    
    @task(1)
    def authentication_flows(self):
        """Auth operations"""
        if random.choice([True, False]):
            # Login
            login_data = {
                "username": f"user_{random.randint(1, 100)}",
                "password": "password123"
            }
            self.client.post("/rest-api/api/auth/login",
                            json=login_data,
                            headers={"Content-Type": "application/json"})
        else:
            # Profile access
            self.client.get("/rest-api/api/auth/profile",
                           headers={"Authorization": self.auth_token})

class MixedTrafficUser(HttpUser):
    """Mixed traffic across both applications"""
    
    wait_time = between(1, 4)
    host = "http://localhost:8080"
    
    def on_start(self):
        """Initialize user session"""
        self.session_id = str(uuid.uuid4())
        self.user_agent = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36", 
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ])
        self.auth_token = f"Bearer token_{random.randint(1000, 9999)}"
    
    @task(3)
    def ecommerce_homepage(self):
        """Visit e-commerce homepage"""
        self.client.get("/ecommerce/", 
                       headers={"User-Agent": self.user_agent})
    
    @task(2)
    def ecommerce_products(self):
        """Browse e-commerce products"""
        endpoints = [
            "/ecommerce/products",
            "/ecommerce/products?category=electronics", 
            f"/ecommerce/products/{random.randint(1, 100)}"
        ]
        self.client.get(random.choice(endpoints),
                       headers={"User-Agent": self.user_agent})
    
    @task(2)
    def api_tasks(self):
        """Access REST API tasks"""
        self.client.get("/rest-api/api/tasks",
                       headers={"Authorization": self.auth_token})
    
    @task(1)
    def api_users(self):
        """Access REST API users"""
        self.client.get("/rest-api/api/users",
                       headers={"Authorization": self.auth_token})

def generate_benign_traffic(duration_minutes=10, users=20, spawn_rate=2):
    """
    Generate benign traffic for model training
    
    Args:
        duration_minutes: How long to run traffic generation
        users: Number of concurrent users
        spawn_rate: Users spawned per second
    """
    setup_logging("INFO", None)
    
    # Setup environment
    env = Environment(user_classes=[MixedTrafficUser])
    
    print(f"🚀 Starting benign traffic generation...")
    print(f"   Duration: {duration_minutes} minutes")
    print(f"   Users: {users} concurrent")
    print(f"   Spawn rate: {spawn_rate} users/second")
    
    # Start test
    env.create_local_runner()
    
    # Start users
    env.runner.start(user_count=users, spawn_rate=spawn_rate)
    
    # Run for specified duration
    time.sleep(duration_minutes * 60)
    
    # Stop test
    env.runner.stop()
    
    # Print stats
    stats = env.runner.stats
    print(f"\n📊 Traffic Generation Complete:")
    print(f"   Total requests: {stats.total.num_requests}")
    print(f"   Failed requests: {stats.total.num_failures}")
    print(f"   Average response time: {stats.total.avg_response_time:.2f}ms")
    print(f"   RPS: {stats.total.total_rps:.2f}")
    
    return stats

if __name__ == "__main__":
    # Generate 30 minutes of diverse benign traffic
    generate_benign_traffic(duration_minutes=30, users=50, spawn_rate=5)
