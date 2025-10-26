#!/usr/bin/env python3
"""
Live Traffic Generator for Transformer WAF
==========================================
Generates realistic benign HTTP traffic to the deployed WAR applications
to create live access logs for LogBERT training.
"""

import requests
import random
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import uuid

class LiveTrafficGenerator:
    def __init__(self):
        self.base_urls = {
            'ecommerce': 'http://localhost:8080/ecommerce',
            'rest_api': 'http://localhost:8080/rest-api'
        }
        self.running = True
        self.stats = {'requests': 0, 'errors': 0}
        
        # Realistic user patterns
        self.user_agents = [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15'
        ]
        
        # Product categories and search terms
        self.products = ['laptop', 'phone', 'tablet', 'headphones', 'camera', 'watch']
        self.categories = ['electronics', 'books', 'clothing', 'home', 'sports']
        
    def generate_ecommerce_traffic(self):
        """Generate realistic e-commerce traffic patterns"""
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(self.user_agents)})
        
        try:
            # Browse products
            response = session.get(f"{self.base_urls['ecommerce']}/products")
            self.stats['requests'] += 1
            
            # Search for products
            search_term = random.choice(self.products)
            response = session.get(f"{self.base_urls['ecommerce']}/search", 
                                 params={'q': search_term, 'category': random.choice(self.categories)})
            self.stats['requests'] += 1
            
            # View specific product
            product_id = random.randint(1, 100)
            response = session.get(f"{self.base_urls['ecommerce']}/products/{product_id}")
            self.stats['requests'] += 1
            
            # Add to cart (sometimes)
            if random.random() < 0.3:
                cart_data = {'product_id': product_id, 'quantity': random.randint(1, 3)}
                response = session.post(f"{self.base_urls['ecommerce']}/cart", json=cart_data)
                self.stats['requests'] += 1
                
                # Checkout (sometimes)
                if random.random() < 0.5:
                    checkout_data = {
                        'name': f'User{random.randint(1, 1000)}',
                        'email': f'user{random.randint(1, 1000)}@example.com'
                    }
                    response = session.post(f"{self.base_urls['ecommerce']}/checkout", json=checkout_data)
                    self.stats['requests'] += 1
            
        except Exception as e:
            self.stats['errors'] += 1
            print(f"E-commerce error: {e}")
    
    def generate_api_traffic(self):
        """Generate REST API traffic"""
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(self.user_agents)})
        
        try:
            # Get tasks
            response = session.get(f"{self.base_urls['rest_api']}/api/tasks")
            self.stats['requests'] += 1
            
            # Create task
            if random.random() < 0.4:
                task_data = {
                    'title': f'Task {uuid.uuid4().hex[:8]}',
                    'description': f'Description for task {random.randint(1, 1000)}',
                    'priority': random.choice(['low', 'medium', 'high'])
                }
                response = session.post(f"{self.base_urls['rest_api']}/api/tasks", json=task_data)
                self.stats['requests'] += 1
                
                if response.status_code == 201:
                    # Update task (sometimes)
                    if random.random() < 0.3:
                        task_id = random.randint(1, 50)
                        update_data = {'status': random.choice(['pending', 'completed', 'cancelled'])}
                        response = session.put(f"{self.base_urls['rest_api']}/api/tasks/{task_id}", json=update_data)
                        self.stats['requests'] += 1
            
            # Get users
            response = session.get(f"{self.base_urls['rest_api']}/api/users")
            self.stats['requests'] += 1
            
        except Exception as e:
            self.stats['errors'] += 1
            print(f"API error: {e}")
    
    def generate_session_traffic(self):
        """Generate a complete user session"""
        # Simulate a real user session with delays
        session_length = random.randint(3, 10)
        
        for _ in range(session_length):
            if not self.running:
                break
                
            # Choose traffic type
            if random.random() < 0.7:
                self.generate_ecommerce_traffic()
            else:
                self.generate_api_traffic()
            
            # Realistic delays between requests
            time.sleep(random.uniform(0.5, 3.0))
    
    def run_continuous_traffic(self, concurrent_users=10):
        """Run continuous traffic generation"""
        print(f"🚀 Starting live traffic generation with {concurrent_users} concurrent users")
        print("📊 Generating realistic benign traffic patterns...")
        
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            while self.running:
                # Submit user sessions
                for _ in range(concurrent_users):
                    if self.running:
                        executor.submit(self.generate_session_traffic)
                
                # Wait before next batch
                time.sleep(random.uniform(2, 5))
                
                # Print stats periodically
                if self.stats['requests'] % 100 == 0:
                    print(f"📈 Requests: {self.stats['requests']}, Errors: {self.stats['errors']}")
    
    def stop(self):
        """Stop traffic generation"""
        self.running = False

def main():
    generator = LiveTrafficGenerator()
    
    try:
        # Run continuous traffic
        generator.run_continuous_traffic(concurrent_users=8)
    except KeyboardInterrupt:
        print("\n🛑 Stopping traffic generation...")
        generator.stop()
        print(f"📊 Final stats - Requests: {generator.stats['requests']}, Errors: {generator.stats['errors']}")

if __name__ == "__main__":
    main()
