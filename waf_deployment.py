#!/usr/bin/env python3
"""
WAF Production Deployment Guide
===============================
Complete guide and tools for deploying the Transformer WAF in production
"""

import os
import json
import subprocess
import requests
from pathlib import Path

class WAFDeployer:
    """Production WAF deployment manager"""
    
    def __init__(self, base_path: str = "/Users/moturisaisushanth/Downloads/samplewar"):
        self.base_path = Path(base_path)
        self.deployment_modes = {
            'standalone': 'Run WAF as independent service',
            'nginx_proxy': 'Integrate with Nginx as reverse proxy',
            'docker': 'Deploy using Docker containers',
            'kubernetes': 'Deploy on Kubernetes cluster'
        }
    
    def check_prerequisites(self):
        """Check system prerequisites for deployment"""
        print("🔍 Checking Prerequisites...")
        
        # Check Python environment
        python_ok = subprocess.run(['python3', '--version'], capture_output=True).returncode == 0
        print(f"   Python 3: {'✅' if python_ok else '❌'}")
        
        # Check Docker
        docker_ok = subprocess.run(['docker', '--version'], capture_output=True).returncode == 0
        print(f"   Docker: {'✅' if docker_ok else '❌'}")
        
        # Check Nginx
        nginx_ok = subprocess.run(['nginx', '-v'], capture_output=True).returncode == 0
        print(f"   Nginx: {'✅' if nginx_ok else '❌'}")
        
        # Check required Python packages
        required_packages = ['uvicorn', 'fastapi', 'torch', 'transformers']
        for package in required_packages:
            try:
                __import__(package)
                print(f"   {package}: ✅")
            except ImportError:
                print(f"   {package}: ❌")
        
        return python_ok
    
    def create_production_config(self):
        """Create production configuration files"""
        print("\n📝 Creating Production Configuration...")
        
        # Production WAF config
        prod_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 4,
                "max_requests": 1000,
                "keepalive": 2
            },
            "security": {
                "rate_limiting": {
                    "enabled": True,
                    "max_requests": 100,
                    "time_window": 60
                },
                "ip_whitelist": [],
                "ip_blacklist": [],
                "threat_score_threshold": 0.7
            },
            "logging": {
                "level": "INFO",
                "file": "/var/log/waf/waf.log",
                "max_size": "100MB",
                "backup_count": 5
            },
            "monitoring": {
                "enabled": True,
                "metrics_endpoint": "/metrics",
                "health_endpoint": "/health"
            }
        }
        
        config_file = self.base_path / "production_config.json"
        with open(config_file, 'w') as f:
            json.dump(prod_config, f, indent=2)
        
        print(f"   ✅ Created: {config_file}")
        return config_file
    
    def create_nginx_config(self):
        """Create Nginx configuration for WAF integration"""
        print("\n🌐 Creating Nginx Configuration...")
        
        nginx_config = """
# WAF-enabled Nginx Configuration
upstream waf_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

upstream app_backend {
    server 127.0.0.1:8080;  # Your application server
    keepalive 32;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=waf_limit:10m rate=10r/s;

server {
    listen 80;
    server_name your-domain.com;
    
    # Enable access logging
    access_log /var/log/nginx/waf_access.log combined;
    error_log /var/log/nginx/waf_error.log;
    
    # WAF Integration - Analyze all requests
    location @waf_check {
        internal;
        proxy_pass http://waf_backend/detect;
        proxy_method POST;
        proxy_set_header Content-Type "application/json";
        proxy_set_body '{
            "ip": "$remote_addr",
            "method": "$request_method", 
            "path": "$uri",
            "query_params": {"args": "$args"},
            "headers": {"user_agent": "$http_user_agent"}
        }';
    }
    
    # Main application proxy with WAF protection
    location / {
        # Rate limiting
        limit_req zone=waf_limit burst=20 nodelay;
        
        # WAF check using auth_request
        auth_request @waf_check;
        
        # Custom headers for WAF response
        auth_request_set $waf_score $upstream_http_x_anomaly_score;
        auth_request_set $waf_blocked $upstream_http_x_blocked;
        
        # Block if WAF says it's malicious
        if ($waf_blocked = "true") {
            return 403 "Request blocked by WAF";
        }
        
        # Add WAF score to response headers (for monitoring)
        add_header X-WAF-Score $waf_score;
        
        # Proxy to application
        proxy_pass http://app_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # WAF management endpoints
    location /waf/ {
        proxy_pass http://waf_backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # Restrict access to WAF management
        allow 127.0.0.1;
        allow 192.168.0.0/16;
        deny all;
    }
}
"""
        
        nginx_file = self.base_path / "nginx_waf.conf"
        with open(nginx_file, 'w') as f:
            f.write(nginx_config)
        
        print(f"   ✅ Created: {nginx_file}")
        return nginx_file
    
    def create_docker_config(self):
        """Create Docker configuration for containerized deployment"""
        print("\n🐳 Creating Docker Configuration...")
        
        # Dockerfile
        dockerfile_content = """
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements_waf.txt .
RUN pip install --no-cache-dir -r requirements_waf.txt

# Copy application code
COPY . .

# Create log directory
RUN mkdir -p /var/log/waf

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "waf_inference_service:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
"""
        
        dockerfile = self.base_path / "Dockerfile.waf"
        with open(dockerfile, 'w') as f:
            f.write(dockerfile_content)
        
        # Docker Compose
        compose_content = """
version: '3.8'

services:
  waf:
    build:
      context: .
      dockerfile: Dockerfile.waf
    ports:
      - "8000:8000"
    environment:
      - WAF_MODE=production
      - LOG_LEVEL=INFO
    volumes:
      - ./logs:/var/log/waf
      - ./models:/app/models
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
  
  dashboard:
    build:
      context: .
      dockerfile: Dockerfile.dashboard  
    ports:
      - "8501:8501"
    depends_on:
      - waf
    environment:
      - WAF_URL=http://waf:8000
    restart: unless-stopped
  
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx_waf.conf:/etc/nginx/conf.d/default.conf
      - ./logs:/var/log/nginx
    depends_on:
      - waf
    restart: unless-stopped

volumes:
  waf_logs:
  waf_models:
"""
        
        compose_file = self.base_path / "docker-compose.waf.yml"
        with open(compose_file, 'w') as f:
            f.write(compose_content)
        
        print(f"   ✅ Created: {dockerfile}")
        print(f"   ✅ Created: {compose_file}")
        return dockerfile, compose_file
    
    def create_systemd_service(self):
        """Create systemd service for WAF"""
        print("\n⚙️  Creating Systemd Service...")
        
        service_content = f"""
[Unit]
Description=Transformer WAF Service
After=network.target

[Service]
Type=simple
User=waf
Group=waf
WorkingDirectory={self.base_path}
Environment=PATH={self.base_path}/venv_new/bin
ExecStart={self.base_path}/venv_new/bin/uvicorn waf_inference_service:app --host 0.0.0.0 --port 8000 --workers 4
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        
        service_file = self.base_path / "waf.service"
        with open(service_file, 'w') as f:
            f.write(service_content)
        
        print(f"   ✅ Created: {service_file}")
        print("   📋 To install: sudo cp waf.service /etc/systemd/system/")
        print("   📋 To enable: sudo systemctl enable waf && sudo systemctl start waf")
        return service_file
    
    def create_monitoring_script(self):
        """Create monitoring and alerting script"""
        print("\n📊 Creating Monitoring Script...")
        
        monitoring_script = '''#!/bin/bash
# WAF Monitoring Script

WAF_URL="http://localhost:8000"
LOG_FILE="/var/log/waf/monitoring.log"
ALERT_THRESHOLD=100  # Alert if more than 100 attacks per minute

# Function to log with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Check WAF health
check_health() {
    if curl -f -s "$WAF_URL/health" > /dev/null; then
        log_message "WAF service is healthy"
        return 0
    else
        log_message "ERROR: WAF service is down!"
        # Send alert (email, Slack, etc.)
        return 1
    fi
}

# Get metrics and check for attack spikes
check_attack_rate() {
    metrics=$(curl -s "$WAF_URL/metrics")
    if [ $? -eq 0 ]; then
        attacks=$(echo "$metrics" | jq '.anomalies_detected // 0')
        total=$(echo "$metrics" | jq '.requests_processed // 0')
        
        if [ "$attacks" -gt "$ALERT_THRESHOLD" ]; then
            log_message "ALERT: High attack rate detected - $attacks attacks out of $total requests"
            # Send high-priority alert
        fi
        
        log_message "Current stats: $attacks attacks out of $total requests"
    else
        log_message "ERROR: Unable to fetch metrics"
    fi
}

# Main monitoring loop
main() {
    log_message "Starting WAF monitoring"
    
    while true; do
        check_health
        check_attack_rate
        sleep 60  # Check every minute
    done
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
'''
        
        monitor_file = self.base_path / "waf_monitor.sh"
        with open(monitor_file, 'w') as f:
            f.write(monitoring_script)
        
        os.chmod(monitor_file, 0o755)  # Make executable
        print(f"   ✅ Created: {monitor_file}")
        return monitor_file
    
    def deploy_production_waf(self, mode: str = "standalone"):
        """Deploy WAF in production mode"""
        print(f"\n🚀 Deploying WAF in {mode} mode...")
        
        if mode == "standalone":
            # Kill existing demo service
            subprocess.run(['pkill', '-f', 'demo_waf_service'], capture_output=True)
            
            # Start production WAF service
            cmd = [
                f"{self.base_path}/venv_new/bin/uvicorn",
                "waf_inference_service:app",
                "--host", "0.0.0.0",
                "--port", "8000", 
                "--workers", "4",
                "--access-log"
            ]
            
            print(f"   🏃 Starting production WAF service...")
            print(f"   📋 Command: {' '.join(cmd)}")
            
            # Start in background
            subprocess.Popen(cmd, cwd=self.base_path)
            
        elif mode == "docker":
            print("   🐳 Building and starting Docker containers...")
            subprocess.run(['docker-compose', '-f', 'docker-compose.waf.yml', 'up', '-d'], 
                         cwd=self.base_path)
        
        elif mode == "nginx_proxy":
            print("   🌐 Setting up Nginx proxy integration...")
            print("   📋 Please copy nginx_waf.conf to /etc/nginx/sites-available/")
            print("   📋 Then: sudo ln -s /etc/nginx/sites-available/nginx_waf.conf /etc/nginx/sites-enabled/")
            print("   📋 And: sudo nginx -t && sudo systemctl reload nginx")
        
        return True
    
    def test_deployment(self):
        """Test the deployed WAF"""
        print("\n🧪 Testing Deployed WAF...")
        
        test_cases = [
            {
                'name': 'Normal Request',
                'data': {'ip': '192.168.1.100', 'method': 'GET', 'path': '/test', 'query_params': {}},
                'expected_blocked': False
            },
            {
                'name': 'SQL Injection',
                'data': {'ip': '192.168.1.100', 'method': 'GET', 'path': '/search', 'query_params': {'q': "' OR 1=1--"}},
                'expected_blocked': True
            },
            {
                'name': 'XSS Attack',
                'data': {'ip': '192.168.1.100', 'method': 'GET', 'path': '/comment', 'query_params': {'msg': '<script>alert(1)</script>'}},
                'expected_blocked': True
            }
        ]
        
        success_count = 0
        for test in test_cases:
            try:
                response = requests.post('http://localhost:8000/detect', 
                                       json=test['data'], timeout=5)
                if response.status_code == 200:
                    result = response.json()
                    blocked = result.get('is_anomalous', False)
                    score = result.get('anomaly_score', 0)
                    
                    if blocked == test['expected_blocked']:
                        print(f"   ✅ {test['name']}: PASS (Score: {score:.3f})")
                        success_count += 1
                    else:
                        print(f"   ❌ {test['name']}: FAIL (Expected: {test['expected_blocked']}, Got: {blocked})")
                else:
                    print(f"   ❌ {test['name']}: HTTP Error {response.status_code}")
            except Exception as e:
                print(f"   ❌ {test['name']}: Error - {e}")
        
        print(f"\n📊 Test Results: {success_count}/{len(test_cases)} passed")
        return success_count == len(test_cases)

def main():
    """Main deployment function"""
    print("🛡️ WAF PRODUCTION DEPLOYMENT SETUP")
    print("=" * 50)
    
    deployer = WAFDeployer()
    
    # Check prerequisites
    prereqs_ok = deployer.check_prerequisites()
    if not prereqs_ok:
        print("❌ Prerequisites not met. Please install missing components.")
        return
    
    # Create configuration files
    deployer.create_production_config()
    deployer.create_nginx_config()
    deployer.create_docker_config()
    deployer.create_systemd_service()
    deployer.create_monitoring_script()
    
    print("\n✅ All configuration files created!")
    print("\n🚀 Next Steps:")
    print("1. Choose deployment mode:")
    print("   - Standalone: python waf_deployment.py --deploy standalone")
    print("   - Docker: docker-compose -f docker-compose.waf.yml up -d")
    print("   - Nginx: Copy nginx_waf.conf and configure")
    print("2. Test deployment: python waf_deployment.py --test")
    print("3. Monitor: ./waf_monitor.sh")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='WAF Production Deployment')
    parser.add_argument('--deploy', choices=['standalone', 'docker', 'nginx_proxy'], 
                       help='Deploy WAF in specified mode')
    parser.add_argument('--test', action='store_true', help='Test deployed WAF')
    
    args = parser.parse_args()
    
    deployer = WAFDeployer()
    
    if args.deploy:
        deployer.deploy_production_waf(args.deploy)
        print(f"✅ WAF deployed in {args.deploy} mode")
    elif args.test:
        deployer.test_deployment()
    else:
        main()
