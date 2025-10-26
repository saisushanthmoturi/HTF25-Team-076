#!/usr/bin/env python3
"""
Complete WAF Integration Script
Launches all components of the Transformer WAF system for live demonstration
"""

import asyncio
import json
import logging
import subprocess
import sys
import time
import signal
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import psutil
import requests

class WAFIntegrationManager:
    """Manages the complete WAF system integration"""
    
    def __init__(self):
        self.processes = {}
        self.services = {
            'tomcat': {'port': 8080, 'path': None, 'process': None},
            'log_processor': {'port': None, 'path': 'live_log_processor.py', 'process': None},
            'continuous_trainer': {'port': None, 'path': 'continuous_logbert_trainer.py', 'process': None},
            'realtime_waf': {'port': 8000, 'path': 'realtime_waf_service.py', 'process': None},
            'traffic_generator': {'port': None, 'path': 'live_traffic_generator.py', 'process': None},
            'streamlit_dashboard': {'port': 8507, 'path': 'simple_waf_dashboard.py', 'process': None}
        }
        
        self.setup_logging()
        self.running = False
        
    def setup_logging(self):
        """Setup logging for the integration manager"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('logs/waf_integration.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('WAFIntegration')
        
    def check_prerequisites(self) -> bool:
        """Check if all required files and dependencies are available"""
        self.logger.info("🔍 Checking prerequisites...")
        
        # Check required Python files
        required_files = [
            'live_log_processor.py',
            'continuous_logbert_trainer.py', 
            'realtime_waf_service.py',
            'live_traffic_generator.py',
            'simple_waf_dashboard.py',
            'logbert_transformer_model.py',
            'waf_inference_service.py',
            'log_parser_normalizer.py',
            'incremental_lora_learning.py'
        ]
        
        missing_files = []
        for file_path in required_files:
            if not Path(file_path).exists():
                missing_files.append(file_path)
                
        if missing_files:
            self.logger.error(f"❌ Missing required files: {missing_files}")
            return False
            
        # Check required directories
        required_dirs = ['logs', 'models', 'plots', 'reports']
        for dir_path in required_dirs:
            Path(dir_path).mkdir(exist_ok=True)
            
        # Check Python dependencies
        required_packages = [
            'torch', 'transformers', 'fastapi', 'uvicorn', 'streamlit',
            'pandas', 'numpy', 'matplotlib', 'seaborn', 'watchdog',
            'drain3', 'locust', 'psutil'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_packages.append(package)
                
        if missing_packages:
            self.logger.warning(f"⚠️ Missing packages (will try to install): {missing_packages}")
            
        self.logger.info("✅ Prerequisites check completed")
        return True
        
    def install_dependencies(self):
        """Install missing dependencies"""
        self.logger.info("📦 Installing dependencies...")
        
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements_waf.txt'
            ])
            self.logger.info("✅ Dependencies installed successfully")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"❌ Failed to install dependencies: {e}")
            
    def check_port_availability(self, port: int) -> bool:
        """Check if a port is available"""
        for conn in psutil.net_connections():
            if conn.laddr.port == port:
                return False
        return True
        
    def start_service(self, service_name: str) -> bool:
        """Start a specific service"""
        service_config = self.services[service_name]
        
        if service_config['path'] is None:
            self.logger.info(f"⏭️ Skipping {service_name} (external service)")
            return True
            
        # Check port availability
        if service_config['port'] and not self.check_port_availability(service_config['port']):
            self.logger.warning(f"⚠️ Port {service_config['port']} already in use for {service_name}")
            return False
            
        try:
            self.logger.info(f"🚀 Starting {service_name}...")
            
            # Special handling for different services
            if service_name == 'streamlit_dashboard':
                cmd = [sys.executable, '-m', 'streamlit', 'run', service_config['path'], '--server.port', str(service_config['port'])]
            elif service_name == 'realtime_waf':
                cmd = [sys.executable, service_config['path']]
            else:
                cmd = [sys.executable, service_config['path']]
                
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            service_config['process'] = process
            self.processes[service_name] = process
            
            # Give service time to start
            time.sleep(2)
            
            # Check if process is still running
            if process.poll() is None:
                self.logger.info(f"✅ {service_name} started successfully (PID: {process.pid})")
                return True
            else:
                stdout, stderr = process.communicate()
                self.logger.error(f"❌ {service_name} failed to start")
                self.logger.error(f"stdout: {stdout}")
                self.logger.error(f"stderr: {stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error starting {service_name}: {e}")
            return False
            
    def check_service_health(self, service_name: str) -> bool:
        """Check if a service is healthy"""
        service_config = self.services[service_name]
        
        if service_config['port'] is None:
            # For services without HTTP endpoints, check if process is running
            process = service_config.get('process')
            return process and process.poll() is None
            
        try:
            url = f"http://localhost:{service_config['port']}"
            if service_name == 'realtime_waf':
                url += "/api/status"
                
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except Exception:
            return False
            
    def start_all_services(self):
        """Start all WAF services in order"""
        self.logger.info("🚀 Starting Transformer WAF System...")
        
        # Start services in dependency order
        service_order = [
            'log_processor',
            'continuous_trainer', 
            'realtime_waf',
            'streamlit_dashboard',
            'traffic_generator'
        ]
        
        started_services = []
        
        for service_name in service_order:
            if self.start_service(service_name):
                started_services.append(service_name)
                time.sleep(3)  # Wait between service starts
            else:
                self.logger.error(f"❌ Failed to start {service_name}")
                # Continue with other services
                
        self.logger.info(f"✅ Started {len(started_services)} services: {started_services}")
        return started_services
        
    def monitor_services(self):
        """Monitor running services"""
        self.logger.info("👁️ Starting service monitoring...")
        
        while self.running:
            try:
                status_report = {
                    'timestamp': datetime.now().isoformat(),
                    'services': {}
                }
                
                all_healthy = True
                
                for service_name, service_config in self.services.items():
                    is_healthy = self.check_service_health(service_name)
                    status_report['services'][service_name] = {
                        'status': 'healthy' if is_healthy else 'unhealthy',
                        'port': service_config['port'],
                        'pid': service_config['process'].pid if service_config['process'] else None
                    }
                    
                    if not is_healthy:
                        all_healthy = False
                        
                # Log status
                if all_healthy:
                    self.logger.info("💚 All services healthy")
                else:
                    unhealthy = [name for name, status in status_report['services'].items() 
                               if status['status'] == 'unhealthy']
                    self.logger.warning(f"⚠️ Unhealthy services: {unhealthy}")
                    
                # Save status report
                with open('logs/service_status.json', 'w') as f:
                    json.dump(status_report, f, indent=2)
                    
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"❌ Error in service monitoring: {e}")
                time.sleep(10)
                
    def show_dashboard_info(self):
        """Show information about accessing dashboards"""
        dashboard_info = f"""
🎛️ TRANSFORMER WAF DASHBOARDS
{'='*50}

🔴 Real-time WAF Dashboard:
   URL: http://localhost:8000
   Features: Live anomaly detection, system status, alerts

🔵 Streamlit Dashboard:  
   URL: http://localhost:8507
   Features: Interactive testing, model analysis, traffic simulation

🟢 System Status:
   Logs: tail -f logs/waf_integration.log
   Service Status: cat logs/service_status.json

🚨 To test anomaly detection:
   1. Open http://localhost:8000
   2. Generate test traffic with the traffic generator
   3. Monitor real-time alerts and anomalies
   
📊 Training Notebook:
   File: transformer_waf_training_notebook.ipynb
   Run with: jupyter notebook transformer_waf_training_notebook.ipynb

⚠️ To stop all services: Ctrl+C or run stop_waf_system.py
        """
        
        print(dashboard_info)
        self.logger.info("📋 Dashboard information displayed")
        
    def create_demo_script(self):
        """Create a demonstration script"""
        demo_script = '''#!/usr/bin/env python3
"""
Transformer WAF Live Demonstration Script
"""

import requests
import time
import json
from datetime import datetime

def test_waf_system():
    """Test the WAF system with various requests"""
    
    # Test endpoints
    waf_url = "http://localhost:8000"
    
    # Test cases
    test_requests = [
        # Benign requests
        {
            "method": "GET",
            "uri": "/index.html",
            "status": 200,
            "user_agent": "Mozilla/5.0",
            "description": "Normal homepage request"
        },
        {
            "method": "POST", 
            "uri": "/api/login",
            "status": 200,
            "user_agent": "Mozilla/5.0",
            "description": "Normal login request"
        },
        # Suspicious requests
        {
            "method": "GET",
            "uri": "/admin/../../../etc/passwd", 
            "status": 404,
            "user_agent": "curl/7.68.0",
            "description": "Directory traversal attempt"
        },
        {
            "method": "GET",
            "uri": "/search?q=<script>alert('XSS')</script>",
            "status": 200,
            "user_agent": "Mozilla/5.0",
            "description": "XSS injection attempt"  
        },
        {
            "method": "POST",
            "uri": "/api/users?id=1' UNION SELECT * FROM users--",
            "status": 200,
            "user_agent": "sqlmap/1.0",
            "description": "SQL injection attempt"
        }
    ]
    
    print("🧪 Testing Transformer WAF System")
    print("="*50)
    
    for i, test_case in enumerate(test_requests, 1):
        print(f"\\n{i}. Testing: {test_case['description']}")
        
        try:
            # Send test request to WAF
            response = requests.post(f"{waf_url}/api/test-anomaly", 
                                   json=test_case, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                prediction = result.get('prediction', {})
                
                print(f"   ✅ Response received")
                print(f"   🎯 Anomaly Score: {prediction.get('anomaly_score', 0):.3f}")
                print(f"   🔍 Is Anomaly: {prediction.get('is_anomaly', False)}")
                print(f"   📊 Confidence: {prediction.get('confidence', 0):.3f}")
            else:
                print(f"   ❌ Error: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Connection error: {e}")
            
        time.sleep(1)
    
    print("\\n🏁 Demonstration completed!")
    print("\\n📊 Check the dashboards for real-time results:")
    print("   - Real-time WAF: http://localhost:8000") 
    print("   - Streamlit Dashboard: http://localhost:8507")

if __name__ == "__main__":
    test_waf_system()
'''
        
        with open('demo_waf_system.py', 'w') as f:
            f.write(demo_script)
            
        # Make executable
        import stat
        st = Path('demo_waf_system.py').stat()
        Path('demo_waf_system.py').chmod(st.st_mode | stat.S_IEXEC)
        
        self.logger.info("📝 Demo script created: demo_waf_system.py")
        
    def stop_all_services(self):
        """Stop all running services"""
        self.logger.info("🛑 Stopping all WAF services...")
        self.running = False
        
        for service_name, process in self.processes.items():
            if process and process.poll() is None:
                try:
                    self.logger.info(f"🔄 Stopping {service_name} (PID: {process.pid})...")
                    process.terminate()
                    
                    # Wait for graceful shutdown
                    try:
                        process.wait(timeout=10)
                        self.logger.info(f"✅ {service_name} stopped gracefully")
                    except subprocess.TimeoutExpired:
                        self.logger.warning(f"⚠️ Force killing {service_name}...")
                        process.kill()
                        process.wait()
                        
                except Exception as e:
                    self.logger.error(f"❌ Error stopping {service_name}: {e}")
                    
        self.logger.info("🏁 All services stopped")
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"🛑 Received signal {signum}, shutting down...")
        self.stop_all_services()
        sys.exit(0)

async def main():
    """Main integration function"""
    # Create integration manager
    manager = WAFIntegrationManager()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, manager.signal_handler)
    signal.signal(signal.SIGTERM, manager.signal_handler)
    
    try:
        print("""
🛡️ TRANSFORMER WAF SYSTEM INTEGRATION
=====================================
        
This script will launch the complete Transformer-based 
Web Application Firewall system with the following components:

🔍 Live Log Processor - Real-time Tomcat log processing
🧠 Continuous Trainer - LogBERT model training on live data  
🚨 Real-time WAF Service - Anomaly detection and alerting
📊 Interactive Dashboards - Monitoring and testing interfaces
🚦 Traffic Generator - Realistic traffic simulation

Press Ctrl+C to stop all services.
        """)
        
        input("Press Enter to start the system...")
        
        # Check prerequisites
        if not manager.check_prerequisites():
            print("❌ Prerequisites check failed. Please install missing dependencies.")
            return
            
        # Install dependencies if needed
        manager.install_dependencies()
        
        # Start all services
        started_services = manager.start_all_services()
        
        if not started_services:
            print("❌ Failed to start any services")
            return
            
        # Show dashboard information
        manager.show_dashboard_info()
        
        # Create demo script
        manager.create_demo_script()
        
        # Start monitoring
        manager.running = True
        await asyncio.create_task(asyncio.to_thread(manager.monitor_services))
        
    except KeyboardInterrupt:
        print("\\n🛑 Shutdown requested...")
    except Exception as e:
        manager.logger.error(f"❌ Unexpected error: {e}")
    finally:
        manager.stop_all_services()

if __name__ == "__main__":
    asyncio.run(main())
