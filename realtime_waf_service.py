#!/usr/bin/env python3
"""
Real-time WAF Service
Integrates all components for live anomaly detection on Tomcat logs
"""

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import websockets
import queue
import threading

# Import WAF components
from live_log_processor import LiveLogProcessor
from continuous_logbert_trainer import ContinuousTrainer
from waf_inference_service import WAFInferenceService

class AlertRequest(BaseModel):
    message: str
    severity: str
    timestamp: Optional[str] = None

class WAFServiceConfig(BaseModel):
    log_directories: List[str]
    model_path: str = "models/logbert_model.pth"
    enable_continuous_training: bool = True
    alert_threshold: float = 0.7
    max_alerts_per_minute: int = 100

class RealTimeWAFService:
    """Real-time WAF service integrating all components"""
    
    def __init__(self, config: WAFServiceConfig):
        self.config = config
        self.app = FastAPI(title="Transformer WAF", version="1.0.0")
        
        # Core components
        self.log_processor = None
        self.continuous_trainer = None
        self.inference_service = None
        
        # Alert management
        self.alert_queue = queue.Queue(maxsize=1000)
        self.alert_history = []
        self.websocket_connections = set()
        
        # Statistics
        self.service_stats = {
            'start_time': datetime.now(),
            'total_requests': 0,
            'total_anomalies': 0,
            'total_alerts': 0,
            'uptime': '0:00:00'
        }
        
        # Setup logging
        self.setup_logging()
        
        # Setup FastAPI routes
        self.setup_routes()
        
    def setup_logging(self):
        """Setup logging for the service"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('logs/realtime_waf_service.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('RealTimeWAFService')
        
    def setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard():
            """Main dashboard"""
            return await self.get_dashboard_html()
            
        @self.app.get("/api/status")
        async def get_status():
            """Get service status"""
            return await self.get_service_status()
            
        @self.app.get("/api/stats")
        async def get_stats():
            """Get service statistics"""
            return await self.get_service_statistics()
            
        @self.app.get("/api/anomalies")
        async def get_anomalies():
            """Get recent anomalies"""
            return await self.get_recent_anomalies()
            
        @self.app.get("/api/alerts")
        async def get_alerts():
            """Get recent alerts"""
            return await self.get_recent_alerts()
            
        @self.app.post("/api/test-anomaly")
        async def test_anomaly(log_entry: Dict):
            """Test anomaly detection on a log entry"""
            return await self.test_anomaly_detection(log_entry)
            
        @self.app.post("/api/alert")
        async def create_alert(alert: AlertRequest):
            """Create a manual alert"""
            return await self.create_manual_alert(alert)
            
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket):
            """WebSocket endpoint for real-time updates"""
            await self.handle_websocket(websocket)
            
    async def initialize(self):
        """Initialize all WAF components"""
        self.logger.info("Initializing Real-time WAF Service...")
        
        # Create directories
        Path("logs").mkdir(exist_ok=True)
        Path("models").mkdir(exist_ok=True)
        Path("alerts").mkdir(exist_ok=True)
        
        try:
            # Initialize log processor
            self.log_processor = LiveLogProcessor(self.config.log_directories)
            await self.log_processor.initialize()
            
            # Initialize inference service
            self.inference_service = WAFInferenceService()
            await self.inference_service.initialize()
            
            # Initialize continuous trainer if enabled
            if self.config.enable_continuous_training:
                self.continuous_trainer = ContinuousTrainer()
                await self.continuous_trainer.initialize()
                
            self.logger.info("All WAF components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing WAF components: {e}")
            raise
            
    async def start(self):
        """Start all WAF services"""
        self.logger.info("Starting Real-time WAF Service...")
        
        try:
            # Start log processor
            await self.log_processor.start()
            
            # Start continuous trainer if enabled
            if self.continuous_trainer:
                await self.continuous_trainer.start()
                
            # Start background tasks
            asyncio.create_task(self.anomaly_monitoring_task())
            asyncio.create_task(self.alert_processing_task())
            asyncio.create_task(self.statistics_update_task())
            asyncio.create_task(self.training_integration_task())
            
            self.logger.info("All WAF services started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting WAF services: {e}")
            raise
            
    async def anomaly_monitoring_task(self):
        """Background task for monitoring anomalies"""
        self.logger.info("Started anomaly monitoring task")
        
        while True:
            try:
                # Get anomalies from log processor
                anomalies = self.log_processor.get_anomalies(max_count=50)
                
                for anomaly in anomalies:
                    await self.process_anomaly(anomaly)
                    
                await asyncio.sleep(1.0)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Error in anomaly monitoring task: {e}")
                await asyncio.sleep(5.0)
                
    async def process_anomaly(self, anomaly: Dict):
        """Process a detected anomaly"""
        try:
            log_entry = anomaly['log_entry']
            prediction = anomaly['prediction']
            anomaly_score = anomaly.get('anomaly_score', 0.0)
            
            # Update statistics
            self.service_stats['total_anomalies'] += 1
            
            # Check if alert threshold is met
            if anomaly_score >= self.config.alert_threshold:
                alert = {
                    'id': f"alert_{datetime.now().timestamp()}",
                    'timestamp': datetime.now().isoformat(),
                    'severity': self.get_alert_severity(anomaly_score),
                    'message': f"Anomalous request detected: {log_entry['method']} {log_entry['uri']}",
                    'details': {
                        'anomaly_score': anomaly_score,
                        'log_entry': log_entry,
                        'prediction': prediction
                    }
                }
                
                await self.create_alert(alert)
                
            # Send real-time update via WebSocket
            await self.broadcast_websocket_update({
                'type': 'anomaly',
                'data': anomaly
            })
            
        except Exception as e:
            self.logger.error(f"Error processing anomaly: {e}")
            
    async def create_alert(self, alert: Dict):
        """Create and process an alert"""
        try:
            # Add to alert queue
            self.alert_queue.put_nowait(alert)
            
            # Add to history
            self.alert_history.append(alert)
            
            # Keep only recent alerts
            if len(self.alert_history) > 1000:
                self.alert_history = self.alert_history[-1000:]
                
            # Update statistics
            self.service_stats['total_alerts'] += 1
            
            # Log alert
            self.logger.warning(f"ALERT: {alert['message']}")
            
            # Save alert to file
            await self.save_alert_to_file(alert)
            
        except Exception as e:
            self.logger.error(f"Error creating alert: {e}")
            
    async def save_alert_to_file(self, alert: Dict):
        """Save alert to file"""
        try:
            alert_file = Path("alerts") / f"alerts_{datetime.now().strftime('%Y%m%d')}.json"
            
            # Read existing alerts
            alerts = []
            if alert_file.exists():
                with open(alert_file, 'r') as f:
                    alerts = json.load(f)
                    
            # Add new alert
            alerts.append(alert)
            
            # Write back
            with open(alert_file, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Error saving alert to file: {e}")
            
    def get_alert_severity(self, anomaly_score: float) -> str:
        """Determine alert severity based on anomaly score"""
        if anomaly_score >= 0.9:
            return "critical"
        elif anomaly_score >= 0.8:
            return "high"
        elif anomaly_score >= 0.7:
            return "medium"
        else:
            return "low"
            
    async def alert_processing_task(self):
        """Background task for processing alerts"""
        self.logger.info("Started alert processing task")
        
        while True:
            try:
                # Process alerts from queue
                alerts_processed = 0
                while not self.alert_queue.empty() and alerts_processed < 10:
                    try:
                        alert = self.alert_queue.get_nowait()
                        await self.process_alert(alert)
                        alerts_processed += 1
                    except queue.Empty:
                        break
                        
                await asyncio.sleep(1.0)
                
            except Exception as e:
                self.logger.error(f"Error in alert processing task: {e}")
                await asyncio.sleep(5.0)
                
    async def process_alert(self, alert: Dict):
        """Process an individual alert"""
        try:
            # Send via WebSocket
            await self.broadcast_websocket_update({
                'type': 'alert',
                'data': alert
            })
            
            # Additional alert processing can be added here
            # (e.g., send to SIEM, email notifications, etc.)
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")
            
    async def statistics_update_task(self):
        """Background task for updating statistics"""
        while True:
            try:
                # Update uptime
                uptime = datetime.now() - self.service_stats['start_time']
                self.service_stats['uptime'] = str(uptime).split('.')[0]
                
                # Get component statistics
                if self.log_processor:
                    log_stats = self.log_processor.get_stats()
                    self.service_stats.update({
                        'logs_processed': log_stats.get('logs_processed', 0),
                        'processing_rate': log_stats.get('processing_rate', 0.0)
                    })
                    
                if self.continuous_trainer:
                    training_stats = self.continuous_trainer.get_training_stats()
                    self.service_stats.update({
                        'total_samples_trained': training_stats.get('total_samples_trained', 0),
                        'training_iterations': training_stats.get('training_iterations', 0)
                    })
                    
                await asyncio.sleep(10)  # Update every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error in statistics update task: {e}")
                await asyncio.sleep(10)
                
    async def training_integration_task(self):
        """Background task for integrating training with log processing"""
        if not self.continuous_trainer:
            return
            
        self.logger.info("Started training integration task")
        
        while True:
            try:
                # Get processed logs for training
                if hasattr(self.log_processor, 'processed_log_queue'):
                    processed_logs = []
                    
                    # Collect a batch of logs
                    for _ in range(50):  # Process up to 50 logs at a time
                        try:
                            log_entry = self.log_processor.processed_log_queue.get_nowait()
                            processed_logs.append(log_entry)
                        except queue.Empty:
                            break
                            
                    # Add to training
                    for log_entry in processed_logs:
                        self.continuous_trainer.add_training_sample(log_entry)
                        
                await asyncio.sleep(5.0)  # Process every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in training integration task: {e}")
                await asyncio.sleep(10)
                
    async def broadcast_websocket_update(self, update: Dict):
        """Broadcast update to all WebSocket connections"""
        if not self.websocket_connections:
            return
            
        message = json.dumps(update, default=str)
        disconnected = set()
        
        for websocket in self.websocket_connections.copy():
            try:
                await websocket.send_text(message)
            except Exception:
                disconnected.add(websocket)
                
        # Remove disconnected WebSockets
        self.websocket_connections -= disconnected
        
    async def handle_websocket(self, websocket):
        """Handle WebSocket connection"""
        await websocket.accept()
        self.websocket_connections.add(websocket)
        
        try:
            while True:
                # Keep connection alive
                await websocket.receive_text()
        except Exception:
            pass
        finally:
            self.websocket_connections.discard(websocket)
            
    async def get_service_status(self):
        """Get current service status"""
        status = {
            'service': 'running',
            'components': {
                'log_processor': 'running' if self.log_processor else 'stopped',
                'inference_service': 'running' if self.inference_service else 'stopped',
                'continuous_trainer': 'running' if self.continuous_trainer else 'disabled'
            },
            'timestamp': datetime.now().isoformat()
        }
        return JSONResponse(content=status)
        
    async def get_service_statistics(self):
        """Get service statistics"""
        return JSONResponse(content=self.service_stats)
        
    async def get_recent_anomalies(self, limit: int = 50):
        """Get recent anomalies"""
        anomalies = []
        if self.log_processor:
            anomalies = self.log_processor.get_anomalies(max_count=limit)
        return JSONResponse(content=anomalies)
        
    async def get_recent_alerts(self, limit: int = 50):
        """Get recent alerts"""
        recent_alerts = self.alert_history[-limit:] if self.alert_history else []
        return JSONResponse(content=recent_alerts)
        
    async def test_anomaly_detection(self, log_entry: Dict):
        """Test anomaly detection on a log entry"""
        try:
            if not self.inference_service:
                raise HTTPException(status_code=503, detail="Inference service not available")
                
            # Extract features
            features = {
                'template': log_entry.get('template', ''),
                'method': log_entry.get('method', ''),
                'uri': log_entry.get('uri', ''),
                'status': log_entry.get('status', 0),
                'user_agent': log_entry.get('user_agent', '')
            }
            
            # Run inference
            prediction = await self.inference_service.predict(features)
            
            return JSONResponse(content={
                'log_entry': log_entry,
                'prediction': prediction,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error in anomaly detection: {e}")
            
    async def create_manual_alert(self, alert: AlertRequest):
        """Create a manual alert"""
        alert_data = {
            'id': f"manual_{datetime.now().timestamp()}",
            'timestamp': alert.timestamp or datetime.now().isoformat(),
            'severity': alert.severity,
            'message': alert.message,
            'type': 'manual',
            'details': {}
        }
        
        await self.create_alert(alert_data)
        return JSONResponse(content=alert_data)
        
    async def get_dashboard_html(self):
        """Get dashboard HTML"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Transformer WAF - Real-time Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
                .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .stat-value { font-size: 2em; font-weight: bold; color: #667eea; }
                .stat-label { color: #666; margin-top: 5px; }
                .alerts-section { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .alert-item { padding: 10px; border-left: 4px solid #f39c12; background: #fff3cd; margin: 10px 0; border-radius: 4px; }
                .alert-critical { border-left-color: #e74c3c; background: #f8d7da; }
                .alert-high { border-left-color: #fd7e14; background: #fff3cd; }
                .alert-medium { border-left-color: #ffc107; background: #fff8cd; }
                .alert-low { border-left-color: #28a745; background: #d4edda; }
                .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
                .status-running { background-color: #28a745; }
                .status-stopped { background-color: #dc3545; }
                .status-disabled { background-color: #6c757d; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Transformer WAF Dashboard</h1>
                    <p>Real-time Web Application Firewall with LogBERT Anomaly Detection</p>
                </div>
                
                <div class="stats-grid" id="stats-grid">
                    <!-- Stats will be loaded here -->
                </div>
                
                <div class="alerts-section">
                    <h2>🚨 Recent Alerts</h2>
                    <div id="alerts-container">
                        <!-- Alerts will be loaded here -->
                    </div>
                </div>
                
                <div class="alerts-section">
                    <h2>📊 System Status</h2>
                    <div id="status-container">
                        <!-- Status will be loaded here -->
                    </div>
                </div>
            </div>
            
            <script>
                // WebSocket connection for real-time updates
                const ws = new WebSocket('ws://localhost:8000/ws');
                
                ws.onmessage = function(event) {
                    const update = JSON.parse(event.data);
                    handleUpdate(update);
                };
                
                function handleUpdate(update) {
                    if (update.type === 'alert') {
                        addAlert(update.data);
                    } else if (update.type === 'anomaly') {
                        updateStats();
                    }
                }
                
                function addAlert(alert) {
                    const container = document.getElementById('alerts-container');
                    const alertElement = document.createElement('div');
                    alertElement.className = `alert-item alert-${alert.severity}`;
                    alertElement.innerHTML = `
                        <strong>${alert.severity.toUpperCase()}</strong> - ${alert.message}
                        <br><small>${alert.timestamp}</small>
                    `;
                    container.insertBefore(alertElement, container.firstChild);
                    
                    // Keep only last 10 alerts
                    while (container.children.length > 10) {
                        container.removeChild(container.lastChild);
                    }
                }
                
                async function updateStats() {
                    try {
                        const response = await fetch('/api/stats');
                        const stats = await response.json();
                        
                        const statsGrid = document.getElementById('stats-grid');
                        statsGrid.innerHTML = `
                            <div class="stat-card">
                                <div class="stat-value">${stats.total_requests || 0}</div>
                                <div class="stat-label">Total Requests</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${stats.total_anomalies || 0}</div>
                                <div class="stat-label">Anomalies Detected</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${stats.total_alerts || 0}</div>
                                <div class="stat-label">Alerts Generated</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${(stats.processing_rate || 0).toFixed(1)}</div>
                                <div class="stat-label">Logs/sec</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${stats.total_samples_trained || 0}</div>
                                <div class="stat-label">Samples Trained</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${stats.uptime || '0:00:00'}</div>
                                <div class="stat-label">Uptime</div>
                            </div>
                        `;
                    } catch (error) {
                        console.error('Error updating stats:', error);
                    }
                }
                
                async function updateStatus() {
                    try {
                        const response = await fetch('/api/status');
                        const status = await response.json();
                        
                        const statusContainer = document.getElementById('status-container');
                        const components = status.components || {};
                        
                        statusContainer.innerHTML = `
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                                <div>
                                    <span class="status-indicator status-${components.log_processor === 'running' ? 'running' : 'stopped'}"></span>
                                    Log Processor: ${components.log_processor || 'unknown'}
                                </div>
                                <div>
                                    <span class="status-indicator status-${components.inference_service === 'running' ? 'running' : 'stopped'}"></span>
                                    Inference Service: ${components.inference_service || 'unknown'}
                                </div>
                                <div>
                                    <span class="status-indicator status-${components.continuous_trainer === 'running' ? 'running' : components.continuous_trainer === 'disabled' ? 'disabled' : 'stopped'}"></span>
                                    Continuous Trainer: ${components.continuous_trainer || 'unknown'}
                                </div>
                            </div>
                        `;
                    } catch (error) {
                        console.error('Error updating status:', error);
                    }
                }
                
                // Initial load and periodic updates
                updateStats();
                updateStatus();
                setInterval(updateStats, 10000);  // Update stats every 10 seconds
                setInterval(updateStatus, 30000); // Update status every 30 seconds
            </script>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)
        
    async def stop(self):
        """Stop all WAF services"""
        self.logger.info("Stopping Real-time WAF Service...")
        
        try:
            # Stop components
            if self.log_processor:
                await self.log_processor.stop()
                
            if self.continuous_trainer:
                await self.continuous_trainer.stop()
                
            self.logger.info("Real-time WAF Service stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping WAF services: {e}")

async def main():
    """Main function"""
    # Configuration
    config = WAFServiceConfig(
        log_directories=[
            "/opt/tomcat/logs",
            "/var/log/tomcat",
            "logs"
        ],
        enable_continuous_training=True,
        alert_threshold=0.7
    )
    
    # Create service
    waf_service = RealTimeWAFService(config)
    
    try:
        # Initialize and start
        await waf_service.initialize()
        await waf_service.start()
        
        # Start FastAPI server
        server_config = uvicorn.Config(
            app=waf_service.app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )
        server = uvicorn.Server(server_config)
        
        await server.serve()
        
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await waf_service.stop()

if __name__ == "__main__":
    asyncio.run(main())
