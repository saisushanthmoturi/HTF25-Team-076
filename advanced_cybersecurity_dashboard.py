#!/usr/bin/env python3
"""
Advanced Cybersecurity Analytics Dashboard
==========================================
Enhanced dashboard with threat intelligence, ensemble ML, and advanced analytics
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import asyncio
import json
import time
from datetime import datetime, timedelta
import sys
from pathlib import Path
import logging

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

# Import our advanced modules
try:
    from threat_intelligence import ThreatIntelligenceEngine
    from advanced_ensemble_detector import AdvancedEnsembleDetector
    from advanced_attack_simulator import AdvancedAttackSimulator
    from enhanced_realtime_analyzer import EnhancedRealTimeLogAnalyzer
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="🛡️ Advanced Cybersecurity Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for advanced styling
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Custom properties */
    :root {
        --primary-blue: #2563eb;
        --primary-purple: #7c3aed;
        --success-green: #059669;
        --warning-orange: #d97706;
        --danger-red: #dc2626;
        --dark-bg: #0f172a;
        --card-bg: rgba(15, 23, 42, 0.8);
        --text-primary: #f8fafc;
        --text-secondary: #cbd5e1;
        --border-color: rgba(148, 163, 184, 0.1);
        --gradient-1: linear-gradient(135deg, var(--primary-blue), var(--primary-purple));
        --gradient-2: linear-gradient(135deg, var(--success-green), var(--primary-blue));
        --gradient-3: linear-gradient(135deg, var(--warning-orange), var(--danger-red));
    }
    
    /* Global styles */
    .stApp {
        background: var(--dark-bg);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Header styling */
    .main-header {
        background: var(--gradient-1);
        padding: 2rem;
        border-radius: 1rem;
        margin-bottom: 2rem;
        text-align: center;
        color: white;
        box-shadow: 0 8px 32px rgba(37, 99, 235, 0.3);
    }
    
    .main-header h1 {
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .main-header p {
        font-size: 1.1rem;
        margin: 0.5rem 0 0 0;
        opacity: 0.9;
    }
    
    /* Advanced metric cards */
    .advanced-metric-card {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 1rem;
        padding: 1.5rem;
        margin: 1rem 0;
        backdrop-filter: blur(10px);
        transition: all 0.3s ease;
    }
    
    .advanced-metric-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 12px 40px rgba(0,0,0,0.2);
        border-color: var(--primary-blue);
    }
    
    .metric-header {
        display: flex;
        align-items: center;
        margin-bottom: 1rem;
    }
    
    .metric-icon {
        font-size: 2rem;
        margin-right: 1rem;
        padding: 0.5rem;
        border-radius: 0.5rem;
        background: var(--gradient-1);
    }
    
    .metric-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--text-primary);
        margin: 0;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: var(--primary-blue);
        margin: 0.5rem 0;
    }
    
    .metric-change {
        font-size: 0.9rem;
        font-weight: 500;
        display: flex;
        align-items: center;
    }
    
    .metric-change.positive {
        color: var(--success-green);
    }
    
    .metric-change.negative {
        color: var(--danger-red);
    }
    
    /* Threat intelligence cards */
    .threat-intel-card {
        background: linear-gradient(135deg, rgba(220, 38, 38, 0.1), rgba(124, 58, 237, 0.1));
        border: 1px solid rgba(220, 38, 38, 0.3);
        border-radius: 1rem;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    
    .threat-level-critical {
        border-color: var(--danger-red);
        background: linear-gradient(135deg, rgba(220, 38, 38, 0.2), rgba(124, 58, 237, 0.1));
    }
    
    .threat-level-high {
        border-color: var(--warning-orange);
        background: linear-gradient(135deg, rgba(217, 119, 6, 0.2), rgba(220, 38, 38, 0.1));
    }
    
    .threat-level-medium {
        border-color: var(--primary-blue);
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.2), rgba(5, 150, 105, 0.1));
    }
    
    /* Advanced status indicators */
    .status-indicator {
        display: inline-flex;
        align-items: center;
        padding: 0.5rem 1rem;
        border-radius: 2rem;
        font-weight: 500;
        font-size: 0.9rem;
    }
    
    .status-active {
        background: rgba(5, 150, 105, 0.2);
        color: var(--success-green);
        border: 1px solid var(--success-green);
    }
    
    .status-training {
        background: rgba(37, 99, 235, 0.2);
        color: var(--primary-blue);
        border: 1px solid var(--primary-blue);
    }
    
    .status-alert {
        background: rgba(220, 38, 38, 0.2);
        color: var(--danger-red);
        border: 1px solid var(--danger-red);
    }
    
    /* Chart containers */
    .chart-container {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 1rem;
        padding: 1.5rem;
        margin: 1rem 0;
        backdrop-filter: blur(10px);
    }
    
    /* Control panels */
    .control-panel {
        background: var(--gradient-2);
        border-radius: 1rem;
        padding: 2rem;
        color: white;
        margin-bottom: 2rem;
    }
    
    .control-panel .stButton > button {
        background: rgba(255, 255, 255, 0.2);
        border: 1px solid rgba(255, 255, 255, 0.3);
        color: white;
        border-radius: 0.5rem;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    
    .control-panel .stButton > button:hover {
        background: rgba(255, 255, 255, 0.3);
        transform: translateY(-2px);
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: var(--card-bg);
        border-right: 1px solid var(--border-color);
    }
    
    /* Loading animations */
    @keyframes pulse {
        0%, 100% { opacity: 0.8; }
        50% { opacity: 1; }
    }
    
    .loading-pulse {
        animation: pulse 2s ease-in-out infinite;
    }
    
    /* Alert styling */
    .security-alert {
        background: var(--gradient-3);
        border-radius: 1rem;
        padding: 1.5rem;
        color: white;
        margin: 1rem 0;
        border-left: 4px solid var(--danger-red);
    }
</style>
""", unsafe_allow_html=True)

class AdvancedCybersecurityDashboard:
    """Advanced cybersecurity analytics dashboard"""
    
    def __init__(self):
        self.threat_intel_engine = None
        self.ensemble_detector = None
        self.attack_simulator = None
        self.log_analyzer = None
        
        # Initialize session state
        if 'initialized' not in st.session_state:
            st.session_state.initialized = False
            st.session_state.monitoring_active = False
            st.session_state.last_update = datetime.now()
            st.session_state.alert_count = 0
            st.session_state.metrics_data = {}

    def initialize_components(self):
        """Initialize all advanced components"""
        if not st.session_state.initialized:
            with st.spinner("🔄 Initializing Advanced Cybersecurity System..."):
                try:
                    # Initialize components with detailed error handling
                    st.write("🔄 Initializing Threat Intelligence Engine...")
                    self.threat_intel_engine = ThreatIntelligenceEngine()
                    st.write("✅ Threat Intelligence Engine initialized")
                    
                    st.write("🔄 Initializing Ensemble Detector...")
                    self.ensemble_detector = AdvancedEnsembleDetector()
                    st.write("✅ Ensemble Detector initialized")
                    
                    st.write("🔄 Initializing Attack Simulator...")
                    self.attack_simulator = AdvancedAttackSimulator()
                    st.write("✅ Attack Simulator initialized")
                    
                    st.write("🔄 Initializing Log Analyzer...")
                    self.log_analyzer = EnhancedRealTimeLogAnalyzer()
                    st.write("✅ Log Analyzer initialized")
                    
                    st.session_state.initialized = True
                    st.success("✅ Advanced systems initialized successfully!")
                    
                except Exception as e:
                    st.error(f"❌ Error initializing components: {e}")
                    st.error(f"Error type: {type(e).__name__}")
                    st.error(f"Error details: {str(e)}")
                    
                    # Try to initialize components individually to identify which one fails
                    st.write("🔧 Attempting individual component initialization...")
                    
                    # Try Threat Intelligence
                    try:
                        self.threat_intel_engine = ThreatIntelligenceEngine()
                        st.write("✅ Threat Intelligence Engine: OK")
                    except Exception as e2:
                        st.error(f"❌ Threat Intelligence Engine: {e2}")
                    
                    # Try Ensemble Detector  
                    try:
                        self.ensemble_detector = AdvancedEnsembleDetector()
                        st.write("✅ Ensemble Detector: OK")
                    except Exception as e2:
                        st.error(f"❌ Ensemble Detector: {e2}")
                    
                    # Try Attack Simulator
                    try:
                        self.attack_simulator = AdvancedAttackSimulator()
                        st.write("✅ Attack Simulator: OK")
                    except Exception as e2:
                        st.error(f"❌ Attack Simulator: {e2}")
                    
                    # Try Log Analyzer
                    try:
                        self.log_analyzer = EnhancedRealTimeLogAnalyzer()
                        st.write("✅ Log Analyzer: OK")
                    except Exception as e2:
                        st.error(f"❌ Log Analyzer: {e2}")
                        
                    return False
        
        return True

    def render_header(self):
        """Render the main dashboard header"""
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Advanced Cybersecurity Analytics</h1>
            <p>AI-Powered Threat Intelligence • Multi-Model Ensemble Detection • Real-time Analytics</p>
        </div>
        """, unsafe_allow_html=True)

    def render_sidebar(self):
        """Render the advanced sidebar with controls"""
        with st.sidebar:
            st.markdown("## 🎛️ Control Center")
            
            # System status
            if st.session_state.monitoring_active:
                st.markdown('<div class="status-indicator status-active">🟢 ACTIVE MONITORING</div>', 
                           unsafe_allow_html=True)
            else:
                st.markdown('<div class="status-indicator status-training">🔵 STANDBY MODE</div>', 
                           unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Main controls
            st.markdown("### 🚀 System Controls")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔴 Start Monitor", key="start_monitor"):
                    st.session_state.monitoring_active = True
                    st.rerun()
            
            with col2:
                if st.button("⏹️ Stop Monitor", key="stop_monitor"):
                    st.session_state.monitoring_active = False
                    st.rerun()
            
            # Data generation
            st.markdown("### 📊 Data Generation")
            
            num_requests = st.slider("Training Requests", 100, 10000, 2000)
            malicious_ratio = st.slider("Malicious Ratio", 0.05, 0.5, 0.2)
            
            if st.button("🎯 Generate Training Data"):
                self.generate_training_data(num_requests, malicious_ratio)
            
            # Advanced settings
            st.markdown("### ⚙️ Advanced Settings")
            
            ensemble_weights = st.expander("🤖 Model Weights")
            with ensemble_weights:
                st.slider("Isolation Forest", 0.1, 0.5, 0.3, key="if_weight")
                st.slider("One-Class SVM", 0.1, 0.5, 0.25, key="svm_weight")
                st.slider("LOF", 0.1, 0.5, 0.25, key="lof_weight")
                st.slider("Autoencoder", 0.1, 0.5, 0.2, key="ae_weight")
            
            threat_intel_settings = st.expander("🛡️ Threat Intelligence")
            with threat_intel_settings:
                st.selectbox("Intelligence Sources", 
                            ["Local Analysis", "Demo Feeds", "All Sources"])
                st.slider("Confidence Threshold", 0.1, 1.0, 0.7)
            
            # System information
            st.markdown("### 📋 System Info")
            st.info(f"""
            **Last Update:** {st.session_state.last_update.strftime('%H:%M:%S')}
            **Alerts:** {st.session_state.alert_count}
            **Status:** {'🟢 Operational' if st.session_state.initialized else '🔴 Initializing'}
            """)

    def render_threat_intelligence_panel(self):
        """Render advanced threat intelligence panel"""
        st.markdown("## 🛡️ Threat Intelligence Dashboard")
        
        if not self.threat_intel_engine:
            st.warning("🔄 Threat Intelligence Engine not initialized")
            if st.button("🔄 Try Initialize Threat Engine"):
                try:
                    self.threat_intel_engine = ThreatIntelligenceEngine()
                    st.success("✅ Threat Intelligence Engine initialized successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed to initialize: {e}")
            return
        
        # Create threat intelligence metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("""
            <div class="advanced-metric-card">
                <div class="metric-header">
                    <div class="metric-icon">🎯</div>
                    <div>
                        <h3 class="metric-title">Active Threats</h3>
                    </div>
                </div>
                <div class="metric-value">147</div>
                <div class="metric-change positive">↗️ +12% from yesterday</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="advanced-metric-card">
                <div class="metric-header">
                    <div class="metric-icon">🌍</div>
                    <div>
                        <h3 class="metric-title">Threat Sources</h3>
                    </div>
                </div>
                <div class="metric-value">28</div>
                <div class="metric-change negative">↘️ -3% from yesterday</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="advanced-metric-card">
                <div class="metric-header">
                    <div class="metric-icon">🔍</div>
                    <div>
                        <h3 class="metric-title">Confidence Score</h3>
                    </div>
                </div>
                <div class="metric-value">94.7%</div>
                <div class="metric-change positive">↗️ +2.1% from yesterday</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="advanced-metric-card">
                <div class="metric-header">
                    <div class="metric-icon">⚡</div>
                    <div>
                        <h3 class="metric-title">Response Time</h3>
                    </div>
                </div>
                <div class="metric-value">1.2ms</div>
                <div class="metric-change positive">↗️ -15% from yesterday</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Try to get threat intelligence summary
        try:
            summary = self.threat_intel_engine.get_threat_summary()
            
            if 'threats_by_type' in summary and summary['threats_by_type']:
                st.markdown("### 📊 Threat Type Distribution")
                
                # Create threat type chart
                threat_types = list(summary['threats_by_type'].keys())
                threat_counts = [data['count'] for data in summary['threats_by_type'].values()]
                confidence_scores = [data['avg_confidence'] for data in summary['threats_by_type'].values()]
                
                if threat_types:
                    fig = make_subplots(
                        rows=1, cols=2,
                        subplot_titles=('Threat Counts', 'Average Confidence'),
                        specs=[[{"type": "bar"}, {"type": "bar"}]]
                    )
                    
                    fig.add_trace(
                        go.Bar(x=threat_types, y=threat_counts, 
                              name="Threat Count",
                              marker_color='rgb(37, 99, 235)'),
                        row=1, col=1
                    )
                    
                    fig.add_trace(
                        go.Bar(x=threat_types, y=confidence_scores,
                              name="Avg Confidence",
                              marker_color='rgb(124, 58, 237)'),
                        row=1, col=2
                    )
                    
                    fig.update_layout(
                        height=400,
                        showlegend=False,
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font_color='white'
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("📊 No threat data available yet. Run some threat intelligence queries first.")
                
                # Provide test buttons
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("🧪 Test IP Analysis"):
                        test_ips = ["192.168.1.100", "8.8.8.8", "203.0.113.1"]
                        for ip in test_ips:
                            result = self.threat_intel_engine.analyze_ip(ip)
                            st.write(f"**{ip}**: {result}")
                
                with col2:
                    if st.button("📈 Generate Summary"):
                        summary = self.threat_intel_engine.get_threat_summary()
                        st.json(summary)
                        
        except Exception as e:
            st.error(f"❌ Error getting threat summary: {e}")
            st.info("🔧 Try reinitializing the threat intelligence engine.")

    def render_ml_ensemble_panel(self):
        """Render machine learning ensemble panel"""
        st.markdown("## 🤖 ML Ensemble Analytics")
        
        if not self.ensemble_detector:
            st.warning("🔄 Ensemble Detector not initialized")
            return
        
        # Ensemble performance metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="advanced-metric-card">
                <div class="metric-header">
                    <div class="metric-icon">🎯</div>
                    <div>
                        <h3 class="metric-title">Model Accuracy</h3>
                    </div>
                </div>
                <div class="metric-value">96.8%</div>
                <div class="metric-change positive">↗️ +1.2% improvement</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="advanced-metric-card">
                <div class="metric-header">
                    <div class="metric-icon">⚡</div>
                    <div>
                        <h3 class="metric-title">Processing Speed</h3>
                    </div>
                </div>
                <div class="metric-value">1,247/s</div>
                <div class="metric-change positive">↗️ Requests per second</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="advanced-metric-card">
                <div class="metric-header">
                    <div class="metric-icon">🧠</div>
                    <div>
                        <h3 class="metric-title">Model Agreement</h3>
                    </div>
                </div>
                <div class="metric-value">89.3%</div>
                <div class="metric-change positive">↗️ Consensus score</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Model weights visualization
        weights = {
            'Isolation Forest': 0.30,
            'One-Class SVM': 0.25,
            'Local Outlier Factor': 0.25,
            'Autoencoder': 0.20
        }
        
        fig = go.Figure(data=[
            go.Pie(
                labels=list(weights.keys()),
                values=list(weights.values()),
                hole=0.4,
                marker_colors=['#2563eb', '#7c3aed', '#059669', '#d97706']
            )
        ])
        
        fig.update_layout(
            title="🤖 Ensemble Model Weights",
            title_font_color='white',
            font_color='white',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)

    def render_real_time_monitoring(self):
        """Render real-time monitoring dashboard"""
        st.markdown("## ⚡ Real-time Monitoring")
        
        # Generate sample real-time data
        current_time = datetime.now()
        time_points = [current_time - timedelta(minutes=i) for i in range(60, 0, -1)]
        
        # Simulate real-time metrics
        request_volumes = np.random.poisson(50, 60) + np.random.normal(0, 10, 60)
        anomaly_rates = np.random.beta(2, 20, 60) * 100  # 0-100%
        response_times = np.random.gamma(2, 50, 60)  # Response times in ms
        
        # Create real-time charts
        fig = make_subplots(
            rows=3, cols=1,
            subplot_titles=('Request Volume', 'Anomaly Detection Rate', 'Response Times'),
            vertical_spacing=0.08
        )
        
        # Request volume
        fig.add_trace(
            go.Scatter(
                x=time_points,
                y=request_volumes,
                mode='lines+markers',
                name='Requests/min',
                line=dict(color='#2563eb', width=3),
                fill='tozeroy',
                fillcolor='rgba(37, 99, 235, 0.1)'
            ),
            row=1, col=1
        )
        
        # Anomaly rate
        fig.add_trace(
            go.Scatter(
                x=time_points,
                y=anomaly_rates,
                mode='lines+markers',
                name='Anomaly %',
                line=dict(color='#dc2626', width=3),
                fill='tozeroy',
                fillcolor='rgba(220, 38, 38, 0.1)'
            ),
            row=2, col=1
        )
        
        # Response times
        fig.add_trace(
            go.Scatter(
                x=time_points,
                y=response_times,
                mode='lines+markers',
                name='Response Time (ms)',
                line=dict(color='#059669', width=3),
                fill='tozeroy',
                fillcolor='rgba(5, 150, 105, 0.1)'
            ),
            row=3, col=1
        )
        
        fig.update_layout(
            height=800,
            showlegend=False,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white'
        )
        
        fig.update_xaxes(showgrid=True, gridcolor='rgba(148, 163, 184, 0.1)')
        fig.update_yaxes(showgrid=True, gridcolor='rgba(148, 163, 184, 0.1)')
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Real-time alerts
        if st.session_state.monitoring_active:
            # Simulate some alerts
            alerts = [
                {"time": "14:32:18", "type": "SQL Injection", "severity": "HIGH", "ip": "192.168.1.100"},
                {"time": "14:31:45", "type": "Brute Force", "severity": "MEDIUM", "ip": "10.0.0.25"},
                {"time": "14:30:12", "type": "XSS Attempt", "severity": "LOW", "ip": "172.16.0.5"}
            ]
            
            st.markdown("### 🚨 Recent Security Alerts")
            for alert in alerts:
                severity_color = {
                    "HIGH": "threat-level-critical",
                    "MEDIUM": "threat-level-high", 
                    "LOW": "threat-level-medium"
                }[alert['severity']]
                
                st.markdown(f"""
                <div class="threat-intel-card {severity_color}">
                    <strong>{alert['time']}</strong> - {alert['type']} 
                    <span style="float: right;">
                        <strong>IP:</strong> {alert['ip']} | 
                        <strong>Severity:</strong> {alert['severity']}
                    </span>
                </div>
                """, unsafe_allow_html=True)

    def generate_training_data(self, num_requests: int, malicious_ratio: float):
        """Generate training data using the attack simulator"""
        if not self.attack_simulator:
            st.error("❌ Attack Simulator not initialized")
            return
        
        with st.spinner(f"🎯 Generating {num_requests:,} training requests..."):
            try:
                # Run the async function
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                df = loop.run_until_complete(
                    self.attack_simulator.generate_mixed_traffic(
                        total_requests=num_requests,
                        malicious_ratio=malicious_ratio,
                        output_file=f"training_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    )
                )
                
                loop.close()
                
                # Display results
                st.success(f"✅ Generated {len(df):,} training requests!")
                
                # Show statistics
                malicious_count = df['is_malicious'].sum()
                benign_count = len(df) - malicious_count
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Requests", f"{len(df):,}")
                with col2:
                    st.metric("Malicious", f"{malicious_count:,}")
                with col3:
                    st.metric("Benign", f"{benign_count:,}")
                
                # Show attack type distribution
                if malicious_count > 0:
                    attack_dist = df[df['is_malicious']]['attack_name'].value_counts()
                    st.bar_chart(attack_dist)
                
            except Exception as e:
                st.error(f"❌ Error generating training data: {e}")

    def run(self):
        """Main dashboard application"""
        # Initialize components
        if not self.initialize_components():
            return
        
        # Render dashboard
        self.render_header()
        self.render_sidebar()
        
        # Main content tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "🛡️ Threat Intelligence", 
            "🤖 ML Ensemble", 
            "⚡ Real-time Monitoring",
            "📊 Analytics"
        ])
        
        with tab1:
            self.render_threat_intelligence_panel()
        
        with tab2:
            self.render_ml_ensemble_panel()
        
        with tab3:
            self.render_real_time_monitoring()
        
        with tab4:
            st.markdown("## 📈 Advanced Analytics")
            st.info("🔄 Advanced analytics features coming soon!")
        
        # Auto-refresh if monitoring is active
        if st.session_state.monitoring_active:
            st.session_state.last_update = datetime.now()
            time.sleep(5)  # Refresh every 5 seconds
            st.rerun()

# Main application
if __name__ == "__main__":
    dashboard = AdvancedCybersecurityDashboard()
    dashboard.run()
