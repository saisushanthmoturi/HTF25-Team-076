"""
Advanced Real-time LogBERT Security Dashboard
Modern UI for continuous log monitoring, ML training, and anomaly detection
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import io
import sys
import time
import json
from pathlib import Path
import warnings

warnings.filterwarnings('ignore')

# Add current directory to path for imports
sys.path.append(str(Path(__file__).parent))

from data_loader import LogDataLoader
from analysis import LogAnalyzer
from visualizations import LogVisualizer
from realtime_log_analyzer import RealTimeLogAnalyzer

# Page configuration
st.set_page_config(
    page_title="🛡️ LogBERT Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for modern UI
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Global styling */
    .main {
        font-family: 'Inter', sans-serif;
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    }
    
    .main-header h1 {
        font-size: 3rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .main-header p {
        font-size: 1.2rem;
        opacity: 0.9;
        font-weight: 300;
    }
    
    /* Status cards */
    .status-card {
        background: white;
        padding: 1.5rem;
        border-radius: 15px;
        box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        border-left: 5px solid;
        margin-bottom: 1rem;
        transition: transform 0.3s ease;
    }
    
    .status-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 30px rgba(0,0,0,0.15);
    }
    
    .status-card.success {
        border-left-color: #10b981;
    }
    
    .status-card.warning {
        border-left-color: #f59e0b;
    }
    
    .status-card.danger {
        border-left-color: #ef4444;
    }
    
    .status-card.info {
        border-left-color: #3b82f6;
    }
    
    /* Metric displays */
    .metric-large {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f2937;
        line-height: 1;
    }
    
    .metric-label {
        font-size: 0.875rem;
        color: #6b7280;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    /* Alert box */
    .alert-box {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        border: 1px solid #fca5a5;
        border-radius: 12px;
        padding: 1rem;
        margin: 1rem 0;
        color: #991b1b;
        font-weight: 500;
    }
    
    .alert-box.success {
        background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
        border-color: #6ee7b7;
        color: #065f46;
    }
    
    .alert-box.info {
        background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
        border-color: #93c5fd;
        color: #1e40af;
    }
    
    /* Navigation tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #f8fafc;
        border-radius: 12px;
        padding: 4px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 12px 24px;
        font-weight: 500;
        font-size: 14px;
    }
    
    /* Real-time indicators */
    .live-indicator {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: #10b981;
        color: white;
        padding: 6px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .live-indicator::before {
        content: '●';
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    /* Dark mode support */
    .dark .status-card {
        background: #1f2937;
        color: white;
    }
    
    .dark .metric-large {
        color: white;
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
        .main-header h1 {
            font-size: 2rem;
        }
        
        .main-header {
            padding: 1.5rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = None
if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()

def initialize_analyzer():
    """Initialize the real-time log analyzer"""
    if st.session_state.analyzer is None:
        # Default Tomcat log paths (adjust based on your setup)
        log_paths = [
            "/opt/tomcat/logs/localhost_access_log.txt",
            "/var/log/tomcat/access.log",
            "./tomcat_access.log"  # Local fallback
        ]
        
        try:
            st.session_state.analyzer = RealTimeLogAnalyzer(log_paths)
            st.session_state.analyzer.load_models()
            st.session_state.monitoring_active = True
            return True
        except Exception as e:
            st.error(f"Failed to initialize analyzer: {str(e)}")
            return False
    return True

def create_modern_header():
    """Create the modern header section"""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ LogBERT Security Monitor</h1>
        <p>Real-time Anomaly Detection • Continuous ML Training • Advanced Threat Analytics</p>
    </div>
    """, unsafe_allow_html=True)

# Initialize session state
if 'data_loaded' not in st.session_state:
    st.session_state.data_loaded = False
if 'df' not in st.session_state:
    st.session_state.df = None
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = {}

@st.cache_data
def load_data_cached(file_path: str = None, use_demo_data: bool = True, num_samples: int = 1000, anomaly_rate: float = 0.15):
    """Load and cache data to prevent reloading on every interaction"""
    loader = LogDataLoader()
    
    if use_demo_data or file_path is None:
        df = loader.generate_synthetic_data(num_samples=num_samples, anomaly_rate=anomaly_rate)
    else:
        df = loader.load_data(file_path)
    
    df = loader.preprocess_for_analysis(df)
    return df

@st.cache_data
def analyze_data_cached(df_hash: str, df: pd.DataFrame):
    """Cached analysis to prevent recomputation"""
    analyzer = LogAnalyzer(df)
    
    stats = analyzer.compute_descriptive_stats()
    metrics = analyzer.compute_evaluation_metrics()
    patterns = analyzer.extract_top_anomalous_patterns()
    
    return {
        'stats': stats,
        'metrics': metrics,
        'patterns': patterns,
        'report': analyzer.generate_summary_report()
    }

def create_overview_tab(df: pd.DataFrame, stats: dict):
    """Create the overview tab content"""
    st.markdown("### 📊 Dataset Overview")
    
    # Key metrics in columns
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Requests",
            value=f"{stats.get('total_requests', 0):,}",
            help="Total number of HTTP requests in the dataset"
        )
    
    with col2:
        anomaly_stats = stats.get('anomaly_stats', {})
        anomaly_rate = anomaly_stats.get('anomaly_rate', 0) * 100
        st.metric(
            label="Anomaly Rate",
            value=f"{anomaly_rate:.1f}%",
            delta=f"{anomaly_stats.get('total_anomalies', 0)} anomalies",
            help="Percentage of requests flagged as anomalous"
        )
    
    with col3:
        st.metric(
            label="Unique IPs",
            value=f"{stats.get('unique_ips', 0):,}",
            help="Number of unique client IP addresses"
        )
    
    with col4:
        date_range = stats.get('date_range', {})
        duration = date_range.get('duration_hours', 0)
        st.metric(
            label="Time Span",
            value=f"{duration:.1f} hours",
            help="Total time period covered by the logs"
        )
    
    # Additional metrics
    st.markdown("### 🔍 Detailed Statistics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### HTTP Methods")
        method_dist = stats.get('method_distribution', {})
        for method, count in method_dist.items():
            percentage = (count / stats.get('total_requests', 1)) * 100
            st.write(f"**{method}**: {count:,} ({percentage:.1f}%)")
    
    with col2:
        st.markdown("#### Status Categories")
        status_cat_dist = stats.get('status_category_distribution', {})
        for category, count in status_cat_dist.items():
            percentage = (count / stats.get('total_requests', 1)) * 100
            st.write(f"**{category}**: {count:,} ({percentage:.1f}%)")
    
    # Score statistics
    st.markdown("### 📈 Anomaly Score Statistics")
    score_stats = stats.get('score_stats', {})
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Mean Score", f"{score_stats.get('mean', 0):.3f}")
    with col2:
        st.metric("Median Score", f"{score_stats.get('median', 0):.3f}")
    with col3:
        st.metric("95th Percentile", f"{score_stats.get('q95', 0):.3f}")
    with col4:
        st.metric("Max Score", f"{score_stats.get('max', 0):.3f}")

def create_distributions_tab(df: pd.DataFrame, visualizer: LogVisualizer):
    """Create the distributions tab content"""
    st.markdown("### 📊 Score and Status Distributions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Anomaly Score Distribution")
        fig_score = visualizer.plot_score_distribution(df, interactive=True)
        if fig_score:
            st.plotly_chart(fig_score, use_container_width=True)
    
    with col2:
        st.markdown("#### HTTP Status Distribution")
        fig_status = visualizer.plot_status_distribution(df, interactive=True)
        if fig_status:
            st.plotly_chart(fig_status, use_container_width=True)
    
    # Method and path distributions
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### HTTP Method Distribution")
        fig_methods = visualizer.plot_method_distribution(df, interactive=True)
        if fig_methods:
            st.plotly_chart(fig_methods, use_container_width=True)
    
    with col2:
        st.markdown("#### Top Requested Paths")
        fig_paths = visualizer.plot_top_paths(df, top_n=10, interactive=True)
        if fig_paths:
            st.plotly_chart(fig_paths, use_container_width=True)
    
    # Additional distributions
    if 'user_agent_category' in df.columns:
        st.markdown("#### User Agent Categories")
        fig_ua = visualizer.plot_user_agent_categories(df, interactive=True)
        if fig_ua:
            st.plotly_chart(fig_ua, use_container_width=True)

def create_timeline_tab(df: pd.DataFrame, visualizer: LogVisualizer):
    """Create the timeline tab content"""
    st.markdown("### ⏱️ Temporal Analysis")
    
    # Detection timeline
    st.markdown("#### Anomaly Detection Timeline")
    fig_timeline = visualizer.plot_detection_timeline(df, interactive=True)
    if fig_timeline:
        st.plotly_chart(fig_timeline, use_container_width=True)
    
    # Hourly activity
    if 'timestamp' in df.columns and not df['timestamp'].isna().all():
        st.markdown("#### Hourly Request Activity")
        fig_hourly = visualizer.plot_hourly_activity(df, interactive=True)
        if fig_hourly:
            st.plotly_chart(fig_hourly, use_container_width=True)

def create_evaluation_tab(df: pd.DataFrame, metrics: dict, visualizer: LogVisualizer):
    """Create the evaluation tab content"""
    if not metrics:
        st.warning("⚠️ Evaluation metrics not available. This requires labeled data.")
        return
    
    st.markdown("### 🎯 Model Evaluation Metrics")
    
    # Performance metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Precision",
            f"{metrics.get('precision', 0):.3f}",
            help="True Positives / (True Positives + False Positives)"
        )
    
    with col2:
        st.metric(
            "Recall",
            f"{metrics.get('recall', 0):.3f}",
            help="True Positives / (True Positives + False Negatives)"
        )
    
    with col3:
        st.metric(
            "F1-Score",
            f"{metrics.get('f1_score', 0):.3f}",
            help="2 * (Precision * Recall) / (Precision + Recall)"
        )
    
    with col4:
        roc_auc = metrics.get('roc_curve', {}).get('auc', 0)
        st.metric(
            "ROC AUC",
            f"{roc_auc:.3f}",
            help="Area Under the ROC Curve"
        )
    
    # Confusion matrix and curves
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Confusion Matrix")
        
        # Determine anomaly column
        anomaly_col = 'label' if 'label' in df.columns and not df['label'].isna().all() else 'predicted_anomaly'
        if anomaly_col not in df.columns:
            threshold = df['score'].quantile(0.9)
            df['predicted_anomaly'] = (df['score'] > threshold).astype(int)
            anomaly_col = 'predicted_anomaly'
        
        y_true = df['label'].values if 'label' in df.columns else df[anomaly_col].values
        y_pred = df[anomaly_col].values
        
        fig_cm = visualizer.plot_confusion_matrix(y_true, y_pred, interactive=True)
        if fig_cm:
            st.plotly_chart(fig_cm, use_container_width=True)
    
    with col2:
        st.markdown("#### ROC Curve")
        fig_roc = visualizer.plot_roc_curve(
            metrics['roc_curve']['fpr'],
            metrics['roc_curve']['tpr'],
            metrics['roc_curve']['auc'],
            interactive=True
        )
        if fig_roc:
            st.plotly_chart(fig_roc, use_container_width=True)
    
    # Precision-Recall curve
    st.markdown("#### Precision-Recall Curve")
    fig_pr = visualizer.plot_precision_recall_curve(
        metrics['pr_curve']['precision'],
        metrics['pr_curve']['recall'],
        metrics['pr_curve']['auc'],
        interactive=True
    )
    if fig_pr:
        st.plotly_chart(fig_pr, use_container_width=True)

def create_patterns_tab(patterns: dict):
    """Create the patterns tab content"""
    st.markdown("### 🚨 Anomalous Pattern Analysis")
    
    if not patterns:
        st.warning("⚠️ No anomalous patterns found in the data.")
        return
    
    # Suspicious paths
    suspicious_paths = patterns.get('suspicious_paths', [])
    if suspicious_paths:
        st.markdown("#### 🔍 Most Suspicious Paths")
        
        for i, path_info in enumerate(suspicious_paths[:10], 1):
            with st.expander(f"{i}. {path_info['path']} ({path_info['count']} occurrences)"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Count**: {path_info['count']}")
                    st.write(f"**Percentage**: {path_info['percentage']:.1f}%")
                with col2:
                    st.write(f"**Average Score**: {path_info['avg_score']:.2f}")
                    st.write(f"**Attack Types**: {', '.join(path_info['attack_types'])}")
    
    # Attack signatures
    attack_signatures = patterns.get('attack_signatures', [])
    if attack_signatures:
        st.markdown("#### ⚠️ Attack Signatures")
        
        signature_df = pd.DataFrame(attack_signatures)
        if not signature_df.empty:
            st.dataframe(
                signature_df[['signature', 'attack_type', 'total_count']].drop_duplicates(),
                use_container_width=True
            )
    
    # Suspicious user agents
    suspicious_uas = patterns.get('suspicious_user_agents', [])
    if suspicious_uas:
        st.markdown("#### 🤖 Suspicious User Agents")
        
        for i, ua_info in enumerate(suspicious_uas[:5], 1):
            with st.expander(f"{i}. {ua_info['category']} ({ua_info['count']} requests)"):
                st.code(ua_info['user_agent'], language='text')
                st.write(f"**Count**: {ua_info['count']}")
                st.write(f"**Average Score**: {ua_info['avg_score']:.2f}")
    
    # IP-based patterns
    ip_patterns = patterns.get('ip_based_patterns', [])
    if ip_patterns:
        st.markdown("#### 🌐 Suspicious IP Patterns")
        
        ip_df = pd.DataFrame(ip_patterns)
        if not ip_df.empty:
            st.dataframe(ip_df, use_container_width=True)

def main():
    """Main dashboard application"""
    # Title and description
    st.markdown('<h1 class="main-header">🛡️ CyberSec Log Analyzer</h1>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="info-box">
    <strong>📋 About this Dashboard</strong><br>
    This interactive dashboard analyzes web server logs using machine learning techniques to detect anomalies and security threats.
    Upload your own log files (CSV, JSON, JSONL) or use the synthetic demo data to explore the capabilities.
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.markdown("## ⚙️ Configuration")
    
    # Data source selection
    data_source = st.sidebar.radio(
        "Choose Data Source",
        ["Demo Data", "Upload File", "Load from LogBERT Results"],
        help="Select whether to use synthetic demo data or upload your own log file"
    )
    
    # Data loading section
    df = None
    
    if data_source == "Demo Data":
        st.sidebar.markdown("### Demo Data Settings")
        num_samples = st.sidebar.slider("Number of Samples", 500, 5000, 1000, step=100)
        anomaly_rate = st.sidebar.slider("Anomaly Rate", 0.05, 0.3, 0.15, step=0.01)
        
        if st.sidebar.button("Generate Demo Data") or not st.session_state.data_loaded:
            with st.spinner("Generating synthetic log data..."):
                df = load_data_cached(use_demo_data=True, num_samples=num_samples, anomaly_rate=anomaly_rate)
                st.session_state.df = df
                st.session_state.data_loaded = True
                st.success(f"✅ Generated {len(df)} synthetic log entries")
    
    elif data_source == "Upload File":
        uploaded_file = st.sidebar.file_uploader(
            "Upload Log File",
            type=['csv', 'json', 'jsonl'],
            help="Upload a log file in CSV, JSON, or JSONL format"
        )
        
        if uploaded_file is not None:
            try:
                with st.spinner("Loading uploaded file..."):
                    # Save uploaded file temporarily
                    temp_file = f"/tmp/{uploaded_file.name}"
                    with open(temp_file, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    
                    df = load_data_cached(file_path=temp_file, use_demo_data=False)
                    st.session_state.df = df
                    st.session_state.data_loaded = True
                    st.success(f"✅ Loaded {len(df)} records from {uploaded_file.name}")
            except Exception as e:
                st.error(f"❌ Error loading file: {str(e)}")
    
    elif data_source == "Load from LogBERT Results":
        logbert_file = "logbert_comprehensive_results.csv"
        if Path(logbert_file).exists():
            if st.sidebar.button("Load LogBERT Results") or not st.session_state.data_loaded:
                try:
                    with st.spinner("Loading LogBERT results..."):
                        # Load and transform LogBERT CSV
                        df_raw = pd.read_csv(logbert_file)
                        
                        # Transform to expected format
                        df = pd.DataFrame()
                        df['timestamp'] = pd.to_datetime(df_raw['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
                        df['method'] = df_raw['request'].str.extract(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS)')
                        df['path'] = df_raw['request'].str.extract(r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)')
                        df['status'] = df_raw['status']
                        df['score'] = df_raw['anomaly_score']
                        df['label'] = df_raw['is_anomaly']
                        df['user_agent'] = df_raw['user_agent']
                        df['ip'] = df_raw['ip']
                        df['predicted_anomaly'] = df_raw['is_anomaly']
                        
                        # Clean up and preprocess
                        loader = LogDataLoader()
                        df = loader.preprocess_for_analysis(df.dropna(subset=['method', 'path']))
                        
                        st.session_state.df = df
                        st.session_state.data_loaded = True
                        st.success(f"✅ Loaded {len(df)} records from LogBERT results")
                except Exception as e:
                    st.error(f"❌ Error loading LogBERT results: {str(e)}")
        else:
            st.sidebar.error("LogBERT results file not found")
    
    # Use session state data if available
    if st.session_state.data_loaded and st.session_state.df is not None:
        df = st.session_state.df
    
    if df is None or df.empty:
        st.warning("⚠️ No data loaded. Please select a data source and load data.")
        return
    
    # Filtering options
    st.sidebar.markdown("### 🔍 Filters")
    
    # Time range filter
    if 'timestamp' in df.columns and not df['timestamp'].isna().all():
        min_date = df['timestamp'].min().date()
        max_date = df['timestamp'].max().date()
        
        date_range = st.sidebar.date_input(
            "Date Range",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date
        )
        
        if len(date_range) == 2:
            start_date, end_date = date_range
            df = df[(df['timestamp'].dt.date >= start_date) & (df['timestamp'].dt.date <= end_date)]
    
    # Status code filter
    status_options = sorted(df['status'].unique())
    selected_statuses = st.sidebar.multiselect(
        "HTTP Status Codes",
        status_options,
        default=status_options,
        help="Filter by HTTP status codes"
    )
    
    if selected_statuses:
        df = df[df['status'].isin(selected_statuses)]
    
    # Method filter
    method_options = df['method'].unique()
    selected_methods = st.sidebar.multiselect(
        "HTTP Methods",
        method_options,
        default=method_options,
        help="Filter by HTTP methods"
    )
    
    if selected_methods:
        df = df[df['method'].isin(selected_methods)]
    
    # Analysis threshold
    anomaly_threshold = st.sidebar.slider(
        "Anomaly Threshold",
        float(df['score'].min()),
        float(df['score'].max()),
        float(df['score'].quantile(0.9)),
        step=0.1,
        help="Threshold for determining anomalies"
    )
    
    # Update predicted anomalies based on threshold
    df['predicted_anomaly'] = (df['score'] > anomaly_threshold).astype(int)
    
    # Run analysis
    with st.spinner("Analyzing data..."):
        # Create a hash for caching
        df_hash = str(hash(df.to_string()))
        analysis_results = analyze_data_cached(df_hash, df)
    
    # Create visualizer
    visualizer = LogVisualizer(theme='plotly_white')
    
    # Main tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview", 
        "📈 Distributions", 
        "⏱️ Timeline", 
        "🎯 Evaluation", 
        "🔍 Patterns"
    ])
    
    with tab1:
        create_overview_tab(df, analysis_results['stats'])
    
    with tab2:
        create_distributions_tab(df, visualizer)
    
    with tab3:
        create_timeline_tab(df, visualizer)
    
    with tab4:
        create_evaluation_tab(df, analysis_results['metrics'], visualizer)
    
    with tab5:
        create_patterns_tab(analysis_results['patterns'])
    
    # Download section
    st.markdown("---")
    st.markdown("### 💾 Export Data")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📄 Download Analysis Report"):
            report = analysis_results['report']
            st.download_button(
                label="Download Report",
                data=report,
                file_name=f"log_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    
    with col2:
        if st.button("📊 Download Processed Data"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"processed_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col3:
        if st.button("📋 View Raw Data"):
            st.dataframe(df.head(100), use_container_width=True)

if __name__ == "__main__":
    main()
