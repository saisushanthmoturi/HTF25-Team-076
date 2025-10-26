"""
Visualizations Module
Creates comprehensive charts and plots for cybersecurity log analysis
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Dict, List, Optional, Any, Tuple
import warnings
from datetime import datetime, timedelta

warnings.filterwarnings('ignore')

# Set consistent styling
plt.style.use('default')
sns.set_palette("husl")

class LogVisualizer:
    """Creates comprehensive visualizations for cybersecurity log analysis"""
    
    def __init__(self, theme: str = 'plotly_white'):
        self.theme = theme
        self.color_palette = {
            'normal': '#2E8B57',      # Sea Green
            'anomaly': '#DC143C',     # Crimson
            'warning': '#FF8C00',     # Dark Orange
            'info': '#4682B4',        # Steel Blue
            'success': '#32CD32',     # Lime Green
            'error': '#B22222'        # Fire Brick
        }
    
    def plot_score_distribution(self, df: pd.DataFrame, interactive: bool = True) -> Optional[go.Figure]:
        """Plot anomaly score distribution with threshold line"""
        if interactive:
            # Interactive Plotly version
            fig = go.Figure()
            
            # Histogram
            fig.add_trace(go.Histogram(
                x=df['score'],
                nbinsx=50,
                name='Score Distribution',
                opacity=0.7,
                marker_color=self.color_palette['info']
            ))
            
            # Mean line
            mean_score = df['score'].mean()
            fig.add_vline(
                x=mean_score,
                line_dash="dash",
                line_color=self.color_palette['warning'],
                annotation_text=f"Mean: {mean_score:.2f}"
            )
            
            # Threshold line (90th percentile)
            threshold = df['score'].quantile(0.9)
            fig.add_vline(
                x=threshold,
                line_dash="dash",
                line_color=self.color_palette['anomaly'],
                annotation_text=f"90th Percentile: {threshold:.2f}"
            )
            
            fig.update_layout(
                title="Anomaly Score Distribution",
                xaxis_title="Anomaly Score",
                yaxis_title="Frequency",
                template=self.theme,
                hovermode='x'
            )
            
            return fig
        else:
            # Static matplotlib version
            plt.figure(figsize=(10, 6))
            plt.hist(df['score'], bins=50, alpha=0.7, color=self.color_palette['info'], edgecolor='black')
            plt.axvline(df['score'].mean(), color=self.color_palette['warning'], linestyle='--', 
                       label=f'Mean: {df["score"].mean():.2f}')
            plt.axvline(df['score'].quantile(0.9), color=self.color_palette['anomaly'], linestyle='--',
                       label=f'90th Percentile: {df["score"].quantile(0.9):.2f}')
            plt.xlabel('Anomaly Score')
            plt.ylabel('Frequency')
            plt.title('Anomaly Score Distribution')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def plot_status_distribution(self, df: pd.DataFrame, interactive: bool = True) -> Optional[go.Figure]:
        """Plot HTTP status code distribution"""
        status_counts = df['status'].value_counts().sort_index()
        
        if interactive:
            # Color mapping for status codes
            colors = []
            for status in status_counts.index:
                if 200 <= status < 300:
                    colors.append(self.color_palette['success'])
                elif 300 <= status < 400:
                    colors.append(self.color_palette['info'])
                elif 400 <= status < 500:
                    colors.append(self.color_palette['warning'])
                elif status >= 500:
                    colors.append(self.color_palette['error'])
                else:
                    colors.append('#888888')
            
            fig = go.Figure(data=[
                go.Bar(
                    x=[str(status) for status in status_counts.index],
                    y=status_counts.values,
                    marker_color=colors,
                    text=status_counts.values,
                    textposition='auto',
                )
            ])
            
            fig.update_layout(
                title="HTTP Status Code Distribution",
                xaxis_title="HTTP Status Code",
                yaxis_title="Count",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(12, 6))
            bars = plt.bar(status_counts.index.astype(str), status_counts.values, alpha=0.7)
            
            # Color bars based on status code
            for i, (status, bar) in enumerate(zip(status_counts.index, bars)):
                if 200 <= status < 300:
                    bar.set_color(self.color_palette['success'])
                elif 300 <= status < 400:
                    bar.set_color(self.color_palette['info'])
                elif 400 <= status < 500:
                    bar.set_color(self.color_palette['warning'])
                elif status >= 500:
                    bar.set_color(self.color_palette['error'])
            
            plt.xlabel('HTTP Status Code')
            plt.ylabel('Count')
            plt.title('HTTP Status Code Distribution')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def plot_detection_timeline(self, df: pd.DataFrame, interactive: bool = True) -> Optional[go.Figure]:
        """Plot anomaly detection timeline"""
        if 'timestamp' not in df.columns or df['timestamp'].isna().all():
            # Use row index as time proxy
            df = df.copy()
            df['timestamp'] = pd.date_range(start='2025-01-01', periods=len(df), freq='1min')
        
        # Determine anomaly column
        anomaly_col = 'label' if 'label' in df.columns and not df['label'].isna().all() else 'predicted_anomaly'
        if anomaly_col not in df.columns:
            # Create predicted anomaly based on score threshold
            threshold = df['score'].quantile(0.9)
            df['predicted_anomaly'] = (df['score'] > threshold).astype(int)
            anomaly_col = 'predicted_anomaly'
        
        normal_data = df[df[anomaly_col] == 0]
        anomaly_data = df[df[anomaly_col] == 1]
        
        if interactive:
            fig = go.Figure()
            
            # Normal requests
            fig.add_trace(go.Scatter(
                x=normal_data['timestamp'],
                y=normal_data['score'],
                mode='markers',
                name='Normal',
                marker=dict(
                    color=self.color_palette['normal'],
                    size=4,
                    opacity=0.6
                ),
                hovertemplate='<b>Normal Request</b><br>' +
                             'Time: %{x}<br>' +
                             'Score: %{y:.2f}<br>' +
                             '<extra></extra>'
            ))
            
            # Anomalous requests
            fig.add_trace(go.Scatter(
                x=anomaly_data['timestamp'],
                y=anomaly_data['score'],
                mode='markers',
                name='Anomaly',
                marker=dict(
                    color=self.color_palette['anomaly'],
                    size=8,
                    opacity=0.8
                ),
                hovertemplate='<b>Anomalous Request</b><br>' +
                             'Time: %{x}<br>' +
                             'Score: %{y:.2f}<br>' +
                             '<extra></extra>'
            ))
            
            # Threshold line
            threshold = df['score'].quantile(0.9)
            fig.add_hline(
                y=threshold,
                line_dash="dash",
                line_color=self.color_palette['warning'],
                annotation_text=f"Threshold: {threshold:.2f}"
            )
            
            fig.update_layout(
                title="Anomaly Detection Timeline",
                xaxis_title="Timestamp",
                yaxis_title="Anomaly Score",
                template=self.theme,
                hovermode='closest'
            )
            
            return fig
        else:
            plt.figure(figsize=(15, 8))
            
            # Plot normal requests
            if len(normal_data) > 0:
                plt.scatter(normal_data['timestamp'], normal_data['score'], 
                           alpha=0.6, s=20, c=self.color_palette['normal'], label='Normal')
            
            # Plot anomalous requests
            if len(anomaly_data) > 0:
                plt.scatter(anomaly_data['timestamp'], anomaly_data['score'], 
                           alpha=0.8, s=40, c=self.color_palette['anomaly'], label='Anomaly')
            
            # Threshold line
            threshold = df['score'].quantile(0.9)
            plt.axhline(threshold, color=self.color_palette['warning'], linestyle='--',
                       label=f'Threshold: {threshold:.2f}')
            
            plt.xlabel('Timestamp')
            plt.ylabel('Anomaly Score')
            plt.title('Anomaly Detection Timeline')
            plt.legend()
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray, 
                            interactive: bool = True) -> Optional[go.Figure]:
        """Plot confusion matrix"""
        from sklearn.metrics import confusion_matrix
        
        cm = confusion_matrix(y_true, y_pred)
        
        if interactive:
            fig = go.Figure(data=go.Heatmap(
                z=cm,
                x=['Normal', 'Anomaly'],
                y=['Normal', 'Anomaly'],
                colorscale='Blues',
                text=cm,
                texttemplate="%{text}",
                textfont={"size": 20},
                hovertemplate='Predicted: %{x}<br>Actual: %{y}<br>Count: %{z}<extra></extra>'
            ))
            
            fig.update_layout(
                title="Confusion Matrix",
                xaxis_title="Predicted",
                yaxis_title="Actual",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(8, 6))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                       xticklabels=['Normal', 'Anomaly'],
                       yticklabels=['Normal', 'Anomaly'])
            plt.title('Confusion Matrix')
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.tight_layout()
            return plt.gcf()
    
    def plot_roc_curve(self, fpr: List[float], tpr: List[float], auc_score: float,
                      interactive: bool = True) -> Optional[go.Figure]:
        """Plot ROC curve"""
        if interactive:
            fig = go.Figure()
            
            # ROC curve
            fig.add_trace(go.Scatter(
                x=fpr,
                y=tpr,
                mode='lines',
                name=f'ROC Curve (AUC = {auc_score:.3f})',
                line=dict(color=self.color_palette['info'], width=3)
            ))
            
            # Diagonal line
            fig.add_trace(go.Scatter(
                x=[0, 1],
                y=[0, 1],
                mode='lines',
                name='Random Classifier',
                line=dict(color='gray', dash='dash')
            ))
            
            fig.update_layout(
                title="ROC Curve",
                xaxis_title="False Positive Rate",
                yaxis_title="True Positive Rate",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, color=self.color_palette['info'], linewidth=3,
                    label=f'ROC Curve (AUC = {auc_score:.3f})')
            plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('ROC Curve')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def plot_precision_recall_curve(self, precision: List[float], recall: List[float], 
                                   auc_score: float, interactive: bool = True) -> Optional[go.Figure]:
        """Plot Precision-Recall curve"""
        if interactive:
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=recall,
                y=precision,
                mode='lines',
                name=f'PR Curve (AUC = {auc_score:.3f})',
                line=dict(color=self.color_palette['success'], width=3),
                fill='tonexty'
            ))
            
            fig.update_layout(
                title="Precision-Recall Curve",
                xaxis_title="Recall",
                yaxis_title="Precision",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(8, 6))
            plt.plot(recall, precision, color=self.color_palette['success'], linewidth=3,
                    label=f'PR Curve (AUC = {auc_score:.3f})')
            plt.fill_between(recall, precision, alpha=0.2)
            plt.xlabel('Recall')
            plt.ylabel('Precision')
            plt.title('Precision-Recall Curve')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def plot_method_distribution(self, df: pd.DataFrame, interactive: bool = True) -> Optional[go.Figure]:
        """Plot HTTP method distribution"""
        method_counts = df['method'].value_counts()
        
        if interactive:
            fig = go.Figure(data=[
                go.Pie(
                    labels=method_counts.index,
                    values=method_counts.values,
                    hole=0.3,
                    marker_colors=[self.color_palette['info'], self.color_palette['success'], 
                                 self.color_palette['warning'], self.color_palette['error']][:len(method_counts)]
                )
            ])
            
            fig.update_layout(
                title="HTTP Method Distribution",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(8, 8))
            plt.pie(method_counts.values, labels=method_counts.index, autopct='%1.1f%%',
                   colors=[self.color_palette['info'], self.color_palette['success'], 
                          self.color_palette['warning'], self.color_palette['error']][:len(method_counts)])
            plt.title('HTTP Method Distribution')
            plt.axis('equal')
            plt.tight_layout()
            return plt.gcf()
    
    def plot_top_paths(self, df: pd.DataFrame, top_n: int = 10, interactive: bool = True) -> Optional[go.Figure]:
        """Plot top requested paths"""
        path_counts = df['path'].value_counts().head(top_n)
        
        if interactive:
            fig = go.Figure(data=[
                go.Bar(
                    y=path_counts.index[::-1],  # Reverse for horizontal bar
                    x=path_counts.values[::-1],
                    orientation='h',
                    marker_color=self.color_palette['info'],
                    text=path_counts.values[::-1],
                    textposition='auto',
                )
            ])
            
            fig.update_layout(
                title=f"Top {top_n} Most Requested Paths",
                xaxis_title="Request Count",
                yaxis_title="Path",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(12, 8))
            plt.barh(range(len(path_counts)), path_counts.values, 
                    color=self.color_palette['info'], alpha=0.7)
            plt.yticks(range(len(path_counts)), path_counts.index)
            plt.xlabel('Request Count')
            plt.title(f'Top {top_n} Most Requested Paths')
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def plot_hourly_activity(self, df: pd.DataFrame, interactive: bool = True) -> Optional[go.Figure]:
        """Plot hourly request activity"""
        if 'timestamp' not in df.columns or df['timestamp'].isna().all():
            return None
        
        df_with_hour = df.copy()
        df_with_hour['hour'] = pd.to_datetime(df_with_hour['timestamp']).dt.hour
        hourly_counts = df_with_hour['hour'].value_counts().sort_index()
        
        if interactive:
            fig = go.Figure(data=[
                go.Scatter(
                    x=hourly_counts.index,
                    y=hourly_counts.values,
                    mode='lines+markers',
                    line=dict(color=self.color_palette['info'], width=3),
                    marker=dict(size=8),
                    fill='tonexty'
                )
            ])
            
            fig.update_layout(
                title="Hourly Request Activity",
                xaxis_title="Hour of Day",
                yaxis_title="Request Count",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(12, 6))
            plt.plot(hourly_counts.index, hourly_counts.values, 
                    color=self.color_palette['info'], linewidth=3, marker='o')
            plt.fill_between(hourly_counts.index, hourly_counts.values, alpha=0.3)
            plt.xlabel('Hour of Day')
            plt.ylabel('Request Count')
            plt.title('Hourly Request Activity')
            plt.xticks(range(0, 24))
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def plot_user_agent_categories(self, df: pd.DataFrame, interactive: bool = True) -> Optional[go.Figure]:
        """Plot user agent category distribution"""
        if 'user_agent_category' not in df.columns:
            return None
        
        ua_counts = df['user_agent_category'].value_counts()
        
        if interactive:
            fig = go.Figure(data=[
                go.Bar(
                    x=ua_counts.index,
                    y=ua_counts.values,
                    marker_color=self.color_palette['info'],
                    text=ua_counts.values,
                    textposition='auto'
                )
            ])
            
            fig.update_layout(
                title="User Agent Categories",
                xaxis_title="Category",
                yaxis_title="Count",
                template=self.theme
            )
            
            return fig
        else:
            plt.figure(figsize=(10, 6))
            plt.bar(ua_counts.index, ua_counts.values, color=self.color_palette['info'], alpha=0.7)
            plt.xlabel('User Agent Category')
            plt.ylabel('Count')
            plt.title('User Agent Categories')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            return plt.gcf()
    
    def create_dashboard_layout(self, df: pd.DataFrame, analysis_results: Dict[str, Any]) -> Dict[str, go.Figure]:
        """Create all visualizations for the dashboard"""
        figures = {}
        
        # Core visualizations
        figures['score_distribution'] = self.plot_score_distribution(df, interactive=True)
        figures['status_distribution'] = self.plot_status_distribution(df, interactive=True)
        figures['detection_timeline'] = self.plot_detection_timeline(df, interactive=True)
        figures['method_distribution'] = self.plot_method_distribution(df, interactive=True)
        figures['top_paths'] = self.plot_top_paths(df, interactive=True)
        
        # Time-based analysis
        if 'timestamp' in df.columns and not df['timestamp'].isna().all():
            figures['hourly_activity'] = self.plot_hourly_activity(df, interactive=True)
        
        # User agent analysis
        if 'user_agent_category' in df.columns:
            figures['user_agent_categories'] = self.plot_user_agent_categories(df, interactive=True)
        
        # Evaluation metrics (if available)
        if 'evaluation_metrics' in analysis_results:
            metrics = analysis_results['evaluation_metrics']
            
            # Determine anomaly column
            anomaly_col = 'label' if 'label' in df.columns and not df['label'].isna().all() else 'predicted_anomaly'
            if anomaly_col not in df.columns:
                threshold = df['score'].quantile(0.9)
                df['predicted_anomaly'] = (df['score'] > threshold).astype(int)
                anomaly_col = 'predicted_anomaly'
            
            y_true = df['label'].values if 'label' in df.columns else df[anomaly_col].values
            y_pred = df[anomaly_col].values
            
            figures['confusion_matrix'] = self.plot_confusion_matrix(y_true, y_pred, interactive=True)
            figures['roc_curve'] = self.plot_roc_curve(
                metrics['roc_curve']['fpr'], 
                metrics['roc_curve']['tpr'], 
                metrics['roc_curve']['auc'], 
                interactive=True
            )
            figures['pr_curve'] = self.plot_precision_recall_curve(
                metrics['pr_curve']['precision'],
                metrics['pr_curve']['recall'],
                metrics['pr_curve']['auc'],
                interactive=True
            )
        
        return figures

# Example usage
if __name__ == "__main__":
    from data_loader import LogDataLoader
    from analysis import LogAnalyzer
    
    # Load test data
    loader = LogDataLoader()
    df = loader.generate_synthetic_data(num_samples=1000, anomaly_rate=0.15)
    df = loader.preprocess_for_analysis(df)
    
    # Analyze
    analyzer = LogAnalyzer(df)
    stats = analyzer.compute_descriptive_stats()
    metrics = analyzer.compute_evaluation_metrics()
    
    # Visualize
    visualizer = LogVisualizer()
    
    # Test individual plots
    fig1 = visualizer.plot_score_distribution(df)
    fig2 = visualizer.plot_detection_timeline(df)
    
    print("Visualizations created successfully!")
    print(f"Score distribution figure: {type(fig1)}")
    print(f"Timeline figure: {type(fig2)}")
