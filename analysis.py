"""
Analysis Module
Performs comprehensive statistical analysis and evaluation of log data
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix,
    roc_curve, precision_recall_curve, auc, classification_report
)
import logging
from collections import Counter
import re
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LogAnalyzer:
    """Comprehensive analysis of web server log data"""
    
    def __init__(self, df: pd.DataFrame):
        self.df = df
        self.has_labels = 'label' in df.columns and not df['label'].isna().all()
        self.analysis_results = {}
        
    def compute_descriptive_stats(self) -> Dict[str, Any]:
        """Compute comprehensive descriptive statistics"""
        logger.info("Computing descriptive statistics...")
        
        stats = {
            'total_requests': len(self.df),
            'unique_ips': self.df['ip'].nunique() if 'ip' in self.df.columns else 0,
            'date_range': self._get_date_range(),
            'path_stats': self._analyze_paths(),
            'score_stats': self._analyze_scores(),
            'anomaly_stats': self._analyze_anomalies(),
            'temporal_stats': self._analyze_temporal_patterns(),
            'user_agent_stats': self._analyze_user_agents()
        }
        
        # Add distributions only if columns exist
        if 'method' in self.df.columns:
            stats['method_distribution'] = self.df['method'].value_counts().to_dict()
            
        if 'status' in self.df.columns:
            stats['status_distribution'] = self.df['status'].value_counts().to_dict()
            
        if 'status_category' in self.df.columns:
            stats['status_category_distribution'] = self.df['status_category'].value_counts().to_dict()
        
        self.analysis_results['descriptive_stats'] = stats
        return stats
    
    def _get_date_range(self) -> Dict[str, Any]:
        """Get date range information"""
        if 'timestamp' not in self.df.columns or self.df['timestamp'].isna().all():
            return {'start': None, 'end': None, 'duration': None}
        
        timestamps = self.df['timestamp'].dropna()
        start_time = timestamps.min()
        end_time = timestamps.max()
        duration = end_time - start_time if start_time and end_time else None
        
        return {
            'start': start_time,
            'end': end_time,
            'duration': duration,
            'duration_hours': duration.total_seconds() / 3600 if duration else 0
        }
    
    def _analyze_paths(self) -> Dict[str, Any]:
        """Analyze URL path patterns"""
        if 'path' not in self.df.columns:
            return {'unique_paths': 0, 'most_common_paths': {}, 'avg_path_length': 0, 'max_path_length': 0, 'avg_path_depth': 0}
        
        path_counts = self.df['path'].value_counts()
        
        return {
            'unique_paths': len(path_counts),
            'most_common_paths': path_counts.head(10).to_dict(),
            'avg_path_length': self.df['path_length'].mean() if 'path_length' in self.df.columns else 0,
            'max_path_length': self.df['path_length'].max() if 'path_length' in self.df.columns else 0,
            'avg_path_depth': self.df['path_depth'].mean() if 'path_depth' in self.df.columns else 0
        }
    
    def _analyze_scores(self) -> Dict[str, Any]:
        """Analyze anomaly score distribution"""
        if 'score' not in self.df.columns:
            return {'mean': 0, 'median': 0, 'std': 0, 'min': 0, 'max': 0, 'q25': 0, 'q75': 0, 'q90': 0, 'q95': 0, 'q99': 0}
        
        scores = self.df['score']
        
        return {
            'mean': scores.mean(),
            'median': scores.median(),
            'std': scores.std(),
            'min': scores.min(),
            'max': scores.max(),
            'q25': scores.quantile(0.25),
            'q75': scores.quantile(0.75),
            'q90': scores.quantile(0.90),
            'q95': scores.quantile(0.95),
            'q99': scores.quantile(0.99)
        }
    
    def _analyze_anomalies(self) -> Dict[str, Any]:
        """Analyze anomaly patterns"""
        anomaly_col = 'label' if self.has_labels else 'predicted_anomaly'
        
        if anomaly_col not in self.df.columns:
            return {'anomaly_rate': 0, 'total_anomalies': 0}
        
        anomalies = self.df[self.df[anomaly_col] == 1]
        total_anomalies = len(anomalies)
        anomaly_rate = total_anomalies / len(self.df) if len(self.df) > 0 else 0
        
        return {
            'total_anomalies': total_anomalies,
            'anomaly_rate': anomaly_rate,
            'anomaly_methods': anomalies['method'].value_counts().to_dict(),
            'anomaly_status': anomalies['status'].value_counts().to_dict(),
            'anomaly_paths': anomalies['path'].value_counts().head(10).to_dict()
        }
    
    def _analyze_temporal_patterns(self) -> Dict[str, Any]:
        """Analyze temporal patterns in the data"""
        if 'timestamp' not in self.df.columns or self.df['timestamp'].isna().all():
            return {}
        
        # Hour-based analysis
        if 'hour' in self.df.columns:
            hourly_counts = self.df['hour'].value_counts().sort_index()
            peak_hour = hourly_counts.idxmax()
        else:
            hourly_counts = {}
            peak_hour = None
        
        # Day of week analysis
        if 'day_of_week' in self.df.columns:
            dow_counts = self.df['day_of_week'].value_counts().sort_index()
            day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            dow_named = {day_names[i]: count for i, count in dow_counts.items()}
        else:
            dow_named = {}
        
        return {
            'hourly_distribution': hourly_counts.to_dict() if isinstance(hourly_counts, pd.Series) else {},
            'peak_hour': peak_hour,
            'day_of_week_distribution': dow_named,
            'weekend_rate': self.df['is_weekend'].mean() if 'is_weekend' in self.df.columns else 0
        }
    
    def _analyze_user_agents(self) -> Dict[str, Any]:
        """Analyze user agent patterns"""
        if 'user_agent' not in self.df.columns:
            return {}
        
        ua_counts = self.df['user_agent'].value_counts()
        ua_category_counts = self.df['user_agent_category'].value_counts() if 'user_agent_category' in self.df.columns else {}
        
        return {
            'unique_user_agents': len(ua_counts),
            'top_user_agents': ua_counts.head(10).to_dict(),
            'user_agent_categories': ua_category_counts.to_dict() if isinstance(ua_category_counts, pd.Series) else {}
        }
    
    def compute_evaluation_metrics(self) -> Optional[Dict[str, Any]]:
        """Compute evaluation metrics if labels are available"""
        if not self.has_labels:
            logger.warning("No labels available for evaluation")
            return None
        
        logger.info("Computing evaluation metrics...")
        
        y_true = self.df['label']
        
        # Use predicted anomaly if available, otherwise use score-based threshold
        if 'predicted_anomaly' in self.df.columns:
            y_pred = self.df['predicted_anomaly']
        else:
            threshold = self.df['score'].quantile(0.9)
            y_pred = (self.df['score'] > threshold).astype(int)
        
        # Basic metrics
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # ROC curve
        y_scores = self.df['score']
        fpr, tpr, roc_thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)
        
        # Precision-Recall curve
        precision_vals, recall_vals, pr_thresholds = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(recall_vals, precision_vals)
        
        # Classification report
        class_report = classification_report(y_true, y_pred, output_dict=True)
        
        metrics = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm.tolist(),
            'roc_curve': {
                'fpr': fpr.tolist(),
                'tpr': tpr.tolist(),
                'thresholds': roc_thresholds.tolist(),
                'auc': roc_auc
            },
            'pr_curve': {
                'precision': precision_vals.tolist(),
                'recall': recall_vals.tolist(),
                'thresholds': pr_thresholds.tolist(),
                'auc': pr_auc
            },
            'classification_report': class_report
        }
        
        self.analysis_results['evaluation_metrics'] = metrics
        return metrics
    
    def extract_top_anomalous_patterns(self, top_n: int = 20) -> Dict[str, Any]:
        """Extract and group top anomalous request patterns"""
        logger.info("Extracting top anomalous patterns...")
        
        anomaly_col = 'label' if self.has_labels else 'predicted_anomaly'
        
        if anomaly_col not in self.df.columns:
            return {}
        
        anomalies = self.df[self.df[anomaly_col] == 1].copy()
        
        if len(anomalies) == 0:
            return {'patterns': [], 'total_anomalies': 0}
        
        patterns = {
            'suspicious_paths': self._extract_suspicious_paths(anomalies, top_n),
            'suspicious_payloads': self._extract_suspicious_payloads(anomalies, top_n),
            'suspicious_user_agents': self._extract_suspicious_user_agents(anomalies, top_n),
            'attack_signatures': self._extract_attack_signatures(anomalies, top_n),
            'temporal_anomalies': self._extract_temporal_anomalies(anomalies),
            'ip_based_patterns': self._extract_ip_patterns(anomalies, top_n)
        }
        
        self.analysis_results['anomalous_patterns'] = patterns
        return patterns
    
    def _extract_suspicious_paths(self, anomalies: pd.DataFrame, top_n: int) -> List[Dict[str, Any]]:
        """Extract suspicious URL paths"""
        path_counts = anomalies['path'].value_counts().head(top_n)
        
        patterns = []
        for path, count in path_counts.items():
            pattern_info = {
                'path': path,
                'count': count,
                'percentage': count / len(anomalies) * 100,
                'attack_types': self._classify_attack_type(path),
                'avg_score': anomalies[anomalies['path'] == path]['score'].mean()
            }
            patterns.append(pattern_info)
        
        return patterns
    
    def _extract_suspicious_payloads(self, anomalies: pd.DataFrame, top_n: int) -> List[Dict[str, Any]]:
        """Extract suspicious payloads"""
        if 'payload' not in anomalies.columns:
            return []
        
        payload_anomalies = anomalies[anomalies['payload'].notna()]
        if len(payload_anomalies) == 0:
            return []
        
        payload_counts = payload_anomalies['payload'].value_counts().head(top_n)
        
        patterns = []
        for payload, count in payload_counts.items():
            pattern_info = {
                'payload': str(payload)[:200],  # Truncate for display
                'count': count,
                'percentage': count / len(payload_anomalies) * 100,
                'attack_types': self._classify_attack_type(str(payload)),
                'avg_score': payload_anomalies[payload_anomalies['payload'] == payload]['score'].mean()
            }
            patterns.append(pattern_info)
        
        return patterns
    
    def _extract_suspicious_user_agents(self, anomalies: pd.DataFrame, top_n: int) -> List[Dict[str, Any]]:
        """Extract suspicious user agents"""
        if 'user_agent' not in anomalies.columns:
            return []
        
        ua_counts = anomalies['user_agent'].value_counts().head(top_n)
        
        patterns = []
        for user_agent, count in ua_counts.items():
            pattern_info = {
                'user_agent': str(user_agent)[:100],  # Truncate for display
                'count': count,
                'percentage': count / len(anomalies) * 100,
                'category': self._categorize_user_agent(str(user_agent)),
                'avg_score': anomalies[anomalies['user_agent'] == user_agent]['score'].mean()
            }
            patterns.append(pattern_info)
        
        return patterns
    
    def _extract_attack_signatures(self, anomalies: pd.DataFrame, top_n: int) -> List[Dict[str, Any]]:
        """Extract common attack signatures"""
        signatures = []
        
        # SQL Injection signatures
        sql_patterns = [r'union\s+select', r'or\s+1\s*=\s*1', r'drop\s+table', r'insert\s+into', r'--', r'/\*.*\*/']
        signatures.extend(self._find_pattern_matches(anomalies, sql_patterns, 'SQL Injection'))
        
        # XSS signatures
        xss_patterns = [r'<script.*?>', r'javascript:', r'onerror\s*=', r'onload\s*=', r'alert\s*\(']
        signatures.extend(self._find_pattern_matches(anomalies, xss_patterns, 'XSS'))
        
        # Path traversal signatures
        path_patterns = [r'\.\./', r'\.\.\\', r'/etc/passwd', r'/windows/system32']
        signatures.extend(self._find_pattern_matches(anomalies, path_patterns, 'Path Traversal'))
        
        # Command injection signatures
        cmd_patterns = [r';\s*ls', r';\s*cat', r';\s*wget', r';\s*curl', r'\|.*nc']
        signatures.extend(self._find_pattern_matches(anomalies, cmd_patterns, 'Command Injection'))
        
        # Sort by frequency and return top N
        signature_counts = Counter([sig['signature'] for sig in signatures])
        top_signatures = []
        
        for signature, count in signature_counts.most_common(top_n):
            # Find the first signature info with this signature
            sig_info = next(s for s in signatures if s['signature'] == signature)
            sig_info['total_count'] = count
            top_signatures.append(sig_info)
        
        return top_signatures
    
    def _find_pattern_matches(self, anomalies: pd.DataFrame, patterns: List[str], attack_type: str) -> List[Dict[str, Any]]:
        """Find pattern matches in anomalous requests"""
        matches = []
        
        # Combine path and payload for searching
        search_texts = []
        for _, row in anomalies.iterrows():
            text_parts = [str(row['path'])]
            if 'payload' in row and pd.notna(row['payload']):
                text_parts.append(str(row['payload']))
            search_texts.append(' '.join(text_parts).lower())
        
        for pattern in patterns:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            for i, text in enumerate(search_texts):
                match = compiled_pattern.search(text)
                if match:
                    matches.append({
                        'signature': match.group(0),
                        'pattern': pattern,
                        'attack_type': attack_type,
                        'context': text[max(0, match.start()-20):match.end()+20],
                        'score': anomalies.iloc[i]['score']
                    })
        
        return matches
    
    def _extract_temporal_anomalies(self, anomalies: pd.DataFrame) -> Dict[str, Any]:
        """Extract temporal anomaly patterns"""
        if 'timestamp' not in anomalies.columns or anomalies['timestamp'].isna().all():
            return {}
        
        # Time-based clustering
        hourly_anomalies = anomalies.groupby(anomalies['timestamp'].dt.hour).size()
        peak_anomaly_hours = hourly_anomalies.nlargest(5)
        
        # Burst detection (simple approach: consecutive anomalies)
        anomalies_sorted = anomalies.sort_values('timestamp')
        time_diffs = anomalies_sorted['timestamp'].diff()
        burst_threshold = pd.Timedelta(minutes=5)
        burst_indicators = time_diffs < burst_threshold
        
        return {
            'peak_anomaly_hours': peak_anomaly_hours.to_dict(),
            'potential_bursts': int(burst_indicators.sum()),
            'total_burst_candidates': len(anomalies_sorted[burst_indicators])
        }
    
    def _extract_ip_patterns(self, anomalies: pd.DataFrame, top_n: int) -> List[Dict[str, Any]]:
        """Extract IP-based anomaly patterns"""
        if 'ip' not in anomalies.columns:
            return []
        
        ip_counts = anomalies['ip'].value_counts().head(top_n)
        
        patterns = []
        for ip, count in ip_counts.items():
            ip_data = anomalies[anomalies['ip'] == ip]
            pattern_info = {
                'ip': ip,
                'count': count,
                'percentage': count / len(anomalies) * 100,
                'avg_score': ip_data['score'].mean(),
                'unique_paths': ip_data['path'].nunique(),
                'methods_used': ip_data['method'].unique().tolist(),
                'time_span': self._calculate_time_span(ip_data)
            }
            patterns.append(pattern_info)
        
        return patterns
    
    def _calculate_time_span(self, data: pd.DataFrame) -> Optional[str]:
        """Calculate time span for IP activity"""
        if 'timestamp' not in data.columns or data['timestamp'].isna().all():
            return None
        
        timestamps = data['timestamp'].dropna()
        if len(timestamps) < 2:
            return "Single request"
        
        time_span = timestamps.max() - timestamps.min()
        return str(time_span)
    
    def _classify_attack_type(self, text: str) -> List[str]:
        """Classify potential attack types based on text content"""
        attack_types = []
        text_lower = text.lower()
        
        # SQL Injection indicators
        if any(indicator in text_lower for indicator in ['union', 'select', 'drop', 'insert', '--', '/*']):
            attack_types.append('SQL Injection')
        
        # XSS indicators
        if any(indicator in text_lower for indicator in ['<script', 'javascript:', 'onerror', 'alert']):
            attack_types.append('XSS')
        
        # Path traversal indicators
        if any(indicator in text_lower for indicator in ['../', '..\\', '/etc/passwd', 'system32']):
            attack_types.append('Path Traversal')
        
        # Command injection indicators
        if any(indicator in text_lower for indicator in [';', '|', '&&', '$(', '`']):
            attack_types.append('Command Injection')
        
        # File inclusion indicators
        if any(indicator in text_lower for indicator in ['include', 'require', 'file=']):
            attack_types.append('File Inclusion')
        
        return attack_types if attack_types else ['Unknown']
    
    def _categorize_user_agent(self, user_agent: str) -> str:
        """Categorize user agent (same as in data_loader but repeated for independence)"""
        if pd.isna(user_agent) or user_agent == '-':
            return 'Unknown'
        
        ua_lower = str(user_agent).lower()
        
        # Security tools
        security_tools = ['sqlmap', 'nikto', 'nessus', 'burp', 'zap', 'nmap']
        if any(tool in ua_lower for tool in security_tools):
            return 'Security Tool'
        
        # Browsers
        if 'chrome' in ua_lower:
            return 'Chrome'
        elif 'firefox' in ua_lower:
            return 'Firefox'
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            return 'Safari'
        
        # Bots and crawlers
        if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider']):
            return 'Bot/Crawler'
        
        # Command line tools
        if 'curl' in ua_lower:
            return 'cURL'
        
        return 'Other'
    
    def generate_summary_report(self) -> str:
        """Generate a comprehensive text summary report"""
        if not self.analysis_results:
            self.compute_descriptive_stats()
            if self.has_labels:
                self.compute_evaluation_metrics()
            self.extract_top_anomalous_patterns()
        
        report_lines = []
        report_lines.append("="*60)
        report_lines.append("LOG ANALYSIS SUMMARY REPORT")
        report_lines.append("="*60)
        
        # Basic stats
        stats = self.analysis_results.get('descriptive_stats', {})
        report_lines.append(f"\n📊 DATASET OVERVIEW")
        report_lines.append(f"Total Requests: {stats.get('total_requests', 0):,}")
        report_lines.append(f"Unique IPs: {stats.get('unique_ips', 0):,}")
        
        if stats.get('date_range', {}).get('duration_hours'):
            report_lines.append(f"Time Range: {stats['date_range']['duration_hours']:.1f} hours")
        
        anomaly_stats = stats.get('anomaly_stats', {})
        report_lines.append(f"Anomalies: {anomaly_stats.get('total_anomalies', 0):,} ({anomaly_stats.get('anomaly_rate', 0)*100:.1f}%)")
        
        # Evaluation metrics if available
        if 'evaluation_metrics' in self.analysis_results:
            metrics = self.analysis_results['evaluation_metrics']
            report_lines.append(f"\n🎯 EVALUATION METRICS")
            report_lines.append(f"Precision: {metrics.get('precision', 0):.3f}")
            report_lines.append(f"Recall: {metrics.get('recall', 0):.3f}")
            report_lines.append(f"F1-Score: {metrics.get('f1_score', 0):.3f}")
            report_lines.append(f"ROC AUC: {metrics.get('roc_curve', {}).get('auc', 0):.3f}")
        
        # Top patterns
        if 'anomalous_patterns' in self.analysis_results:
            patterns = self.analysis_results['anomalous_patterns']
            suspicious_paths = patterns.get('suspicious_paths', [])
            if suspicious_paths:
                report_lines.append(f"\n🚨 TOP SUSPICIOUS PATHS")
                for i, path_info in enumerate(suspicious_paths[:5], 1):
                    report_lines.append(f"{i}. {path_info['path']} ({path_info['count']} times)")
        
        report_lines.append("\n" + "="*60)
        
        return "\n".join(report_lines)

# Example usage
if __name__ == "__main__":
    from data_loader import LogDataLoader
    
    # Load synthetic data for testing
    loader = LogDataLoader()
    df = loader.generate_synthetic_data(num_samples=1000, anomaly_rate=0.15)
    df = loader.preprocess_for_analysis(df)
    
    # Analyze
    analyzer = LogAnalyzer(df)
    
    # Compute all analyses
    stats = analyzer.compute_descriptive_stats()
    metrics = analyzer.compute_evaluation_metrics()
    patterns = analyzer.extract_top_anomalous_patterns()
    
    # Generate report
    report = analyzer.generate_summary_report()
    print(report)
