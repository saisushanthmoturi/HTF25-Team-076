#!/usr/bin/env python3
"""
Advanced Threat Intelligence Integration Module
==============================================
Integrates external threat feeds, IP reputation, and advanced anomaly scoring
"""

import asyncio
import aiohttp
import requests
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import logging
from pathlib import Path

@dataclass
class ThreatIntelligenceData:
    """Data structure for threat intelligence information"""
    ip_address: str
    threat_type: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str
    malware_families: List[str]
    attack_types: List[str]

class ThreatIntelligenceEngine:
    """Advanced threat intelligence analysis engine"""
    
    def __init__(self, db_path: str = "data/threat_intelligence.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self._init_database()
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Threat intelligence sources (free APIs)
        self.intel_sources = {
            'abuseipdb': {
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'headers': {'Key': 'YOUR_API_KEY', 'Accept': 'application/json'},
                'rate_limit': 1000  # requests per day
            },
            'virustotal': {
                'url': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
                'params': {'apikey': 'YOUR_API_KEY'},
                'rate_limit': 500
            }
        }
        
        # Local threat patterns
        self.advanced_patterns = {
            'tor_exit_nodes': set(),
            'known_malware_c2': set(),
            'suspicious_domains': set(),
            'attack_signatures': []
        }
        
        # Load cached intelligence
        self._load_cached_intelligence()

    def _init_database(self):
        """Initialize SQLite database for threat intelligence"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    description TEXT,
                    malware_families TEXT,
                    attack_types TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, source)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip_address TEXT PRIMARY KEY,
                    reputation_score REAL NOT NULL,
                    country TEXT,
                    asn TEXT,
                    last_updated TIMESTAMP NOT NULL,
                    is_malicious BOOLEAN DEFAULT 0
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_hash TEXT UNIQUE NOT NULL,
                    pattern_type TEXT NOT NULL,
                    pattern_data TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    def _load_cached_intelligence(self):
        """Load cached threat intelligence from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Load recent threat IPs
                cursor = conn.execute('''
                    SELECT ip_address, threat_type, confidence 
                    FROM threat_intelligence 
                    WHERE last_seen > datetime('now', '-30 days')
                    AND confidence > 0.7
                ''')
                
                for ip, threat_type, confidence in cursor:
                    if threat_type == 'tor_exit':
                        self.advanced_patterns['tor_exit_nodes'].add(ip)
                    elif threat_type == 'malware_c2':
                        self.advanced_patterns['known_malware_c2'].add(ip)
                
                self.logger.info(f"Loaded {len(self.advanced_patterns['tor_exit_nodes'])} Tor exit nodes")
                self.logger.info(f"Loaded {len(self.advanced_patterns['known_malware_c2'])} C2 servers")
                
        except Exception as e:
            self.logger.error(f"Error loading cached intelligence: {e}")

    async def enrich_ip_intelligence(self, ip_address: str) -> Optional[ThreatIntelligenceData]:
        """Enrich IP address with threat intelligence from multiple sources"""
        try:
            # Check local cache first
            cached_intel = self._get_cached_intelligence(ip_address)
            if cached_intel and self._is_cache_fresh(cached_intel):
                return cached_intel
            
            # Gather intelligence from multiple sources
            intelligence_tasks = []
            
            # Add simulated threat intelligence (for demo)
            demo_intel = self._get_demo_intelligence(ip_address)
            if demo_intel:
                return demo_intel
            
            # In production, you would integrate with real threat feeds here
            # intelligence_tasks.append(self._query_abuseipdb(ip_address))
            # intelligence_tasks.append(self._query_virustotal(ip_address))
            
            # Combine results from all sources
            # results = await asyncio.gather(*intelligence_tasks, return_exceptions=True)
            
            # For now, return enhanced local analysis
            return self._analyze_ip_locally(ip_address)
            
        except Exception as e:
            self.logger.error(f"Error enriching IP intelligence for {ip_address}: {e}")
            return None

    def _get_demo_intelligence(self, ip_address: str) -> Optional[ThreatIntelligenceData]:
        """Generate demo threat intelligence data for testing"""
        # Simulate threat intelligence for specific IP patterns
        suspicious_patterns = {
            '10.0.0.': 'internal_scan',
            '192.168.': 'internal_recon',
            '172.16.': 'lateral_movement',
            '127.0.0.1': 'localhost_abuse'
        }
        
        for pattern, threat_type in suspicious_patterns.items():
            if ip_address.startswith(pattern):
                return ThreatIntelligenceData(
                    ip_address=ip_address,
                    threat_type=threat_type,
                    confidence=0.85,
                    source='demo_intel',
                    first_seen=datetime.now() - timedelta(days=5),
                    last_seen=datetime.now(),
                    description=f"Suspicious {threat_type} activity detected",
                    malware_families=['generic_scanner'],
                    attack_types=['reconnaissance', 'scanning']
                )
        
        # High-risk IPs for demo
        high_risk_ips = {
            '203.0.113.1': ('botnet_c2', 0.95),
            '198.51.100.1': ('tor_exit', 0.80),
            '192.0.2.1': ('malware_dropper', 0.90)
        }
        
        if ip_address in high_risk_ips:
            threat_type, confidence = high_risk_ips[ip_address]
            return ThreatIntelligenceData(
                ip_address=ip_address,
                threat_type=threat_type,
                confidence=confidence,
                source='threat_feed_demo',
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now() - timedelta(hours=2),
                description=f"Known {threat_type} infrastructure",
                malware_families=['mirai', 'emotet'] if threat_type == 'botnet_c2' else [],
                attack_types=['ddos', 'spam'] if threat_type == 'botnet_c2' else ['anonymization']
            )
        
        return None

    def _analyze_ip_locally(self, ip_address: str) -> ThreatIntelligenceData:
        """Perform local IP analysis based on patterns"""
        confidence = 0.1  # Base confidence for unknown IPs
        threat_type = 'unknown'
        description = "No specific threat intelligence available"
        attack_types = []
        malware_families = []
        
        # Analyze IP characteristics
        if ip_address in self.advanced_patterns['tor_exit_nodes']:
            threat_type = 'tor_exit'
            confidence = 0.8
            description = "Tor exit node - potential anonymization"
            attack_types = ['anonymization']
        elif ip_address in self.advanced_patterns['known_malware_c2']:
            threat_type = 'malware_c2'
            confidence = 0.9
            description = "Known malware command and control server"
            attack_types = ['malware', 'command_control']
            malware_families = ['generic']
        elif self._is_suspicious_ip_pattern(ip_address):
            threat_type = 'suspicious_pattern'
            confidence = 0.4
            description = "IP matches suspicious patterns"
            attack_types = ['reconnaissance']
        
        return ThreatIntelligenceData(
            ip_address=ip_address,
            threat_type=threat_type,
            confidence=confidence,
            source='local_analysis',
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            description=description,
            malware_families=malware_families,
            attack_types=attack_types
        )

    def _is_suspicious_ip_pattern(self, ip_address: str) -> bool:
        """Check if IP matches suspicious patterns"""
        suspicious_patterns = [
            # Cloud provider ranges often used for attacks
            '173.252.', '31.13.', '157.240.',  # Facebook/Meta
            '8.8.8.', '8.8.4.',  # Google DNS (suspicious if used as source)
            '1.1.1.', '1.0.0.',  # Cloudflare DNS
        ]
        
        return any(ip_address.startswith(pattern) for pattern in suspicious_patterns)

    def _get_cached_intelligence(self, ip_address: str) -> Optional[ThreatIntelligenceData]:
        """Retrieve cached threat intelligence"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT * FROM threat_intelligence 
                    WHERE ip_address = ? 
                    ORDER BY last_seen DESC 
                    LIMIT 1
                ''', (ip_address,))
                
                row = cursor.fetchone()
                if row:
                    return ThreatIntelligenceData(
                        ip_address=row[1],
                        threat_type=row[2],
                        confidence=row[3],
                        source=row[4],
                        first_seen=datetime.fromisoformat(row[5]),
                        last_seen=datetime.fromisoformat(row[6]),
                        description=row[7] or "",
                        malware_families=json.loads(row[8] or "[]"),
                        attack_types=json.loads(row[9] or "[]")
                    )
        except Exception as e:
            self.logger.error(f"Error retrieving cached intelligence: {e}")
        
        return None

    def _is_cache_fresh(self, intel: ThreatIntelligenceData, max_age_hours: int = 24) -> bool:
        """Check if cached intelligence is still fresh"""
        age = datetime.now() - intel.last_seen
        return age.total_seconds() < (max_age_hours * 3600)

    def cache_intelligence(self, intel: ThreatIntelligenceData):
        """Cache threat intelligence data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO threat_intelligence
                    (ip_address, threat_type, confidence, source, first_seen, last_seen, 
                     description, malware_families, attack_types)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    intel.ip_address, intel.threat_type, intel.confidence, intel.source,
                    intel.first_seen.isoformat(), intel.last_seen.isoformat(),
                    intel.description, json.dumps(intel.malware_families),
                    json.dumps(intel.attack_types)
                ))
        except Exception as e:
            self.logger.error(f"Error caching intelligence: {e}")

    def calculate_threat_score(self, log_data: Dict, intel: Optional[ThreatIntelligenceData] = None) -> float:
        """Calculate advanced threat score based on log data and intelligence"""
        base_score = 0.0
        
        # Intelligence-based scoring
        if intel:
            base_score += intel.confidence * 0.4
            
            # Boost score for specific threat types
            threat_multipliers = {
                'malware_c2': 1.0,
                'botnet_c2': 0.9,
                'tor_exit': 0.3,
                'suspicious_pattern': 0.2,
                'internal_scan': 0.7,
                'lateral_movement': 0.8
            }
            base_score *= threat_multipliers.get(intel.threat_type, 0.1)
        
        # Behavioral scoring from log data
        suspicious_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
        if log_data.get('method') in suspicious_methods:
            base_score += 0.1
        
        # Error codes indicating attacks
        error_codes = [403, 404, 500, 501, 502, 503]
        if log_data.get('status') in error_codes:
            base_score += 0.15
        
        # Suspicious paths
        path = log_data.get('path', '').lower()
        suspicious_paths = ['admin', 'wp-admin', '.env', 'config', 'backup', 'sql']
        if any(sus_path in path for sus_path in suspicious_paths):
            base_score += 0.2
        
        # User agent analysis
        user_agent = log_data.get('user_agent', '').lower()
        scanner_agents = ['sqlmap', 'nmap', 'nikto', 'burp', 'curl', 'wget', 'python']
        if any(scanner in user_agent for scanner in scanner_agents):
            base_score += 0.3
        
        # Normalize score to 0-1 range
        return min(max(base_score, 0.0), 1.0)

    def get_threat_summary(self) -> Dict:
        """Get summary of threat intelligence data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT 
                        threat_type,
                        COUNT(*) as count,
                        AVG(confidence) as avg_confidence,
                        MAX(last_seen) as latest_seen
                    FROM threat_intelligence 
                    WHERE last_seen > datetime('now', '-7 days')
                    GROUP BY threat_type
                    ORDER BY count DESC
                ''')
                
                threat_summary = {}
                for row in cursor:
                    threat_summary[row[0]] = {
                        'count': row[1],
                        'avg_confidence': round(row[2], 3),
                        'latest_seen': row[3]
                    }
                
                return {
                    'total_threats': sum(data['count'] for data in threat_summary.values()),
                    'threat_types': len(threat_summary),
                    'threats_by_type': threat_summary
                }
                
        except Exception as e:
            self.logger.error(f"Error generating threat summary: {e}")
            return {'error': str(e)}

# Example usage and testing
async def main():
    """Test the threat intelligence engine"""
    engine = ThreatIntelligenceEngine()
    
    # Test IPs
    test_ips = [
        '192.168.1.100',  # Internal IP
        '203.0.113.1',    # High-risk demo IP
        '198.51.100.1',   # Tor exit demo IP
        '8.8.8.8',        # Google DNS
        '127.0.0.1'       # Localhost
    ]
    
    print("🛡️ Advanced Threat Intelligence Analysis")
    print("=" * 50)
    
    for ip in test_ips:
        intel = await engine.enrich_ip_intelligence(ip)
        if intel:
            print(f"\n📍 IP: {ip}")
            print(f"   Threat Type: {intel.threat_type}")
            print(f"   Confidence: {intel.confidence:.2f}")
            print(f"   Source: {intel.source}")
            print(f"   Description: {intel.description}")
            
            # Cache the intelligence
            engine.cache_intelligence(intel)
            
            # Calculate threat score
            log_data = {
                'method': 'POST',
                'path': '/admin/login',
                'status': 403,
                'user_agent': 'sqlmap/1.4.12'
            }
            
            threat_score = engine.calculate_threat_score(log_data, intel)
            print(f"   Threat Score: {threat_score:.3f}")
    
    # Print summary
    print("\n📊 Threat Intelligence Summary:")
    summary = engine.get_threat_summary()
    for threat_type, data in summary.get('threats_by_type', {}).items():
        print(f"   {threat_type}: {data['count']} instances (avg confidence: {data['avg_confidence']})")

if __name__ == "__main__":
    asyncio.run(main())
