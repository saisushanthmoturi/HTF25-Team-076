#!/usr/bin/env python3
"""
Advanced Attack Simulation & Training Data Generator
===================================================
Generates realistic cybersecurity attack patterns for continuous model training
"""

import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import json
import asyncio
import aiohttp
import threading
import time
from dataclasses import dataclass
from pathlib import Path
import logging
from faker import Faker
import ipaddress
import re

@dataclass
class AttackPattern:
    """Data structure for attack patterns"""
    name: str
    category: str
    severity: str
    frequency: float
    duration_range: Tuple[int, int]
    ip_patterns: List[str]
    user_agents: List[str]
    paths: List[str]
    methods: List[str]
    payload_patterns: List[str]
    response_codes: List[int]
    
class AdvancedAttackSimulator:
    """Advanced cybersecurity attack pattern simulator"""
    
    def __init__(self, output_dir: str = "data/attack_simulation"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.faker = Faker()
        self.logger = logging.getLogger(__name__)
        
        # Initialize attack patterns
        self.attack_patterns = self._initialize_attack_patterns()
        
        # Benign traffic patterns
        self.benign_patterns = self._initialize_benign_patterns()
        
        # IP pools for different types of traffic
        self.ip_pools = {
            'normal_users': self._generate_ip_pool('normal', 1000),
            'corporate_networks': self._generate_ip_pool('corporate', 50),
            'tor_exits': self._generate_ip_pool('tor', 100),
            'botnets': self._generate_ip_pool('botnet', 200),
            'scanners': self._generate_ip_pool('scanner', 50),
            'cloud_providers': self._generate_ip_pool('cloud', 100)
        }
        
        # User agent libraries
        self.user_agents = {
            'legitimate': self._load_legitimate_user_agents(),
            'scanners': self._load_scanner_user_agents(),
            'bots': self._load_bot_user_agents()
        }
        
        # Attack campaigns (persistent attacks over time)
        self.active_campaigns = []
        
        # Ensure IP pools have safe defaults
        for pool_name in ['normal_users', 'corporate_networks', 'tor_exits', 'botnets', 'scanners', 'cloud_providers']:
            if pool_name not in self.ip_pools or not self.ip_pools[pool_name]:
                self.ip_pools[pool_name] = self._generate_ip_pool('default', 50)
        
        # Statistics tracking
        self.generation_stats = {
            'total_requests': 0,
            'benign_requests': 0,
            'malicious_requests': 0,
            'attacks_by_category': {},
            'start_time': datetime.now()
        }

    def _initialize_attack_patterns(self) -> Dict[str, AttackPattern]:
        """Initialize comprehensive attack patterns"""
        return {
            'sql_injection': AttackPattern(
                name='SQL Injection Attack',
                category='injection',
                severity='high',
                frequency=0.15,
                duration_range=(30, 300),
                ip_patterns=['192.168.', '10.0.', '172.16.', 'random'],
                user_agents=['scanner', 'bot'],
                paths=[
                    '/login.php?id=1\' OR \'1\'=\'1',
                    '/search?q=\' UNION SELECT * FROM users--',
                    '/admin/users.php?id=1\' AND 1=1--',
                    '/api/user?id=1\'; DROP TABLE users;--',
                    '/product.php?id=1\' OR sleep(5)--'
                ],
                methods=['GET', 'POST'],
                payload_patterns=[
                    'OR 1=1--',
                    'UNION SELECT',
                    '\' OR \'a\'=\'a',
                    'EXEC xp_cmdshell',
                    'INSERT INTO'
                ],
                response_codes=[500, 200, 403, 400]
            ),
            
            'xss_attack': AttackPattern(
                name='Cross-Site Scripting',
                category='injection',
                severity='medium',
                frequency=0.12,
                duration_range=(10, 120),
                ip_patterns=['random'],
                user_agents=['legitimate', 'scanner'],
                paths=[
                    '/search?q=<script>alert(1)</script>',
                    '/comment.php?msg=<img src=x onerror=alert(1)>',
                    '/profile.php?name=<svg onload=alert(1)>',
                    '/forum.php?post=<iframe src=javascript:alert(1)>',
                    '/contact.php?feedback=<script>document.location=evil.com</script>'
                ],
                methods=['GET', 'POST'],
                payload_patterns=[
                    '<script>',
                    'javascript:',
                    'onerror=',
                    'onload=',
                    'document.cookie'
                ],
                response_codes=[200, 400, 403]
            ),
            
            'directory_traversal': AttackPattern(
                name='Directory Traversal',
                category='path_traversal',
                severity='high',
                frequency=0.10,
                duration_range=(20, 180),
                ip_patterns=['tor_exits', 'scanners'],
                user_agents=['scanner', 'bot'],
                paths=[
                    '/file.php?path=../../../etc/passwd',
                    '/download?file=....//....//etc/shadow',
                    '/include.php?page=../../../../windows/system32/drivers/etc/hosts',
                    '/view.php?doc=../../config/database.conf',
                    '/backup?file=../../../home/user/.ssh/id_rsa'
                ],
                methods=['GET'],
                payload_patterns=[
                    '../',
                    '..\\',
                    '/etc/passwd',
                    '/windows/system32',
                    '.ssh/id_rsa'
                ],
                response_codes=[404, 403, 200, 500]
            ),
            
            'brute_force': AttackPattern(
                name='Brute Force Authentication',
                category='authentication',
                severity='high',
                frequency=0.20,
                duration_range=(300, 1800),
                ip_patterns=['botnets', 'tor_exits'],
                user_agents=['bot', 'scanner'],
                paths=[
                    '/login',
                    '/admin/login',
                    '/wp-login.php',
                    '/api/auth',
                    '/ssh/',
                    '/ftp/'
                ],
                methods=['POST'],
                payload_patterns=[
                    'password=123456',
                    'password=admin',
                    'password=password',
                    'username=admin',
                    'auth_token='
                ],
                response_codes=[401, 403, 429, 200]
            ),
            
            'dos_attack': AttackPattern(
                name='Denial of Service',
                category='availability',
                severity='critical',
                frequency=0.05,
                duration_range=(120, 600),
                ip_patterns=['botnets', 'cloud_providers'],
                user_agents=['bot'],
                paths=[
                    '/heavy-computation',
                    '/api/search',
                    '/generate-report',
                    '/upload',
                    '/api/data'
                ],
                methods=['GET', 'POST', 'PUT'],
                payload_patterns=[
                    'size=999999',
                    'count=10000',
                    'recursive=true'
                ],
                response_codes=[503, 502, 500, 429]
            ),
            
            'reconnaissance': AttackPattern(
                name='Network Reconnaissance',
                category='reconnaissance',
                severity='medium',
                frequency=0.25,
                duration_range=(60, 900),
                ip_patterns=['scanners', 'random'],
                user_agents=['scanner'],
                paths=[
                    '/robots.txt',
                    '/admin/',
                    '/.git/',
                    '/.env',
                    '/config.php',
                    '/backup/',
                    '/test/',
                    '/api/',
                    '/phpinfo.php',
                    '/server-status'
                ],
                methods=['GET', 'HEAD', 'OPTIONS'],
                payload_patterns=[],
                response_codes=[404, 403, 200, 301]
            ),
            
            'api_abuse': AttackPattern(
                name='API Abuse',
                category='abuse',
                severity='medium',
                frequency=0.08,
                duration_range=(180, 600),
                ip_patterns=['cloud_providers', 'random'],
                user_agents=['bot', 'legitimate'],
                paths=[
                    '/api/v1/users',
                    '/api/search?limit=9999',
                    '/api/export',
                    '/api/admin/users',
                    '/api/internal/'
                ],
                methods=['GET', 'POST', 'PUT', 'DELETE'],
                payload_patterns=[
                    'limit=9999',
                    'offset=0',
                    'admin=true',
                    'export=all'
                ],
                response_codes=[429, 403, 401, 200]
            ),
            
            'malware_c2': AttackPattern(
                name='Malware Command & Control',
                category='malware',
                severity='critical',
                frequency=0.03,
                duration_range=(60, 300),
                ip_patterns=['cloud_providers', 'random'],
                user_agents=['bot'],
                paths=[
                    '/api/beacon',
                    '/update.php',
                    '/check.asp',
                    '/heartbeat',
                    '/config.json'
                ],
                methods=['POST', 'GET'],
                payload_patterns=[
                    'id=bot',
                    'cmd=',
                    'update=true',
                    'encrypted='
                ],
                response_codes=[200, 404]
            ),
            
            'data_exfiltration': AttackPattern(
                name='Data Exfiltration',
                category='exfiltration',
                severity='critical',
                frequency=0.02,
                duration_range=(300, 1200),
                ip_patterns=['tor_exits', 'cloud_providers'],
                user_agents=['legitimate'],
                paths=[
                    '/api/export/users',
                    '/backup/database.sql',
                    '/admin/export',
                    '/api/dump',
                    '/download/logs'
                ],
                methods=['GET', 'POST'],
                payload_patterns=[
                    'format=json',
                    'all=true',
                    'compressed=true'
                ],
                response_codes=[200, 206, 403]
            )
        }

    def _initialize_benign_patterns(self) -> Dict[str, List]:
        """Initialize benign traffic patterns"""
        return {
            'normal_browsing': {
                'paths': [
                    '/', '/home', '/about', '/contact', '/services',
                    '/products', '/blog', '/news', '/faq', '/help',
                    '/search', '/category/', '/user/profile', '/dashboard'
                ],
                'methods': ['GET', 'POST'],
                'user_agents': 'legitimate',
                'response_codes': [200, 301, 302, 404]
            },
            'api_usage': {
                'paths': [
                    '/api/status', '/api/health', '/api/version',
                    '/api/users/me', '/api/data', '/api/search',
                    '/api/analytics', '/api/metrics'
                ],
                'methods': ['GET', 'POST', 'PUT'],
                'user_agents': 'legitimate',
                'response_codes': [200, 201, 400, 401, 404]
            },
            'file_operations': {
                'paths': [
                    '/upload', '/download/', '/files/', '/images/',
                    '/documents/', '/media/', '/assets/'
                ],
                'methods': ['GET', 'POST', 'PUT'],
                'user_agents': 'legitimate',
                'response_codes': [200, 201, 404, 413]
            },
            'authentication': {
                'paths': [
                    '/login', '/logout', '/register', '/forgot-password',
                    '/reset-password', '/verify-email', '/2fa'
                ],
                'methods': ['GET', 'POST'],
                'user_agents': 'legitimate',
                'response_codes': [200, 302, 400, 401, 422]
            }
        }

    def _generate_ip_pool(self, pool_type: str, count: int) -> List[str]:
        """Generate IP address pools for different traffic types"""
        ips = []
        
        if pool_type == 'normal':
            # Residential and corporate IP ranges
            ranges = ['192.168.', '10.0.', '172.16.', '203.0.113.', '198.51.100.']
            for _ in range(count):
                base = random.choice(ranges)
                if len(base.split('.')) == 2:
                    ip = f"{base}{random.randint(1,254)}.{random.randint(1,254)}"
                else:
                    ip = f"{base}{random.randint(1,254)}"
                ips.append(ip)
                
        elif pool_type == 'tor':
            # Simulated Tor exit node IPs
            for _ in range(count):
                ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                ips.append(ip)
                
        elif pool_type == 'botnet':
            # Botnet IPs (compromised residential)
            for _ in range(count):
                ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                ips.append(ip)
                
        elif pool_type == 'cloud':
            # Cloud provider IP ranges
            aws_ranges = ['52.', '54.', '18.', '34.', '35.']
            for _ in range(count):
                base = random.choice(aws_ranges)
                ip = f"{base}{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                ips.append(ip)
                
        else:  # scanner, corporate, etc.
            for _ in range(count):
                ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                ips.append(ip)
        
        return ips

    def _load_legitimate_user_agents(self) -> List[str]:
        """Load legitimate user agent strings"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ]

    def _load_scanner_user_agents(self) -> List[str]:
        """Load security scanner user agent strings"""
        return [
            'sqlmap/1.7.12#stable (http://sqlmap.org)',
            'Nmap Scripting Engine',
            'Nikto/2.5.0',
            'dirb/2.22',
            'gobuster/3.1.0',
            'Burp Suite Professional',
            'OWASP ZAP/2.12.0',
            'curl/7.68.0',
            'wget/1.20.3',
            'python-requests/2.28.1',
            'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)'
        ]

    def _load_bot_user_agents(self) -> List[str]:
        """Load bot user agent strings"""
        return [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
            'Twitterbot/1.0',
            'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)',
            'Python/3.9 aiohttp/3.8.1',
            'Go-http-client/1.1',
            'okhttp/4.9.0',
            'bot/1.0',
            'crawler/2.0'
        ]

    async def generate_attack_campaign(self, attack_type: str, duration_minutes: int, 
                                     requests_per_minute: int = 10) -> List[Dict]:
        """Generate a sustained attack campaign"""
        attack_pattern = self.attack_patterns.get(attack_type)
        if not attack_pattern:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        campaign_logs = []
        start_time = datetime.now()
        
        # Select attacking IPs (could be single IP or botnet)
        if attack_type in ['brute_force', 'dos_attack']:
            # Use multiple IPs for distributed attacks
            botnet_ips = self.ip_pools.get('botnets', [])
            tor_ips = self.ip_pools.get('tor_exits', [])
            all_attacking_ips = botnet_ips + tor_ips
            
            if not all_attacking_ips:
                all_attacking_ips = self.ip_pools.get('normal_users', [self.faker.ipv4() for _ in range(10)])
            
            attacking_ips = random.sample(
                all_attacking_ips,
                min(50, requests_per_minute // 2, len(all_attacking_ips))
            )
            if not attacking_ips:
                attacking_ips = [self.faker.ipv4()]
        else:
            # Single IP or small group
            ip_pool_options = []
            for pool_name in attack_pattern.ip_patterns:
                if pool_name == 'random':
                    ip_pool_options.append(self.faker.ipv4())
                elif pool_name == 'tor' and 'tor_exits' in self.ip_pools:
                    ip_pool_options.extend(self.ip_pools['tor_exits'][:5])
                elif pool_name in self.ip_pools:
                    ip_pool_options.extend(self.ip_pools[pool_name][:5])
            
            # Fallback to normal IPs if no options
            if not ip_pool_options:
                ip_pool_options = self.ip_pools.get('normal_users', [self.faker.ipv4() for _ in range(5)])
                
            attacking_ips = ip_pool_options[:min(5, len(ip_pool_options))]
            if not attacking_ips:
                attacking_ips = [self.faker.ipv4()]
        
        # Generate attack requests over time
        for minute in range(duration_minutes):
            current_time = start_time + timedelta(minutes=minute)
            
            for _ in range(requests_per_minute):
                # Add some randomness to request timing
                request_time = current_time + timedelta(
                    seconds=random.randint(0, 59),
                    microseconds=random.randint(0, 999999)
                )
                
                # Generate attack request
                attack_log = self._generate_attack_request(attack_pattern, attacking_ips, request_time)
                campaign_logs.append(attack_log)
                
                # Small delay to simulate realistic timing
                await asyncio.sleep(0.001)
        
        self.logger.info(f"Generated {len(campaign_logs)} requests for {attack_type} campaign")
        return campaign_logs

    def _generate_attack_request(self, pattern: AttackPattern, source_ips: List[str], 
                               timestamp: datetime) -> Dict:
        """Generate a single attack request"""
        
        # Select components
        ip = random.choice(source_ips)
        path = random.choice(pattern.paths)
        method = random.choice(pattern.methods)
        response_code = random.choice(pattern.response_codes)
        
        # Select user agent
        ua_categories = []
        for ua_cat in pattern.user_agents:
            if ua_cat in self.user_agents:
                ua_categories.extend(self.user_agents[ua_cat])
        
        # Fallback to legitimate user agents if none found
        if not ua_categories:
            ua_categories = self.user_agents['legitimate']
        
        user_agent = random.choice(ua_categories)
        
        # Add payload if applicable
        if pattern.payload_patterns and random.random() < 0.7:
            payload = random.choice(pattern.payload_patterns)
            if '?' in path:
                path += f"&payload={payload}"
            else:
                path += f"?payload={payload}"
        
        # Calculate response size (attacks often have different response patterns)
        if response_code == 200:
            response_size = random.randint(1000, 50000)
        elif response_code in [403, 404]:
            response_size = random.randint(100, 1000)
        else:
            response_size = random.randint(500, 5000)
        
        # Generate referrer (often missing in attacks)
        referer = ""
        if random.random() < 0.3:  # 30% chance of having a referer
            referer = f"http://{self.faker.domain_name()}/"
        
        return {
            'timestamp': timestamp,
            'ip_address': ip,
            'method': method,
            'path': path,
            'status': response_code,
            'size': response_size,
            'referer': referer,
            'user_agent': user_agent,
            'attack_type': pattern.category,
            'attack_name': pattern.name,
            'severity': pattern.severity,
            'is_malicious': True
        }

    def generate_benign_traffic(self, num_requests: int, time_span_hours: int = 24) -> List[Dict]:
        """Generate benign traffic patterns"""
        benign_logs = []
        start_time = datetime.now() - timedelta(hours=time_span_hours)
        
        for _ in range(num_requests):
            # Random timestamp within the time span
            random_minutes = random.randint(0, time_span_hours * 60)
            timestamp = start_time + timedelta(minutes=random_minutes)
            
            # Select benign pattern
            pattern_name = random.choice(list(self.benign_patterns.keys()))
            pattern = self.benign_patterns[pattern_name]
            
            # Generate benign request
            ip = random.choice(self.ip_pools['normal_users'])
            path = random.choice(pattern['paths'])
            method = random.choice(pattern['methods'])
            response_code = random.choice(pattern['response_codes'])
            
            # Select user agent based on pattern specification
            if isinstance(pattern['user_agents'], str):
                if pattern['user_agents'] in self.user_agents:
                    user_agent = random.choice(self.user_agents[pattern['user_agents']])
                else:
                    user_agent = random.choice(self.user_agents['legitimate'])
            else:
                user_agent = random.choice(self.user_agents['legitimate'])
            
            # Realistic response sizes for benign traffic
            if response_code == 200:
                response_size = random.randint(5000, 100000)
            elif response_code in [301, 302]:
                response_size = random.randint(200, 500)
            else:
                response_size = random.randint(1000, 10000)
            
            # Often have referrers
            referer = ""
            if random.random() < 0.7:
                referer = f"http://{self.faker.domain_name()}/"
            
            benign_log = {
                'timestamp': timestamp,
                'ip_address': ip,
                'method': method,
                'path': path,
                'status': response_code,
                'size': response_size,
                'referer': referer,
                'user_agent': user_agent,
                'attack_type': 'benign',
                'attack_name': pattern_name,
                'severity': 'none',
                'is_malicious': False
            }
            
            benign_logs.append(benign_log)
        
        return benign_logs

    async def generate_mixed_traffic(self, total_requests: int, malicious_ratio: float = 0.1,
                                   output_file: Optional[str] = None) -> pd.DataFrame:
        """Generate mixed traffic with both benign and malicious requests"""
        
        malicious_count = int(total_requests * malicious_ratio)
        benign_count = total_requests - malicious_count
        
        self.logger.info(f"Generating {total_requests} requests ({malicious_count} malicious, {benign_count} benign)")
        
        # Generate benign traffic
        benign_logs = self.generate_benign_traffic(benign_count)
        
        # Generate malicious traffic (distributed across attack types)
        malicious_logs = []
        attack_distribution = {
            'reconnaissance': 0.35,
            'brute_force': 0.20,
            'sql_injection': 0.15,
            'xss_attack': 0.10,
            'directory_traversal': 0.08,
            'dos_attack': 0.05,
            'api_abuse': 0.04,
            'malware_c2': 0.02,
            'data_exfiltration': 0.01
        }
        
        for attack_type, ratio in attack_distribution.items():
            attack_requests = int(malicious_count * ratio)
            if attack_requests > 0:
                # Generate as mini-campaigns
                campaign_logs = await self.generate_attack_campaign(
                    attack_type, 
                    duration_minutes=random.randint(10, 60),
                    requests_per_minute=max(1, attack_requests // 30)
                )
                malicious_logs.extend(campaign_logs[:attack_requests])
        
        # Combine and shuffle
        all_logs = benign_logs + malicious_logs
        random.shuffle(all_logs)
        
        # Sort by timestamp
        all_logs.sort(key=lambda x: x['timestamp'])
        
        # Create DataFrame
        df = pd.DataFrame(all_logs)
        
        # Update statistics
        self.generation_stats['total_requests'] += len(all_logs)
        self.generation_stats['benign_requests'] += benign_count
        self.generation_stats['malicious_requests'] += len(malicious_logs)
        
        for attack_type in attack_distribution.keys():
            attack_count = len([log for log in malicious_logs if log['attack_name'].lower().replace(' ', '_') == attack_type])
            self.generation_stats['attacks_by_category'][attack_type] = \
                self.generation_stats['attacks_by_category'].get(attack_type, 0) + attack_count
        
        # Save to file if specified
        if output_file:
            output_path = self.output_dir / output_file
            df.to_csv(output_path, index=False)
            self.logger.info(f"Saved {len(df)} requests to {output_path}")
        
        return df

    def get_statistics(self) -> Dict:
        """Get traffic generation statistics"""
        return {
            'generation_stats': self.generation_stats,
            'available_attacks': list(self.attack_patterns.keys()),
            'ip_pool_sizes': {k: len(v) for k, v in self.ip_pools.items()},
            'user_agent_counts': {k: len(v) for k, v in self.user_agents.items()}
        }

    def save_attack_patterns(self, filename: str = "attack_patterns.json"):
        """Save attack patterns configuration"""
        patterns_dict = {}
        for name, pattern in self.attack_patterns.items():
            patterns_dict[name] = {
                'name': pattern.name,
                'category': pattern.category,
                'severity': pattern.severity,
                'frequency': pattern.frequency,
                'duration_range': pattern.duration_range,
                'ip_patterns': pattern.ip_patterns,
                'user_agents': pattern.user_agents,
                'paths': pattern.paths,
                'methods': pattern.methods,
                'payload_patterns': pattern.payload_patterns,
                'response_codes': pattern.response_codes
            }
        
        with open(self.output_dir / filename, 'w') as f:
            json.dump(patterns_dict, f, indent=2)
        
        self.logger.info(f"Saved attack patterns to {filename}")

# Example usage and testing
async def main():
    """Test the advanced attack simulator"""
    print("🎯 Advanced Attack Simulation & Training Data Generator")
    print("=" * 60)
    
    simulator = AdvancedAttackSimulator()
    
    # Generate mixed traffic dataset
    print("Generating mixed traffic dataset...")
    df = await simulator.generate_mixed_traffic(
        total_requests=5000,
        malicious_ratio=0.2,
        output_file="mixed_attack_simulation.csv"
    )
    
    # Show statistics
    print(f"\n📊 Generated Dataset Statistics:")
    print(f"   Total Requests: {len(df):,}")
    print(f"   Malicious: {df['is_malicious'].sum():,}")
    print(f"   Benign: {(~df['is_malicious']).sum():,}")
    
    print(f"\n🔍 Attack Type Distribution:")
    attack_counts = df[df['is_malicious']]['attack_name'].value_counts()
    for attack, count in attack_counts.items():
        print(f"   {attack}: {count}")
    
    print(f"\n🌐 IP Address Analysis:")
    unique_ips = df['ip_address'].nunique()
    print(f"   Unique IP Addresses: {unique_ips}")
    
    print(f"\n🕐 Time Range:")
    print(f"   Start: {df['timestamp'].min()}")
    print(f"   End: {df['timestamp'].max()}")
    
    # Show sample malicious requests
    print(f"\n🚨 Sample Malicious Requests:")
    malicious_samples = df[df['is_malicious']].sample(3)
    for _, row in malicious_samples.iterrows():
        print(f"   {row['attack_name']}: {row['method']} {row['path'][:50]}...")
    
    # System statistics
    print(f"\n⚙️ System Statistics:")
    stats = simulator.get_statistics()
    print(f"   Available Attack Types: {len(stats['available_attacks'])}")
    print(f"   Total IP Pools: {sum(stats['ip_pool_sizes'].values()):,}")
    print(f"   User Agent Categories: {len(stats['user_agent_counts'])}")
    
    # Save attack patterns
    simulator.save_attack_patterns()
    print(f"\n💾 Attack patterns saved to attack_patterns.json")

if __name__ == "__main__":
    asyncio.run(main())
