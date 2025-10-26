#!/usr/bin/env python3
"""
Complete System Demonstration - ML + Cybersecurity Analysis
===========================================================
Showcases all advanced features working in harmony
"""

import asyncio
import numpy as np
import pandas as pd
from datetime import datetime
import time

# Import all advanced components
from threat_intelligence import ThreatIntelligenceEngine
from advanced_attack_simulator import AdvancedAttackSimulator

async def demonstration():
    """Complete system demonstration"""
    print("🎯 ADVANCED ML + CYBERSECURITY SYSTEM DEMONSTRATION")
    print("="*65)
    print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Initialize components
    print("🔧 Initializing System Components...")
    threat_intel = ThreatIntelligenceEngine()
    attack_sim = AdvancedAttackSimulator()
    print("   ✅ All components initialized successfully")
    print()
    
    # Demo 1: Threat Intelligence
    print("🔍 DEMO 1: Advanced Threat Intelligence")
    print("-" * 45)
    
    demo_ips = ['192.168.1.100', '8.8.8.8', '203.0.113.1', '127.0.0.1']
    
    for ip in demo_ips:
        intel = await threat_intel.enrich_ip_intelligence(ip)
        if intel:
            print(f"📍 {ip}:")
            print(f"   🚨 Threat Type: {intel.threat_type}")
            print(f"   💯 Confidence: {intel.confidence:.2f}")
            print(f"   📊 Source: {intel.source}")
            print(f"   📝 Description: {intel.description}")
        else:
            print(f"📍 {ip}: No threat intelligence available")
        print()
    
    # Demo 2: Attack Simulation
    print("⚔️  DEMO 2: Advanced Attack Simulation")
    print("-" * 45)
    
    attack_types = ['sql_injection', 'xss_attack', 'brute_force']
    
    for attack_type in attack_types:
        print(f"🎯 Simulating {attack_type} attack...")
        campaign = await attack_sim.generate_attack_campaign(
            attack_type=attack_type,
            duration_minutes=1,
            requests_per_minute=3
        )
        
        print(f"   📊 Generated {len(campaign)} attack scenarios")
        
        if campaign:
            sample = campaign[0]
            print(f"   🌐 Sample method: {sample.get('method', 'N/A')}")
            print(f"   🎯 Sample path: {sample.get('path', 'N/A')[:50]}...")
            print(f"   🔧 Payload preview: {sample.get('payload', 'N/A')[:30]}...")
        print()
    
    # Demo 3: Threat Scoring
    print("📊 DEMO 3: Real-time Threat Scoring")
    print("-" * 45)
    
    sample_requests = [
        {
            'source_ip': '203.0.113.1',
            'method': 'POST',
            'path': '/admin/login',
            'status_code': 401,
            'user_agent': 'curl/7.68.0',
            'request_size': 1024
        },
        {
            'source_ip': '192.168.1.1', 
            'method': 'GET',
            'path': '/search?q=laptop',
            'status_code': 200,
            'user_agent': 'Mozilla/5.0 (Chrome)',
            'request_size': 512
        },
        {
            'source_ip': '10.0.0.1',
            'method': 'GET', 
            'path': '/admin/../../../etc/passwd',
            'status_code': 404,
            'user_agent': 'python-requests/2.28.1',
            'request_size': 2048
        }
    ]
    
    for i, request in enumerate(sample_requests):
        print(f"🔍 Analyzing request {i+1}:")
        print(f"   📍 IP: {request['source_ip']}")
        print(f"   🌐 Request: {request['method']} {request['path']}")
        
        threat_score = threat_intel.calculate_threat_score(request)
        
        if threat_score > 0.7:
            risk_level = "🔴 HIGH"
        elif threat_score > 0.4:
            risk_level = "🟡 MEDIUM"  
        else:
            risk_level = "🟢 LOW"
            
        print(f"   🎯 Threat Score: {threat_score:.3f} ({risk_level})")
        print()
    
    # Demo 4: System Statistics
    print("📈 DEMO 4: System Performance Statistics")
    print("-" * 45)
    
    summary = threat_intel.get_threat_summary()
    print(f"🔍 Threat Intelligence Summary:")
    print(f"   📊 Total threats tracked: {summary.get('total_threats', 0)}")
    print(f"   🎯 Unique threat types: {summary.get('threat_types', 0)}")
    
    available_patterns = list(attack_sim.attack_patterns.keys())
    print(f"\\n⚔️  Attack Simulation Capabilities:")
    print(f"   📊 Available attack patterns: {len(available_patterns)}")
    print(f"   🎯 Pattern types: {', '.join(available_patterns[:5])}...")
    
    print(f"\\n🖥️  Dashboard Availability:")
    print(f"   📱 Advanced Dashboard: http://localhost:8502")
    print(f"   🔄 Monitoring System: http://localhost:8501") 
    print(f"   📊 Analytics Dashboard: http://localhost:8503")
    
    print(f"\\n🌐 Web Application Targets:")
    print(f"   🛒 E-commerce App: http://localhost:8080/ecommerce/")
    print(f"   🔗 REST API App: http://localhost:8080/rest-api/")
    
    # Final status
    print()
    print("🎉 DEMONSTRATION COMPLETE!")
    print("="*65)
    print("✅ All advanced features operational and demonstrated")
    print("🚀 System ready for production cybersecurity analysis")
    print(f"🕐 Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    try:
        asyncio.run(demonstration())
    except KeyboardInterrupt:
        print("\\n⚠️ Demonstration interrupted by user")
    except Exception as e:
        print(f"\\n❌ Demonstration failed: {str(e)}")
        import traceback
        traceback.print_exc()
