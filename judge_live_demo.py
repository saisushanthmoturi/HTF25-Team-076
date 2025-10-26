#!/usr/bin/env python3
"""
JUDGE LIVE ATTACK DEMONSTRATION
===============================
Shows judges live attacks against Tomcat applications with real-time monitoring
"""

import os
import sys
import time
import json
import requests
import threading
import subprocess
from datetime import datetime
import webbrowser

def print_judge_banner():
    """Print demonstration banner for judges"""
    print("\n" + "="*80)
    print("🎯 LIVE WAF ATTACK DEMONSTRATION FOR JUDGES")
    print("="*80)
    print("🛡️  Real-time Protection Against Live Attacks")
    print("🌐 Protecting Tomcat Applications")
    print("📊 Live Dashboard Monitoring")
    print("="*80)

def run_live_attacks_for_judges():
    """Execute live attacks that judges can observe"""
    print("\n🎬 EXECUTING LIVE ATTACKS FOR JUDGE OBSERVATION")
    print("-" * 60)
    
    # Ecommerce attacks from the warning examples
    ecommerce_attacks = [
        ("SQL Injection", "search.jsp?query=' OR 1=1--"),
        ("XSS Attack", "search.jsp?query=<script>alert('xss')</script>"),
        ("Path Traversal", "../../../etc/passwd"),
        ("Admin Bypass", "admin.jsp?user=admin' OR '1'='1"),
    ]
    
    base_url = "http://localhost:8080/ecommerce-app/"
    
    print(f"🛒 Testing Ecommerce App: {base_url}")
    
    for attack_name, attack_payload in ecommerce_attacks:
        full_url = base_url + attack_payload
        print(f"\n🎯 {attack_name}:")
        print(f"   URL: {full_url}")
        
        try:
            response = requests.get(full_url, timeout=5)
            print(f"   Status Code: {response.status_code}")
            print(f"   Response Size: {len(response.text)} bytes")
            
            # Check if it looks like it was blocked
            response_text = response.text.lower()
            if (response.status_code in [403, 406, 500] or 
                'blocked' in response_text or 
                'forbidden' in response_text or
                'access denied' in response_text):
                print(f"   🚫 BLOCKED by WAF!")
            else:
                print(f"   ⚠️  PASSED - No blocking detected")
                
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
        
        time.sleep(2)  # Pause between attacks for judges to observe
    
    # REST API attacks
    print(f"\n🔌 Testing REST API App: http://localhost:8080/rest-api-app/")
    
    rest_attacks = [
        ("API SQL Injection", "api/users?id=' OR 1=1--"),
        ("API XSS", "api/search?q=<script>alert('api-xss')</script>"),
        ("API Path Traversal", "api/../../../etc/passwd"),
    ]
    
    rest_base = "http://localhost:8080/rest-api-app/"
    
    for attack_name, attack_payload in rest_attacks:
        full_url = rest_base + attack_payload
        print(f"\n🎯 {attack_name}:")
        print(f"   URL: {full_url}")
        
        try:
            response = requests.get(full_url, timeout=5)
            print(f"   Status Code: {response.status_code}")
            print(f"   Response Size: {len(response.text)} bytes")
            
            if response.status_code in [403, 406, 500]:
                print(f"   🚫 BLOCKED by WAF!")
            else:
                print(f"   ⚠️  PASSED - No blocking detected")
                
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
        
        time.sleep(2)

def show_judge_access_info():
    """Show judges how to access the demonstration"""
    print("\n📋 JUDGE ACCESS INFORMATION")
    print("="*60)
    
    print("🌐 LIVE APPLICATIONS TO TEST:")
    print("   • Ecommerce Store:  http://localhost:8080/ecommerce-app/")
    print("   • REST API Service: http://localhost:8080/rest-api-app/")
    print("   • Tomcat Manager:   http://localhost:8080/")
    
    print("\n🎯 MANUAL ATTACK TESTING:")
    print("   Copy these URLs to test attacks manually:")
    print("   1. http://localhost:8080/ecommerce-app/search.jsp?query=' OR 1=1--")
    print("   2. http://localhost:8080/ecommerce-app/search.jsp?query=<script>alert('xss')</script>")
    print("   3. http://localhost:8080/rest-api-app/api/users?id=' OR 1=1--")
    
    print("\n📊 MONITORING DASHBOARDS:")
    print("   • WAF Dashboard:    http://localhost:8501 (if running)")
    print("   • Live Log Monitor: Check terminal output")
    
    print("\n🔧 DEMONSTRATION CONTROLS:")
    print("   • Start WAF:        python demo_transformer_waf.py")
    print("   • Start Dashboard:  streamlit run transformer_waf_dashboard.py")
    print("   • Live Attacks:     python live_attack_demonstrator.py")

def continuous_attack_demo():
    """Run continuous attacks for judges to observe"""
    print("\n🔄 STARTING CONTINUOUS ATTACK DEMONSTRATION")
    print("Attacks will repeat every 30 seconds for judge observation")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            print(f"\n🕐 {datetime.now().strftime('%H:%M:%S')} - Attack Cycle Starting")
            run_live_attacks_for_judges()
            print(f"\n⏳ Waiting 30 seconds before next attack cycle...")
            time.sleep(30)
    except KeyboardInterrupt:
        print("\n🛑 Attack demonstration stopped by user")

def main():
    """Main judge demonstration"""
    print_judge_banner()
    
    # Check if Tomcat is running
    print("🔍 Checking Tomcat applications...")
    try:
        response = requests.get("http://localhost:8080/ecommerce-app/", timeout=5)
        print("✅ Ecommerce app is accessible")
    except:
        print("❌ Ecommerce app is not accessible")
    
    try:
        response = requests.get("http://localhost:8080/rest-api-app/", timeout=5)
        print("✅ REST API app is accessible")
    except:
        print("❌ REST API app is not accessible")
    
    # Show access information
    show_judge_access_info()
    
    # Run initial attack demonstration
    run_live_attacks_for_judges()
    
    print("\n🎬 JUDGE DEMONSTRATION OPTIONS:")
    print("1. Run continuous attacks (press 'c')")
    print("2. Open browser windows (press 'b')")
    print("3. Exit (press 'q')")
    
    choice = input("\nEnter your choice: ").lower()
    
    if choice == 'c':
        continuous_attack_demo()
    elif choice == 'b':
        print("🌐 Opening browser windows...")
        try:
            webbrowser.open("http://localhost:8080/ecommerce-app/")
            time.sleep(2)
            webbrowser.open("http://localhost:8501")
        except:
            pass
        print("✅ Browser windows opened")
    else:
        print("📋 Demonstration complete - applications remain running for judge testing")

if __name__ == "__main__":
    main()
