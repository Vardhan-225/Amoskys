#!/usr/bin/env python3
"""
Test Data Population Script for AMOSKYS Dashboard Testing
Populates the system with sample agents, events, and metrics
"""

import requests
import json
import time
from datetime import datetime, timedelta, timezone
import random
import sys

# Configuration
API_BASE_URL = "http://127.0.0.1:5001"
AGENT_ID = "flowagent-001"
AGENT_SECRET = "amoskys-neural-flow-secure-key-2025"
API_TOKEN = None  # Will be populated after login

# Sample threat types
THREAT_TYPES = [
    'suspicious_connection',
    'malware_detection',
    'anomalous_traffic',
    'brute_force_attempt',
    'data_exfiltration',
    'unauthorized_access',
    'privilege_escalation'
]

# Sample source IPs
SOURCE_IPS = [
    '192.168.1.100',
    '192.168.1.101',
    '192.168.1.102',
    '10.0.0.50',
    '10.0.0.51',
    '203.0.113.42',
    '198.51.100.89'
]

def login():
    """Get JWT token from API"""
    global API_TOKEN
    try:
        response = requests.post(f"{API_BASE_URL}/api/auth/login", json={
            "agent_id": AGENT_ID,
            "secret": AGENT_SECRET
        })
        if response.status_code == 200:
            data = response.json()
            API_TOKEN = data.get('token')
            print("✅ Authentication successful")
            return API_TOKEN
        else:
            print(f"❌ Authentication failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error during authentication: {e}")
        return None

def register_agent(agent_name, agent_type="process_monitor"):
    """Register a test agent"""
    if not API_TOKEN:
        return None
    
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    
    agent_data = {
        "name": agent_name,
        "type": agent_type,
        "hostname": f"server-{agent_name.split('-')[-1]}",
        "platform": random.choice(['linux', 'windows', 'macos']),
        "version": "1.0.0",
        "status": "active"
    }
    
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/agents/register",
            json=agent_data,
            headers=headers
        )
        if response.status_code in [200, 201]:
            result = response.json()
            agent_id = result.get('agent_id') or result.get('id')
            print(f"✅ Registered agent: {agent_name} (ID: {agent_id})")
            return agent_id
        else:
            print(f"⚠️  Agent registration failed: {response.status_code} - {response.text[:100]}")
            return None
    except Exception as e:
        print(f"❌ Error registering agent: {e}")
        return None

def submit_event(event_type, severity, source_ip, description=""):
    """Submit a security event"""
    if not API_TOKEN:
        return False
    
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    
    event_data = {
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": "192.168.1.1",
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([22, 80, 443, 3306, 5432]),
        "protocol": random.choice(['tcp', 'udp']),
        "description": description or f"Security event: {event_type}",
        "metadata": {
            "detection_confidence": round(random.uniform(0.7, 0.99), 2),
            "threat_score": random.randint(30, 95)
        }
    }
    
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/events/submit",
            json=event_data,
            headers=headers
        )
        if response.status_code == 200:
            print(f"  📝 Event submitted: {event_type} ({severity})")
            return True
        else:
            print(f"  ⚠️  Event submission returned {response.status_code}")
            return False
    except Exception as e:
        print(f"  ❌ Error submitting event: {e}")
        return False

def populate_test_data():
    """Populate system with test data"""
    print("\n" + "="*60)
    print("🧠 AMOSKYS Test Data Population")
    print("="*60 + "\n")
    
    # Step 0: Authenticate
    print("🔐 Step 0: Authenticating")
    print("-" * 60)
    if not login():
        print("❌ Failed to authenticate. Exiting.")
        return
    
    # Step 1: Register agents
    print("\n📍 Step 1: Registering Test Agents")
    print("-" * 60)
    agent_ids = []
    for i in range(3):
        agent_name = f"test-agent-{i+1}"
        agent_id = register_agent(agent_name)
        if agent_id:
            agent_ids.append(agent_id)
    
    if not agent_ids:
        print("\n⚠️  No agents were registered. Will still submit events.")
    
    # Step 2: Submit events
    print("\n📍 Step 2: Submitting Security Events")
    print("-" * 60)
    
    event_count = 0
    
    # Mix of severities for variety
    severities = ['low', 'low', 'medium', 'high', 'critical']
    
    for severity in severities * 2:  # Submit multiple events
        event_type = random.choice(THREAT_TYPES)
        source_ip = random.choice(SOURCE_IPS)
        
        if submit_event(event_type, severity, source_ip):
            event_count += 1
        time.sleep(0.3)  # Small delay between submissions
    
    # Step 3: Summary
    print("\n" + "="*60)
    print("✅ Test Data Population Complete!")
    print("="*60)
    print(f"✓ Agents registered: {len(agent_ids)}")
    print(f"✓ Events submitted: {event_count}")
    print("\n📊 Dashboards should now show data at:")
    print("   • http://127.0.0.1:5001/dashboard/soc")
    print("   • http://127.0.0.1:5001/dashboard/cortex")
    print("   • http://127.0.0.1:5001/dashboard/agents")
    print("\n⏱️  Refresh your browser to see the populated data")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        populate_test_data()
    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
