"""
AMOSKYS Agent Integration Script
Demonstrates how external agents can connect to the API Gateway

This script shows how the FlowAgent (or other agents) can:
1. Authenticate with the API Gateway
2. Register themselves
3. Send heartbeats
4. Submit security events
"""

import requests
import time
import json
from datetime import datetime

# API Configuration
API_BASE = "http://localhost:8000/api"
AGENT_ID = "flowagent-001"
AGENT_SECRET = "amoskys-neural-flow-secure-key-2025"

class AMOSKYSAgentClient:
    def __init__(self, base_url, agent_id, secret):
        self.base_url = base_url
        self.agent_id = agent_id
        self.secret = secret
        self.token = None
        self.session = requests.Session()
    
    def authenticate(self):
        """Authenticate with the API Gateway and get JWT token"""
        response = self.session.post(
            f"{self.base_url}/auth/login",
            json={"agent_id": self.agent_id, "secret": self.secret}
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data['token']
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}'
            })
            print(f"✅ Authenticated as {self.agent_id}")
            return True
        else:
            print(f"❌ Authentication failed: {response.text}")
            return False
    
    def register(self):
        """Register this agent with metadata"""
        agent_data = {
            'hostname': 'amoskys-test-host',
            'platform': 'Linux-Neural-Security-1.0',
            'version': '2.3.0',
            'capabilities': [
                'network_monitoring',
                'flow_analysis',
                'anomaly_detection',
                'event_correlation'
            ]
        }
        
        response = self.session.post(
            f"{self.base_url}/agents/register",
            json=agent_data
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Agent registered successfully")
            print(f"   Registration time: {data['agent_info']['registered_at']}")
            return True
        else:
            print(f"❌ Registration failed: {response.text}")
            return False
    
    def ping(self):
        """Send heartbeat to the server"""
        response = self.session.post(
            f"{self.base_url}/agents/ping",
            json={"request_config": True}
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"💓 Heartbeat acknowledged")
            print(f"   Server time: {data['server_time']}")
            print(f"   CPU: {data['system_metrics']['cpu_percent']}%")
            print(f"   Memory: {data['system_metrics']['memory_percent']}%")
            
            if 'config_update' in data:
                print(f"   📋 Config update: {data['config_update']}")
            return True
        else:
            print(f"❌ Ping failed: {response.text}")
            return False
    
    def submit_event(self, event_type, severity, source_ip, description, **kwargs):
        """Submit a security event"""
        event_data = {
            'event_type': event_type,
            'severity': severity,
            'source_ip': source_ip,
            'description': description,
            **kwargs
        }
        
        response = self.session.post(
            f"{self.base_url}/events/submit",
            json=event_data
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"🚨 Event submitted: {data['event_id']}")
            print(f"   Type: {event_type} | Severity: {severity}")
            print(f"   Time: {data['timestamp']}")
            return data['event_id']
        else:
            print(f"❌ Event submission failed: {response.text}")
            return None
    
    def get_system_status(self):
        """Get overall system status"""
        response = self.session.get(f"{self.base_url}/system/status")
        
        if response.status_code == 200:
            data = response.json()
            print(f"🖥️  System Status: {data['status']}")
            print(f"   Platform: {data['platform']}")
            print(f"   Version: {data['version']}")
            
            metrics = data['metrics']
            print(f"   Agents: {metrics['active_agents']}/{metrics['total_agents']} active")
            print(f"   Events: {metrics['total_events']} total, {metrics['events_last_hour']} last hour")
            print(f"   Health: {metrics['system_health']}")
            return True
        else:
            print(f"❌ Status check failed: {response.text}")
            return False

def simulate_agent_workflow():
    """Simulate a complete agent workflow"""
    print("🧠🛡️ AMOSKYS Agent Integration Demo")
    print("=" * 50)
    
    # Create agent client
    agent = AMOSKYSAgentClient(API_BASE, AGENT_ID, AGENT_SECRET)
    
    # Step 1: Authenticate
    if not agent.authenticate():
        return
    
    # Step 2: Register
    if not agent.register():
        return
    
    # Step 3: Send initial heartbeat
    if not agent.ping():
        return
    
    # Step 4: Get system status
    if not agent.get_system_status():
        return
    
    # Step 5: Submit some sample security events
    events = [
        {
            'event_type': 'network_anomaly',
            'severity': 'medium',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.1',
            'protocol': 'TCP',
            'description': 'Unusual SSH connection attempt from internal network'
        },
        {
            'event_type': 'malware_detection',
            'severity': 'high',
            'source_ip': '192.168.1.150',
            'description': 'Suspicious executable detected in user directory',
            'metadata': {
                'file_hash': 'a1b2c3d4e5f6',
                'file_size': 2048576,
                'detection_engine': 'AMOSKYS_Neural_V2.3'
            }
        },
        {
            'event_type': 'intrusion_attempt',
            'severity': 'critical',
            'source_ip': '203.0.113.45',
            'destination_ip': '192.168.1.10',
            'source_port': 4444,
            'destination_port': 22,
            'protocol': 'TCP',
            'description': 'Brute force SSH attack detected from external IP',
            'metadata': {
                'attempt_count': 127,
                'duration_minutes': 15,
                'blocked': True
            }
        }
    ]
    
    print("\n📡 Submitting security events...")
    for event in events:
        agent.submit_event(**event)
        time.sleep(1)  # Small delay between events
    
    # Step 6: Final heartbeat and status check
    print("\n💓 Final heartbeat...")
    agent.ping()
    
    print("\n📊 Final system status...")
    agent.get_system_status()
    
    print("\n✅ Agent workflow completed successfully!")
    print("🔗 View events at: http://localhost:8000/api/events/list")
    print("📖 API docs at: http://localhost:8000/api/docs")

if __name__ == "__main__":
    simulate_agent_workflow()
