#!/usr/bin/env python3
"""
AMOSKYS Neural Security Command Platform
Phase 2.4 Dashboard Testing Suite
Comprehensive testing of all dashboard components
"""
import requests
import json
import time
import threading
import sys
import os
from urllib.parse import urljoin
import socketio

# Add the web directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web'))

class Phase24Tester:
    """Comprehensive Phase 2.4 Dashboard Testing"""
    
    def __init__(self, base_url='http://localhost:8000'):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = {
            'passed': 0,
            'failed': 0,
            'errors': []
        }
        
    def log(self, message, test_type='INFO'):
        """Log test message"""
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] [{test_type}] {message}")
        
    def test_result(self, test_name, passed, error=None):
        """Record test result"""
        if passed:
            self.results['passed'] += 1
            self.log(f"✅ {test_name}", 'PASS')
        else:
            self.results['failed'] += 1
            self.results['errors'].append(f"{test_name}: {error}")
            self.log(f"❌ {test_name}: {error}", 'FAIL')
    
    def test_web_server_running(self):
        """Test if the web server is running"""
        try:
            response = self.session.get(self.base_url, timeout=5)
            self.test_result('Web Server Running', response.status_code == 200)
            return response.status_code == 200
        except Exception as e:
            self.test_result('Web Server Running', False, str(e))
            return False
    
    def test_dashboard_blueprint_registration(self):
        """Test dashboard blueprint is properly registered"""
        try:
            # Test main dashboard redirect
            response = self.session.get(urljoin(self.base_url, '/dashboard/'), timeout=5)
            self.test_result('Dashboard Blueprint Registered', 
                           response.status_code in [200, 302])
            
            # Test cortex dashboard specifically
            response = self.session.get(urljoin(self.base_url, '/dashboard/cortex'), timeout=5)
            self.test_result('Cortex Dashboard Accessible', response.status_code == 200)
            
        except Exception as e:
            self.test_result('Dashboard Blueprint Registered', False, str(e))
    
    def test_all_dashboard_pages(self):
        """Test all dashboard pages are accessible"""
        dashboards = ['cortex', 'soc', 'agents', 'system', 'neural']
        
        for dashboard in dashboards:
            try:
                url = urljoin(self.base_url, f'/dashboard/{dashboard}')
                response = self.session.get(url, timeout=5)
                self.test_result(f'{dashboard.title()} Dashboard Page', 
                               response.status_code == 200)
                
                # Check for expected content
                if response.status_code == 200:
                    content = response.text.lower()
                    expected_content = {
                        'cortex': ['command center', 'threat score'],
                        'soc': ['security operations', 'live events'],
                        'agents': ['agent network', 'agent status'],
                        'system': ['system health', 'cpu usage'],
                        'neural': ['neural insights', 'readiness']
                    }
                    
                    has_content = any(keyword in content for keyword in expected_content[dashboard])
                    self.test_result(f'{dashboard.title()} Dashboard Content', has_content)
                    
            except Exception as e:
                self.test_result(f'{dashboard.title()} Dashboard Page', False, str(e))
    
    def test_dashboard_api_endpoints(self):
        """Test all dashboard API endpoints"""
        endpoints = [
            '/dashboard/api/live/threats',
            '/dashboard/api/live/agents', 
            '/dashboard/api/live/metrics',
            '/dashboard/api/live/threat-score',
            '/dashboard/api/live/event-clustering',
            '/dashboard/api/neural/readiness',
            '/dashboard/api/agents/register',
            '/dashboard/api/system/health'
        ]
        
        for endpoint in endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=5)
                
                # Most endpoints should return 200, register might return 405 for GET
                expected_codes = [200, 405] if 'register' in endpoint else [200]
                success = response.status_code in expected_codes
                
                self.test_result(f'API Endpoint {endpoint}', success)
                
                # Test JSON response for successful GET requests
                if response.status_code == 200:
                    try:
                        data = response.json()
                        self.test_result(f'API JSON Response {endpoint}', 
                                       isinstance(data, dict))
                    except json.JSONDecodeError:
                        self.test_result(f'API JSON Response {endpoint}', False, 
                                       'Invalid JSON response')
                        
            except Exception as e:
                self.test_result(f'API Endpoint {endpoint}', False, str(e))
    
    def test_main_interface_navigation(self):
        """Test navigation links in main interface"""
        try:
            response = self.session.get(urljoin(self.base_url, '/command'), timeout=5)
            
            if response.status_code == 200:
                content = response.text
                
                # Check for dashboard navigation links
                expected_links = [
                    '/dashboard/cortex',
                    '/dashboard/soc', 
                    '/dashboard/agents',
                    '/dashboard/system',
                    '/dashboard/neural'
                ]
                
                for link in expected_links:
                    has_link = link in content
                    dashboard_name = link.split('/')[-1]
                    self.test_result(f'Navigation Link {dashboard_name.title()}', has_link)
                    
            else:
                self.test_result('Main Interface Navigation', False, 
                               f'Command interface returned {response.status_code}')
                
        except Exception as e:
            self.test_result('Main Interface Navigation', False, str(e))
    
    def test_socketio_connection(self):
        """Test SocketIO real-time connection"""
        try:
            # Create SocketIO client
            sio = socketio.SimpleClient()
            
            # Connect to dashboard namespace
            sio.connect(self.base_url, namespace='/dashboard')
            self.test_result('SocketIO Connection', True)
            
            # Test join dashboard
            sio.emit('join_dashboard', {'dashboard': 'cortex'})
            
            # Wait for initial data
            try:
                event = sio.receive(timeout=5)
                if event[0] == 'initial_data':
                    self.test_result('SocketIO Initial Data', True)
                else:
                    self.test_result('SocketIO Initial Data', False, 
                                   f'Expected initial_data, got {event[0]}')
            except Exception:
                self.test_result('SocketIO Initial Data', False, 'Timeout waiting for data')
            
            # Test manual update request
            sio.emit('request_update', {'dashboard': 'cortex'})
            
            # Clean disconnect
            sio.disconnect()
            
        except Exception as e:
            self.test_result('SocketIO Connection', False, str(e))
    
    def test_dashboard_utilities(self):
        """Test dashboard utility functions"""
        try:
            # Import dashboard utilities
            from web.app.dashboard.utils import (
                get_live_threats_data, get_live_agents_data, get_live_metrics_data,
                calculate_threat_score, get_neural_readiness_status
            )
            
            # Test each utility function
            utilities = [
                ('Live Threats Data', get_live_threats_data),
                ('Live Agents Data', get_live_agents_data), 
                ('Live Metrics Data', get_live_metrics_data),
                ('Threat Score Calculation', calculate_threat_score),
                ('Neural Readiness Status', get_neural_readiness_status)
            ]
            
            for name, func in utilities:
                try:
                    result = func()
                    self.test_result(f'Utility Function {name}', 
                                   isinstance(result, (dict, list, int, float)))
                except Exception as e:
                    self.test_result(f'Utility Function {name}', False, str(e))
                    
        except ImportError as e:
            self.test_result('Dashboard Utilities Import', False, str(e))
    
    def test_template_rendering(self):
        """Test that templates render without errors"""
        dashboards = ['cortex', 'soc', 'agents', 'system', 'neural']
        
        for dashboard in dashboards:
            try:
                url = urljoin(self.base_url, f'/dashboard/{dashboard}')
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Check for template errors
                    has_errors = any(error in content.lower() for error in [
                        'templatenotfound', 'templatesyntaxerror', 'jinja2', 'error'
                    ])
                    
                    # Check for expected base template elements
                    has_base_elements = all(element in content for element in [
                        'AMOSKYS', 'Chart.js', 'socket.io'
                    ])
                    
                    self.test_result(f'{dashboard.title()} Template Rendering', 
                                   not has_errors and has_base_elements)
                else:
                    self.test_result(f'{dashboard.title()} Template Rendering', False,
                                   f'HTTP {response.status_code}')
                    
            except Exception as e:
                self.test_result(f'{dashboard.title()} Template Rendering', False, str(e))
    
    def test_performance_metrics(self):
        """Test dashboard performance"""
        dashboards = ['cortex', 'soc', 'agents', 'system', 'neural']
        
        for dashboard in dashboards:
            try:
                url = urljoin(self.base_url, f'/dashboard/{dashboard}')
                start_time = time.time()
                self.session.get(url, timeout=10)
                load_time = time.time() - start_time
                
                # Dashboard should load within 3 seconds
                self.test_result(f'{dashboard.title()} Load Performance', 
                               load_time < 3.0)
                
                if load_time >= 3.0:
                    self.log(f"⚠️  {dashboard.title()} loaded in {load_time:.2f}s", 'WARN')
                    
            except Exception as e:
                self.test_result(f'{dashboard.title()} Load Performance', False, str(e))
    
    def run_all_tests(self):
        """Run all Phase 2.4 tests"""
        self.log("🚀 Starting AMOSKYS Phase 2.4 Dashboard Testing Suite")
        self.log("="*60)
        
        # Core functionality tests
        self.log("📋 Testing Core Functionality...")
        if not self.test_web_server_running():
            self.log("❌ Web server not running, skipping remaining tests")
            return self.print_results()
            
        self.test_dashboard_blueprint_registration()
        self.test_all_dashboard_pages()
        self.test_dashboard_api_endpoints()
        self.test_main_interface_navigation()
        
        # Real-time functionality tests
        self.log("📡 Testing Real-time Functionality...")
        self.test_socketio_connection()
        
        # Backend tests
        self.log("⚙️  Testing Backend Components...")
        self.test_dashboard_utilities()
        self.test_template_rendering()
        
        # Performance tests
        self.log("🚀 Testing Performance...")
        self.test_performance_metrics()
        
        return self.print_results()
    
    def print_results(self):
        """Print test results summary"""
        self.log("="*60)
        total_tests = self.results['passed'] + self.results['failed']
        success_rate = (self.results['passed'] / total_tests * 100) if total_tests > 0 else 0
        
        self.log("📊 Test Results Summary:")
        self.log(f"   Total Tests: {total_tests}")
        self.log(f"   ✅ Passed: {self.results['passed']}")
        self.log(f"   ❌ Failed: {self.results['failed']}")
        self.log(f"   📈 Success Rate: {success_rate:.1f}%")
        
        if self.results['errors']:
            self.log("\n🔍 Failed Tests:")
            for error in self.results['errors']:
                self.log(f"   • {error}")
        
        if success_rate >= 90:
            self.log("🎉 Phase 2.4 Dashboard Implementation: EXCELLENT")
        elif success_rate >= 75:
            self.log("✅ Phase 2.4 Dashboard Implementation: GOOD")
        elif success_rate >= 50:
            self.log("⚠️  Phase 2.4 Dashboard Implementation: NEEDS IMPROVEMENT")
        else:
            self.log("❌ Phase 2.4 Dashboard Implementation: REQUIRES FIXES")
            
        return success_rate >= 75

def main():
    """Main test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AMOSKYS Phase 2.4 Dashboard Testing')
    parser.add_argument('--url', default='http://localhost:8000', 
                       help='Base URL for testing (default: http://localhost:8000)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    tester = Phase24Tester(args.url)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
