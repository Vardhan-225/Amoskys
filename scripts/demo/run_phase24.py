#!/usr/bin/env python3
"""
AMOSKYS Neural Security Command Platform
Phase 2.4 Development Server
Easy launch script for testing dashboard functionality
"""
import os
import sys
import subprocess
import signal
import time
import threading
from pathlib import Path

class DevelopmentServer:
    """Development server manager for Phase 2.4 testing"""
    
    def __init__(self):
        self.server_process = None
        self.running = False
        self.web_dir = Path(__file__).parent / 'web'
        
    def log(self, message, level='INFO'):
        """Log message with timestamp"""
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")
    
    def check_dependencies(self):
        """Check if required dependencies are available"""
        self.log("🔍 Checking dependencies...")
        
        try:
            import flask
            self.log(f"✅ Flask {flask.__version__}")
        except ImportError:
            self.log("❌ Flask not found. Please install: pip install flask", 'ERROR')
            return False
            
        try:
            import flask_socketio
            self.log("✅ Flask-SocketIO (installed)")
        except ImportError:
            self.log("❌ Flask-SocketIO not found. Please install: pip install flask-socketio", 'ERROR')
            return False
            
        try:
            import psutil
            self.log(f"✅ psutil {psutil.__version__}")
        except ImportError:
            self.log("❌ psutil not found. Please install: pip install psutil", 'ERROR')
            return False
            
        return True
    
    def install_dependencies(self):
        """Install required dependencies"""
        self.log("📦 Installing dependencies...")
        
        requirements_file = self.web_dir / 'requirements.txt'
        if requirements_file.exists():
            try:
                subprocess.run([
                    sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)
                ], check=True, capture_output=True, text=True)
                self.log("✅ Dependencies installed successfully")
                return True
            except subprocess.CalledProcessError as e:
                self.log(f"❌ Failed to install dependencies: {e}", 'ERROR')
                return False
        else:
            self.log(f"❌ Requirements file not found: {requirements_file}", 'ERROR')
            return False
    
    def start_server(self, port=8000, debug=True):
        """Start the development server"""
        if not self.web_dir.exists():
            self.log(f"❌ Web directory not found: {self.web_dir}", 'ERROR')
            return False
            
        # Change to web directory
        original_cwd = os.getcwd()
        os.chdir(self.web_dir)
        
        try:
            self.log(f"🚀 Starting AMOSKYS Phase 2.4 development server on port {port}...")
            
            # Set environment variables
            env = os.environ.copy()
            env['FLASK_DEBUG'] = 'true' if debug else 'false'
            env['PYTHONPATH'] = str(self.web_dir)
            
            # Start server
            self.server_process = subprocess.Popen([
                sys.executable, 'wsgi.py'
            ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            self.running = True
            
            # Monitor server output
            def monitor_output():
                if self.server_process and self.server_process.stdout:
                    for line in iter(self.server_process.stdout.readline, ''):
                        if line.strip():
                            print(f"[SERVER] {line.strip()}")
                        
            output_thread = threading.Thread(target=monitor_output, daemon=True)
            output_thread.start()
            
            # Wait a moment for server to start
            time.sleep(3)
            
            if self.server_process.poll() is None:
                self.log("✅ Server started successfully")
                self.log(f"🌐 Dashboard available at: http://localhost:{port}")
                self.log("📊 Available dashboards:")
                self.log("   • Command Center: http://localhost:8000/dashboard/cortex")
                self.log("   • SOC Operations: http://localhost:8000/dashboard/soc")
                self.log("   • Agent Network: http://localhost:8000/dashboard/agents")
                self.log("   • System Health: http://localhost:8000/dashboard/system")
                self.log("   • Neural Insights: http://localhost:8000/dashboard/neural")
                self.log("\n🔑 Press Ctrl+C to stop the server")
                return True
            else:
                self.log("❌ Server failed to start", 'ERROR')
                return False
                
        except Exception as e:
            self.log(f"❌ Failed to start server: {e}", 'ERROR')
            return False
        finally:
            os.chdir(original_cwd)
    
    def stop_server(self):
        """Stop the development server"""
        if self.server_process and self.running:
            self.log("🛑 Stopping development server...")
            
            try:
                # Try graceful shutdown first
                self.server_process.terminate()
                
                # Wait for graceful shutdown
                try:
                    self.server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown fails
                    self.server_process.kill()
                    self.server_process.wait()
                    
                self.running = False
                self.log("✅ Server stopped")
                
            except Exception as e:
                self.log(f"⚠️  Error stopping server: {e}", 'WARN')
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        self.log("\n⚠️  Interrupt received, shutting down...")
        self.stop_server()
        sys.exit(0)
    
    def run_tests(self):
        """Run Phase 2.4 tests"""
        self.log("🧪 Running Phase 2.4 tests...")
        
        test_script = Path(__file__).parent / 'test_phase24.py'
        if test_script.exists():
            try:
                result = subprocess.run([
                    sys.executable, str(test_script)
                ], capture_output=True, text=True)
                
                print(result.stdout)
                if result.stderr:
                    print(result.stderr)
                    
                if result.returncode == 0:
                    self.log("✅ All tests passed!")
                else:
                    self.log("❌ Some tests failed", 'WARN')
                    
                return result.returncode == 0
                
            except Exception as e:
                self.log(f"❌ Failed to run tests: {e}", 'ERROR')
                return False
        else:
            self.log(f"❌ Test script not found: {test_script}", 'ERROR')
            return False
    
    def main(self):
        """Main development server runner"""
        import argparse
        
        parser = argparse.ArgumentParser(description='AMOSKYS Phase 2.4 Development Server')
        parser.add_argument('--port', type=int, default=8000, help='Server port')
        parser.add_argument('--no-debug', action='store_true', help='Disable debug mode')
        parser.add_argument('--install-deps', action='store_true', help='Install dependencies first')
        parser.add_argument('--test', action='store_true', help='Run tests after starting server')
        parser.add_argument('--test-only', action='store_true', help='Only run tests, don\'t start server')
        
        args = parser.parse_args()
        
        # Handle signals
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        print("🧠🛡️  AMOSKYS Neural Security Command Platform")
        print("Phase 2.4 - Cortex Dashboard Development Server")
        print("=" * 50)
        
        # Test only mode
        if args.test_only:
            success = self.run_tests()
            sys.exit(0 if success else 1)
        
        # Install dependencies if requested
        if args.install_deps and not self.install_dependencies():
            sys.exit(1)
        
        # Check dependencies
        if not self.check_dependencies():
            self.log("⚠️  Missing dependencies. Use --install-deps to install them.")
            sys.exit(1)
        
        # Start server
        if not self.start_server(port=args.port, debug=not args.no_debug):
            sys.exit(1)
        
        # Run tests if requested
        if args.test:
            time.sleep(2)  # Give server time to fully start
            self.run_tests()
        
        # Keep server running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_server()

if __name__ == '__main__':
    server = DevelopmentServer()
    server.main()
