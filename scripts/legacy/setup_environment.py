#!/usr/bin/env python3
"""
AMOSKYS Neural Security Command Platform
Automated Environment Setup & Dependency Manager
Version 2.0 - Enhanced with auto-fixes and upgrades
"""

import subprocess
import sys
import os
import platform
import venv
from pathlib import Path
import shutil
import json
import time

class AmoskysEnvironmentManager:
    """Enhanced environment management with auto-fixes"""
    
    def __init__(self, project_root=None):
        self.project_root = Path(project_root or os.getcwd())
        self.venv_path = self.project_root / 'venv'
        self.web_path = self.project_root / 'web'
        self.requirements_path = self.web_path / 'requirements.txt'
        self.platform = platform.system().lower()
        
        # Colors for output
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'reset': '\033[0m'
        }
    
    def print_colored(self, message, color='white', bold=False):
        """Print colored messages"""
        color_code = self.colors.get(color, self.colors['white'])
        bold_code = self.colors['bold'] if bold else ''
        reset_code = self.colors['reset']
        print(f"{bold_code}{color_code}{message}{reset_code}")
    
    def print_banner(self):
        """Print the setup banner"""
        self.print_colored("="*80, 'cyan', True)
        self.print_colored("🧠🛡️  AMOSKYS NEURAL SECURITY COMMAND PLATFORM", 'green', True)
        self.print_colored("Automated Environment Setup & Dependency Manager v2.0", 'cyan')
        self.print_colored("="*80, 'cyan', True)
        print()
    
    def run_command(self, command, description, shell=False, check_output=False):
        """Run a command with error handling"""
        self.print_colored(f"⚡ {description}...", 'yellow')
        
        try:
            if shell:
                if check_output:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
                    return result.stdout.strip()
                else:
                    subprocess.run(command, shell=True, check=True)
            else:
                if check_output:
                    result = subprocess.run(command, capture_output=True, text=True, check=True)
                    return result.stdout.strip()
                else:
                    subprocess.run(command, check=True)
            
            self.print_colored(f"  ✅ {description} completed", 'green')
            return True
            
        except subprocess.CalledProcessError as e:
            self.print_colored(f"  ❌ {description} failed: {e}", 'red')
            if check_output and hasattr(e, 'stderr'):
                self.print_colored(f"     Error: {e.stderr}", 'red')
            return False
        except Exception as e:
            self.print_colored(f"  ❌ {description} failed: {e}", 'red')
            return False
    
    def check_python_version(self):
        """Check Python version compatibility"""
        self.print_colored("🐍 Checking Python version...", 'blue')
        
        version = sys.version_info
        if version.major == 3 and version.minor >= 8:
            self.print_colored(f"  ✅ Python {version.major}.{version.minor}.{version.micro} (compatible)", 'green')
            return True
        else:
            self.print_colored(f"  ❌ Python {version.major}.{version.minor}.{version.micro} (requires Python 3.8+)", 'red')
            return False
    
    def create_virtual_environment(self):
        """Create or update virtual environment"""
        if self.venv_path.exists():
            self.print_colored("🔄 Virtual environment exists, checking...", 'yellow')
            
            # Check if venv is working
            if self.platform == 'windows':
                python_exe = self.venv_path / 'Scripts' / 'python.exe'
                pip_exe = self.venv_path / 'Scripts' / 'pip.exe'
            else:
                python_exe = self.venv_path / 'bin' / 'python'
                pip_exe = self.venv_path / 'bin' / 'pip'
            
            if python_exe.exists() and pip_exe.exists():
                self.print_colored("  ✅ Virtual environment is valid", 'green')
                return True
            else:
                self.print_colored("  ⚠️  Virtual environment corrupted, recreating...", 'yellow')
                shutil.rmtree(self.venv_path)
        
        self.print_colored("🏗️  Creating virtual environment...", 'blue')
        try:
            venv.create(self.venv_path, with_pip=True)
            self.print_colored("  ✅ Virtual environment created", 'green')
            return True
        except Exception as e:
            self.print_colored(f"  ❌ Failed to create virtual environment: {e}", 'red')
            return False
    
    def get_venv_commands(self):
        """Get the correct virtual environment commands for the platform"""
        if self.platform == 'windows':
            activate_cmd = str(self.venv_path / 'Scripts' / 'activate.bat')
            python_cmd = str(self.venv_path / 'Scripts' / 'python.exe')
            pip_cmd = str(self.venv_path / 'Scripts' / 'pip.exe')
        else:
            activate_cmd = f"source {self.venv_path / 'bin' / 'activate'}"
            python_cmd = str(self.venv_path / 'bin' / 'python')
            pip_cmd = str(self.venv_path / 'bin' / 'pip')
        
        return activate_cmd, python_cmd, pip_cmd
    
    def upgrade_pip(self):
        """Upgrade pip to latest version"""
        _, _, pip_cmd = self.get_venv_commands()
        
        self.print_colored("📦 Upgrading pip to latest version...", 'blue')
        success = self.run_command([pip_cmd, 'install', '--upgrade', 'pip'], "Upgrade pip")
        
        if success:
            # Get pip version
            try:
                version = self.run_command([pip_cmd, '--version'], "Check pip version", check_output=True)
                self.print_colored(f"  ✅ Pip upgraded: {version}", 'green')
            except Exception:
                pass
        
        return success
    
    def install_dependencies(self):
        """Install project dependencies"""
        _, _, pip_cmd = self.get_venv_commands()
        
        if not self.requirements_path.exists():
            self.print_colored(f"  ❌ Requirements file not found: {self.requirements_path}", 'red')
            return False
        
        self.print_colored("📋 Installing project dependencies...", 'blue')
        
        # Install requirements
        success = self.run_command([
            pip_cmd, 'install', '-r', str(self.requirements_path)
        ], "Install requirements")
        
        if success:
            # Install additional dependencies that might be missing
            additional_deps = ['PyJWT', 'python-socketio[asyncio]']
            for dep in additional_deps:
                self.run_command([pip_cmd, 'install', dep], f"Install {dep}")
        
        return success
    
    def verify_installation(self):
        """Verify that all dependencies are correctly installed"""
        _, python_cmd, _ = self.get_venv_commands()
        
        self.print_colored("🔍 Verifying installation...", 'blue')
        
        # Test imports
        test_imports = [
            'flask',
            'flask_socketio',
            'psutil',
            'jwt',
            'eventlet'
        ]
        
        all_good = True
        for module in test_imports:
            try:
                result = self.run_command([
                    python_cmd, '-c', f'import {module}; print(f"{module}: OK")'
                ], f"Test import {module}", check_output=True)
                
                if result:
                    self.print_colored(f"  ✅ {module}: OK", 'green')
                else:
                    self.print_colored(f"  ❌ {module}: FAILED", 'red')
                    all_good = False
                    
            except Exception as e:
                self.print_colored(f"  ❌ {module}: FAILED - {e}", 'red')
                all_good = False
        
        return all_good
    
    def test_dashboard_system(self):
        """Test that the dashboard system loads correctly"""
        _, python_cmd, _ = self.get_venv_commands()
        
        self.print_colored("🧪 Testing dashboard system...", 'blue')
        
        test_code = '''
import sys
sys.path.insert(0, "web")
try:
    from app import create_app
    app, socketio = create_app()
    
    with app.test_client() as client:
        response = client.get("/dashboard/cortex")
        if response.status_code == 200:
            print("Dashboard system: OK")
        else:
            print(f"Dashboard system: FAILED (HTTP {response.status_code})")
            
except Exception as e:
    print(f"Dashboard system: FAILED - {e}")
'''
        
        try:
            result = self.run_command([
                python_cmd, '-c', test_code
            ], "Test dashboard system", check_output=True)
            
            if result and "OK" in str(result):
                self.print_colored("  ✅ Dashboard system working", 'green')
                return True
            else:
                self.print_colored(f"  ❌ Dashboard system test failed: {result}", 'red')
                return False
                
        except Exception as e:
            self.print_colored(f"  ❌ Dashboard system test failed: {e}", 'red')
            return False
    
    def create_startup_scripts(self):
        """Create convenient startup scripts"""
        self.print_colored("📝 Creating startup scripts...", 'blue')
        
        _, python_cmd, _ = self.get_venv_commands()
        
        # Create a startup script
        if self.platform == 'windows':
            script_content = f'''@echo off
echo 🧠🛡️ Starting AMOSKYS Dashboard Server...
echo.
cd /d "{self.web_path}"
"{python_cmd}" wsgi.py
pause
'''
            script_path = self.project_root / 'start_amoskys.bat'
        else:
            script_content = f'''#!/bin/bash
echo "🧠🛡️ Starting AMOSKYS Dashboard Server..."
echo ""
cd "{self.web_path}"
"{python_cmd}" wsgi.py
'''
            script_path = self.project_root / 'start_amoskys.sh'
        
        try:
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            if self.platform != 'windows':
                script_path.chmod(0o755)
            
            self.print_colored(f"  ✅ Created startup script: {script_path.name}", 'green')
            return True
            
        except Exception as e:
            self.print_colored(f"  ❌ Failed to create startup script: {e}", 'red')
            return False
    
    def print_success_info(self):
        """Print success information and next steps"""
        print()
        self.print_colored("🎉 AMOSKYS Environment Setup Complete!", 'green', True)
        print()
        
        self.print_colored("📊 Available Commands:", 'cyan', True)
        
        if self.platform == 'windows':
            self.print_colored("  • Double-click: start_amoskys.bat", 'white')
        else:
            self.print_colored("  • Quick start: ./start_amoskys.sh", 'white')
        
        self.print_colored("  • Manual start: cd web && python wsgi.py", 'white')
        self.print_colored("  • Run tests: python test_phase24.py", 'white')
        self.print_colored("  • Interactive demo: python demo_phase24.py", 'white')
        
        print()
        self.print_colored("🌐 Dashboard URLs (when server is running):", 'cyan', True)
        self.print_colored("  • Command Center: http://localhost:8080/dashboard/cortex", 'white')
        self.print_colored("  • SOC Operations: http://localhost:8080/dashboard/soc", 'white')
        self.print_colored("  • Agent Network: http://localhost:8080/dashboard/agents", 'white')
        self.print_colored("  • System Health: http://localhost:8080/dashboard/system", 'white')
        self.print_colored("  • Neural Insights: http://localhost:8080/dashboard/neural", 'white')
        
        print()
        self.print_colored("🔧 Features Enabled:", 'cyan', True)
        self.print_colored("  ✅ Real-time WebSocket updates", 'green')
        self.print_colored("  ✅ Mobile-responsive design", 'green')
        self.print_colored("  ✅ Neural network aesthetics", 'green')
        self.print_colored("  ✅ Comprehensive monitoring", 'green')
        self.print_colored("  ✅ Auto-dependency management", 'green')
        
    def setup_complete_environment(self):
        """Complete environment setup process"""
        self.print_banner()
        
        steps = [
            ("Check Python version", self.check_python_version),
            ("Create virtual environment", self.create_virtual_environment),
            ("Upgrade pip", self.upgrade_pip),
            ("Install dependencies", self.install_dependencies),
            ("Verify installation", self.verify_installation),
            ("Test dashboard system", self.test_dashboard_system),
            ("Create startup scripts", self.create_startup_scripts)
        ]
        
        success_count = 0
        total_steps = len(steps)
        
        for step_name, step_func in steps:
            self.print_colored(f"\n📋 Step {success_count + 1}/{total_steps}: {step_name}", 'magenta', True)
            
            if step_func():
                success_count += 1
            else:
                self.print_colored(f"\n❌ Setup failed at step: {step_name}", 'red', True)
                self.print_colored("Please check the error messages above and try again.", 'yellow')
                return False
        
        self.print_success_info()
        return True

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AMOSKYS Environment Setup')
    parser.add_argument('--project-root', help='Project root directory')
    parser.add_argument('--force-recreate', action='store_true', 
                       help='Force recreate virtual environment')
    
    args = parser.parse_args()
    
    manager = AmoskysEnvironmentManager(args.project_root)
    
    if args.force_recreate and manager.venv_path.exists():
        print("🔄 Force recreating virtual environment...")
        shutil.rmtree(manager.venv_path)
    
    success = manager.setup_complete_environment()
    
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()
