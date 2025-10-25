#!/usr/bin/env python3
"""
AMOSKYS Neural Security Command Platform
Environment Setup & Requirements Management Automation
Professional Grade Implementation

This script provides comprehensive environment management with:
- Automated virtual environment creation
- Intelligent dependency resolution
- Multi-platform compatibility
- Development vs Production modes
- Automated testing and validation
"""

import os
import sys
import subprocess
import platform
import venv
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import argparse
import json
import tempfile

class Colors:
    """Terminal color codes for better UX"""
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class EnvironmentManager:
    """Professional environment management system"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.venv_path = project_root / ".venv"
        self.requirements_dir = project_root / "requirements"
        self.platform = platform.system().lower()
        self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        
    def print_status(self, message: str, status: str = "INFO") -> None:
        """Print colored status messages"""
        color_map = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED
        }
        color = color_map.get(status, Colors.BLUE)
        print(f"{color}[{status}]{Colors.END} {message}")
    
    def print_header(self, title: str) -> None:
        """Print section header"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}")
        print(f"{title}")
        print(f"{'='*60}{Colors.END}\n")
    
    def check_python_version(self) -> bool:
        """Verify Python version compatibility"""
        self.print_status("Checking Python version compatibility...")
        
        if sys.version_info < (3, 9):
            self.print_status(
                f"Python {self.python_version} detected. AMOSKYS requires Python 3.9+", 
                "ERROR"
            )
            return False
        
        if sys.version_info >= (3, 13):
            self.print_status(
                f"Python {self.python_version} - Latest version detected ✓", 
                "SUCCESS"
            )
        else:
            self.print_status(
                f"Python {self.python_version} - Compatible version ✓", 
                "SUCCESS"
            )
        
        return True
    
    def cleanup_old_environment(self) -> None:
        """Remove existing virtual environment"""
        if self.venv_path.exists():
            self.print_status("Removing existing virtual environment...")
            shutil.rmtree(self.venv_path)
            self.print_status("Old environment removed ✓", "SUCCESS")
    
    def create_virtual_environment(self) -> bool:
        """Create fresh virtual environment"""
        self.print_status("Creating new virtual environment...")
        
        try:
            venv.create(
                self.venv_path,
                system_site_packages=False,
                clear=True,
                symlinks=platform.system() != "Windows",
                with_pip=True
            )
            self.print_status("Virtual environment created ✓", "SUCCESS")
            return True
            
        except Exception as e:
            self.print_status(f"Failed to create virtual environment: {e}", "ERROR")
            return False
    
    def get_pip_executable(self) -> Path:
        """Get platform-specific pip executable path"""
        if platform.system() == "Windows":
            return self.venv_path / "Scripts" / "pip.exe"
        else:
            return self.venv_path / "bin" / "pip"
    
    def get_python_executable(self) -> Path:
        """Get platform-specific python executable path"""
        if platform.system() == "Windows":
            return self.venv_path / "Scripts" / "python.exe"
        else:
            return self.venv_path / "bin" / "python"
    
    def upgrade_pip(self) -> bool:
        """Upgrade pip to latest version"""
        self.print_status("Upgrading pip to latest version...")
        
        pip_exec = self.get_pip_executable()
        try:
            result = subprocess.run(
                [str(pip_exec), "install", "--upgrade", "pip", "setuptools", "wheel"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.print_status("Pip upgraded successfully ✓", "SUCCESS")
                return True
            else:
                self.print_status(f"Pip upgrade failed: {result.stderr}", "ERROR")
                return False
                
        except subprocess.TimeoutExpired:
            self.print_status("Pip upgrade timed out", "ERROR")
            return False
        except Exception as e:
            self.print_status(f"Pip upgrade error: {e}", "ERROR")
            return False
    
    def select_requirements_file(self, mode: str) -> Path:
        """Select appropriate requirements file based on mode"""
        requirements_map = {
            "production": "requirements/requirements.txt",
            "development": "requirements/requirements.txt",  # Same base, dev tools included conditionally
            "minimal": "requirements/requirements-clean.txt",
            "testing": "requirements/requirements.txt"
        }

        req_file = self.project_root / requirements_map.get(mode, "requirements/requirements.txt")

        if not req_file.exists():
            # Fallback to requirements/requirements.txt, then root requirements.txt
            req_file = self.project_root / "requirements" / "requirements.txt"
            if not req_file.exists():
                req_file = self.project_root / "requirements.txt"

        return req_file
    
    def install_requirements(self, mode: str = "development") -> bool:
        """Install requirements with intelligent dependency resolution"""
        self.print_status(f"Installing requirements for {mode} mode...")
        
        pip_exec = self.get_pip_executable()
        req_file = self.select_requirements_file(mode)
        
        if not req_file.exists():
            self.print_status(f"Requirements file not found: {req_file}", "ERROR")
            return False
        
        self.print_status(f"Using requirements file: {req_file}")
        
        try:
            # Install with optimizations
            cmd = [
                str(pip_exec), "install",
                "-r", str(req_file),
                "--upgrade",
                "--no-cache-dir",  # Fresh install
                "--disable-pip-version-check"
            ]
            
            # Add timeout and better error handling
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900  # 15 minutes max
            )
            
            if result.returncode == 0:
                self.print_status("Requirements installed successfully ✓", "SUCCESS")
                return True
            else:
                self.print_status("Requirements installation failed:", "ERROR")
                self.print_status(result.stderr, "ERROR")
                return False
                
        except subprocess.TimeoutExpired:
            self.print_status("Requirements installation timed out", "ERROR")
            return False
        except Exception as e:
            self.print_status(f"Requirements installation error: {e}", "ERROR")
            return False
    
    def verify_installation(self) -> bool:
        """Verify critical dependencies are installed correctly"""
        self.print_status("Verifying installation...")
        
        python_exec = self.get_python_executable()
        
        # Critical imports to test
        test_imports = [
            ("flask", "Flask web framework"),
            ("grpc", "gRPC protocol support"),
            ("yaml", "YAML configuration parsing"),
            ("cryptography", "Cryptographic functions"),
            ("prometheus_client", "Metrics collection"),
            ("pytest", "Testing framework")
        ]
        
        failed_imports = []
        
        for module, description in test_imports:
            try:
                result = subprocess.run(
                    [str(python_exec), "-c", f"import {module}; print(f'{module} ✓')"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    self.print_status(f"{description}: {result.stdout.strip()}", "SUCCESS")
                else:
                    self.print_status(f"{description}: Import failed", "ERROR")
                    failed_imports.append(module)
                    
            except Exception as e:
                self.print_status(f"{description}: Error - {e}", "ERROR")
                failed_imports.append(module)
        
        if failed_imports:
            self.print_status(f"Failed imports: {', '.join(failed_imports)}", "ERROR")
            return False
        
        self.print_status("All critical dependencies verified ✓", "SUCCESS")
        return True
    
    def run_basic_tests(self) -> bool:
        """Run basic test suite to verify functionality"""
        self.print_status("Running basic test suite...")
        
        python_exec = self.get_python_executable()
        
        try:
            # Run a subset of tests for quick verification
            result = subprocess.run(
                [str(python_exec), "-m", "pytest", "tests/", "-v", "--tb=short", "-x"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.print_status("Basic tests passed ✓", "SUCCESS")
                return True
            else:
                self.print_status("Some tests failed - check full test suite", "WARNING")
                # Still return True as basic setup is working
                return True
                
        except subprocess.TimeoutExpired:
            self.print_status("Test run timed out", "WARNING")
            return True
        except Exception as e:
            self.print_status(f"Test execution error: {e}", "WARNING")
            return True
    
    def print_summary(self, success: bool) -> None:
        """Print setup summary"""
        self.print_header("SETUP SUMMARY")
        
        if success:
            self.print_status("🎉 AMOSKYS environment setup completed successfully!", "SUCCESS")
            self.print_status("", "INFO")
            self.print_status("Next steps:", "INFO")
            self.print_status("1. Activate the environment:", "INFO")
            
            if platform.system() == "Windows":
                self.print_status(f"   source {self.venv_path}/Scripts/activate", "INFO")
            else:
                self.print_status(f"   source {self.venv_path}/bin/activate", "INFO")
            
            self.print_status("2. Run the full test suite:", "INFO")
            self.print_status("   make check", "INFO")
            self.print_status("3. Start the application:", "INFO")
            self.print_status("   python -m amoskys", "INFO")
        else:
            self.print_status("❌ Environment setup failed", "ERROR")
            self.print_status("Please check the error messages above and try again", "ERROR")
    
    def setup_environment(self, mode: str = "development", force: bool = False) -> bool:
        """Main environment setup orchestration"""
        self.print_header("AMOSKYS ENVIRONMENT SETUP")
        self.print_status(f"Platform: {platform.platform()}")
        self.print_status(f"Python: {self.python_version}")
        self.print_status(f"Mode: {mode}")
        
        # Step 1: Check Python version
        if not self.check_python_version():
            return False
        
        # Step 2: Clean up old environment if forced or if it exists
        if force or self.venv_path.exists():
            self.cleanup_old_environment()
        
        # Step 3: Create virtual environment
        if not self.create_virtual_environment():
            return False
        
        # Step 4: Upgrade pip
        if not self.upgrade_pip():
            return False
        
        # Step 5: Install requirements
        if not self.install_requirements(mode):
            return False
        
        # Step 6: Verify installation
        if not self.verify_installation():
            return False
        
        # Step 7: Run basic tests
        if mode in ["development", "testing"]:
            self.run_basic_tests()
        
        return True

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="AMOSKYS Environment Setup & Requirements Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_environment_pro.py                    # Development setup
  python setup_environment_pro.py --mode production  # Production setup
  python setup_environment_pro.py --force            # Force clean rebuild
  python setup_environment_pro.py --minimal          # Minimal dependencies only
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["development", "production", "minimal", "testing"],
        default="development",
        help="Environment setup mode"
    )
    
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force clean rebuild of environment"
    )
    
    args = parser.parse_args()
    
    # Get project root (go up two levels from scripts/automation/ to repo root)
    project_root = Path(__file__).parent.parent.parent.absolute()

    # Initialize environment manager
    env_manager = EnvironmentManager(project_root)
    
    # Run setup
    success = env_manager.setup_environment(args.mode, args.force)
    
    # Print summary
    env_manager.print_summary(success)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
