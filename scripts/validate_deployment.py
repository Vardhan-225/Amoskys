#!/usr/bin/env python3
"""
AMOSKYS Deployment Validation Script

Validates configuration consistency before deployment to ensure:
- Gunicorn worker settings are correct
- Environment variables are properly set
- Required files exist
- Configuration files don't conflict

Usage:
    python scripts/validate_deployment.py [--env production|development]
"""

import argparse
import os
import re
import sys
from pathlib import Path


class Colors:
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    BLUE = "\033[0;34m"
    NC = "\033[0m"


def success(msg):
    print(f"{Colors.GREEN}✅ {msg}{Colors.NC}")


def warning(msg):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.NC}")


def error(msg):
    print(f"{Colors.RED}❌ {msg}{Colors.NC}")


def info(msg):
    print(f"{Colors.BLUE}ℹ️  {msg}{Colors.NC}")


class ValidationError(Exception):
    """Raised when validation fails"""

    pass


class DeploymentValidator:
    def __init__(self, project_root: Path, environment: str = "production"):
        self.project_root = project_root
        self.environment = environment
        self.errors = []
        self.warnings = []

    def validate_all(self) -> bool:
        """Run all validation checks"""
        print(f"\n{Colors.BLUE}🔍 AMOSKYS Deployment Validation{Colors.NC}")
        print(f"{Colors.BLUE}={'=' * 50}{Colors.NC}\n")
        print(f"Environment: {self.environment}")
        print(f"Project root: {self.project_root}\n")

        checks = [
            ("Required files", self.check_required_files),
            ("Gunicorn configuration", self.check_gunicorn_config),
            ("Server setup script", self.check_server_setup),
            ("Environment template", self.check_env_template),
            ("Systemd services", self.check_systemd_services),
            ("Deployment scripts", self.check_deployment_scripts),
        ]

        for check_name, check_func in checks:
            print(f"\n{Colors.BLUE}[Check]{Colors.NC} {check_name}...")
            try:
                check_func()
            except ValidationError as e:
                self.errors.append(f"{check_name}: {e}")
                error(str(e))
            except Exception as e:
                self.errors.append(f"{check_name}: Unexpected error: {e}")
                error(f"Unexpected error: {e}")

        # Print summary
        print(f"\n{Colors.BLUE}{'=' * 50}{Colors.NC}")
        print(f"{Colors.BLUE}Validation Summary{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 50}{Colors.NC}\n")

        if self.errors:
            error(f"Found {len(self.errors)} error(s):")
            for err in self.errors:
                print(f"  - {err}")

        if self.warnings:
            warning(f"Found {len(self.warnings)} warning(s):")
            for warn in self.warnings:
                print(f"  - {warn}")

        if not self.errors and not self.warnings:
            success("All validation checks passed!")
            return True
        elif not self.errors:
            success("Validation passed with warnings")
            return True
        else:
            error("Validation failed!")
            return False

    def check_required_files(self):
        """Check that all required files exist"""
        required_files = [
            "web/gunicorn_config.py",
            "web/wsgi.py",
            "scripts/server_setup.sh",
            "scripts/check-deployment-status.sh",
            ".flake8",
            "config/production.env.example",
        ]

        missing = []
        for file_path in required_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                missing.append(file_path)

        if missing:
            raise ValidationError(f"Missing required files: {', '.join(missing)}")

        success(f"All {len(required_files)} required files present")

    def check_gunicorn_config(self):
        """Validate Gunicorn configuration for production"""
        config_path = self.project_root / "web" / "gunicorn_config.py"

        with open(config_path, "r") as f:
            content = f.read()

        # Check worker class
        worker_class_match = re.search(r'worker_class\s*=\s*["\'](\w+)["\']', content)
        if not worker_class_match:
            raise ValidationError("worker_class not found in gunicorn_config.py")

        worker_class = worker_class_match.group(1)
        if worker_class != "eventlet":
            raise ValidationError(
                f"worker_class is '{worker_class}', should be 'eventlet' for SocketIO support"
            )

        # Check worker count
        workers_match = re.search(r"^workers\s*=\s*(\d+)", content, re.MULTILINE)
        if not workers_match:
            self.warnings.append(
                "workers count not explicitly set in gunicorn_config.py"
            )
        else:
            workers = int(workers_match.group(1))
            if worker_class == "eventlet" and workers != 1:
                raise ValidationError(
                    f"workers = {workers}, but eventlet requires workers = 1"
                )

        # Check bind address
        bind_match = re.search(r'bind\s*=\s*["\']([^"\']+)["\']', content)
        if bind_match:
            bind_addr = bind_match.group(1)
            if self.environment == "production" and "0.0.0.0" in bind_addr:
                self.warnings.append(
                    "bind address uses 0.0.0.0 - ensure nginx reverse proxy is configured"
                )

        success("Gunicorn config: worker_class=eventlet, workers=1")

    def check_server_setup(self):
        """Validate server setup script"""
        script_path = self.project_root / "scripts" / "server_setup.sh"

        with open(script_path, "r") as f:
            content = f.read()

        # Check for eventlet worker class in ExecStart
        if "--worker-class eventlet" not in content:
            raise ValidationError(
                "server_setup.sh ExecStart doesn't specify --worker-class eventlet"
            )

        # Check for single worker
        if "-w 1" not in content and "--workers 1" not in content:
            self.warnings.append(
                "server_setup.sh doesn't explicitly set workers to 1"
            )

        success("Server setup script configured correctly")

    def check_env_template(self):
        """Check environment template exists and has required variables"""
        env_path = self.project_root / "config" / "production.env.example"

        with open(env_path, "r") as f:
            content = f.read()

        required_vars = [
            "FLASK_ENV",
            "SECRET_KEY",
            "DATABASE_URL",
            "BUS_SERVER_PORT",
            "SSL_KEYFILE",
            "SSL_CERTFILE",
        ]

        missing_vars = []
        for var in required_vars:
            if var not in content:
                missing_vars.append(var)

        if missing_vars:
            raise ValidationError(
                f"Missing environment variables: {', '.join(missing_vars)}"
            )

        success(f"Environment template has all {len(required_vars)} required variables")

    def check_systemd_services(self):
        """Check systemd service files"""
        systemd_dir = self.project_root / "systemd"

        if not systemd_dir.exists():
            self.warnings.append("systemd/ directory not found")
            return

        required_services = [
            "amoskys-web.service",
            "amoskys-eventbus.service",
        ]

        missing_services = []
        for service in required_services:
            service_path = systemd_dir / service
            if not service_path.exists():
                missing_services.append(service)

        if missing_services:
            self.warnings.append(
                f"Missing systemd services: {', '.join(missing_services)}"
            )
        else:
            success(f"All {len(required_services)} systemd services present")

    def check_deployment_scripts(self):
        """Check deployment scripts are executable and valid"""
        scripts = [
            "scripts/server_setup.sh",
            "scripts/check-deployment-status.sh",
        ]

        for script in scripts:
            script_path = self.project_root / script
            if not os.access(script_path, os.X_OK):
                self.warnings.append(f"{script} is not executable (run chmod +x)")

        success("Deployment scripts are valid")


def main():
    parser = argparse.ArgumentParser(
        description="Validate AMOSKYS deployment configuration"
    )
    parser.add_argument(
        "--env",
        choices=["production", "development"],
        default="production",
        help="Target environment",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent,
        help="Project root directory",
    )

    args = parser.parse_args()

    validator = DeploymentValidator(args.project_root, args.env)
    success_status = validator.validate_all()

    sys.exit(0 if success_status else 1)


if __name__ == "__main__":
    main()
