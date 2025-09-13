#!/usr/bin/env python3
"""
AMOSKYS Neural Security Command Platform
Comprehensive Repository Assessment & Health Check
Professional Analysis Tool

This script provides deep analysis of:
- Architecture & Component Assessment
- Performance Metrics & Bottlenecks  
- Security Posture & Vulnerabilities
- Code Quality & Technical Debt
- Development Workflow & CI/CD
- Future Roadmap & Recommendations
"""

import os
import sys
import json
import time
import subprocess
import platform
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import ast
import re

@dataclass
class AssessmentResult:
    """Assessment result data structure"""
    component: str
    status: str  # "excellent", "good", "needs_attention", "critical"
    score: int  # 0-100
    details: List[str]
    recommendations: List[str]
    metrics: Dict[str, Any]

class Colors:
    """Terminal colors for better output"""
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class RepositoryAssessor:
    """Comprehensive repository assessment system"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.assessment_time = datetime.now()
        self.results: List[AssessmentResult] = []
        
    def print_header(self, title: str, level: int = 1) -> None:
        """Print formatted section header"""
        if level == 1:
            print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}")
            print(f"{title}")
            print(f"{'='*80}{Colors.END}\n")
        elif level == 2:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'-'*60}")
            print(f"{title}")
            print(f"{'-'*60}{Colors.END}\n")
        else:
            print(f"\n{Colors.BOLD}{title}{Colors.END}")
    
    def print_status(self, message: str, status: str = "INFO") -> None:
        """Print colored status message"""
        color_map = {
            "EXCELLENT": Colors.GREEN,
            "GOOD": Colors.BLUE,
            "WARNING": Colors.YELLOW,
            "CRITICAL": Colors.RED,
            "INFO": Colors.CYAN
        }
        color = color_map.get(status, Colors.CYAN)
        print(f"{color}[{status}]{Colors.END} {message}")
    
    def analyze_codebase_structure(self) -> AssessmentResult:
        """Analyze codebase architecture and structure"""
        self.print_header("Codebase Structure Analysis", 2)
        
        details = []
        recommendations = []
        metrics = {}
        score = 0
        
        # Count files by type
        py_files = list(self.project_root.rglob("*.py"))
        yaml_files = list(self.project_root.rglob("*.yaml")) + list(self.project_root.rglob("*.yml"))
        proto_files = list(self.project_root.rglob("*.proto"))
        md_files = list(self.project_root.rglob("*.md"))
        
        metrics["python_files"] = len(py_files)
        metrics["config_files"] = len(yaml_files)
        metrics["proto_files"] = len(proto_files)
        metrics["doc_files"] = len(md_files)
        
        # Analyze directory structure
        src_dir = self.project_root / "src"
        web_dir = self.project_root / "web"
        tests_dir = self.project_root / "tests"
        docs_dir = self.project_root / "docs"
        
        structure_score = 0
        if src_dir.exists():
            details.append("✓ Source code properly organized in src/ directory")
            structure_score += 20
        else:
            details.append("✗ No src/ directory found")
            recommendations.append("Organize source code in src/ directory")
        
        if web_dir.exists():
            details.append("✓ Web interface separated in web/ directory")
            structure_score += 15
        
        if tests_dir.exists():
            details.append("✓ Tests organized in tests/ directory")
            structure_score += 20
        else:
            recommendations.append("Create dedicated tests/ directory")
        
        if docs_dir.exists():
            details.append("✓ Documentation organized in docs/ directory")
            structure_score += 15
        
        # Check for important configuration files
        config_files = [
            ("pyproject.toml", "Modern Python project configuration"),
            ("Makefile", "Build automation"),
            ("requirements.txt", "Python dependencies"),
            (".gitignore", "Git ignore rules"),
            ("README.md", "Project documentation")
        ]
        
        for filename, description in config_files:
            if (self.project_root / filename).exists():
                details.append(f"✓ {description} present")
                structure_score += 6
            else:
                recommendations.append(f"Add {filename} for {description}")
        
        score = min(structure_score, 100)
        
        # Determine status
        if score >= 85:
            status = "excellent"
        elif score >= 70:
            status = "good"
        elif score >= 50:
            status = "needs_attention"
        else:
            status = "critical"
        
        self.print_status(f"Python files: {metrics['python_files']}")
        self.print_status(f"Configuration files: {metrics['config_files']}")
        self.print_status(f"Protocol files: {metrics['proto_files']}")
        self.print_status(f"Documentation files: {metrics['doc_files']}")
        self.print_status(f"Structure score: {score}/100", status.upper())
        
        return AssessmentResult(
            component="Codebase Structure",
            status=status,
            score=score,
            details=details,
            recommendations=recommendations,
            metrics=metrics
        )
    
    def analyze_dependencies(self) -> AssessmentResult:
        """Analyze dependency management and security"""
        self.print_header("Dependency Analysis", 2)
        
        details = []
        recommendations = []
        metrics = {}
        score = 0
        
        # Check requirements files
        req_files = list(self.project_root.rglob("requirements*.txt"))
        req_dir = self.project_root / "requirements"
        
        metrics["requirements_files"] = len(req_files)
        metrics["has_requirements_dir"] = req_dir.exists()
        
        if len(req_files) > 0:
            details.append(f"✓ Found {len(req_files)} requirements files")
            score += 20
        else:
            details.append("✗ No requirements files found")
            recommendations.append("Create requirements.txt for dependency management")
        
        if req_dir.exists():
            details.append("✓ Requirements organized in dedicated directory")
            score += 15
        
        # Check for modern dependency management
        pyproject_file = self.project_root / "pyproject.toml"
        if pyproject_file.exists():
            details.append("✓ Modern pyproject.toml configuration present")
            score += 20
        
        # Check for lockfiles
        lockfiles = [
            "requirements-lock.txt",
            "Pipfile.lock",
            "poetry.lock",
            "conda-lock.yml"
        ]
        
        has_lockfile = False
        for lockfile in lockfiles:
            if (self.project_root / lockfile).exists():
                details.append(f"✓ Lockfile found: {lockfile}")
                has_lockfile = True
                score += 15
                break
        
        if not has_lockfile:
            recommendations.append("Add dependency lockfile for reproducible builds")
        
        # Analyze virtual environment
        venv_dirs = [".venv", "venv", ".env"]
        has_venv = any((self.project_root / vdir).exists() for vdir in venv_dirs)
        
        if has_venv:
            details.append("✓ Virtual environment directory present")
            score += 10
        
        # Check for security scanning
        security_configs = [
            ".safety",
            "safety-policy.json",
            ".bandit",
            "bandit.yaml"
        ]
        
        has_security = any((self.project_root / sfile).exists() for sfile in security_configs)
        if has_security:
            details.append("✓ Security scanning configuration found")
            score += 10
        else:
            recommendations.append("Add security scanning tools (safety, bandit)")
        
        # Calculate final score
        score = min(score, 100)
        
        if score >= 85:
            status = "excellent"
        elif score >= 70:
            status = "good"
        elif score >= 50:
            status = "needs_attention"
        else:
            status = "critical"
        
        self.print_status(f"Requirements files: {metrics['requirements_files']}")
        self.print_status(f"Has lockfile: {has_lockfile}")
        self.print_status(f"Has virtual env: {has_venv}")
        self.print_status(f"Dependency score: {score}/100", status.upper())
        
        return AssessmentResult(
            component="Dependency Management",
            status=status,
            score=score,
            details=details,
            recommendations=recommendations,
            metrics=metrics
        )
    
    def analyze_testing_infrastructure(self) -> AssessmentResult:
        """Analyze testing setup and coverage"""
        self.print_header("Testing Infrastructure Analysis", 2)
        
        details = []
        recommendations = []
        metrics = {}
        score = 0
        
        # Check for test directory
        tests_dir = self.project_root / "tests"
        if tests_dir.exists():
            test_files = list(tests_dir.rglob("test_*.py"))
            metrics["test_files"] = len(test_files)
            
            if len(test_files) > 0:
                details.append(f"✓ Found {len(test_files)} test files")
                score += 30
            else:
                details.append("✗ Tests directory exists but no test files found")
                recommendations.append("Add test files to tests/ directory")
        else:
            metrics["test_files"] = 0
            details.append("✗ No tests directory found")
            recommendations.append("Create tests/ directory and add test files")
        
        # Check for pytest configuration
        pytest_configs = [
            "pytest.ini",
            "pyproject.toml",  # can contain pytest config
            "setup.cfg"
        ]
        
        has_pytest_config = False
        for config_file in pytest_configs:
            config_path = self.project_root / config_file
            if config_path.exists():
                # Check if it contains pytest configuration
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                        if 'pytest' in content.lower():
                            details.append(f"✓ Pytest configuration found in {config_file}")
                            has_pytest_config = True
                            score += 15
                            break
                except:
                    pass
        
        if not has_pytest_config:
            recommendations.append("Add pytest configuration")
        
        # Check for coverage configuration
        coverage_configs = [
            ".coveragerc",
            "pyproject.toml",  # can contain coverage config
            "setup.cfg"
        ]
        
        has_coverage_config = False
        for config_file in coverage_configs:
            config_path = self.project_root / config_file
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                        if 'coverage' in content.lower():
                            details.append(f"✓ Coverage configuration found in {config_file}")
                            has_coverage_config = True
                            score += 15
                            break
                except:
                    pass
        
        if not has_coverage_config:
            recommendations.append("Add test coverage configuration")
        
        # Try to run tests and get results
        try:
            venv_python = self.project_root / ".venv" / "bin" / "python"
            if not venv_python.exists() and platform.system() == "Windows":
                venv_python = self.project_root / ".venv" / "Scripts" / "python.exe"
            
            if venv_python.exists():
                result = subprocess.run(
                    [str(venv_python), "-m", "pytest", "--collect-only", "-q"],
                    cwd=self.project_root,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    # Parse collected tests
                    output_lines = result.stdout.split('\n')
                    collected_tests = 0
                    for line in output_lines:
                        if "collected" in line and "item" in line:
                            try:
                                collected_tests = int(line.split()[0])
                                break
                            except:
                                pass
                    
                    metrics["collected_tests"] = collected_tests
                    if collected_tests > 0:
                        details.append(f"✓ {collected_tests} tests collected successfully")
                        score += 25
                    else:
                        details.append("⚠ No tests collected")
                        
                else:
                    details.append("⚠ Test collection failed")
                    metrics["collected_tests"] = 0
            else:
                details.append("⚠ Virtual environment not found - cannot run test analysis")
                
        except Exception as e:
            details.append(f"⚠ Could not analyze test execution: {str(e)}")
            metrics["collected_tests"] = 0
        
        # Check for CI/CD configuration
        ci_configs = [
            ".github/workflows",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".travis.yml",
            "azure-pipelines.yml"
        ]
        
        has_ci = False
        for ci_config in ci_configs:
            if (self.project_root / ci_config).exists():
                details.append(f"✓ CI/CD configuration found: {ci_config}")
                has_ci = True
                score += 15
                break
        
        if not has_ci:
            recommendations.append("Add CI/CD pipeline configuration")
        
        # Calculate final score
        score = min(score, 100)
        
        if score >= 85:
            status = "excellent"
        elif score >= 70:
            status = "good"
        elif score >= 50:
            status = "needs_attention"
        else:
            status = "critical"
        
        self.print_status(f"Test files: {metrics.get('test_files', 0)}")
        self.print_status(f"Collected tests: {metrics.get('collected_tests', 0)}")
        self.print_status(f"Has CI/CD: {has_ci}")
        self.print_status(f"Testing score: {score}/100", status.upper())
        
        return AssessmentResult(
            component="Testing Infrastructure",
            status=status,
            score=score,
            details=details,
            recommendations=recommendations,
            metrics=metrics
        )
    
    def analyze_code_quality(self) -> AssessmentResult:
        """Analyze code quality and style"""
        self.print_header("Code Quality Analysis", 2)
        
        details = []
        recommendations = []
        metrics = {}
        score = 0
        
        # Check for code formatting tools
        formatting_configs = [
            (".black", "Black code formatter"),
            ("pyproject.toml", "Black/isort in pyproject.toml"),
            (".flake8", "Flake8 linter"),
            (".pylintrc", "Pylint configuration"),
            (".isort.cfg", "isort import sorter")
        ]
        
        formatting_score = 0
        for config_file, tool_name in formatting_configs:
            config_path = self.project_root / config_file
            if config_path.exists():
                if config_file == "pyproject.toml":
                    # Check if it contains relevant tool configs
                    try:
                        with open(config_path, 'r') as f:
                            content = f.read()
                            if any(tool in content for tool in ['[tool.black]', '[tool.isort]', '[tool.flake8]']):
                                details.append(f"✓ Code quality tools configured in {config_file}")
                                formatting_score += 20
                    except:
                        pass
                else:
                    details.append(f"✓ {tool_name} configuration found")
                    formatting_score += 15
        
        score += min(formatting_score, 40)
        
        # Analyze Python code for basic quality metrics
        py_files = list(self.project_root.rglob("*.py"))
        if py_files:
            # Sample a few files for quality analysis
            sample_files = py_files[:min(10, len(py_files))]
            
            total_lines = 0
            total_functions = 0
            total_classes = 0
            files_with_docstrings = 0
            
            for py_file in sample_files:
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = content.split('\n')
                        total_lines += len(lines)
                        
                    # Parse AST for analysis
                    try:
                        tree = ast.parse(content)
                        file_functions = 0
                        file_classes = 0
                        has_module_docstring = False
                        
                        for node in ast.walk(tree):
                            if isinstance(node, ast.FunctionDef):
                                file_functions += 1
                                total_functions += 1
                            elif isinstance(node, ast.ClassDef):
                                file_classes += 1
                                total_classes += 1
                            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                                if isinstance(node.value.value, str) and node.lineno <= 3:
                                    has_module_docstring = True
                        
                        if has_module_docstring or '"""' in content[:500]:
                            files_with_docstrings += 1
                            
                    except SyntaxError:
                        pass  # Skip files with syntax errors
                        
                except Exception:
                    pass
            
            metrics["total_python_lines"] = total_lines
            metrics["total_functions"] = total_functions
            metrics["total_classes"] = total_classes
            metrics["files_with_docstrings"] = files_with_docstrings
            metrics["docstring_percentage"] = (files_with_docstrings / len(sample_files)) * 100 if sample_files else 0
            
            # Quality scoring
            if metrics["docstring_percentage"] > 70:
                details.append(f"✓ Good documentation coverage ({metrics['docstring_percentage']:.1f}%)")
                score += 20
            elif metrics["docstring_percentage"] > 40:
                details.append(f"⚠ Moderate documentation coverage ({metrics['docstring_percentage']:.1f}%)")
                score += 10
                recommendations.append("Improve docstring coverage")
            else:
                details.append(f"✗ Low documentation coverage ({metrics['docstring_percentage']:.1f}%)")
                recommendations.append("Add docstrings to modules, classes, and functions")
            
            # Check average function/class per file ratio
            avg_functions_per_file = total_functions / len(sample_files) if sample_files else 0
            avg_classes_per_file = total_classes / len(sample_files) if sample_files else 0
            
            if 2 <= avg_functions_per_file <= 15:
                details.append("✓ Good function organization")
                score += 15
            elif avg_functions_per_file > 20:
                recommendations.append("Consider breaking down large modules")
            
            if 0.5 <= avg_classes_per_file <= 3:
                details.append("✓ Good class organization")
                score += 15
        
        # Check for type hints
        type_hint_files = 0
        sample_files = []
        if py_files:
            sample_files = py_files[:min(5, len(py_files))]
            for py_file in sample_files:
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'typing' in content or '->' in content or ': ' in content:
                            type_hint_files += 1
                except:
                    pass
        
        type_hint_percentage = (type_hint_files / len(sample_files)) * 100 if sample_files else 0
        metrics["type_hint_percentage"] = type_hint_percentage
        
        if type_hint_percentage > 60:
            details.append(f"✓ Good type hint usage ({type_hint_percentage:.1f}%)")
            score += 10
        else:
            recommendations.append("Add type hints for better code clarity")
        
        # Calculate final score
        score = min(score, 100)
        
        if score >= 85:
            status = "excellent"
        elif score >= 70:
            status = "good"
        elif score >= 50:
            status = "needs_attention"
        else:
            status = "critical"
        
        self.print_status(f"Python files analyzed: {len(sample_files) if py_files else 0}")
        self.print_status(f"Functions found: {metrics.get('total_functions', 0)}")
        self.print_status(f"Classes found: {metrics.get('total_classes', 0)}")
        self.print_status(f"Documentation coverage: {metrics.get('docstring_percentage', 0):.1f}%")
        self.print_status(f"Code quality score: {score}/100", status.upper())
        
        return AssessmentResult(
            component="Code Quality",
            status=status,
            score=score,
            details=details,
            recommendations=recommendations,
            metrics=metrics
        )
    
    def analyze_security_posture(self) -> AssessmentResult:
        """Analyze security configuration and practices"""
        self.print_header("Security Posture Analysis", 2)
        
        details = []
        recommendations = []
        metrics = {}
        score = 0
        
        # Check for security-related files and configurations
        security_files = [
            ("certs/", "TLS certificates directory"),
            (".env.example", "Environment variables template"),
            (".gitignore", "Git ignore rules"),
            ("SECURITY.md", "Security policy documentation")
        ]
        
        for sec_file, description in security_files:
            if (self.project_root / sec_file).exists():
                details.append(f"✓ {description} present")
                score += 10
            else:
                if sec_file in [".gitignore", "certs/"]:
                    recommendations.append(f"Add {sec_file} for {description}")
        
        # Check for sensitive data exposure
        gitignore_path = self.project_root / ".gitignore"
        if gitignore_path.exists():
            try:
                with open(gitignore_path, 'r') as f:
                    gitignore_content = f.read()
                    
                security_patterns = [
                    "*.key", "*.pem", ".env", "secrets/", "config/*.yaml",
                    "__pycache__", ".venv", "*.log"
                ]
                
                ignored_patterns = 0
                for pattern in security_patterns:
                    if pattern in gitignore_content:
                        ignored_patterns += 1
                
                if ignored_patterns >= 6:
                    details.append("✓ Good gitignore security coverage")
                    score += 15
                elif ignored_patterns >= 3:
                    details.append("⚠ Basic gitignore security coverage")
                    score += 8
                    recommendations.append("Improve gitignore to exclude sensitive files")
                else:
                    details.append("✗ Poor gitignore security coverage")
                    recommendations.append("Add comprehensive gitignore rules")
                    
            except:
                pass
        
        # Check for hardcoded secrets (basic scan)
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']'
        ]
        
        potential_secrets = 0
        py_files = list(self.project_root.rglob("*.py"))
        sample_files = py_files[:min(20, len(py_files))]
        
        for py_file in sample_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    for pattern in secret_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            potential_secrets += 1
                            break
            except:
                pass
        
        metrics["potential_hardcoded_secrets"] = potential_secrets
        
        if potential_secrets == 0:
            details.append("✓ No obvious hardcoded secrets found")
            score += 20
        elif potential_secrets <= 2:
            details.append("⚠ Potential hardcoded secrets detected")
            score += 10
            recommendations.append("Review and remove hardcoded secrets")
        else:
            details.append("✗ Multiple potential hardcoded secrets found")
            recommendations.append("Audit code for hardcoded credentials")
        
        # Check for security dependencies
        security_deps = [
            "cryptography",
            "pyjwt", 
            "bcrypt",
            "passlib"
        ]
        
        req_files = list(self.project_root.rglob("requirements*.txt"))
        found_security_deps = []
        
        for req_file in req_files:
            try:
                with open(req_file, 'r') as f:
                    content = f.read().lower()
                    for dep in security_deps:
                        if dep in content:
                            found_security_deps.append(dep)
            except:
                pass
        
        found_security_deps = list(set(found_security_deps))
        metrics["security_dependencies"] = found_security_deps
        
        if len(found_security_deps) >= 2:
            details.append(f"✓ Good security dependencies: {', '.join(found_security_deps)}")
            score += 15
        elif len(found_security_deps) >= 1:
            details.append(f"⚠ Basic security dependencies: {', '.join(found_security_deps)}")
            score += 8
        else:
            recommendations.append("Add security-focused dependencies")
        
        # Check for security scanning tools
        security_tools = [
            "bandit",
            "safety",
            "pip-audit"
        ]
        
        found_tools = []
        for req_file in req_files:
            try:
                with open(req_file, 'r') as f:
                    content = f.read().lower()
                    for tool in security_tools:
                        if tool in content:
                            found_tools.append(tool)
            except:
                pass
        
        found_tools = list(set(found_tools))
        if found_tools:
            details.append(f"✓ Security scanning tools: {', '.join(found_tools)}")
            score += 15
        else:
            recommendations.append("Add security scanning tools (bandit, safety)")
        
        # Calculate final score
        score = min(score, 100)
        
        if score >= 85:
            status = "excellent"
        elif score >= 70:
            status = "good"
        elif score >= 50:
            status = "needs_attention"
        else:
            status = "critical"
        
        self.print_status(f"Security dependencies: {len(found_security_deps)}")
        self.print_status(f"Potential secrets: {potential_secrets}")
        self.print_status(f"Security tools: {len(found_tools)}")
        self.print_status(f"Security score: {score}/100", status.upper())
        
        return AssessmentResult(
            component="Security Posture",
            status=status,
            score=score,
            details=details,
            recommendations=recommendations,
            metrics=metrics
        )
    
    def analyze_documentation(self) -> AssessmentResult:
        """Analyze documentation quality and completeness"""
        self.print_header("Documentation Analysis", 2)
        
        details = []
        recommendations = []
        metrics = {}
        score = 0
        
        # Check for documentation files
        doc_files = [
            ("README.md", "Project overview"),
            ("CONTRIBUTING.md", "Contribution guidelines"),
            ("CHANGELOG.md", "Version history"),
            ("LICENSE", "License information"),
            ("docs/", "Documentation directory")
        ]
        
        found_docs = 0
        for doc_file, description in doc_files:
            if (self.project_root / doc_file).exists():
                details.append(f"✓ {description} present")
                found_docs += 1
                score += 15
            else:
                if doc_file in ["README.md", "docs/"]:
                    recommendations.append(f"Add {doc_file} for {description}")
        
        metrics["documentation_files"] = found_docs
        
        # Check README quality
        readme_path = self.project_root / "README.md"
        if readme_path.exists():
            try:
                with open(readme_path, 'r', encoding='utf-8') as f:
                    readme_content = f.read()
                    
                readme_sections = [
                    "installation", "usage", "features", "requirements",
                    "getting started", "configuration", "examples"
                ]
                
                found_sections = 0
                for section in readme_sections:
                    if section.lower() in readme_content.lower():
                        found_sections += 1
                
                metrics["readme_sections"] = found_sections
                metrics["readme_length"] = len(readme_content)
                
                if found_sections >= 5:
                    details.append("✓ Comprehensive README content")
                    score += 15
                elif found_sections >= 3:
                    details.append("⚠ Basic README content")
                    score += 8
                    recommendations.append("Expand README with more sections")
                else:
                    details.append("✗ Minimal README content")
                    recommendations.append("Improve README with installation, usage, and features")
                    
            except:
                pass
        
        # Check docs directory structure
        docs_dir = self.project_root / "docs"
        if docs_dir.exists():
            doc_files_in_dir = list(docs_dir.rglob("*.md"))
            metrics["docs_directory_files"] = len(doc_files_in_dir)
            
            if len(doc_files_in_dir) >= 10:
                details.append(f"✓ Extensive documentation ({len(doc_files_in_dir)} files)")
                score += 15
            elif len(doc_files_in_dir) >= 5:
                details.append(f"⚠ Moderate documentation ({len(doc_files_in_dir)} files)")
                score += 10
            else:
                details.append(f"✗ Limited documentation ({len(doc_files_in_dir)} files)")
                recommendations.append("Expand documentation in docs/ directory")
        
        # Check for API documentation
        api_doc_indicators = [
            "swagger", "openapi", "api.md", "endpoints",
            "docs/api", "apidoc"
        ]
        
        has_api_docs = False
        all_files = list(self.project_root.rglob("*"))
        
        for file_path in all_files:
            for indicator in api_doc_indicators:
                if indicator.lower() in str(file_path).lower():
                    has_api_docs = True
                    break
            if has_api_docs:
                break
        
        if has_api_docs:
            details.append("✓ API documentation found")
            score += 10
        else:
            recommendations.append("Add API documentation")
        
        # Check for inline code documentation
        py_files = list(self.project_root.rglob("*.py"))
        if py_files:
            sample_files = py_files[:min(10, len(py_files))]
            files_with_docstrings = 0
            
            for py_file in sample_files:
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if '"""' in content or "'''" in content:
                            files_with_docstrings += 1
                except:
                    pass
            
            docstring_percentage = (files_with_docstrings / len(sample_files)) * 100
            metrics["inline_documentation_percentage"] = docstring_percentage
            
            if docstring_percentage >= 70:
                details.append(f"✓ Good inline documentation ({docstring_percentage:.1f}%)")
                score += 10
            else:
                recommendations.append("Improve inline code documentation")
        
        # Calculate final score
        score = min(score, 100)
        
        if score >= 85:
            status = "excellent"
        elif score >= 70:
            status = "good"
        elif score >= 50:
            status = "needs_attention"
        else:
            status = "critical"
        
        self.print_status(f"Documentation files: {found_docs}")
        self.print_status(f"README sections: {metrics.get('readme_sections', 0)}")
        self.print_status(f"Docs directory files: {metrics.get('docs_directory_files', 0)}")
        self.print_status(f"Documentation score: {score}/100", status.upper())
        
        return AssessmentResult(
            component="Documentation",
            status=status,
            score=score,
            details=details,
            recommendations=recommendations,
            metrics=metrics
        )
    
    def generate_overall_assessment(self) -> Dict[str, Any]:
        """Generate overall assessment summary"""
        
        if not self.results:
            return {"error": "No assessment results available"}
        
        # Calculate overall score
        total_score = sum(result.score for result in self.results)
        avg_score = total_score / len(self.results)
        
        # Determine overall status
        if avg_score >= 85:
            overall_status = "excellent"
        elif avg_score >= 70:
            overall_status = "good"
        elif avg_score >= 50:
            overall_status = "needs_attention"
        else:
            overall_status = "critical"
        
        # Collect all recommendations
        all_recommendations = []
        critical_issues = []
        
        for result in self.results:
            all_recommendations.extend(result.recommendations)
            if result.status == "critical":
                critical_issues.append(result.component)
        
        # Priority recommendations
        priority_recommendations = []
        if critical_issues:
            priority_recommendations.append(f"Address critical issues in: {', '.join(critical_issues)}")
        
        # Add top recommendations
        priority_recommendations.extend(all_recommendations[:5])
        
        return {
            "overall_score": round(avg_score, 1),
            "overall_status": overall_status,
            "components_assessed": len(self.results),
            "critical_components": critical_issues,
            "priority_recommendations": priority_recommendations,
            "assessment_time": self.assessment_time.isoformat(),
            "detailed_results": [asdict(result) for result in self.results]
        }
    
    def print_summary_report(self) -> None:
        """Print comprehensive summary report"""
        self.print_header("COMPREHENSIVE ASSESSMENT SUMMARY")
        
        overall = self.generate_overall_assessment()
        
        # Overall status
        status_color = {
            "excellent": "EXCELLENT",
            "good": "GOOD", 
            "needs_attention": "WARNING",
            "critical": "CRITICAL"
        }
        
        self.print_status(
            f"Overall Score: {overall['overall_score']}/100",
            status_color[overall['overall_status']]
        )
        
        print(f"\n{Colors.BOLD}Component Scores:{Colors.END}")
        for result in sorted(self.results, key=lambda x: x.score, reverse=True):
            status_symbol = {
                "excellent": "🟢",
                "good": "🔵", 
                "needs_attention": "🟡",
                "critical": "🔴"
            }
            
            print(f"  {status_symbol[result.status]} {result.component:<25} {result.score:>3}/100")
        
        # Critical issues
        if overall['critical_components']:
            print(f"\n{Colors.BOLD}{Colors.RED}Critical Issues:{Colors.END}")
            for component in overall['critical_components']:
                print(f"  ⚠️  {component}")
        
        # Priority recommendations
        print(f"\n{Colors.BOLD}Priority Recommendations:{Colors.END}")
        for i, rec in enumerate(overall['priority_recommendations'][:8], 1):
            print(f"  {i}. {rec}")
        
        # Next steps
        print(f"\n{Colors.BOLD}Suggested Next Steps:{Colors.END}")
        
        if overall['overall_score'] >= 85:
            print("  🎉 Excellent! Consider advanced optimizations and monitoring")
        elif overall['overall_score'] >= 70:
            print("  👍 Good foundation. Focus on addressing remaining recommendations")
        elif overall['overall_score'] >= 50:
            print("  ⚠️  Needs attention. Prioritize critical issues and core improvements")
        else:
            print("  🚨 Critical state. Immediate action required on foundational issues")
        
        print(f"\n{Colors.BOLD}Assessment completed at: {overall['assessment_time']}{Colors.END}")
    
    def save_detailed_report(self, output_file: Optional[Path] = None) -> Path:
        """Save detailed assessment report to JSON"""
        if not output_file:
            timestamp = self.assessment_time.strftime("%Y%m%d_%H%M%S")
            output_file = self.project_root / f"assessment_report_{timestamp}.json"
        
        overall_assessment = self.generate_overall_assessment()
        
        with open(output_file, 'w') as f:
            json.dump(overall_assessment, f, indent=2, default=str)
        
        self.print_status(f"Detailed report saved: {output_file}", "INFO")
        return output_file
    
    def run_full_assessment(self) -> Dict[str, Any]:
        """Run complete repository assessment"""
        self.print_header("AMOSKYS REPOSITORY ASSESSMENT")
        self.print_status(f"Starting assessment at {self.assessment_time}")
        self.print_status(f"Project root: {self.project_root}")
        
        # Run all assessments
        assessments = [
            self.analyze_codebase_structure,
            self.analyze_dependencies,
            self.analyze_testing_infrastructure,
            self.analyze_code_quality,
            self.analyze_security_posture,
            self.analyze_documentation
        ]
        
        for assessment_func in assessments:
            try:
                result = assessment_func()
                self.results.append(result)
            except Exception as e:
                self.print_status(f"Assessment error in {assessment_func.__name__}: {e}", "CRITICAL")
        
        # Generate and display summary
        self.print_summary_report()
        
        # Save detailed report
        report_file = self.save_detailed_report()
        
        return self.generate_overall_assessment()

def main():
    """Main assessment entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="AMOSKYS Repository Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for detailed JSON report"
    )
    
    parser.add_argument(
        "--component",
        choices=[
            "structure", "dependencies", "testing", 
            "quality", "security", "documentation"
        ],
        help="Run assessment for specific component only"
    )
    
    args = parser.parse_args()
    
    # Get project root (go up 2 levels from scripts/automation/)
    project_root = Path(__file__).parent.parent.parent.absolute()
    
    # Initialize assessor
    assessor = RepositoryAssessor(project_root)
    
    # Run assessment
    if args.component:
        # Run specific component assessment
        component_map = {
            "structure": assessor.analyze_codebase_structure,
            "dependencies": assessor.analyze_dependencies,
            "testing": assessor.analyze_testing_infrastructure,
            "quality": assessor.analyze_code_quality,
            "security": assessor.analyze_security_posture,
            "documentation": assessor.analyze_documentation
        }
        
        result = component_map[args.component]()
        assessor.results.append(result)
        assessor.print_summary_report()
    else:
        # Run full assessment
        assessor.run_full_assessment()
    
    # Save report if requested
    if args.output:
        assessor.save_detailed_report(args.output)

if __name__ == "__main__":
    main()
