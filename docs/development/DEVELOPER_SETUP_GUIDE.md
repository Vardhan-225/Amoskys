# AMOSKYS Professional Setup Guide

## 🧠⚡ Quick Start for Developers

Welcome to the AMOSKYS Neural Security Command Platform. This guide will get you up and running in under 5 minutes.

### Prerequisites
- Python 3.11+ installed
- Git access to the repository
- Terminal/Command Prompt access

### 🚀 One-Command Setup

```bash
# Clone and setup in one go
git clone https://github.com/your-org/Amoskys.git
cd Amoskys
python setup_environment_pro.py
```

### ✅ Verify Installation

```bash
# Check system health
make health-check

# Run full test suite
make check

# Assess repository status
make assess
```

---

## 📋 Manual Setup (If Needed)

### 1. Environment Creation
```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (macOS/Linux)
source .venv/bin/activate
```

### 2. Dependencies Installation
```bash
# Install all dependencies
pip install -r requirements.txt
```

### 3. Verification
```bash
# Test the installation
python -m pytest tests/ -v
```

---

## 🛠️ Development Workflow

### Daily Commands
```bash
# Start development session
make dev-start

# Run tests during development
make test-watch

# Code quality check
make lint

# Full pre-commit check
make pre-commit
```

### Git Workflow
```bash
# Before committing
make pre-commit

# Push changes
git add .
git commit -m "feat: your feature description"
git push origin your-branch
```

---

## 🔧 Available Make Commands

| Command | Description |
|---------|-------------|
| `make env-setup` | Professional environment setup |
| `make check` | Run full test suite |
| `make assess` | Repository health assessment |
| `make health-check` | System verification |
| `make env-clean` | Clean and rebuild environment |
| `make lint` | Code quality checks |
| `make format` | Auto-format code |
| `make security` | Security scanning |

---

## 🎯 Project Structure

```
Amoskys/
├── amoskys/                 # Core package
│   ├── cli/                # Command-line interface
│   ├── core/               # Core platform components
│   ├── modules/            # Security modules
│   └── utils/              # Utility functions
├── web/                    # Web interface
│   └── app/               # Flask application
├── tests/                  # Test suite
├── docs/                   # Documentation
├── scripts/               # Automation scripts
├── requirements.txt       # Dependencies
└── Makefile              # Development commands
```

---

## 🔍 Troubleshooting

### Common Issues

**Import Errors**
```bash
# Recreate environment
make env-clean
python setup_environment_pro.py
```

**Test Failures**
```bash
# Run individual test
python -m pytest tests/test_specific.py -v

# Run with detailed output
python -m pytest tests/ -v -s
```

**WebSocket Issues**
```bash
# Check Flask-SocketIO installation
pip show Flask-SocketIO

# Reinstall if needed
pip install --force-reinstall Flask-SocketIO==5.3.6
```

### Environment Issues

**Python Version**
```bash
# Check Python version
python --version

# Should be 3.11 or higher
```

**Virtual Environment**
```bash
# Ensure you're in the virtual environment
which python  # Should point to .venv/bin/python
```

---

## 📊 Monitoring & Assessment

### Repository Health
```bash
# Full assessment
make assess

# Check specific areas
python assess_repository.py --area security
python assess_repository.py --area testing
```

### Performance Metrics
```bash
# Test execution time
time make check

# Memory usage during tests
python -m memory_profiler -m pytest tests/
```

---

## 🔐 Security Considerations

### Development Security
- Keep dependencies updated
- Never commit secrets
- Use environment variables for configuration
- Run security scans regularly

### Security Commands
```bash
# Security scan
make security

# Dependency vulnerability check
pip-audit

# Code security analysis
bandit -r amoskys/
```

---

## 🧪 Testing

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **System Tests**: Full system verification
- **Security Tests**: Security posture validation

### Running Specific Tests
```bash
# Unit tests only
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# Security tests
python -m pytest tests/security/ -v
```

---

## 📈 Continuous Integration

### GitHub Actions
The repository includes automated CI/CD with:
- Multi-version Python testing (3.11, 3.12, 3.13)
- Security scanning
- Code quality checks
- Dependency vulnerability detection

### Local CI Simulation
```bash
# Run the same checks as CI
make ci-local
```

---

## 🎓 Learning Resources

### Understanding AMOSKYS
1. Read `docs/ARCHITECTURE.md` for system overview
2. Review `amoskys/core/` for core concepts
3. Explore `tests/` for usage examples

### Security Concepts
- mTLS authentication
- Certificate management
- Network security monitoring
- Threat detection algorithms

### Development Best Practices
- Follow PEP 8 style guidelines
- Write comprehensive tests
- Document new features
- Use type hints

---

## 🤝 Contributing

### Before You Start
1. Read `CONTRIBUTING.md`
2. Set up development environment
3. Run `make assess` to understand current state
4. Check open issues for contribution opportunities

### Contribution Workflow
1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Run `make pre-commit`
5. Submit pull request

---

## 📞 Support

### Getting Help
- Check documentation in `docs/`
- Review test examples in `tests/`
- Run `python assess_repository.py` for health status
- Create issues for bugs or feature requests

### Emergency Procedures
```bash
# Complete environment reset
make env-clean
python setup_environment_pro.py

# Full system verification
make health-check
make check
```

---

## 🧠 Welcome to AMOSKYS

You're now ready to develop on the AMOSKYS Neural Security Command Platform. The system is designed for security professionals, researchers, and developers who need robust, scalable cybersecurity solutions.

**Remember**: This is a neural command platform - every action contributes to the collective intelligence. Code responsibly, test thoroughly, and maintain the security posture that makes AMOSKYS a trusted platform.

*The neurons await your commands. The platform stands ready for your innovations.*
