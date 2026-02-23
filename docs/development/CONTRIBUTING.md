# Amoskys Contributing Guide

Thank you for your interest in contributing to Amoskys! This guide will help you get started.

## Development Setup

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/Amoskys.git
cd Amoskys
```

2. **Set up development environment**:
```bash
make setup-dev
source .venv/bin/activate
```

3. **Generate protocol buffers**:
```bash
make proto
```

4. **Run tests**:
```bash
make test
```

## Code Style

We use automated code formatting and linting:

- **Black** for code formatting
- **isort** for import sorting  
- **flake8** for linting
- **mypy** for type checking

Run formatting and linting:
```bash
make format
make lint
```

## Testing

### Test Categories
- **Unit tests** (`tests/unit/`): Test individual functions and classes
- **Component tests** (`tests/component/`): Test service interactions
- **Integration tests** (`tests/integration/`): End-to-end testing
- **Golden tests** (`tests/golden/`): Binary compatibility verification

### Running Tests
```bash
# All tests
make test

# Specific test category
pytest tests/unit/
pytest tests/component/

# With coverage
make test-coverage
```

## Architecture Guidelines

### Security First
- All network communication must use mTLS
- All messages must be signed with Ed25519
- Never log sensitive information
- Follow principle of least privilege

### Performance
- Target < 50ms latency for detection pipeline
- Design for horizontal scaling
- Use async/await for I/O operations
- Profile performance-critical code

### Reliability
- Use WAL for data persistence
- Implement graceful degradation
- Add comprehensive error handling
- Include health check endpoints

## Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Write tests** for new functionality
3. **Ensure all tests pass**: `make test`
4. **Run linting**: `make lint`
5. **Update documentation** if needed
6. **Submit pull request** with clear description

### PR Requirements
- [ ] All tests passing
- [ ] Code coverage maintained
- [ ] Documentation updated
- [ ] Security considerations addressed
- [ ] Performance impact assessed

## Release Process

### Semantic Versioning
We follow [semantic versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Steps
1. Update version in relevant files
2. Update CHANGELOG.md
3. Create and push git tag
4. GitHub Actions handles the rest

## Security

### Reporting Vulnerabilities
Please report security vulnerabilities privately to [security@infraspectre.dev](mailto:security@infraspectre.dev).

### Security Guidelines
- Use secure coding practices
- Validate all inputs
- Use constant-time comparisons for secrets
- Regular dependency security scans

## Community

### Communication
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Security Issues**: Private email to security team

### Code of Conduct
Be respectful, inclusive, and constructive. We're building something important together.

## Getting Help

- **Documentation**: Check `docs/` directory
- **Examples**: See `examples/` directory
- **Issues**: Search existing GitHub issues
- **Discussions**: Ask questions in GitHub Discussions

## Development Environment

### Required Tools
- Python 3.9+
- Make
- Protocol Buffers compiler
- Docker (for containerized testing)

### Recommended Tools
- VS Code with Python extension
- PyCharm (Professional or Community)
- Git with proper configuration

### Environment Variables
```bash
# Development
export PYTHONPATH=/path/to/Amoskys/src
export IS_CONFIG_PATH=/path/to/Amoskys/config/infraspectre.yaml

# Testing
export IS_TEST_MODE=true
export BUS_SERVER_PORT=50052  # Use different port for tests
```

## Documentation

### Documentation Standards
- Use Markdown for all documentation
- Include code examples
- Update docs with code changes
- Use clear, concise language

### Documentation Structure
```
docs/
├── ARCHITECTURE.md     # System design
├── COMPONENTS.md       # Component details
├── ENVIRONMENT.md      # Setup guide
├── DOCKER_DEPLOY.md    # Deployment guide
└── runbooks/          # Operational procedures
```

## Performance Testing

### Benchmarking
```bash
# Run performance tests
make benchmark

# Load testing
cd tools && python loadgen.py --help
```

### Performance Targets
- **Detection Latency**: < 50ms p95
- **Throughput**: > 1M packets/second/core  
- **Memory Usage**: < 2GB per service
- **Startup Time**: < 5 seconds

## Debugging

### Logging
- Use structured logging (JSON format)
- Include correlation IDs
- Log at appropriate levels
- Never log sensitive data

### Observability
- Use Prometheus metrics
- Include health check endpoints
- Implement distributed tracing
- Monitor error rates and latency

Thank you for contributing to Amoskys! 🛡️
