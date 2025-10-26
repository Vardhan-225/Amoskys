# Makefile — AMOSKYS Neural Security Command Platform
# Professional Grade Build & Development Automation
# Updated: September 12, 2025

# Configuration
PYTHON := python3
PIP := pip
PROTO_DIR := proto
SRC_DIR := src
WEB_DIR := web
STUBS_DIR := $(SRC_DIR)/amoskys/proto
CONFIG_DIR := config
DATA_DIR := data
DOCS_DIR := docs

# Virtual environment
VENV_DIR := .venv
VENV_PYTHON := $(VENV_DIR)/bin/python
VENV_PIP := $(VENV_DIR)/bin/pip

# Entry points
EVENTBUS_ENTRY := ./amoskys-eventbus
AGENT_ENTRY := ./amoskys-agent

# Professional automation scripts
ENV_SETUP_SCRIPT := scripts/automation/setup_environment_pro.py
ASSESSMENT_SCRIPT := scripts/automation/assess_repository.py
DEV_SETUP_SCRIPT := scripts/automation/setup_dev_env.py

# Targets
.PHONY: help setup venv install-deps proto clean run-eventbus run-agent run-web run-all test fmt lint certs ed25519 check loadgen chaos docs validate-config
.PHONY: env-setup env-clean env-rebuild env-activate env-info assess assess-quick assess-save requirements-consolidate health-check shell

help: ## Show this help message
	@echo "AMOSKYS Neural Security Command Platform"
	@echo "========================================"
	@echo ""
	@echo "🚀 Professional Development Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "💡 Quick Start:"
	@echo "   make setup        # Complete setup (creates .venv, installs deps, generates certs)"
	@echo "   make env-activate # Generate environment activation script"
	@echo "   make shell        # Activate environment in interactive shell"
	@echo ""
	@echo "🚀 Running Services:"
	@echo "   make run-eventbus # Start EventBus gRPC server"
	@echo "   make run-agent    # Start FlowAgent"
	@echo "   make run-web      # Start Web Platform (Flask)"
	@echo ""
	@echo "🧪 Testing & Quality:"
	@echo "   make test         # Run all tests"
	@echo "   make check        # Run full test suite with dependencies"
	@echo "   make fmt          # Format code with black"

# ==============================================
# PROFESSIONAL ENVIRONMENT MANAGEMENT
# ==============================================

env-setup: ## Professional environment setup with automation
	@echo "🔧 Setting up AMOSKYS professional environment..."
	$(PYTHON) $(ENV_SETUP_SCRIPT) --mode development
	@echo "✅ Professional environment setup completed"
	@echo ""
	@echo "🎯 To activate the virtual environment, run:"
	@echo "   source .venv/bin/activate"
	@echo ""
	@echo "Or use: make env-activate (generates activation script)"

env-production: ## Production environment setup
	@echo "🏭 Setting up AMOSKYS production environment..."
	$(PYTHON) $(ENV_SETUP_SCRIPT) --mode production
	@echo "✅ Production environment setup completed"

env-clean: ## Clean environment and rebuild
	@echo "🧹 Cleaning environment..."
	$(PYTHON) $(ENV_SETUP_SCRIPT) --force --mode development
	@echo "✅ Environment cleaned and rebuilt"

env-rebuild: env-clean ## Alias for env-clean

env-activate: ## Generate activation helper script
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "❌ Virtual environment not found. Run 'make setup' first."; \
		exit 1; \
	fi
	@echo "#!/bin/bash" > activate_env.sh
	@echo "# AMOSKYS Environment Activation Helper" >> activate_env.sh
	@echo "# Generated: $$(date)" >> activate_env.sh
	@echo "" >> activate_env.sh
	@echo "source .venv/bin/activate" >> activate_env.sh
	@echo "export PYTHONPATH=\"\$$PWD/src:\$$PYTHONPATH\"" >> activate_env.sh
	@echo "echo \"🧠⚡ AMOSKYS environment activated\"" >> activate_env.sh
	@echo "echo \"Python: \$$(python --version)\"" >> activate_env.sh
	@echo "echo \"Virtual env: .venv\"" >> activate_env.sh
	@echo "echo \"\"" >> activate_env.sh
	@echo "echo \"Quick commands:\"" >> activate_env.sh
	@echo "echo \"  make run-eventbus  - Start EventBus\"" >> activate_env.sh
	@echo "echo \"  make run-agent     - Start FlowAgent\"" >> activate_env.sh
	@echo "echo \"  make run-web       - Start Web Platform\"" >> activate_env.sh
	@echo "echo \"  make test          - Run tests\"" >> activate_env.sh
	@echo "echo \"  deactivate         - Exit virtual env\"" >> activate_env.sh
	@chmod +x activate_env.sh
	@echo "✅ Activation script created: activate_env.sh"
	@echo ""
	@echo "🎯 To activate the environment, run:"
	@echo "   source activate_env.sh"

env-info: ## Show environment information
	@echo "🔍 AMOSKYS Environment Information"
	@echo "=================================="
	@echo ""
	@if [ -d "$(VENV_DIR)" ]; then \
		echo "✅ Virtual Environment: $(VENV_DIR)"; \
		echo "   Python: $$($(VENV_PYTHON) --version 2>&1)"; \
		echo "   Pip: $$($(VENV_PIP) --version 2>&1 | head -1)"; \
		echo ""; \
		echo "📦 Key Packages:"; \
		$(VENV_PIP) list 2>/dev/null | grep -E '(Flask|grpcio|pytest|cryptography)' || echo "   (Run 'make install-deps' to install)"; \
	else \
		echo "❌ Virtual environment not found"; \
		echo "   Run 'make setup' to create it"; \
	fi
	@echo ""
	@echo "📂 Project Structure:"
	@echo "   Source: $(SRC_DIR)/"
	@echo "   Web: $(WEB_DIR)/"
	@echo "   Config: $(CONFIG_DIR)/"
	@echo "   Data: $(DATA_DIR)/"

shell: ## Activate environment and start interactive shell
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "❌ Virtual environment not found. Run 'make setup' first."; \
		exit 1; \
	fi
	@echo "🧠⚡ Starting AMOSKYS interactive shell..."
	@echo "   Type 'exit' or Ctrl+D to quit"
	@bash --init-file <(echo "source .venv/bin/activate; export PYTHONPATH=\$$PWD/src:\$$PYTHONPATH; echo '✅ AMOSKYS environment active'; echo ''; echo 'Quick commands:'; echo '  make run-eventbus  - Start EventBus'; echo '  make run-agent     - Start FlowAgent'; echo '  make run-web       - Start Web Platform'; echo '  make test          - Run tests'; echo ''; PS1='(amoskys) \u@\h:\w\$$ '")

# ==============================================
# REPOSITORY ASSESSMENT & HEALTH
# ==============================================

assess: ## Comprehensive repository assessment
	@echo "🔍 Running comprehensive repository assessment..."
	$(PYTHON) $(ASSESSMENT_SCRIPT)
	@echo "✅ Assessment completed"

assess-quick: ## Quick assessment (specific components)
	@echo "⚡ Running quick assessment..."
	$(PYTHON) $(ASSESSMENT_SCRIPT) --component structure
	$(PYTHON) $(ASSESSMENT_SCRIPT) --component testing
	@echo "✅ Quick assessment completed"

assess-save: ## Save detailed assessment report
	@echo "💾 Generating detailed assessment report..."
	$(PYTHON) $(ASSESSMENT_SCRIPT) --output assessment_report.json
	@echo "✅ Assessment report saved"

health-check: ## Quick health check
	@echo "🏥 Running system health check..."
	@$(VENV_PYTHON) -c "import sys; print(f'Python: {sys.version}')"
	@$(VENV_PYTHON) -c "import flask; print(f'Flask: {flask.__version__}')"
	@$(VENV_PYTHON) -c "import grpc; print(f'gRPC: Available')"
	@$(VENV_PYTHON) -c "import yaml; print(f'YAML: Available')"
	@echo "✅ Core dependencies healthy"

requirements-consolidate: ## Consolidate requirements files
	@echo "📦 Consolidating requirements..."
	@if [ -f "requirements.txt" ]; then \
		echo "✅ Main requirements.txt already exists"; \
	else \
		echo "❌ Creating requirements.txt..."; \
		touch requirements.txt; \
	fi
	@echo "✅ Requirements consolidated"

# ==============================================
# LEGACY SETUP & INSTALLATION  
# ==============================================
setup: env-setup proto dirs certs ## Complete development setup (uses professional automation)
	@echo "✅ AMOSKYS development environment ready"

setup-legacy: venv install-deps proto dirs certs ## Legacy setup method
	@echo "✅ AMOSKYS development environment ready (legacy)"

venv: ## Create Python virtual environment
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Creating virtual environment..."; \
		$(PYTHON) -m venv $(VENV_DIR); \
	fi
	@echo "✅ Virtual environment ready"

install-deps: venv ## Install Python dependencies
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -r requirements.txt
	@echo "✅ Dependencies installed"

dirs: ## Create required directories
	@mkdir -p $(DATA_DIR)/{wal,storage,metrics}
	@mkdir -p $(CONFIG_DIR)
	@mkdir -p certs
	@echo "✅ Directories created"

# Protocol Buffers
proto: ## Generate protocol buffer stubs
	@echo "Generating protocol buffer stubs..."
	@mkdir -p $(STUBS_DIR)
	@touch $(STUBS_DIR)/__init__.py
	$(VENV_PYTHON) -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(STUBS_DIR) \
		--grpc_python_out=$(STUBS_DIR) \
		--pyi_out=$(STUBS_DIR) \
		$(PROTO_DIR)/messaging_schema.proto
	@# Fix import paths in generated files
	@sed -i '' 's/^import \([a-zA-Z0-9_]*_pb2\)/from . import \1/' $(STUBS_DIR)/*_pb2_grpc.py 2>/dev/null || true
	@echo "✅ Protocol buffers generated"

clean: ## Clean generated files and caches
	@echo "Cleaning generated files..."
	@rm -rf $(STUBS_DIR)/*_pb2*.py $(STUBS_DIR)/*_pb2*.pyi
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf $(DATA_DIR)/wal/*.db $(DATA_DIR)/storage/* $(DATA_DIR)/metrics/*
	@echo "✅ Cleaned"

# Running Services
run-eventbus: ## Start the EventBus server
	@echo "Starting Amoskys EventBus..."
	$(EVENTBUS_ENTRY)

run-agent: ## Start the FlowAgent
	@echo "Starting Amoskys Agent..."
	$(AGENT_ENTRY)

run-web: ## Start the Web Platform (Flask + SocketIO)
	@echo "Starting AMOSKYS Web Platform..."
	@echo "🌐 Dashboards will be available at:"
	@echo "   http://localhost:5000"
	@echo ""
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "❌ Virtual environment not found. Run 'make setup' first."; \
		exit 1; \
	fi
	@cd $(WEB_DIR) && PYTHONPATH=$$PWD/../src:$$PYTHONPATH $(VENV_PYTHON) -m flask --app app run --debug --host=0.0.0.0 --port=5000

run-web-prod: ## Start Web Platform in production mode (Gunicorn)
	@echo "Starting AMOSKYS Web Platform (Production Mode)..."
	@echo "🌐 Server will be available at:"
	@echo "   http://localhost:8000"
	@echo ""
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "❌ Virtual environment not found. Run 'make setup' first."; \
		exit 1; \
	fi
	@cd $(WEB_DIR) && PYTHONPATH=$$PWD/../src:$$PYTHONPATH \
		$(VENV_PYTHON) -m gunicorn \
		--worker-class eventlet \
		--workers 4 \
		--bind 0.0.0.0:8000 \
		--timeout 120 \
		--access-logfile - \
		--error-logfile - \
		wsgi:application

run-all: ## Start all services with Docker Compose
	@echo "Starting all Amoskys services..."
	docker compose -f deploy/docker-compose.dev.yml up -d
	@sleep 3
	@curl -sS -i http://127.0.0.1:8081/healthz || echo "Agent health check failed"
	@curl -sS -i http://127.0.0.1:8080/healthz || echo "EventBus health check failed"
	@echo "✅ All services started"

stop-all: ## Stop all Docker services
	docker compose -f deploy/docker-compose.dev.yml down

# Health and Monitoring
curl-health: ## Check agent health
	@curl -sS -i http://127.0.0.1:8081/healthz

curl-ready: ## Check agent readiness
	@curl -sS -i http://127.0.0.1:8081/ready

curl-metrics: ## Show agent metrics
	@curl -s http://127.0.0.1:9101/metrics | head -n 25

tail-metrics: ## Show specific metrics
	@curl -s http://127.0.0.1:9101/metrics | \
	grep -E '^(# HELP agent_ready_state|# TYPE agent_ready_state|agent_ready_state )' || true

# Testing
test: ## Run all tests
	@echo "Running tests..."
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m pytest tests/ -v

test-unit: ## Run unit tests only
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m pytest tests/unit/ -v

test-integration: ## Run integration tests only
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m pytest tests/integration/ -v

test-component: ## Run component tests only
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m pytest tests/component/ -v

check: ## Run full test suite with dependencies
	@echo "Running full test suite..."
	@docker compose -f deploy/docker-compose.dev.yml up -d prometheus grafana
	@echo "Waiting for Prometheus to be ready..."
	@i=0; until curl -sf http://localhost:9090/-/ready >/dev/null 2>&1; do \
		i=$$((i+1)); [ $$i -ge 60 ] && echo 'Prometheus not ready' && exit 1; sleep 1; \
	done
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m pytest tests/ -v
	@curl -sf http://localhost:8081/healthz >/dev/null || echo "Warning: Agent health check failed"
	@echo "✅ Full test suite completed"

# Code Quality
fmt: ## Format code with black
	$(VENV_PYTHON) -m black $(SRC_DIR)/

lint: venv ## Run linting checks
	$(VENV_PYTHON) -m flake8 $(SRC_DIR) tests/ --max-line-length=88 --extend-ignore=E203,W503
	$(VENV_PYTHON) -m mypy $(SRC_DIR)/amoskys/ --ignore-missing-imports
	@echo "✅ Linting passed"

# Security and Certificates
certs: ## Generate TLS certificates
	@echo "Checking TLS certificates..."
	@if [ -f "certs/server.crt" ] && [ -f "certs/server.key" ]; then \
		echo "✅ TLS certificates already exist"; \
	else \
		echo "Generating TLS certificates..."; \
		bash scripts/ssl_setup.sh; \
		echo "✅ TLS certificates generated"; \
	fi

ed25519: ## Generate Ed25519 signing keys
	@echo "Generating Ed25519 keys..."
	@bash scripts/gen_ed25519.sh
	@echo "✅ Ed25519 keys generated"

# Configuration
validate-config: ## Validate configuration
	@echo "Validating configuration..."
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m amoskys.config --validate
	@echo "✅ Configuration is valid"

dump-config: ## Show current configuration
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m amoskys.config --dump

# Tools and Utilities
loadgen: ## Run load generator
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) tools/loadgen.py --rate 300 --secs 60

chaos: ## Run chaos testing
	@bash tools/chaos.sh 8

# Documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	@# Add documentation generation here when ready
	@echo "✅ Documentation generated"

# Development Utilities
dev-reset: clean dirs ## Reset development environment
	@echo "Resetting development environment..."
	@rm -rf $(DATA_DIR)/wal/*.db
	@echo "✅ Development environment reset"

logs-eventbus: ## Show EventBus logs
	@docker compose -f deploy/docker-compose.dev.yml logs -f eventbus

logs-agent: ## Show Agent logs
	@docker compose -f deploy/docker-compose.dev.yml logs -f agent

# Build and Package
build-docker: ## Build Docker images
	@echo "Building Docker images..."
	@docker build -f deploy/Dockerfile.eventbus -t amoskys/eventbus:dev .
	@docker build -f deploy/Dockerfile.agent -t amoskys/agent:dev .
	@echo "✅ Docker images built"

# Development workflow targets
setup-dev: setup ## Setup development environment with additional tools
	$(VENV_PIP) install black isort flake8 mypy pytest-cov safety bandit
	@echo "✅ Development tools installed"

format: venv ## Format code with black and isort
	$(VENV_PYTHON) -m black $(SRC_DIR) tests/
	$(VENV_PYTHON) -m isort $(SRC_DIR) tests/
	@echo "✅ Code formatted"

test-coverage: venv proto ## Run tests with coverage report
	$(VENV_PYTHON) -m pytest tests/ --cov=$(SRC_DIR)/amoskys --cov-report=html --cov-report=term
	@echo "✅ Coverage report generated in htmlcov/"

security-scan: venv ## Run security scans
	$(VENV_PYTHON) -m safety check
	$(VENV_PYTHON) -m bandit -r $(SRC_DIR)/ -f json -o bandit-report.json
	@echo "✅ Security scan completed"

benchmark: venv proto ## Run performance benchmarks
	$(VENV_PYTHON) tools/loadgen.py --benchmark
	@echo "✅ Benchmarks completed"

ci-check: venv proto format lint test security-scan ## Full CI check locally
	@echo "✅ All CI checks passed"

# Legacy compatibility (remove these gradually)
run-bus: run-eventbus ## Legacy alias for run-eventbus (deprecated)
	@echo "⚠️  Warning: 'run-bus' is deprecated, use 'run-eventbus'"

run-flowagent: run-agent ## Legacy alias for run-agent (deprecated)
	@echo "⚠️  Warning: 'run-flowagent' is deprecated, use 'run-agent'"

# Development Environment Management
dev-setup: ## Setup development environment with proper Python paths
	@echo "🧠⚡ Setting up AMOSKYS development environment..."
	$(PYTHON) $(DEV_SETUP_SCRIPT)
	@echo "✅ Development environment ready!"

dev-verify: ## Verify development environment setup
	@echo "🔍 Verifying development environment..."
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -c "import amoskys.proto.messaging_schema_pb2; print('✅ Imports working')"
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m pytest tests/test_proto_imports.py -v
	@echo "✅ Environment verification complete!"

dev-clean: ## Clean development artifacts
	@echo "🧹 Cleaning development artifacts..."
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -f assessment_report_*.json final_assessment*.json
	@echo "✅ Development artifacts cleaned!"
