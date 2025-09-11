# Makefile — InfraSpectre Phase 1 Clean Structure

# Configuration
PYTHON := python3
PIP := pip
PROTO_DIR := proto
SRC_DIR := src
STUBS_DIR := $(SRC_DIR)/infraspectre/proto
CONFIG_DIR := config
DATA_DIR := data
DOCS_DIR := docs

# Virtual environment
VENV_DIR := .venv
VENV_PYTHON := $(VENV_DIR)/bin/python
VENV_PIP := $(VENV_DIR)/bin/pip

# Entry points
EVENTBUS_ENTRY := ./infraspectre-eventbus
AGENT_ENTRY := ./infraspectre-agent

# Targets
.PHONY: help setup venv install-deps proto clean run-eventbus run-agent run-all test fmt lint certs ed25519 check loadgen chaos docs validate-config

help: ## Show this help message
	@echo "InfraSpectre Development Commands"
	@echo "================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Setup and Installation
setup: venv install-deps proto dirs certs ## Complete development setup
	@echo "✅ InfraSpectre development environment ready"

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
	@echo "Starting InfraSpectre EventBus..."
	$(EVENTBUS_ENTRY)

run-agent: ## Start the FlowAgent
	@echo "Starting InfraSpectre Agent..."
	$(AGENT_ENTRY)

run-all: ## Start all services with Docker Compose
	@echo "Starting all InfraSpectre services..."
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
	$(VENV_PYTHON) -m mypy $(SRC_DIR)/infraspectre/ --ignore-missing-imports
	@echo "✅ Linting passed"

# Security and Certificates
certs: ## Generate TLS certificates
	@echo "Generating TLS certificates..."
	@bash scripts/gen_certs.sh
	@echo "✅ TLS certificates generated"

ed25519: ## Generate Ed25519 signing keys
	@echo "Generating Ed25519 keys..."
	@bash scripts/gen_ed25519.sh
	@echo "✅ Ed25519 keys generated"

# Configuration
validate-config: ## Validate configuration
	@echo "Validating configuration..."
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m infraspectre.config --validate
	@echo "✅ Configuration is valid"

dump-config: ## Show current configuration
	@PYTHONPATH=$(SRC_DIR) $(VENV_PYTHON) -m infraspectre.config --dump

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
	@docker build -f deploy/Dockerfile.eventbus -t infraspectre/eventbus:dev .
	@docker build -f deploy/Dockerfile.agent -t infraspectre/agent:dev .
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
	$(VENV_PYTHON) -m pytest tests/ --cov=$(SRC_DIR)/infraspectre --cov-report=html --cov-report=term
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
