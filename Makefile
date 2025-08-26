# Makefile — InfraSpectre dev DX

PYTHON := $(PWD)/InfraSpectre/.venv/bin/python
export PATH := $(dir $(PYTHON)):$(PATH)

PY?=python3
PIP?=pip
PROTO_DIR=proto
STUBS_DIR=InfraSpectre/proto_stubs
BUS_DIR=InfraSpectre/common/eventbus
AGENT_DIR=InfraSpectre/agents/flowagent
PYTHON = $(shell which python)

.PHONY: setup proto clean run-bus run-agent run-all test fmt lint certs ed25519 check-grpcio-tools run-flowagent curl-health curl-metrics curl-ready tail-metrics loadgen chaos fitness check lint-make

setup:
	$(PIP) install -r InfraSpectre/requirements.txt
	@echo "✅ Python deps installed"

check-grpcio-tools:
	@$(PYTHON) -c "import grpc_tools; print('grpc_tools found')" 2>/dev/null || \
		(echo 'ERROR: grpcio-tools not installed in this Python environment.' && echo 'Run: pip install grpcio-tools' && exit 1)

proto:
	mkdir -p InfraSpectre/proto_stubs
	touch InfraSpectre/proto_stubs/__init__.py
	$(PYTHON) -m grpc_tools.protoc \
		-I proto \
		--python_out=InfraSpectre/proto_stubs \
		--grpc_python_out=InfraSpectre/proto_stubs \
		--pyi_out=InfraSpectre/proto_stubs \
		proto/messaging_schema.proto
	@sed -i '' -E 's/^import ([A-Za-z0-9_]+_pb2) /from . import \1 /' InfraSpectre/proto_stubs/*_pb2_grpc.py || true

clean:
	rm -rf $(STUBS_DIR)/*
	touch $(STUBS_DIR)/__init__.py
	@echo "🧹 Cleaned"

run-bus:
	$(PY) $(BUS_DIR)/server.py

run-agent:
	$(PY) $(AGENT_DIR)/main.py

run-flowagent:
	$(PYTHON) -m InfraSpectre.agents.flowagent.main

curl-health:
	curl -sS -i http://127.0.0.1:8081/healthz

curl-ready:
	@curl -sS -i http://127.0.0.1:8081/ready

curl-metrics:
	curl -s http://127.0.0.1:9101/metrics | head -n 25

tail-metrics:
	@curl -s http://127.0.0.1:9101/metrics | \
	grep -E '^(# HELP agent_ready_state|# TYPE agent_ready_state|agent_ready_state )' || true

run-all:
	docker compose -f deploy/docker-compose.dev.yml up -d prometheus grafana eventbus agent
	$(PYTHON) -m InfraSpectre.agents.flowagent.main &
	sleep 2
	curl -sS -i http://127.0.0.1:8081/healthz
	curl -sS -i http://127.0.0.1:8081/ready
	curl -s http://127.0.0.1:9101/metrics | grep agent_ready_state || true
	@echo "✅ All services up and agent health/ready/metrics checked"

fmt:
	black InfraSpectre

lint:
	ruff InfraSpectre && mypy InfraSpectre || true

lint-make:
	@awk 'BEGIN{ bad=0 } /^[^\t#][^:]*:/ { in=1; next } in && NF==0 { next } in && $$0 ~ /^ / { print "Non-TAB indent in recipe at:", NR; bad=1 } /^[^\t#][^:]*:/ { in=1; next } /^[^ \t]/ { in=0 } END{ exit(bad) }' Makefile

test:
	$(PYTHON) -m pytest -q

check:
	docker compose -f deploy/docker-compose.dev.yml up -d prometheus grafana
	@i=0; until curl -sf http://localhost:9090/-/ready >/dev/null; do \
		i=$$((i+1)); [ $$i -ge 60 ] && echo 'Prometheus not ready' && exit 1; sleep 1; \
	done
	$(PYTHON) -m pytest -q
	curl -sf http://localhost:8081/healthz >/dev/null || true
	@echo "✅ tests & health OK"

certs:
	bash scripts/gen_certs.sh

ed25519:
	bash scripts/gen_ed25519.sh

loadgen:
	python tools/loadgen.py --rate 300 --secs 60

chaos:
	tools/chaos.sh 8

fitness:
	$(PYTHON) -m pytest -q tests/component/test_fitness.py
