# AMOSKYS Proto Build System
#
# Generates Python protobuf + gRPC stubs from .proto files and patches
# the import paths for the amoskys.proto package namespace.
#
# Usage:
#   make -C proto generate    # regenerate all proto stubs
#   make -C proto clean        # remove generated files
#   make -C proto verify       # check stubs import correctly
#
# Why this exists:
#   grpc_tools.protoc generates bare imports (import messaging_schema_pb2)
#   but AMOSKYS uses package-qualified imports (from amoskys.proto import ...).
#   This Makefile runs protoc then patches the imports automatically.

PROTO_SRC := $(wildcard *.proto)
OUT_DIR := ../src/amoskys/proto
PYTHON := python3

.PHONY: generate clean verify

generate: $(PROTO_SRC)
	@echo "=== Generating protobuf stubs ==="
	$(PYTHON) -m grpc_tools.protoc \
		--proto_path=. \
		--python_out=$(OUT_DIR) \
		--grpc_python_out=$(OUT_DIR) \
		$(PROTO_SRC)
	@echo "=== Patching imports for amoskys.proto namespace ==="
	@$(PYTHON) patch_imports.py $(OUT_DIR)
	@echo "=== Done. Verify with: make -C proto verify ==="

clean:
	rm -f $(OUT_DIR)/*_pb2.py $(OUT_DIR)/*_pb2_grpc.py

verify:
	@$(PYTHON) -c "\
import sys; sys.path.insert(0, '../src'); \
from amoskys.proto import messaging_schema_pb2, universal_telemetry_pb2; \
from amoskys.proto import messaging_schema_pb2_grpc, universal_telemetry_pb2_grpc; \
print('OK: All proto imports verified')"
