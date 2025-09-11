# InfraSpectre Migration Plan - Phase 1 Foundation Cleanup

## Current Status
✅ New directory structure created
🔄 Legacy code needs migration
❌ Old structure needs cleanup

## Migration Mapping

### Source Files (InfraSpectre/) → Target (src/infraspectre/)
```
./InfraSpectre/agents/flowagent/main.py → src/infraspectre/agents/flowagent/main.py
./InfraSpectre/agents/flowagent/wal_sqlite.py → src/infraspectre/agents/flowagent/wal_sqlite.py
./InfraSpectre/common/crypto/signing.py → src/infraspectre/common/crypto/signing.py
./InfraSpectre/common/crypto/canonical.py → src/infraspectre/common/crypto/canonical.py
./InfraSpectre/common/eventbus/server.py → src/infraspectre/eventbus/server.py
./InfraSpectre/proto_stubs/* → src/infraspectre/proto/*
./InfraSpectre/common/eventbus/trust_map.yaml → config/trust_map.yaml
```

### Files to Remove (duplicates)
```
./InfraSpectre/agents/flowagent/wal.py (duplicate of wal_sqlite.py)
./common/eventbus/server.py (old duplicate)
./agents/flowagent/main.py (old duplicate)
```

### Import Path Updates Required
```
Old: from InfraSpectre.proto_stubs import messaging_schema_pb2 as pb
New: from src.infraspectre.proto import messaging_schema_pb2 as pb

Old: from InfraSpectre.common.crypto.canonical import canonical_bytes
New: from src.infraspectre.common.crypto.canonical import canonical_bytes
```

## Steps
1. ✅ Create new directory structure
2. 🔄 Migrate core source files
3. ⏳ Update import paths
4. ⏳ Update configuration files
5. ⏳ Update tests
6. ⏳ Update Makefile and Docker files
7. ⏳ Remove legacy directories
8. ⏳ Update documentation
