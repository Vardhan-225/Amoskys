# Amoskys Migration Plan - Phase 1 Foundation Cleanup

## Current Status
✅ New directory structure created
🔄 Legacy code needs migration
❌ Old structure needs cleanup

## Migration Mapping

### Source Files (Amoskys/) → Target (src/amoskys/)
```
./Amoskys/agents/flowagent/main.py → src/amoskys/agents/flowagent/main.py
./Amoskys/agents/flowagent/wal_sqlite.py → src/amoskys/agents/flowagent/wal_sqlite.py
./Amoskys/common/crypto/signing.py → src/amoskys/common/crypto/signing.py
./Amoskys/common/crypto/canonical.py → src/amoskys/common/crypto/canonical.py
./Amoskys/common/eventbus/server.py → src/amoskys/eventbus/server.py
./Amoskys/proto_stubs/* → src/amoskys/proto/*
./Amoskys/common/eventbus/trust_map.yaml → config/trust_map.yaml
```

### Files to Remove (duplicates)
```
./Amoskys/agents/flowagent/wal.py (duplicate of wal_sqlite.py)
./common/eventbus/server.py (old duplicate)
./agents/flowagent/main.py (old duplicate)
```

### Import Path Updates Required
```
Old: from Amoskys.proto_stubs import messaging_schema_pb2 as pb
New: from src.infraspectre.proto import messaging_schema_pb2 as pb

Old: from Amoskys.common.crypto.canonical import canonical_bytes
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
