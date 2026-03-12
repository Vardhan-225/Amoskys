#!/usr/bin/env python3
"""Patch protoc-generated imports for the amoskys.proto package namespace.

grpc_tools.protoc generates bare imports like:
    import messaging_schema_pb2 as messaging__schema__pb2

AMOSKYS needs package-qualified imports:
    from amoskys.proto import messaging_schema_pb2 as messaging__schema__pb2

This script is called by `make -C proto generate` after protoc runs.
"""

import re
import sys
from pathlib import Path

# Proto modules that need namespace qualification
PROTO_MODULES = [
    "messaging_schema_pb2",
    "messaging_schema_pb2_grpc",
    "universal_telemetry_pb2",
    "universal_telemetry_pb2_grpc",
]


def patch_file(filepath: Path) -> int:
    """Patch bare proto imports in a single file. Returns count of patches."""
    text = filepath.read_text()
    original = text
    patches = 0

    for module in PROTO_MODULES:
        # Pattern: "import <module> as <alias>" → "from amoskys.proto import <module> as <alias>"
        pattern = rf"^import ({re.escape(module)}) as (.+)$"
        replacement = r"from amoskys.proto import \1 as \2"
        text, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
        patches += count

        # Pattern: "import <module>\n" → "from amoskys.proto import <module>\n"
        pattern = rf"^import ({re.escape(module)})$"
        replacement = r"from amoskys.proto import \1"
        text, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
        patches += count

    if text != original:
        filepath.write_text(text)
        print(f"  Patched {filepath.name}: {patches} import(s) fixed")

    return patches


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_dir>")
        sys.exit(1)

    out_dir = Path(sys.argv[1])
    total = 0

    for pb_file in sorted(out_dir.glob("*_pb2*.py")):
        total += patch_file(pb_file)

    print(f"  Total: {total} import(s) patched across all files")


if __name__ == "__main__":
    main()
