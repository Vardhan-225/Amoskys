#!/usr/bin/env python3
"""
AMOSKYS Development Environment Setup
Ensures proper Python path configuration for all components
"""
import os
import sys
from pathlib import Path

def setup_python_path():
    """Setup Python path for AMOSKYS development"""
    # Calculate project root (go up 2 levels from scripts/automation/)
    project_root = Path(__file__).parent.parent.parent.absolute()
    src_path = project_root / "src"
    
    # Add src to Python path if not already present
    src_str = str(src_path)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)
    
    # Set PYTHONPATH environment variable
    current_pythonpath = os.environ.get('PYTHONPATH', '')
    if src_str not in current_pythonpath:
        if current_pythonpath:
            os.environ['PYTHONPATH'] = f"{src_str}:{current_pythonpath}"
        else:
            os.environ['PYTHONPATH'] = src_str
    
    print(f"✅ Python path configured: {src_str}")
    return src_path

def verify_imports():
    """Verify that AMOSKYS imports work correctly"""
    try:
        import amoskys.proto.messaging_schema_pb2 as pb
        import amoskys.proto.messaging_schema_pb2_grpc as pbrpc
        print("✅ Protobuf imports working correctly")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

if __name__ == "__main__":
    print("🧠⚡ AMOSKYS Development Environment Setup")
    setup_python_path()
    if verify_imports():
        print("🎯 Environment setup complete - ready for development!")
    else:
        print("⚠️  Import verification failed - check your environment")
        sys.exit(1)
