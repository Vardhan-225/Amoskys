"""
AMOSKYS Flow Agent - Module Entry Point

Run with: python -m amoskys.agents.flowagent [options]

Note: This agent uses custom WAL-based reliability and its own run loop.
The standard CLI framework may be integrated in a future version.
"""

from .main import main

if __name__ == "__main__":
    main()
