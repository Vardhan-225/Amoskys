"""
AMOSKYS SNMP Agent - Module Entry Point

Run with: python -m amoskys.agents.snmp [options]

Note: This agent uses async collection and has its own CLI handling.
The standard CLI framework may be integrated in a future version.
"""

from .snmp_agent import main

if __name__ == "__main__":
    main()
