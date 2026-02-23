"""AMOSKYS File Integrity Agent - Module Entry Point (Legacy).

The v1 FIMAgent has been removed. Use amoskys.agents.fim (FIMAgentV2) instead.
"""

import sys


def main() -> None:
    """Entry point for file integrity agent module."""
    print(
        "ERROR: file_integrity agent (v1) has been removed. "
        "Use 'python -m amoskys.agents.fim' instead.",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
