"""Allow running Argos via ``python -m amoskys.agents.Web.argos``."""

from amoskys.agents.Web.argos.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
