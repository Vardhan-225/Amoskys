"""
AMOSKYS Cortex Dashboard Module
Phase 2.4 - Neural Security Visualization Interface

This module implements the AMOSKYS Cortex Dashboard, providing real-time
visualization of security events, agent status, and system metrics through
an intelligent neural interface.

Route modules are imported below to register their @dashboard_bp.route()
decorators on the shared Blueprint instance.
"""

import logging

from flask import Blueprint

logger = logging.getLogger("web.app.dashboard")

# Constants (used by route modules via `from . import _MSG_DB_UNAVAILABLE`)
UTC_TIMEZONE_SUFFIX = "+00:00"
_MSG_DB_UNAVAILABLE = "Database unavailable"
_MSG_FUSION_UNAVAILABLE = "Fusion engine not available"

# Dashboard Blueprint — shared by all route modules
dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

# Import route modules AFTER blueprint is defined.
# Each module does `from . import dashboard_bp` and registers routes on it.
from . import routes_agents  # noqa: E402, F401
from . import routes_deploy  # noqa: E402, F401
from . import routes_health  # noqa: E402, F401
from . import routes_igris  # noqa: E402, F401
from . import routes_live  # noqa: E402, F401
from . import routes_observatory  # noqa: E402, F401
from . import routes_pages  # noqa: E402, F401
from . import routes_soma  # noqa: E402, F401
from . import routes_threats  # noqa: E402, F401
