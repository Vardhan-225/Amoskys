"""
AMOSKYS Web Routes Module

Contains view routes for serving HTML templates.
"""

from ..main_routes import main_bp
from .auth_views import auth_views_bp

__all__ = ["main_bp", "auth_views_bp"]
