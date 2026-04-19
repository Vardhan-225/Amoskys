"""AMOSKYS Web — Authentication + customer-zero binding.

v1 is deliberately simple: a single admin account defined by two env
vars, server-side session, decorator for protected routes. This is
sufficient for the "we're our own first customer" phase. When the
second paying customer arrives, swap in a proper users table.

Env vars:
    AMOSKYS_WEB_ADMIN_EMAIL     Email the admin uses to sign in.
                                 Fallback: "ops@amoskys.com"
    AMOSKYS_WEB_ADMIN_PASSWORD  Password in cleartext (env, not DB).
                                 If unset, auth is disabled.
    AMOSKYS_WEB_CUSTOMER_SITE   Domain of the "customer zero" site.
                                 Fallback: "lab.amoskys.com"

Session keys:
    web_user_email              The signed-in user's email
    web_user_site               The domain they're bound to

Deployed to:
    /opt/amoskys-web/src/app/web_product/auth.py
"""

from __future__ import annotations

import hmac
import os
from functools import wraps
from typing import Optional

from flask import abort, redirect, request, session, url_for


def admin_email() -> str:
    return os.environ.get("AMOSKYS_WEB_ADMIN_EMAIL", "ops@amoskys.com").strip().lower()


def admin_password() -> str:
    return os.environ.get("AMOSKYS_WEB_ADMIN_PASSWORD", "").strip()


def customer_site() -> str:
    return os.environ.get("AMOSKYS_WEB_CUSTOMER_SITE", "lab.amoskys.com").strip().lower()


def is_auth_configured() -> bool:
    """True iff an admin password is set in env."""
    return bool(admin_password())


def check_credentials(email: str, password: str) -> bool:
    """Constant-time compare against env credentials."""
    if not is_auth_configured():
        return False
    email_ok = hmac.compare_digest(
        (email or "").strip().lower(), admin_email()
    )
    password_ok = hmac.compare_digest(
        (password or "").strip(), admin_password()
    )
    return email_ok and password_ok


def current_user_email() -> Optional[str]:
    return session.get("web_user_email")


def current_user_site() -> Optional[str]:
    return session.get("web_user_site")


def signed_in() -> bool:
    return bool(current_user_email())


def sign_in(email: str) -> None:
    session["web_user_email"] = email.strip().lower()
    session["web_user_site"] = customer_site()
    session.permanent = True


def sign_out() -> None:
    session.pop("web_user_email", None)
    session.pop("web_user_site", None)


def require_signed_in(fn):
    """Decorator: redirect to /web/signin if not authenticated."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not signed_in():
            return redirect(url_for("web.signin", next=request.path))
        return fn(*args, **kwargs)
    return wrapper
