"""
AMOSKYS Admin Panel Blueprint
User management and system administration
"""

from flask import Blueprint, render_template, jsonify, request, g
from ..middleware.auth import require_login, require_role
from amoskys.db.web_db import get_web_session_context
from amoskys.auth.models import User, UserRole, Session, AuthAuditLog, AuditEventType
from sqlalchemy import select, func, desc
from datetime import datetime, timedelta
import json

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# =============================================================================
# Admin Dashboard Views
# =============================================================================


@admin_bp.route("/")
@require_login
@require_role("admin")
def admin_dashboard():
    """Main admin dashboard"""
    return render_template("admin/dashboard.html")


@admin_bp.route("/users")
@require_login
@require_role("admin")
def users_list():
    """User management page"""
    return render_template("admin/users.html")


@admin_bp.route("/audit")
@require_login
@require_role("admin")
def audit_log():
    """Security audit log page"""
    return render_template("admin/audit.html")


@admin_bp.route("/sessions")
@require_login
@require_role("admin")
def sessions_list():
    """Active sessions page"""
    return render_template("admin/sessions.html")


# =============================================================================
# Admin API Endpoints
# =============================================================================


@admin_bp.route("/api/users", methods=["GET"])
@require_login
@require_role("admin")
def api_get_users():
    """Get all users with pagination and filtering"""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        search = request.args.get("search", "").strip()
        role_filter = request.args.get("role", "").strip()
        status_filter = request.args.get("status", "").strip()

        with get_web_session_context() as db:
            query = select(User)

            # Apply filters
            if search:
                query = query.where(
                    User.email.ilike(f"%{search}%")
                    | User.full_name.ilike(f"%{search}%")
                )

            if role_filter and role_filter in ["user", "admin"]:
                query = query.where(User.role == UserRole(role_filter))

            if status_filter == "active":
                query = query.where(User.is_active.is_(True))
            elif status_filter == "inactive":
                query = query.where(User.is_active.is_(False))
            elif status_filter == "verified":
                query = query.where(User.is_verified.is_(True))
            elif status_filter == "unverified":
                query = query.where(User.is_verified.is_(False))

            # Get total count
            count_query = select(func.count()).select_from(query.subquery())
            total = db.execute(count_query).scalar()

            # Apply pagination
            query = query.order_by(desc(User.created_at))
            query = query.offset((page - 1) * per_page).limit(per_page)

            users = db.execute(query).scalars().all()

            return jsonify(
                {
                    "success": True,
                    "users": [
                        {
                            "id": u.id,
                            "email": u.email,
                            "full_name": u.full_name,
                            "role": u.role.value,
                            "is_active": u.is_active,
                            "is_verified": u.is_verified,
                            "mfa_enabled": u.mfa_enabled,
                            "last_login_at": (
                                u.last_login_at.isoformat() if u.last_login_at else None
                            ),
                            "created_at": (
                                u.created_at.isoformat() if u.created_at else None
                            ),
                        }
                        for u in users
                    ],
                    "pagination": {
                        "page": page,
                        "per_page": per_page,
                        "total": total,
                        "pages": (total + per_page - 1) // per_page,
                    },
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/api/users/<user_id>", methods=["GET"])
@require_login
@require_role("admin")
def api_get_user(user_id):
    """Get single user details"""
    try:
        with get_web_session_context() as db:
            user = db.execute(
                select(User).where(User.id == user_id)
            ).scalar_one_or_none()

            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

            # Get user's sessions
            sessions = (
                db.execute(select(Session).where(Session.user_id == user_id))
                .scalars()
                .all()
            )

            # Get recent audit logs
            audit_logs = (
                db.execute(
                    select(AuthAuditLog)
                    .where(AuthAuditLog.user_id == user_id)
                    .order_by(desc(AuthAuditLog.created_at))
                    .limit(20)
                )
                .scalars()
                .all()
            )

            return jsonify(
                {
                    "success": True,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "full_name": user.full_name,
                        "role": user.role.value,
                        "is_active": user.is_active,
                        "is_verified": user.is_verified,
                        "mfa_enabled": user.mfa_enabled,
                        "mfa_type": user.mfa_type.value if user.mfa_type else None,
                        "timezone": user.timezone,
                        "last_login_at": (
                            user.last_login_at.isoformat()
                            if user.last_login_at
                            else None
                        ),
                        "created_at": (
                            user.created_at.isoformat() if user.created_at else None
                        ),
                        "updated_at": (
                            user.updated_at.isoformat() if user.updated_at else None
                        ),
                    },
                    "sessions": [
                        {
                            "id": s.id,
                            "ip_address": s.ip_address,
                            "user_agent": s.user_agent,
                            "created_at": (
                                s.created_at.isoformat() if s.created_at else None
                            ),
                            "expires_at": (
                                s.expires_at.isoformat() if s.expires_at else None
                            ),
                            "is_active": (
                                s.expires_at > datetime.utcnow()
                                if s.expires_at
                                else False
                            ),
                        }
                        for s in sessions
                    ],
                    "audit_logs": [
                        {
                            "event_type": log.event_type.value,
                            "ip_address": log.ip_address,
                            "metadata": log.event_metadata,
                            "created_at": (
                                log.created_at.isoformat() if log.created_at else None
                            ),
                        }
                        for log in audit_logs
                    ],
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/api/users/<user_id>", methods=["PATCH"])
@require_login
@require_role("admin")
def api_update_user(user_id):
    """Update user properties"""
    try:
        data = request.get_json() or {}

        with get_web_session_context() as db:
            user = db.execute(
                select(User).where(User.id == user_id)
            ).scalar_one_or_none()

            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

            # Prevent self-demotion for admins
            current_user = g.current_user
            if (
                user.id == current_user.id
                and "role" in data
                and data["role"] != "admin"
            ):
                return (
                    jsonify(
                        {"success": False, "error": "Cannot demote yourself from admin"}
                    ),
                    400,
                )

            # Track if user is being suspended for audit logging
            was_suspended = False

            # Update allowed fields
            if "is_active" in data:
                new_is_active = bool(data["is_active"])
                # Log suspension (active -> inactive transition)
                if user.is_active and not new_is_active:
                    was_suspended = True
                user.is_active = new_is_active

            if "is_verified" in data:
                user.is_verified = bool(data["is_verified"])

            if "role" in data and data["role"] in ["user", "admin"]:
                user.role = UserRole(data["role"])

            if "full_name" in data:
                user.full_name = data["full_name"]

            # Create audit log for suspension
            if was_suspended:
                audit_log = AuthAuditLog(
                    user_id=user.id,
                    event_type=AuditEventType.ACCOUNT_SUSPENDED,
                    ip_address=request.headers.get(
                        "X-Forwarded-For", request.remote_addr
                    ),
                    user_agent=request.headers.get("User-Agent"),
                    event_metadata_json=json.dumps(
                        {
                            "suspended_user_email": user.email,
                            "suspended_by_admin": current_user.email,
                            "suspended_by_admin_id": current_user.id,
                        }
                    ),
                )
                db.add(audit_log)

            db.commit()

            return jsonify(
                {
                    "success": True,
                    "message": "User updated successfully",
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "role": user.role.value,
                        "is_active": user.is_active,
                        "is_verified": user.is_verified,
                    },
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/api/users/<user_id>/sessions", methods=["DELETE"])
@require_login
@require_role("admin")
def api_revoke_user_sessions(user_id):
    """Revoke all sessions for a user"""
    try:
        with get_web_session_context() as db:
            user = db.execute(
                select(User).where(User.id == user_id)
            ).scalar_one_or_none()

            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

            # Delete all sessions
            result = db.execute(
                Session.__table__.delete().where(Session.user_id == user_id)
            )
            db.commit()

            return jsonify(
                {
                    "success": True,
                    "message": f"Revoked {result.rowcount} sessions for {user.email}",
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/api/users/<user_id>", methods=["DELETE"])
@require_login
@require_role("admin")
def api_delete_user(user_id):
    """Delete a user permanently"""
    try:
        with get_web_session_context() as db:
            user = db.execute(
                select(User).where(User.id == user_id)
            ).scalar_one_or_none()

            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

            # Prevent self-deletion
            current_user = g.current_user
            if user.id == current_user.id:
                return (
                    jsonify(
                        {"success": False, "error": "Cannot delete your own account"}
                    ),
                    400,
                )

            email = user.email
            user_role = user.role.value

            # Create audit log before deletion
            audit_log = AuthAuditLog(
                user_id=None,  # User will be deleted, don't link to them
                event_type=AuditEventType.ACCOUNT_DELETED,
                ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
                user_agent=request.headers.get("User-Agent"),
                event_metadata_json=json.dumps(
                    {
                        "deleted_user_email": email,
                        "deleted_user_role": user_role,
                        "deleted_by_admin": current_user.email,
                        "deleted_by_admin_id": current_user.id,
                    }
                ),
            )
            db.add(audit_log)

            # Delete user (cascade will handle sessions and tokens)
            db.delete(user)
            db.commit()

            return jsonify(
                {
                    "success": True,
                    "message": f"User {email} has been permanently deleted",
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/api/stats", methods=["GET"])
@require_login
@require_role("admin")
def api_get_stats():
    """Get admin dashboard statistics"""
    try:
        with get_web_session_context() as db:
            # User counts
            total_users = db.execute(select(func.count(User.id))).scalar()
            active_users = db.execute(
                select(func.count(User.id)).where(User.is_active.is_(True))
            ).scalar()
            verified_users = db.execute(
                select(func.count(User.id)).where(User.is_verified.is_(True))
            ).scalar()
            admin_users = db.execute(
                select(func.count(User.id)).where(User.role == UserRole.ADMIN)
            ).scalar()

            # Session counts
            now = datetime.utcnow()
            active_sessions = db.execute(
                select(func.count(Session.id)).where(Session.expires_at > now)
            ).scalar()

            # Recent signups (last 7 days)
            week_ago = now - timedelta(days=7)
            recent_signups = db.execute(
                select(func.count(User.id)).where(User.created_at >= week_ago)
            ).scalar()

            # Recent logins (last 24 hours)
            day_ago = now - timedelta(days=1)
            recent_logins = db.execute(
                select(func.count(User.id)).where(User.last_login_at >= day_ago)
            ).scalar()

            return jsonify(
                {
                    "success": True,
                    "stats": {
                        "total_users": total_users,
                        "active_users": active_users,
                        "verified_users": verified_users,
                        "admin_users": admin_users,
                        "active_sessions": active_sessions,
                        "recent_signups": recent_signups,
                        "recent_logins": recent_logins,
                    },
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/api/audit", methods=["GET"])
@require_login
@require_role("admin")
def api_get_audit_logs():
    """Get audit logs with pagination"""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        event_type = request.args.get("event_type", "").strip()
        user_id = request.args.get("user_id", "").strip()

        with get_web_session_context() as db:
            query = select(AuthAuditLog).join(
                User, AuthAuditLog.user_id == User.id, isouter=True
            )

            if event_type:
                query = query.where(AuthAuditLog.event_type == event_type)

            if user_id:
                query = query.where(AuthAuditLog.user_id == user_id)

            # Get total
            count_query = select(func.count()).select_from(query.subquery())
            total = db.execute(count_query).scalar()

            # Apply pagination
            query = query.order_by(desc(AuthAuditLog.created_at))
            query = query.offset((page - 1) * per_page).limit(per_page)

            logs = db.execute(query).scalars().all()

            return jsonify(
                {
                    "success": True,
                    "logs": [
                        {
                            "id": log.id,
                            "event_type": log.event_type.value,
                            "user_id": log.user_id,
                            "ip_address": log.ip_address,
                            "user_agent": log.user_agent,
                            "metadata": log.event_metadata,
                            "created_at": (
                                log.created_at.isoformat() if log.created_at else None
                            ),
                        }
                        for log in logs
                    ],
                    "pagination": {
                        "page": page,
                        "per_page": per_page,
                        "total": total,
                        "pages": (total + per_page - 1) // per_page,
                    },
                }
            )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
