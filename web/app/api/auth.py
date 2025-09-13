"""
AMOSKYS API Authentication Module
JWT-based authentication with role-based access control
"""

from flask import Blueprint, request, jsonify, current_app, g
from functools import wraps
import jwt
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
import secrets
from typing import Optional, Dict, Any

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# In-memory token store (replace with Redis in production)
VALID_TOKENS = set()
AGENT_CREDENTIALS = {
    'flowagent-001': {
        'secret': 'amoskys-neural-flow-secure-key-2025',
        'role': 'agent',
        'permissions': ['event.submit', 'agent.ping', 'agent.status', 'agent.register', 'agent.list']
    },
    'admin': {
        'secret': 'amoskys-neural-admin-secure-key-2025',
        'role': 'admin',
        'permissions': ['*']
    }
}

def generate_jwt(agent_id: str, role: str, permissions: list) -> str:
    """Generate JWT token for authenticated agent"""
    payload = {
        'agent_id': agent_id,
        'role': role,
        'permissions': permissions,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }
    
    secret_key = current_app.config.get('SECRET_KEY', 'amoskys-neural-security-dev-key')
    return jwt.encode(payload, secret_key, algorithm='HS256')

def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode JWT token"""
    try:
        secret_key = current_app.config.get('SECRET_KEY', 'amoskys-neural-security-dev-key')
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(permissions=None):
    """Decorator for API authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            payload = verify_jwt(token)
            
            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Check permissions
            if permissions:
                user_permissions = payload.get('permissions', [])
                if '*' not in user_permissions:
                    for required_perm in permissions:
                        if required_perm not in user_permissions:
                            return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add user info to request context
            g.current_user = payload
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate agent and return JWT token"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON payload'}), 400
    
    agent_id = data.get('agent_id')
    secret = data.get('secret')
    
    if not agent_id or not secret:
        return jsonify({'error': 'Missing agent_id or secret'}), 400
    
    # Verify credentials
    agent_info = AGENT_CREDENTIALS.get(agent_id)
    if not agent_info or not hmac.compare_digest(agent_info['secret'], secret):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate JWT
    token = generate_jwt(agent_id, agent_info['role'], agent_info['permissions'])
    
    return jsonify({
        'status': 'success',
        'token': token,
        'agent_id': agent_id,
        'role': agent_info['role'],
        'expires_in': 86400  # 24 hours
    })

@auth_bp.route('/verify', methods=['POST'])
@require_auth()
def verify():
    """Verify current authentication status"""
    return jsonify({
        'status': 'authenticated',
        'agent_id': g.current_user['agent_id'],
        'role': g.current_user['role'],
        'permissions': g.current_user['permissions']
    })

@auth_bp.route('/refresh', methods=['POST'])
@require_auth()
def refresh():
    """Refresh JWT token"""
    user = g.current_user
    new_token = generate_jwt(user['agent_id'], user['role'], user['permissions'])
    
    return jsonify({
        'status': 'success',
        'token': new_token,
        'expires_in': 86400
    })
