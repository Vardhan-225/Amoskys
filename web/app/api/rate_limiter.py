"""
AMOSKYS Rate Limiter Module
Prevents API abuse and DoS attacks

Usage:
    from .rate_limiter import require_rate_limit
    
    @api_bp.route('/endpoint')
    @require_rate_limit
    def my_endpoint():
        return jsonify({'status': 'success'})
"""

from flask import request, jsonify
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Per-IP rate limiter with sliding window
    
    Args:
        max_requests: Maximum requests per window
        window_seconds: Time window in seconds
    """
    
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)  # IP -> [timestamps]
        self.blocked_ips = {}  # IP -> unblock_time
    
    def is_allowed(self, ip_address):
        """Check if IP is within rate limit"""
        if not ip_address:
            return True  # Allow if no IP (development)
        
        # Check if IP is temporarily blocked
        if ip_address in self.blocked_ips:
            unblock_time = self.blocked_ips[ip_address]
            if datetime.now() < unblock_time:
                logger.warning(f'Rate limited IP attempted access: {ip_address}')
                return False
            else:
                del self.blocked_ips[ip_address]
        
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        # Clean old requests (sliding window)
        self.requests[ip_address] = [
            ts for ts in self.requests[ip_address] 
            if ts > cutoff
        ]
        
        # Check if limit exceeded
        if len(self.requests[ip_address]) >= self.max_requests:
            # Block this IP for 1 minute
            self.blocked_ips[ip_address] = now + timedelta(minutes=1)
            logger.warning(f'Rate limit exceeded for IP: {ip_address}')
            return False
        
        # Record this request
        self.requests[ip_address].append(now)
        return True
    
    def get_requests_remaining(self, ip_address):
        """Get remaining requests for IP in current window"""
        if not ip_address:
            return self.max_requests
        
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)
        count = len([ts for ts in self.requests[ip_address] if ts > cutoff])
        return max(0, self.max_requests - count)
    
    def get_retry_after(self, ip_address):
        """Get seconds until IP is unblocked"""
        if ip_address not in self.blocked_ips:
            return 0
        
        unblock_time = self.blocked_ips[ip_address]
        retry_after = (unblock_time - datetime.now()).total_seconds()
        return max(0, int(retry_after))
    
    def clear(self):
        """Clear all rate limit data (for testing)"""
        self.requests.clear()
        self.blocked_ips.clear()


# Global rate limiter instance
_rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


def require_rate_limit(max_requests=100, window_seconds=60):
    """
    Decorator to enforce rate limiting on API endpoints
    
    Args:
        max_requests: Maximum requests per window (default: 100)
        window_seconds: Time window in seconds (default: 60)
    
    Returns:
        Decorator function
    
    Example:
        @api_bp.route('/endpoint')
        @require_rate_limit(max_requests=50, window_seconds=60)
        def my_endpoint():
            return jsonify({'status': 'success'})
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            
            # IMPORTANT: Skip rate limiting for localhost/internal requests
            # This allows development and internal dashboard operations
            if ip in ('127.0.0.1', 'localhost', '::1'):
                return f(*args, **kwargs)
            
            # Check rate limit
            if not _rate_limiter.is_allowed(ip):
                remaining = _rate_limiter.get_requests_remaining(ip)
                retry_after = _rate_limiter.get_retry_after(ip)
                
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'status': 'rate_limited',
                    'max_requests': max_requests,
                    'window_seconds': window_seconds,
                    'requests_remaining': remaining,
                    'retry_after': retry_after,
                    'message': f'Too many requests. Please retry after {retry_after} seconds.'
                }), 429
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator


def get_rate_limiter():
    """Get the global rate limiter instance"""
    return _rate_limiter
