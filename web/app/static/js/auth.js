/**
 * AMOSKYS Authentication JavaScript Module
 * 
 * Shared utilities for authentication pages:
 * - Form validation
 * - API communication
 * - Session management
 * - UI helpers
 */

// =============================================================================
// Constants
// =============================================================================

const AUTH_API_BASE = '/api/auth';
const SESSION_COOKIE_NAME = 'amoskys_session';

// =============================================================================
// API Functions
// =============================================================================

/**
 * Make an authenticated API request
 * @param {string} endpoint - API endpoint (relative to /api/auth/)
 * @param {object} options - Fetch options
 * @returns {Promise<object>} - Response data
 */
async function authFetch(endpoint, options = {}) {
    const url = endpoint.startsWith('/') ? endpoint : `${AUTH_API_BASE}/${endpoint}`;
    
    const defaultOptions = {
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
    };
    
    const response = await fetch(url, { ...defaultOptions, ...options });
    const data = await response.json();
    
    return {
        ok: response.ok,
        status: response.status,
        data,
    };
}

/**
 * Check if user is authenticated
 * @returns {Promise<object|null>} - User data if authenticated, null otherwise
 */
async function checkAuth() {
    try {
        const { ok, data } = await authFetch('me');
        if (ok && data.success) {
            return data.user;
        }
        return null;
    } catch (error) {
        console.error('Auth check failed:', error);
        return null;
    }
}

/**
 * Logout the current user
 * @returns {Promise<boolean>} - True if logout successful
 */
async function logout() {
    try {
        const { ok } = await authFetch('logout', { method: 'POST' });
        if (ok) {
            window.location.href = '/auth/login?logged_out=1';
            return true;
        }
        return false;
    } catch (error) {
        console.error('Logout failed:', error);
        return false;
    }
}

/**
 * Logout from all devices
 * @returns {Promise<boolean>} - True if logout successful
 */
async function logoutAll() {
    try {
        const { ok } = await authFetch('logout-all', { method: 'POST' });
        if (ok) {
            window.location.href = '/auth/login?logged_out_all=1';
            return true;
        }
        return false;
    } catch (error) {
        console.error('Logout all failed:', error);
        return false;
    }
}

// =============================================================================
// Validation Functions
// =============================================================================

/**
 * Validate email format
 * @param {string} email 
 * @returns {boolean}
 */
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Check password strength
 * @param {string} password 
 * @returns {object} - { score: 0-5, requirements: {...}, strength: 'weak'|'fair'|'good'|'strong' }
 */
function checkPasswordStrength(password) {
    const requirements = {
        length: password.length >= 12,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
    };
    
    const score = Object.values(requirements).filter(Boolean).length;
    
    let strength = 'weak';
    if (score >= 5) strength = 'strong';
    else if (score >= 4) strength = 'good';
    else if (score >= 2) strength = 'fair';
    
    return { score, requirements, strength };
}

/**
 * Validate password meets all requirements
 * @param {string} password 
 * @returns {object} - { valid: boolean, errors: string[] }
 */
function validatePassword(password) {
    const errors = [];
    
    if (password.length < 12) {
        errors.push('Password must be at least 12 characters');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain an uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain a lowercase letter');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain a number');
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Password must contain a special character');
    }
    
    return {
        valid: errors.length === 0,
        errors,
    };
}

// =============================================================================
// UI Helper Functions
// =============================================================================

/**
 * Show error message
 * @param {string} message - Error message to display
 * @param {string} containerId - ID of error container (default: 'error-message')
 */
function showError(message, containerId = 'error-message') {
    const errorDiv = document.getElementById(containerId);
    const errorText = document.getElementById('error-text');
    
    if (errorDiv && errorText) {
        errorText.innerHTML = message;
        errorDiv.style.display = 'flex';
        
        // Scroll to error
        errorDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

/**
 * Hide error message
 * @param {string} containerId - ID of error container
 */
function hideError(containerId = 'error-message') {
    const errorDiv = document.getElementById(containerId);
    if (errorDiv) {
        errorDiv.style.display = 'none';
    }
}

/**
 * Show success message
 * @param {string} message - Success message to display
 * @param {string} containerId - ID of success container
 */
function showSuccess(message, containerId = 'success-message') {
    const successDiv = document.getElementById(containerId);
    const successText = document.getElementById('success-text');
    
    if (successDiv && successText) {
        successText.textContent = message;
        successDiv.style.display = 'flex';
    }
}

/**
 * Show field-level error
 * @param {string} fieldId - ID of the input field
 * @param {string} message - Error message
 */
function showFieldError(fieldId, message) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    
    const group = input.closest('.form-group');
    const errorEl = document.getElementById(fieldId + '-error');
    
    if (group) group.classList.add('has-error');
    if (input) input.classList.add('error');
    if (errorEl) errorEl.textContent = message;
}

/**
 * Clear field-level error
 * @param {string} fieldId - ID of the input field
 */
function clearFieldError(fieldId) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    
    const group = input.closest('.form-group');
    
    if (group) group.classList.remove('has-error');
    if (input) input.classList.remove('error');
}

/**
 * Clear all field errors
 */
function clearAllFieldErrors() {
    document.querySelectorAll('.form-group.has-error').forEach(el => {
        el.classList.remove('has-error');
    });
    document.querySelectorAll('.form-input.error').forEach(el => {
        el.classList.remove('error');
    });
}

/**
 * Set loading state on button
 * @param {HTMLElement|string} button - Button element or ID
 * @param {boolean} loading - Loading state
 */
function setButtonLoading(button, loading) {
    const btn = typeof button === 'string' ? document.getElementById(button) : button;
    if (!btn) return;
    
    if (loading) {
        btn.classList.add('btn-loading');
        btn.disabled = true;
    } else {
        btn.classList.remove('btn-loading');
        btn.disabled = false;
    }
}

// =============================================================================
// Password Visibility Toggle
// =============================================================================

/**
 * Initialize password visibility toggles
 */
function initPasswordToggles() {
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', function() {
            const wrapper = this.closest('.input-wrapper');
            const input = wrapper.querySelector('input');
            
            if (input) {
                const type = input.type === 'password' ? 'text' : 'password';
                input.type = type;
                
                // Update icon if needed
                const eyeOpen = this.querySelector('.eye-open');
                const eyeClosed = this.querySelector('.eye-closed');
                
                if (eyeOpen && eyeClosed) {
                    eyeOpen.style.display = type === 'password' ? 'block' : 'none';
                    eyeClosed.style.display = type === 'password' ? 'none' : 'block';
                }
            }
        });
    });
}

// =============================================================================
// Session Management
// =============================================================================

/**
 * Get URL parameters
 * @returns {URLSearchParams}
 */
function getUrlParams() {
    return new URLSearchParams(window.location.search);
}

/**
 * Check for logout messages and display them
 */
function checkLogoutMessages() {
    const params = getUrlParams();
    
    if (params.get('logged_out') === '1') {
        showSuccess('You have been logged out successfully.');
    }
    
    if (params.get('logged_out_all') === '1') {
        showSuccess('You have been logged out from all devices.');
    }
    
    if (params.get('session_expired') === '1') {
        showError('Your session has expired. Please sign in again.');
    }
}

// =============================================================================
// Auto-initialize
// =============================================================================

document.addEventListener('DOMContentLoaded', function() {
    // Initialize password toggles
    initPasswordToggles();
    
    // Check for logout/session messages
    checkLogoutMessages();
});

// =============================================================================
// Export for module usage
// =============================================================================

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        authFetch,
        checkAuth,
        logout,
        logoutAll,
        isValidEmail,
        checkPasswordStrength,
        validatePassword,
        showError,
        hideError,
        showSuccess,
        showFieldError,
        clearFieldError,
        clearAllFieldErrors,
        setButtonLoading,
        initPasswordToggles,
        getUrlParams,
    };
}
