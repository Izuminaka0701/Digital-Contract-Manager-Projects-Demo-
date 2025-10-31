// Main JavaScript - Common utilities and helpers (ES5 Compatible)

// API Base URL
var API_BASE = '/api';

// Check if user is authenticated
function isAuthenticated() {
    return !!sessionStorage.getItem('access_token');
}

// Get access token
function getAccessToken() {
    return sessionStorage.getItem('access_token');
}

// Get refresh token
function getRefreshToken() {
    return sessionStorage.getItem('refresh_token');
}

// Set tokens
function setTokens(accessToken, refreshToken) {
    sessionStorage.setItem('access_token', accessToken);
    sessionStorage.setItem('refresh_token', refreshToken);
}

// Clear tokens
function clearTokens() {
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('refresh_token');
}

// API request with authentication
async function apiRequest(endpoint, options) {
    options = options || {};
    var token = getAccessToken();
    var headers = options.headers || {};
    headers['Content-Type'] = 'application/json';
    
    if (token) {
        headers['Authorization'] = 'Bearer ' + token;
    }
    
    var requestOptions = {
        method: options.method || 'GET',
        headers: headers
    };
    
    if (options.body) {
        requestOptions.body = options.body;
    }
    
    var response = await fetch(API_BASE + endpoint, requestOptions);
    
    // Handle token refresh on 401
    if (response.status === 401 && getRefreshToken()) {
        var refreshed = await refreshAccessToken();
        if (refreshed) {
            // Retry original request
            headers['Authorization'] = 'Bearer ' + getAccessToken();
            requestOptions.headers = headers;
            return fetch(API_BASE + endpoint, requestOptions);
        } else {
            // Refresh failed, logout
            handleLogout();
            throw new Error('Authentication failed');
        }
    }
    
    return response;
}

// Refresh access token
async function refreshAccessToken() {
    var refreshToken = getRefreshToken();
    if (!refreshToken) return false;
    
    try {
        var response = await fetch(API_BASE + '/auth/refresh', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + refreshToken
            }
        });
        
        if (response.ok) {
            var data = await response.json();
            setTokens(data.access_token, data.refresh_token);
            return true;
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
    }
    
    return false;
}

// Get current user
async function getCurrentUser() {
    try {
        var response = await apiRequest('/auth/me');
        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.error('Get user error:', error);
    }
    return null;
}

// Handle logout
async function handleLogout() {
    try {
        await apiRequest('/auth/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        clearTokens();
        window.location.href = '/';
    }
}

// Require authentication
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/';
    }
}

// Modal functions
function closeModal(modalId) {
    var modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        // Clear form errors
        var errorDiv = modal.querySelector('.form-error');
        if (errorDiv) errorDiv.textContent = '';
    }
}

// Close modal on outside click
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
    }
}

// Format date
function formatDate(dateString) {
    var date = new Date(dateString);
    var options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    return date.toLocaleDateString('en-US', options);
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Show success notification
function showSuccess(message) {
    showNotification(message, 'success');
}

// Show error notification
function showError(message) {
    showNotification(message, 'error');
}

// Show notification (simple implementation)
function showNotification(message, type) {
    type = type || 'info';
    
    // Remove existing notification
    var existing = document.querySelector('.notification');
    if (existing) {
        existing.remove();
    }
    
    // Create notification
    var notification = document.createElement('div');
    notification.className = 'notification notification-' + type;
    notification.textContent = message;
    
    // Set base styles
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.padding = '1rem 1.5rem';
    notification.style.borderRadius = '8px';
    notification.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.15)';
    notification.style.zIndex = '10000';
    notification.style.animation = 'slideIn 0.3s ease-out';
    notification.style.maxWidth = '400px';
    notification.style.fontWeight = '500';
    
    // Set type-specific styles
    if (type === 'success') {
        notification.style.background = '#d4edda';
        notification.style.color = '#155724';
        notification.style.borderLeft = '4px solid #28a745';
    } else if (type === 'error') {
        notification.style.background = '#f8d7da';
        notification.style.color = '#721c24';
        notification.style.borderLeft = '4px solid #dc3545';
    } else {
        notification.style.background = '#d1ecf1';
        notification.style.color = '#0c5460';
        notification.style.borderLeft = '4px solid #17a2b8';
    }
    
    document.body.appendChild(notification);
    
    // Auto remove after 3 seconds
    setTimeout(function() {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(function() {
            notification.remove();
        }, 300);
    }, 3000);
}

// Add animation styles only once
if (!document.getElementById('notification-styles')) {
    var style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = 
        '@keyframes slideIn {' +
        '  from { transform: translateX(400px); opacity: 0; }' +
        '  to { transform: translateX(0); opacity: 1; }' +
        '}' +
        '@keyframes slideOut {' +
        '  from { transform: translateX(0); opacity: 1; }' +
        '  to { transform: translateX(400px); opacity: 0; }' +
        '}';
    document.head.appendChild(style);
}

// File size formatter
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    var k = 1024;
    var sizes = ['Bytes', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Validate file type
function isValidPDF(file) {
    return file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
}

// Debounce function for search
function debounce(func, wait) {
    var timeout;
    return function executedFunction() {
        var args = arguments;
        var context = this;
        var later = function() {
            clearTimeout(timeout);
            func.apply(context, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Copy to clipboard helper
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showSuccess('Copied to clipboard');
    } catch (err) {
        console.error('Copy failed:', err);
        // Fallback for older browsers
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showSuccess('Copied to clipboard');
        } catch (e) {
            showError('Failed to copy to clipboard');
        }
        document.body.removeChild(textarea);
    }
}

// Format time ago
function formatTimeAgo(dateString) {
    var date = new Date(dateString);
    var now = new Date();
    var seconds = Math.floor((now - date) / 1000);
    
    var intervals = {
        year: 31536000,
        month: 2592000,
        week: 604800,
        day: 86400,
        hour: 3600,
        minute: 60
    };
    
    for (var unit in intervals) {
        if (intervals.hasOwnProperty(unit)) {
            var secondsInUnit = intervals[unit];
            var interval = Math.floor(seconds / secondsInUnit);
            if (interval >= 1) {
                return interval + ' ' + unit + (interval > 1 ? 's' : '') + ' ago';
            }
        }
    }
    
    return 'Just now';
}

// Loading spinner helper
function showLoading(elementId) {
    var element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = '<div class="loading-spinner">Loading...</div>';
    }
}

// Validate password strength
function validatePassword(password) {
    var minLength = 8;
    var hasUpperCase = /[A-Z]/.test(password);
    var hasLowerCase = /[a-z]/.test(password);
    var hasNumbers = /\d/.test(password);
    
    var errors = [];
    
    if (password.length < minLength) {
        errors.push('Password must be at least ' + minLength + ' characters');
    }
    if (!hasUpperCase) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (!hasLowerCase) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (!hasNumbers) {
        errors.push('Password must contain at least one number');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

// Truncate text
function truncateText(text, maxLength) {
    maxLength = maxLength || 50;
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Format hash (show first and last characters)
function formatHash(hash, startChars, endChars) {
    startChars = startChars || 8;
    endChars = endChars || 8;
    if (hash.length <= startChars + endChars) return hash;
    return hash.substring(0, startChars) + '...' + hash.substring(hash.length - endChars);
}

// Export functions for use in other files
window.contractManagerUtils = {
    apiRequest: apiRequest,
    isAuthenticated: isAuthenticated,
    getAccessToken: getAccessToken,
    getCurrentUser: getCurrentUser,
    handleLogout: handleLogout,
    requireAuth: requireAuth,
    showSuccess: showSuccess,
    showError: showError,
    formatDate: formatDate,
    formatTimeAgo: formatTimeAgo,
    formatFileSize: formatFileSize,
    formatHash: formatHash,
    escapeHtml: escapeHtml,
    copyToClipboard: copyToClipboard,
    validatePassword: validatePassword,
    truncateText: truncateText,
    debounce: debounce,
    isValidPDF: isValidPDF
};