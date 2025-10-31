// Authentication JavaScript
const API_BASE = '/api';

// Token management
function setTokens(accessToken, refreshToken) {
    sessionStorage.setItem('access_token', accessToken);
    sessionStorage.setItem('refresh_token', refreshToken);
}

function getAccessToken() {
    return sessionStorage.getItem('access_token');
}

function getRefreshToken() {
    return sessionStorage.getItem('refresh_token');
}

function clearTokens() {
    sessionStorage.removeItem('access_token');
    sessionStorage.removeItem('refresh_token');
}

function isAuthenticated() {
    return !!getAccessToken();
}

// API helper with auth
async function apiRequest(endpoint, options = {}) {
    const token = getAccessToken();
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    
    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
    });
    
    // Handle token refresh on 401
    if (response.status === 401 && getRefreshToken()) {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
            // Retry original request
            headers['Authorization'] = `Bearer ${getAccessToken()}`;
            return fetch(`${API_BASE}${endpoint}`, {
                ...options,
                headers
            });
        } else {
            // Refresh failed, logout
            handleLogout();
            throw new Error('Authentication failed');
        }
    }
    
    return response;
}

async function refreshAccessToken() {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return false;
    
    try {
        const response = await fetch(`${API_BASE}/auth/refresh`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${refreshToken}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            setTokens(data.access_token, data.refresh_token);
            return true;
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
    }
    
    return false;
}

// Modal functions
function showModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
    // Clear form errors
    const errorDiv = document.querySelector(`#${modalId} .form-error`);
    if (errorDiv) errorDiv.textContent = '';
}

function showLoginModal() {
    closeModal('registerModal');
    showModal('loginModal');
}

function showRegisterModal() {
    closeModal('loginModal');
    showModal('registerModal');
}

// Close modal on outside click
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
    }
}

// Handle registration
async function handleRegister(event) {
    event.preventDefault();
    
    const form = event.target;
    const errorDiv = document.getElementById('registerError');
    errorDiv.textContent = '';
    
    const formData = {
        email: form.email.value,
        password: form.password.value,
        full_name: form.full_name.value
    };
    
    try {
        const response = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Registration successful, now login
            await handleAutoLogin(formData.email, formData.password);
        } else {
            errorDiv.textContent = data.detail || 'Registration failed';
        }
    } catch (error) {
        errorDiv.textContent = 'Network error. Please try again.';
        console.error('Registration error:', error);
    }
}

// Handle login
async function handleLogin(event) {
    event.preventDefault();
    
    const form = event.target;
    const errorDiv = document.getElementById('loginError');
    errorDiv.textContent = '';
    
    const formData = {
        email: form.email.value,
        password: form.password.value
    };
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            setTokens(data.access_token, data.refresh_token);
            window.location.href = '/dashboard';
        } else {
            errorDiv.textContent = data.detail || 'Login failed';
        }
    } catch (error) {
        errorDiv.textContent = 'Network error. Please try again.';
        console.error('Login error:', error);
    }
}

// Auto login after registration
async function handleAutoLogin(email, password) {
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            setTokens(data.access_token, data.refresh_token);
            window.location.href = '/dashboard';
        }
    } catch (error) {
        console.error('Auto login error:', error);
    }
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

// Check authentication on protected pages
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/';
    }
}

// Get current user info
async function getCurrentUser() {
    try {
        const response = await apiRequest('/auth/me');
        if (response.ok) {
            return await response.json();
        }
    } catch (error) {
        console.error('Get user error:', error);
    }
    return null;
}