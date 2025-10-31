// Keys Management JavaScript

let allKeys = [];
let deleteKeyId = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    requireAuth();
    await loadKeys();
});

// Load all keys
async function loadKeys() {
    try {
        const response = await apiRequest('/keys/');
        if (response.ok) {
            const data = await response.json();
            allKeys = data.keys;
            displayKeys(allKeys);
        } else {
            showError('Failed to load keys');
        }
    } catch (error) {
        console.error('Error loading keys:', error);
        showError('Failed to load keys');
    }
}

// Display keys
function displayKeys(keys) {
    const grid = document.getElementById('keysGrid');
    const emptyState = document.getElementById('emptyState');
    
    if (!keys || keys.length === 0) {
        grid.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }
    
    grid.style.display = 'grid';
    emptyState.style.display = 'none';
    
    grid.innerHTML = keys.map(key => `
        <div class="key-card">
            <div class="key-header">
                <div class="key-icon">🔑</div>
                <div class="key-info">
                    <h3>${escapeHtml(key.name)}</h3>
                    <span class="key-fingerprint">${key.fingerprint}</span>
                </div>
                <span class="status-badge status-${key.status}">${key.status}</span>
            </div>
            <div class="key-body">
                <div class="key-meta">
                    <div class="meta-item">
                        <span class="meta-label">Created:</span>
                        <span class="meta-value">${formatDate(key.created_at)}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Algorithm:</span>
                        <span class="meta-value">RSA-PSS 2048</span>
                    </div>
                </div>
            </div>
            <div class="key-actions">
                <button onclick="viewKeyDetails('${key.id}')" class="btn btn-outline btn-sm">View Public Key</button>
                ${key.status === 'active' ? `
                    <button onclick="showDeleteModal('${key.id}')" class="btn btn-danger btn-sm">Delete</button>
                ` : ''}
            </div>
        </div>
    `).join('');
}

// Show generate modal
function showGenerateModal() {
    document.getElementById('generateModal').style.display = 'block';
    document.getElementById('generateForm').reset();
    document.getElementById('generateError').textContent = '';
}

// Handle generate key
async function handleGenerate(event) {
    event.preventDefault();
    
    const errorDiv = document.getElementById('generateError');
    errorDiv.textContent = '';
    
    const name = document.getElementById('keyName').value;
    const password = document.getElementById('keyPassword').value;
    const passwordConfirm = document.getElementById('keyPasswordConfirm').value;
    
    // Validate passwords match
    if (password !== passwordConfirm) {
        errorDiv.textContent = 'Passwords do not match';
        return;
    }
    
    // Validate password strength
    if (password.length < 8) {
        errorDiv.textContent = 'Password must be at least 8 characters';
        return;
    }
    
    const btn = document.getElementById('generateBtn');
    btn.disabled = true;
    btn.textContent = 'Generating...';
    
    try {
        const response = await apiRequest('/keys/generate', {
            method: 'POST',
            body: JSON.stringify({ name, password })
        });
        
        if (response.ok) {
            closeModal('generateModal');
            await loadKeys();
            showSuccess('Signing key generated successfully');
        } else {
            const data = await response.json();
            errorDiv.textContent = data.detail || 'Key generation failed';
        }
    } catch (error) {
        console.error('Generate error:', error);
        errorDiv.textContent = 'Network error. Please try again.';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Generate Key';
    }
}

// View key details
function viewKeyDetails(keyId) {
    const key = allKeys.find(k => k.id === keyId);
    const detailsDiv = document.getElementById('keyDetails');
    
    detailsDiv.innerHTML = `
        <div class="key-details-header">
            <div class="key-icon-large">🔑</div>
            <div>
                <h3>${escapeHtml(key.name)}</h3>
                <p class="key-fingerprint">${key.fingerprint}</p>
            </div>
        </div>
        
        <div class="detail-section">
            <h4>Key Information</h4>
            <div class="detail-row">
                <span class="detail-label">Status:</span>
                <span class="status-badge status-${key.status}">${key.status}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Algorithm:</span>
                <span>RSA-PSS 2048-bit</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Created:</span>
                <span>${formatDate(key.created_at)}</span>
            </div>
        </div>
        
        <div class="detail-section">
            <h4>Public Key (PEM Format)</h4>
            <textarea class="public-key-textarea" readonly>${key.public_key}</textarea>
            <button onclick="copyPublicKey('${keyId}')" class="btn btn-outline btn-sm">
                📋 Copy to Clipboard
            </button>
        </div>
        
        <div class="info-box">
            <strong>ℹ️ Note:</strong> This is your public key. You can share it with others to verify your signatures. Your private key is securely encrypted and never displayed.
        </div>
    `;
    
    document.getElementById('detailsModal').style.display = 'block';
}

// Copy public key to clipboard
function copyPublicKey(keyId) {
    const key = allKeys.find(k => k.id === keyId);
    
    navigator.clipboard.writeText(key.public_key).then(() => {
        showSuccess('Public key copied to clipboard');
    }).catch(err => {
        console.error('Copy failed:', err);
        showError('Failed to copy to clipboard');
    });
}

// Show delete modal
function showDeleteModal(keyId) {
    deleteKeyId = keyId;
    const key = allKeys.find(k => k.id === keyId);
    
    document.getElementById('deleteKeyName').textContent = 
        `Are you sure you want to delete "${key.name}"?`;
    document.getElementById('deleteModal').style.display = 'block';
    document.getElementById('deleteError').textContent = '';
}

// Confirm delete
async function confirmDelete() {
    if (!deleteKeyId) return;
    
    const errorDiv = document.getElementById('deleteError');
    errorDiv.textContent = '';
    
    const btn = document.getElementById('deleteBtn');
    btn.disabled = true;
    btn.textContent = 'Deleting...';
    
    try {
        const response = await apiRequest(`/keys/${deleteKeyId}`, {
            method: 'DELETE'
        });
        
        if (response.ok || response.status === 204) {
            closeModal('deleteModal');
            await loadKeys();
            showSuccess('Signing key deleted successfully');
        } else {
            const data = await response.json();
            errorDiv.textContent = data.detail || 'Delete failed';
        }
    } catch (error) {
        console.error('Delete error:', error);
        errorDiv.textContent = 'Network error. Please try again.';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Delete Key';
        deleteKeyId = null;
    }
}

// Utility functions
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showSuccess(message) {
    // Simple alert for now - replace with toast notification
    alert(message);
}

function showError(message) {
    alert(message);
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}