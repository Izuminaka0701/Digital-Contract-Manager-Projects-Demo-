// Contracts Management JavaScript

let allContracts = [];
let currentContractId = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    requireAuth();
    await loadContracts();
    await loadSigningKeys();
});

// Load all contracts
async function loadContracts() {
    try {
        const response = await apiRequest('/contracts/');
        if (response.ok) {
            const data = await response.json();
            allContracts = data.contracts;
            displayContracts(allContracts);
        } else {
            showError('Failed to load contracts');
        }
    } catch (error) {
        console.error('Error loading contracts:', error);
        showError('Failed to load contracts');
    }
}

// Display contracts
function displayContracts(contracts) {
    const grid = document.getElementById('contractsGrid');
    const emptyState = document.getElementById('emptyState');
    
    if (!contracts || contracts.length === 0) {
        grid.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }
    
    grid.style.display = 'grid';
    emptyState.style.display = 'none';
    
    grid.innerHTML = contracts.map(contract => `
        <div class="contract-card" data-status="${contract.status}">
            <div class="contract-header">
                <h3>${escapeHtml(contract.title)}</h3>
                <span class="status-badge status-${contract.status}">${contract.status}</span>
            </div>
            <div class="contract-body">
                ${contract.description ? `<p>${escapeHtml(contract.description)}</p>` : ''}
                <div class="contract-meta">
                    <div class="meta-item">
                        <span class="meta-label">File Hash:</span>
                        <span class="meta-value monospace">${contract.file_hash.substring(0, 16)}...</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Created:</span>
                        <span class="meta-value">${formatDate(contract.created_at)}</span>
                    </div>
                    ${contract.signed_at ? `
                        <div class="meta-item">
                            <span class="meta-label">Signed:</span>
                            <span class="meta-value">${formatDate(contract.signed_at)}</span>
                        </div>
                    ` : ''}
                </div>
            </div>
            <div class="contract-actions">
                <button onclick="viewDetails('${contract.id}')" class="btn btn-outline btn-sm">View Details</button>
                ${contract.status === 'pending' ? `
                    <button onclick="showSignModal('${contract.id}')" class="btn btn-success btn-sm">Sign</button>
                ` : ''}
                ${contract.status === 'signed' ? `
                    <button onclick="verifyContract('${contract.id}')" class="btn btn-info btn-sm">Verify</button>
                ` : ''}
            </div>
        </div>
    `).join('');
}

// Filter contracts
function filterContracts() {
    const statusFilter = document.getElementById('statusFilter').value;
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    
    let filtered = allContracts;
    
    // Filter by status
    if (statusFilter !== 'all') {
        filtered = filtered.filter(c => c.status === statusFilter);
    }
    
    // Filter by search term
    if (searchTerm) {
        filtered = filtered.filter(c => 
            c.title.toLowerCase().includes(searchTerm) ||
            (c.description && c.description.toLowerCase().includes(searchTerm))
        );
    }
    
    displayContracts(filtered);
}

// Show upload modal
function showUploadModal() {
    document.getElementById('uploadModal').style.display = 'block';
    document.getElementById('uploadForm').reset();
    document.getElementById('uploadError').textContent = '';
}

// Handle upload
async function handleUpload(event) {
    event.preventDefault();
    
    const form = event.target;
    const errorDiv = document.getElementById('uploadError');
    errorDiv.textContent = '';
    
    const fileInput = document.getElementById('contractFile');
    const file = fileInput.files[0];
    
    if (!file) {
        errorDiv.textContent = 'Please select a file';
        return;
    }
    
    if (file.size > 10 * 1024 * 1024) {
        errorDiv.textContent = 'File size must be less than 10MB';
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', document.getElementById('contractTitle').value);
    formData.append('description', document.getElementById('contractDescription').value);
    
    try {
        const token = getAccessToken();
        const response = await fetch('/api/contracts/upload', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });
        
        if (response.ok) {
            closeModal('uploadModal');
            await loadContracts();
            showSuccess('Contract uploaded successfully');
        } else {
            const data = await response.json();
            errorDiv.textContent = data.detail || 'Upload failed';
        }
    } catch (error) {
        console.error('Upload error:', error);
        errorDiv.textContent = 'Network error. Please try again.';
    }
}

// Load signing keys for dropdown
async function loadSigningKeys() {
    try {
        const response = await apiRequest('/keys/');
        if (response.ok) {
            const data = await response.json();
            const select = document.getElementById('signingKey');
            select.innerHTML = '<option value="">-- Select a key --</option>' +
                data.keys.filter(k => k.status === 'active').map(key => `
                    <option value="${key.id}">${escapeHtml(key.name)} (${key.fingerprint})</option>
                `).join('');
        }
    } catch (error) {
        console.error('Error loading keys:', error);
    }
}

// Show sign modal
function showSignModal(contractId) {
    currentContractId = contractId;
    const contract = allContracts.find(c => c.id === contractId);
    
    document.getElementById('signContractName').textContent = 
        `Contract: ${contract.title}`;
    document.getElementById('signModal').style.display = 'block';
    document.getElementById('signForm').reset();
    document.getElementById('signError').textContent = '';
}

// Handle sign
async function handleSign(event) {
    event.preventDefault();
    
    const errorDiv = document.getElementById('signError');
    errorDiv.textContent = '';
    
    const keyId = document.getElementById('signingKey').value;
    const password = document.getElementById('keyPassword').value;
    
    if (!keyId) {
        errorDiv.textContent = 'Please select a signing key';
        return;
    }
    
    try {
        const response = await apiRequest(`/contracts/${currentContractId}/sign`, {
            method: 'POST',
            body: JSON.stringify({
                key_id: keyId,
                key_password: password
            })
        });
        
        if (response.ok) {
            closeModal('signModal');
            await loadContracts();
            showSuccess('Contract signed successfully');
        } else {
            const data = await response.json();
            errorDiv.textContent = data.detail || 'Signing failed';
        }
    } catch (error) {
        console.error('Sign error:', error);
        errorDiv.textContent = 'Network error. Please try again.';
    }
}

// Verify contract
async function verifyContract(contractId) {
    try {
        const response = await apiRequest('/contracts/verify', {
            method: 'POST',
            body: JSON.stringify({ contract_id: contractId })
        });
        
        if (response.ok) {
            const data = await response.json();
            showVerifyResult(data);
        } else {
            showError('Verification failed');
        }
    } catch (error) {
        console.error('Verify error:', error);
        showError('Verification failed');
    }
}

// Show verify result
function showVerifyResult(result) {
    const resultDiv = document.getElementById('verifyResult');
    
    resultDiv.innerHTML = `
        <div class="verify-status ${result.valid ? 'verify-success' : 'verify-failure'}">
            <div class="verify-icon">${result.valid ? '✅' : '❌'}</div>
            <h3>${result.valid ? 'Signature Valid' : 'Signature Invalid'}</h3>
            <p>${result.message}</p>
        </div>
        <div class="verify-details">
            <div class="detail-row">
                <span class="detail-label">Contract ID:</span>
                <span class="detail-value monospace">${result.contract_id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">File Hash:</span>
                <span class="detail-value monospace">${result.file_hash}</span>
            </div>
            ${result.signer_email ? `
                <div class="detail-row">
                    <span class="detail-label">Signed by:</span>
                    <span class="detail-value">${result.signer_email}</span>
                </div>
            ` : ''}
            ${result.signed_at ? `
                <div class="detail-row">
                    <span class="detail-label">Signed at:</span>
                    <span class="detail-value">${formatDate(result.signed_at)}</span>
                </div>
            ` : ''}
        </div>
    `;
    
    document.getElementById('verifyModal').style.display = 'block';
}

// View contract details
async function viewDetails(contractId) {
    const contract = allContracts.find(c => c.id === contractId);
    const detailsDiv = document.getElementById('contractDetails');
    
    detailsDiv.innerHTML = `
        <h2>${escapeHtml(contract.title)}</h2>
        <div class="details-grid">
            <div class="detail-section">
                <h3>Contract Information</h3>
                <div class="detail-row">
                    <span class="detail-label">Status:</span>
                    <span class="status-badge status-${contract.status}">${contract.status}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Created:</span>
                    <span>${formatDate(contract.created_at)}</span>
                </div>
                ${contract.signed_at ? `
                    <div class="detail-row">
                        <span class="detail-label">Signed:</span>
                        <span>${formatDate(contract.signed_at)}</span>
                    </div>
                ` : ''}
            </div>
            <div class="detail-section">
                <h3>Cryptographic Data</h3>
                <div class="detail-row">
                    <span class="detail-label">File Hash:</span>
                    <code class="code-block">${contract.file_hash}</code>
                </div>
                ${contract.signature ? `
                    <div class="detail-row">
                        <span class="detail-label">Signature:</span>
                        <code class="code-block">${contract.signature.substring(0, 100)}...</code>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
    
    document.getElementById('detailsModal').style.display = 'block';
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
    alert(message); // Replace with toast notification
}

function showError(message) {
    alert(message); // Replace with toast notification
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}