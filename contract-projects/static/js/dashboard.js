// Dashboard JavaScript
let statusChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    requireAuth();
    await loadDashboardData();
});

async function loadDashboardData() {
    try {
        // Load user info
        const user = await getCurrentUser();
        if (user) {
            document.getElementById('userGreeting').textContent = 
                `Welcome back, ${user.full_name}!`;
        }
        
        // Load dashboard stats
        const response = await apiRequest('/audit/dashboard');
        if (response.ok) {
            const data = await response.json();
            updateStats(data);
            updateActivityFeed(data.recent_activity);
            renderChart(data);
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
        showError('Failed to load dashboard data');
    }
}

function updateStats(data) {
    document.getElementById('totalContracts').textContent = data.total_contracts;
    document.getElementById('signedContracts').textContent = data.signed_contracts;
    document.getElementById('pendingContracts').textContent = data.pending_contracts;
    document.getElementById('totalKeys').textContent = data.total_keys;
}

function updateActivityFeed(activities) {
    const activityList = document.getElementById('activityList');
    
    if (!activities || activities.length === 0) {
        activityList.innerHTML = '<p class="empty-state">No recent activity</p>';
        return;
    }
    
    activityList.innerHTML = activities.map(activity => {
        const icon = getActivityIcon(activity.action);
        const time = formatTimeAgo(activity.created_at);
        const description = getActivityDescription(activity);
        
        return `
            <div class="activity-item">
                <div class="activity-icon">${icon}</div>
                <div class="activity-content">
                    <p class="activity-description">${description}</p>
                    <span class="activity-time">${time}</span>
                </div>
            </div>
        `;
    }).join('');
}

function getActivityIcon(action) {
    const icons = {
        'user_login': '🔓',
        'user_logout': '🔒',
        'user_register': '👤',
        'contract_upload': '📤',
        'contract_sign': '✍️',
        'contract_verify': '🔍',
        'key_generate': '🔑',
        'key_delete': '🗑️'
    };
    return icons[action] || '📋';
}

function getActivityDescription(activity) {
    const descriptions = {
        'user_login': 'You logged in',
        'user_logout': 'You logged out',
        'user_register': 'Account created',
        'contract_upload': 'Uploaded a contract',
        'contract_sign': 'Signed a contract',
        'contract_verify': 'Verified a contract',
        'key_generate': 'Generated a signing key',
        'key_delete': 'Deleted a signing key'
    };
    return descriptions[activity.action] || activity.action;
}

function formatTimeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    const intervals = {
        year: 31536000,
        month: 2592000,
        week: 604800,
        day: 86400,
        hour: 3600,
        minute: 60
    };
    
    for (const [unit, secondsInUnit] of Object.entries(intervals)) {
        const interval = Math.floor(seconds / secondsInUnit);
        if (interval >= 1) {
            return `${interval} ${unit}${interval > 1 ? 's' : ''} ago`;
        }
    }
    
    return 'Just now';
}

function renderChart(data) {
    const ctx = document.getElementById('statusChart');
    
    // Destroy existing chart
    if (statusChart) {
        statusChart.destroy();
    }
    
    const chartData = {
        labels: ['Signed', 'Pending', 'Verified'],
        datasets: [{
            label: 'Contracts',
            data: [
                data.signed_contracts,
                data.pending_contracts,
                0 // Add verified count when available
            ],
            backgroundColor: [
                'rgba(46, 213, 115, 0.8)',
                'rgba(255, 184, 0, 0.8)',
                'rgba(52, 152, 219, 0.8)'
            ],
            borderColor: [
                'rgba(46, 213, 115, 1)',
                'rgba(255, 184, 0, 1)',
                'rgba(52, 152, 219, 1)'
            ],
            borderWidth: 2
        }]
    };
    
    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: {
                            size: 14
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

function showError(message) {
    // Simple error notification (you can enhance this)
    alert(message);
}