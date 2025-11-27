// Dashboard JavaScript - Real-time updates with Socket.IO and Chart.js

// Initialize Socket.IO connection
const socket = io();

// Chart.js configuration
let entropyChart = null;
let entropyData = {
    labels: [],
    datasets: [{
        label: 'Network Entropy',
        data: [],
        borderColor: '#00ff41',
        backgroundColor: 'rgba(0, 255, 65, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 4
    }]
};

// Packet and threat counters
let packetCount = 0;
let threatCount = 0;

// Initialize entropy chart
function initEntropyChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    
    entropyChart = new Chart(ctx, {
        type: 'line',
        data: entropyData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 0
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: true,
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00ff41',
                    bodyColor: '#ffffff',
                    borderColor: '#00ff41',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: '#888888',
                        font: {
                            size: 10,
                            family: 'monospace'
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                },
                y: {
                    ticks: {
                        color: '#888888',
                        font: {
                            size: 10,
                            family: 'monospace'
                        }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    beginAtZero: true
                }
            }
        }
    });
}

// Update entropy chart
function updateEntropyChart(entropyValue, timestamp) {
    const maxDataPoints = 100;
    
    // Add new data point
    const timeLabel = new Date(timestamp * 1000).toLocaleTimeString();
    entropyData.labels.push(timeLabel);
    entropyData.datasets[0].data.push(entropyValue);
    
    // Limit data points
    if (entropyData.labels.length > maxDataPoints) {
        entropyData.labels.shift();
        entropyData.datasets[0].data.shift();
    }
    
    // Update chart
    if (entropyChart) {
        entropyChart.update('none');
    }
}

// Format timestamp
function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString();
}

// Add threat log entry (also adds to packet-log)
function addThreatLog(threat) {
    const packetLogContainer = document.getElementById('packet-log');
    
    // Remove empty message
    const emptyMsg = packetLogContainer.querySelector('.log-empty');
    if (emptyMsg) {
        emptyMsg.remove();
    }
    
    const entry = document.createElement('div');
    entry.className = 'log-entry new threat-entry';
    
    const severity = threat.severity || 'low';
    const threatType = threat.threat_type || 'Unknown';
    const srcIp = threat.src_ip || 'N/A';
    const score = threat.threat_score || 0;
    const description = threat.description || 'No description';
    
    entry.innerHTML = `
        <div>
            <span class="log-time">${formatTime(threat.timestamp)}</span>
            <span class="log-type threat">THREAT</span>
            <span class="log-severity ${severity}">${severity.toUpperCase()}</span>
            <strong>${threatType}</strong>
        </div>
        <div class="log-details">
            Source: <span class="log-ip">${srcIp}</span> | 
            Score: <strong>${score.toFixed(1)}</strong> | 
            ${description}
        </div>
    `;
    
    // Add to packet log with red flash effect
    packetLogContainer.insertBefore(entry, packetLogContainer.firstChild);
    
    // Flash red border/glow
    entry.style.border = '2px solid #ff0040';
    entry.style.boxShadow = '0 0 20px rgba(255, 0, 64, 0.8)';
    setTimeout(() => {
        entry.style.border = '';
        entry.style.boxShadow = '';
    }, 2000);
    
    // Increment threat count
    threatCount++;
    updateThreatCount();
    
    // Limit entries
    const entries = packetLogContainer.querySelectorAll('.log-entry');
    if (entries.length > 100) {
        entries[entries.length - 1].remove();
    }
}

// Add packet log entry
function addPacketLog(packet) {
    const logContainer = document.getElementById('packet-log');
    
    // Remove empty message
    const emptyMsg = logContainer.querySelector('.log-empty');
    if (emptyMsg) {
        emptyMsg.remove();
    }
    
    const entry = document.createElement('div');
    entry.className = 'log-entry new';
    
    const srcIp = packet.src_ip || 'N/A';
    const dstIp = packet.dst_ip || 'N/A';
    const srcPort = packet.src_port || 'N/A';
    const dstPort = packet.dst_port || 'N/A';
    const protocol = packet.protocol || 'N/A';
    const size = packet.size || 0;
    
    entry.innerHTML = `
        <div>
            <span class="log-time">${formatTime(packet.timestamp)}</span>
            <span class="log-type packet">PACKET</span>
            <strong>${protocol}</strong>
        </div>
        <div class="log-details">
            <span class="log-ip">${srcIp}:${srcPort}</span> → 
            <span class="log-ip">${dstIp}:${dstPort}</span> | 
            Size: ${size} bytes
        </div>
    `;
    
    logContainer.insertBefore(entry, logContainer.firstChild);
    
    // Increment packet count
    packetCount++;
    updatePacketCount();
    
    // Limit entries
    const entries = logContainer.querySelectorAll('.log-entry');
    if (entries.length > 100) {
        entries[entries.length - 1].remove();
    }
}

// Add honeypot log entry
function addHoneypotLog(hit) {
    const logContainer = document.getElementById('honeypot-log');
    
    // Remove empty message
    const emptyMsg = logContainer.querySelector('.log-empty');
    if (emptyMsg) {
        emptyMsg.remove();
    }
    
    const entry = document.createElement('div');
    entry.className = 'log-entry new';
    
    const service = hit.service || 'Unknown';
    const clientIp = hit.client_ip || 'N/A';
    const clientPort = hit.client_port || 'N/A';
    const details = hit.details || {};
    
    let detailsText = '';
    if (typeof details === 'object') {
        if (details.method) detailsText = `${details.method} ${details.path || ''}`;
        else if (details.command) detailsText = `Command: ${details.command}`;
        else if (details.type) detailsText = `Type: ${details.type}`;
        else detailsText = JSON.stringify(details).substring(0, 50);
    } else {
        detailsText = details;
    }
    
    entry.innerHTML = `
        <div>
            <span class="log-time">${formatTime(hit.timestamp)}</span>
            <span class="log-type honeypot">HONEYPOT</span>
            <strong>${service}</strong>
        </div>
        <div class="log-details">
            Client: <span class="log-ip">${clientIp}:${clientPort}</span> | 
            ${detailsText}
        </div>
    `;
    
    logContainer.insertBefore(entry, logContainer.firstChild);
    
    // Limit entries
    const entries = logContainer.querySelectorAll('.log-entry');
    if (entries.length > 50) {
        entries[entries.length - 1].remove();
    }
}

// Update statistics
function updateStats(stats) {
    if (stats.packets_captured !== undefined) {
        document.getElementById('stat-packets').textContent = stats.packets_captured.toLocaleString();
    }
    if (stats.threats_detected !== undefined) {
        document.getElementById('stat-threats').textContent = stats.threats_detected.toLocaleString();
    }
    if (stats.honeypot_hits !== undefined) {
        document.getElementById('stat-honeypot').textContent = stats.honeypot_hits.toLocaleString();
    }
    if (stats.blocked_ips !== undefined) {
        document.getElementById('stat-blocked').textContent = stats.blocked_ips.toLocaleString();
    }
}

// Update threat count
function updateThreatCount() {
    const threatCountEl = document.getElementById('threat-count');
    const threatCountDisplay = document.getElementById('threat-count-display');
    if (threatCountEl) threatCountEl.textContent = threatCount;
    if (threatCountDisplay) threatCountDisplay.textContent = threatCount.toLocaleString();
}

// Update packet count
function updatePacketCount() {
    const packetCountEl = document.getElementById('packet-count');
    const packetCountDisplay = document.getElementById('packet-count-display');
    if (packetCountEl) packetCountEl.textContent = packetCount;
    if (packetCountDisplay) packetCountDisplay.textContent = packetCount.toLocaleString();
}

// Trigger attack function (called by button onclick)
function triggerAttack(type) {
    // Visual feedback on button
    const button = document.querySelector(`[data-attack="${type}"]`);
    if (button) {
        button.style.borderColor = '#ff00ff';
        button.style.boxShadow = '0 0 20px rgba(255, 0, 255, 0.6)';
        setTimeout(() => {
            button.style.borderColor = '';
            button.style.boxShadow = '';
        }, 500);
    }
    
    // Send POST request to backend
    fetch(`/api/simulate/${type}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log(`Attack ${type} triggered:`, data);
        showToast(`Attack triggered: ${type}`);
    })
    .catch(error => {
        console.error(`Error triggering attack ${type}:`, error);
        // Fallback to Socket.IO if API endpoint doesn't exist
        socket.emit('trigger_attack', { attack_type: type });
    });
}

// Show toast notification
function showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Attack button handler (for backward compatibility)
function setupAttackButtons() {
    // Buttons now use onclick, but keep this for any dynamic buttons
    const buttons = document.querySelectorAll('.attack-btn');
    buttons.forEach(button => {
        if (!button.onclick) {
            button.addEventListener('click', () => {
                const attackType = button.getAttribute('data-attack');
                triggerAttack(attackType);
            });
        }
    });
}

// Handle attack trigger response
socket.on('attack_triggered', (data) => {
    if (data.status === 'success') {
        console.log(`Attack ${data.attack_type} triggered successfully`);
    } else {
        console.error(`Failed to trigger attack: ${data.attack_type}`);
    }
});

// Socket.IO event handlers
socket.on('connect', () => {
    console.log('Connected to dashboard server');
    socket.emit('request_data');
});

socket.on('connected', (data) => {
    console.log('Dashboard connected:', data);
});

// Handle packet_stream events
socket.on('packet_stream', (packet) => {
    addPacketLog(packet);
    
    // Update entropy chart if entropy data is available
    // (entropy is updated separately via entropy_update events)
});

socket.on('packet_feed', (packets) => {
    packets.forEach(packet => {
        addPacketLog(packet);
    });
});

socket.on('new_threat', (threat) => {
    addThreatLog(threat);
});

socket.on('threat_feed', (threats) => {
    threats.forEach(threat => {
        addThreatLog(threat);
    });
});

// Handle honeypot_log events
socket.on('honeypot_log', (hit) => {
    addHoneypotLog(hit);
});

socket.on('honeypot_feed', (hits) => {
    hits.forEach(hit => {
        addHoneypotLog(hit);
    });
});

// Handle entropy updates (from packet_stream or separate events)
socket.on('entropy_update', (data) => {
    updateEntropyChart(data.entropy, data.timestamp);
});

socket.on('entropy_data', (data) => {
    data.forEach(point => {
        updateEntropyChart(point.entropy, point.timestamp);
    });
});

socket.on('stats_update', (stats) => {
    updateStats(stats);
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initEntropyChart();
    setupAttackButtons();
    console.log('Dashboard initialized');
});

