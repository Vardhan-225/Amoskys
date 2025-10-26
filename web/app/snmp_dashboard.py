"""
Quick SNMP Dashboard Test
Creates a simple HTML page showing SNMP metrics without database queries
"""

from flask import Blueprint, render_template_string

snmp_test_bp = Blueprint('snmp_test', __name__, url_prefix='/snmp')

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AMOSKYS SNMP Telemetry Dashboard</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 40px 20px;
            background: rgba(0, 255, 136, 0.05);
            border-radius: 10px;
            margin-bottom: 30px;
            border: 1px solid rgba(0, 255, 136, 0.2);
        }
        h1 {
            color: #00ff88;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }
        .subtitle {
            color: #a0a0a0;
            font-size: 1.2em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(22, 33, 62, 0.8);
            padding: 25px;
            border-radius: 10px;
            border: 1px solid rgba(0, 255, 136, 0.2);
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: #00ff88;
        }
        .stat-label {
            color: #a0a0a0;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        .stat-value {
            color: #00ff88;
            font-size: 2.5em;
            font-weight: bold;
        }
        .status-online {
            color: #00ff88;
        }
        .status-offline {
            color: #ff4444;
        }
        .device-list {
            background: rgba(22, 33, 62, 0.8);
            padding: 25px;
            border-radius: 10px;
            border: 1px solid rgba(0, 255, 136, 0.2);
            margin-bottom: 30px;
        }
        .device-item {
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 3px solid #00ff88;
        }
        .device-name {
            font-size: 1.2em;
            color: #00ff88;
            margin-bottom: 5px;
        }
        .device-info {
            color: #a0a0a0;
            font-size: 0.9em;
        }
        .refresh-btn {
            background: #00ff88;
            color: #1a1a2e;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            font-size: 1em;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: #00cc6a;
            transform: scale(1.05);
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #666;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🧠⚡ AMOSKYS SNMP Telemetry</h1>
        <p class="subtitle">Real-Time Device Monitoring Dashboard</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total Events</div>
            <div class="stat-value" id="total-events">--</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Active Devices</div>
            <div class="stat-value" id="total-devices">--</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Events (Last Hour)</div>
            <div class="stat-value" id="events-hour">--</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Avg Payload Size</div>
            <div class="stat-value" id="avg-payload">--</div>
        </div>
    </div>

    <div class="device-list">
        <h2 style="color: #00ff88; margin-bottom: 20px;">📡 Monitored Devices</h2>
        <div id="device-container">
            <p style="color: #666;">Loading devices...</p>
        </div>
    </div>

    <div style="text-align: center;">
        <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
    </div>

    <div class="footer">
        <p>AMOSKYS Neural Security Command Platform</p>
        <p>Last Updated: <span id="last-update">Never</span></p>
    </div>

    <script>
        async function loadData() {
            try {
                // Load stats
                const statsRes = await fetch('/api/snmp/stats');
                const stats = await statsRes.json();
                
                document.getElementById('total-events').textContent = stats.total_events || 0;
                document.getElementById('total-devices').textContent = stats.total_devices || 0;
                document.getElementById('events-hour').textContent = stats.events_last_hour || 0;
                document.getElementById('avg-payload').textContent = 
                    stats.avg_payload_bytes ? stats.avg_payload_bytes + ' B' : '0 B';
                
                // Load devices
                const devicesRes = await fetch('/api/snmp/devices');
                const devicesData = await devicesRes.json();
                
                const container = document.getElementById('device-container');
                if (devicesData.devices && devicesData.devices.length > 0) {
                    container.innerHTML = devicesData.devices.map(device => `
                        <div class="device-item">
                            <div class="device-name">
                                <span class="status-${device.status}"">●</span>
                                ${device.device_id}
                            </div>
                            <div class="device-info">
                                Last Seen: ${new Date(device.last_seen).toLocaleString()} |
                                Events: ${device.event_count} |
                                Status: <span class="status-${device.status}">${device.status.toUpperCase()}</span>
                            </div>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = '<p style="color: #666;">No devices found. Waiting for SNMP telemetry...</p>';
                }
                
                document.getElementById('last-update').textContent = new Date().toLocaleString();
            } catch (error) {
                console.error('Error loading data:', error);
                document.getElementById('device-container').innerHTML = 
                    '<p style="color: #ff4444;">Error loading data. Check console for details.</p>';
            }
        }

        // Load data on page load
        loadData();

        // Auto-refresh every 30 seconds
        setInterval(loadData, 30000);
    </script>
</body>
</html>
"""

@snmp_test_bp.route('/dashboard')
def dashboard():
    """SNMP Telemetry Dashboard"""
    return render_template_string(DASHBOARD_HTML)
