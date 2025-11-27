"""
Dashboard Server Module - Flask + Socket.IO real-time dashboard
"""
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
import json

class DashboardServer:
    def __init__(self, port=5000):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'cybersecurity_dashboard_secret_key_2024'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='eventlet')
        self.port = port
        self.running = False
        
        # Data stores
        self.packet_feed = []
        self.threat_feed = []
        self.honeypot_feed = []
        self.entropy_data = []
        self.stats = {
            'packets_captured': 0,
            'threats_detected': 0,
            'honeypot_hits': 0,
            'blocked_ips': 0
        }
        
        # Callbacks
        self.attack_trigger_callback = None
        self.stats_callback = None
        
        # Setup routes
        self._setup_routes()
        self._setup_socket_handlers()
    
    def set_attack_trigger_callback(self, callback):
        """Set callback for attack triggers"""
        self.attack_trigger_callback = callback
    
    def set_stats_callback(self, callback):
        """Set callback for stats API endpoint"""
        self.stats_callback = callback
    
    def _setup_routes(self):
        """Setup Flask routes"""
        @self.app.route('/')
        def index():
            return render_template('dashboard.html')
        
        @self.app.route('/api/stats', methods=['GET'])
        def get_stats():
            """API endpoint for system statistics"""
            if hasattr(self, 'stats_callback') and self.stats_callback:
                stats = self.stats_callback()
                return jsonify(stats)
            return jsonify({
                'packets_scanned': self.stats.get('packets_captured', 0),
                'threats_detected': self.stats.get('threats_detected', 0),
                'honeypot_hits': self.stats.get('honeypot_hits', 0),
                'blocked_ips': self.stats.get('blocked_ips', 0)
            })
        
        @self.app.route('/api/simulate/<attack_type>', methods=['POST'])
        def simulate_attack(attack_type):
            """API endpoint for attack simulation"""
            if self.attack_trigger_callback:
                success = self.attack_trigger_callback(attack_type)
                if success:
                    return jsonify({'status': 'success', 'attack_type': attack_type})
                else:
                    return jsonify({'status': 'error', 'message': f'Unknown attack type: {attack_type}'}), 400
            return jsonify({'status': 'error', 'message': 'Attack simulator not available'}), 500
    
    def _setup_socket_handlers(self):
        """Setup Socket.IO event handlers"""
        @self.socketio.on('connect')
        def handle_connect():
            print(f"[Dashboard] Client connected")
            emit('connected', {'status': 'connected'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            print(f"[Dashboard] Client disconnected")
        
        @self.socketio.on('request_data')
        def handle_request_data():
            """Send current data to client"""
            # Send as packet_stream events
            for packet in self.packet_feed[-100:]:
                emit('packet_stream', packet)
            emit('threat_feed', self.threat_feed[-50:])
            for hit in self.honeypot_feed[-50:]:
                emit('honeypot_log', hit)
            emit('entropy_data', self.entropy_data[-100:])
            emit('stats_update', self.stats)
        
        @self.socketio.on('trigger_attack')
        def handle_trigger_attack(data):
            """Handle attack trigger request"""
            attack_type = data.get('attack_type')
            if attack_type and self.attack_trigger_callback:
                print(f"[Dashboard] Attack triggered: {attack_type}")
                self.attack_trigger_callback(attack_type)
                emit('attack_triggered', {'attack_type': attack_type, 'status': 'success'})
            else:
                emit('attack_triggered', {'attack_type': attack_type, 'status': 'error'})
    
    def add_packet(self, packet_info):
        """Add packet to feed"""
        packet_entry = {
            'timestamp': time.time(),
            'src_ip': packet_info.get('src_ip', 'N/A'),
            'dst_ip': packet_info.get('dst_ip', 'N/A'),
            'src_port': packet_info.get('src_port', 'N/A'),
            'dst_port': packet_info.get('dst_port', 'N/A'),
            'protocol': packet_info.get('protocol', 'N/A'),
            'size': packet_info.get('size', 0),
            'flags': packet_info.get('flags', 'N/A')
        }
        
        self.packet_feed.append(packet_entry)
        if len(self.packet_feed) > 1000:
            self.packet_feed.pop(0)
        
        self.stats['packets_captured'] += 1
        
        # Emit to all clients (using packet_stream as required)
        self.socketio.emit('packet_stream', packet_entry)
        self.socketio.emit('stats_update', self.stats)
    
    def add_threat(self, threat_info):
        """Add threat to feed"""
        threat_entry = {
            'timestamp': time.time(),
            'threat_type': threat_info.get('threat_type', 'Unknown'),
            'severity': threat_info.get('severity', 'low'),
            'src_ip': threat_info.get('src_ip', 'N/A'),
            'dst_ip': threat_info.get('dst_ip', 'N/A'),
            'threat_score': threat_info.get('threat_score', 0),
            'description': threat_info.get('description', 'No description')
        }
        
        self.threat_feed.append(threat_entry)
        if len(self.threat_feed) > 500:
            self.threat_feed.pop(0)
        
        self.stats['threats_detected'] += 1
        
        # Emit to all clients
        self.socketio.emit('new_threat', threat_entry)
        self.socketio.emit('stats_update', self.stats)
    
    def add_honeypot_hit(self, hit_info):
        """Add honeypot hit to feed"""
        hit_entry = {
            'timestamp': time.time(),
            'service': hit_info.get('service', 'Unknown'),
            'client_ip': hit_info.get('client_ip', 'N/A'),
            'client_port': hit_info.get('client_port', 'N/A'),
            'details': hit_info.get('details', {})
        }
        
        self.honeypot_feed.append(hit_entry)
        if len(self.honeypot_feed) > 500:
            self.honeypot_feed.pop(0)
        
        self.stats['honeypot_hits'] += 1
        
        # Emit to all clients (using honeypot_log as required)
        self.socketio.emit('honeypot_log', hit_entry)
        self.socketio.emit('stats_update', self.stats)
    
    def update_entropy(self, entropy_value):
        """Update entropy data"""
        entropy_entry = {
            'timestamp': time.time(),
            'entropy': entropy_value
        }
        
        self.entropy_data.append(entropy_entry)
        if len(self.entropy_data) > 500:
            self.entropy_data.pop(0)
        
        # Emit to all clients
        self.socketio.emit('entropy_update', entropy_entry)
    
    def update_stats(self, stats):
        """Update statistics"""
        self.stats.update(stats)
        self.socketio.emit('stats_update', self.stats)
    
    def start(self):
        """Start the dashboard server (called from main, but actual run happens in main.py)"""
        self.running = True
        print(f"[Dashboard Server] Routes configured for port {self.port}")
    
    def stop(self):
        """Stop the dashboard server"""
        self.running = False

