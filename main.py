"""
Main Entry Point - AI-Powered Intrusion Detection & Live Network Attack Simulation System
Orchestrates all components: packet sniffer, ML detector, threat engine, honeypots, and dashboard
"""
import time
import signal
import sys
import threading
from packet_sniffer import PacketSniffer
from ml_detector import MLDetector
from threat_engine import ThreatEngine
from honeypot import Honeypot
from dashboard_server import DashboardServer
from attack_simulator import AttackSimulator

class IDSSystem:
    def __init__(self):
        # Initialize ThreatEngine with SQLite database
        self.threat_engine = ThreatEngine(block_threshold=0.7)  # 0..1 range
        
        # Initialize MLDetector with callback
        self.ml_detector = MLDetector(callback=self._on_detection)
        
        # Initialize PacketSniffer with callback
        self.packet_sniffer = PacketSniffer(callback=self._on_packet)
        
        # Initialize DashboardServer
        self.dashboard = DashboardServer(port=5000)
        
        # Setup honeypot with callbacks for dashboard and SQLite
        self.honeypot = Honeypot(
            callback=self._on_honeypot_hit,
            log_callback=self._on_honeypot_log
        )
        
        # Initialize AttackSimulator
        self.attack_simulator = AttackSimulator(
            target_ip="127.0.0.1",
            callback=self._on_attack_event
        )
        
        # Register callbacks with dashboard
        self.dashboard.set_attack_trigger_callback(self.trigger_attack)
        self.dashboard.set_stats_callback(self._get_system_stats)
        
        self.running = False
        self.packet_count = 0
        self.unique_ips = set()
    
    def _on_honeypot_log(self, message, metadata):
        """Handle honeypot log callback - emit Socket.IO and store in SQLite"""
        try:
            # Extract information from metadata
            service_name = metadata.get('service', 'Unknown')
            port = metadata.get('port', 0)
            raw_request = metadata.get('raw_request', '')
            
            # Get IP and timestamp from most recent hit
            src_ip = '127.0.0.1'
            timestamp = time.time()
            if self.honeypot.hit_log:
                last_hit = self.honeypot.hit_log[-1]
                src_ip = last_hit.get('client_ip', '127.0.0.1')
                timestamp = last_hit.get('timestamp', time.time())
            
            # Emit honeypot_log via Socket.IO
            hit_entry = {
                'timestamp': timestamp,
                'service': service_name,
                'client_ip': src_ip,
                'client_port': last_hit.get('client_port', 0) if self.honeypot.hit_log else 0,
                'details': metadata.get('details', {})
            }
            self.dashboard.socketio.emit('honeypot_log', hit_entry)
            
            # Store in SQLite via ThreatEngine
            self.threat_engine.store_honeypot_event(
                timestamp=timestamp,
                src_ip=src_ip,
                port=port,
                service_name=service_name,
                raw_request_text=str(raw_request)[:1000]  # Limit size, ensure string
            )
        except Exception as e:
            print(f"[System] Error in honeypot log callback: {e}")
        
    def _on_packet(self, packet_info):
        """Handle new packet - wire PacketSniffer → MLDetector → ThreatEngine → Socket.IO"""
        # Track packet count and unique IPs
        self.packet_count += 1
        if packet_info.get('src_ip'):
            self.unique_ips.add(packet_info.get('src_ip'))
        
        # Emit packet_stream via Socket.IO
        self.dashboard.add_packet(packet_info)
        
        # Send to ML detector for analysis
        detection = self.ml_detector.detect_anomalies(packet_info)
        
        # Update entropy in dashboard if available
        if self.ml_detector.entropy_history:
            latest_entropy = self.ml_detector.entropy_history[-1]
            self.dashboard.update_entropy(latest_entropy)
    
    def _on_detection(self, detection):
        """Handle ML detection - wire MLDetector → ThreatEngine → Socket.IO"""
        # Process through threat engine (stores in SQLite)
        threat_entry = self.threat_engine.process_detection(detection)
        
        if threat_entry:
            # Convert threat_entry to dashboard format
            dashboard_threat = {
                'timestamp': threat_entry.get('timestamp', time.time()),
                'threat_type': threat_entry.get('classification', 'Unknown'),
                'severity': threat_entry.get('severity', 'low'),
                'src_ip': threat_entry.get('src_ip', 'N/A'),
                'dst_ip': threat_entry.get('dst_ip', 'N/A'),
                'threat_score': threat_entry.get('threat_score', 0.0) * 100,  # Convert 0..1 to 0..100 for display
                'description': f"{threat_entry.get('classification', 'Unknown')} - {threat_entry.get('severity', 'low')} severity"
            }
            
            # Emit new_threat via Socket.IO
            self.dashboard.add_threat(dashboard_threat)
            
            # Update stats
            stats = self.threat_engine.get_threat_statistics()
            self.dashboard.update_stats({
                'blocked_ips': stats['currently_blocked']
            })
    
    def _on_honeypot_hit(self, hit_info):
        """Handle honeypot hit - emit to dashboard and optionally flag as threat"""
        # Emit to dashboard (also handled by log_callback, but this is for immediate display)
        self.dashboard.add_honeypot_hit(hit_info)
        
        # Optionally create a threat detection for honeypot interaction
        client_ip = hit_info.get('client_ip')
        if client_ip:
            fake_packet = {
                'src_ip': client_ip,
                'dst_ip': '127.0.0.1',
                'timestamp': time.time()
            }
            
            detection = {
                'timestamp': time.time(),
                'packet_info': fake_packet,
                'anomalies': [{
                    'type': 'honeypot_interaction',
                    'severity': 'medium',
                    'description': f"Honeypot interaction detected on {hit_info.get('service')} service"
                }],
                'threat_score': 0.4,  # 0..1 range
                'classification': 'Suspicious Traffic',
                'features': {}
            }
            
            self.threat_engine.process_detection(detection)
    
    def _on_attack_event(self, attack_event):
        """Handle attack simulation event - log to dashboard"""
        # Log attack events to dashboard as threats (for visualization)
        threat_entry = {
            'timestamp': attack_event.get('timestamp', time.time()),
            'threat_type': f"Simulated {attack_event.get('type', 'attack')}",
            'severity': 'high',
            'src_ip': '127.0.0.1',
            'dst_ip': self.attack_simulator.target_ip,
            'threat_score': 60,  # Display value (0-100)
            'description': f"Attack simulation: {attack_event.get('type')} - {str(attack_event.get('details', ''))[:100]}"
        }
        
        self.dashboard.add_threat(threat_entry)
    
    def _get_system_stats(self):
        """Get system statistics for API endpoint"""
        threat_stats = self.threat_engine.get_threat_statistics()
        honeypot_stats = self.honeypot.get_statistics()
        
        return {
            'packets_scanned': self.packet_count,
            'threats_detected': threat_stats.get('total_threats', 0),
            'unique_ips': len(self.unique_ips),
            'blocked_ips': threat_stats.get('currently_blocked', 0),
            'honeypot_hits': honeypot_stats.get('total_hits', 0),
            'threats_by_severity': threat_stats.get('threats_by_severity', {}),
            'threats_by_classification': threat_stats.get('threats_by_classification', {})
        }
    
    def start(self):
        """Start all system components"""
        if self.running:
            print("[System] Already running")
            return
        
        print("=" * 60)
        print("AI-Powered Intrusion Detection System")
        print("=" * 60)
        print("\n[System] Starting all components...\n")
        
        self.running = True
        
        # Start packet sniffer in background thread
        print("[System] Starting packet sniffer on loopback adapter...")
        try:
            self.packet_sniffer.start(interface="\\Device\\NPF_Loopback")

            print("[System] Packet sniffer started successfully")
        except Exception as e:
            print(f"[System] Warning: Packet sniffer error: {e}")
            print("[System] Continuing without packet capture...")
        
        # Start honeypots in background threads
        print("[System] Starting honeypot services...")
        self.honeypot.start(http_port=8081, ssh_port=22222, ftp_port=21212)

        print("[System] Honeypot services started")
        
        # Start Flask-SocketIO app on 0.0.0.0:5000 (runs in main thread)
        print("[System] Starting Flask-SocketIO server...")
        print(f"[System] Dashboard will be available at: http://0.0.0.0:5000")
        print(f"[System] Also accessible at: http://localhost:5000")
        
        print("\n" + "=" * 60)
        print("System is now running!")
        print("=" * 60)
        print(f"\n[Dashboard] Access at: http://localhost:5000")
        print(f"[Honeypots] HTTP: http://localhost:8888")
        print(f"[Honeypots] SSH: localhost:2222")
        print(f"[Honeypots] FTP: localhost:2121")
        print("\n[System] Press Ctrl+C to stop\n")
        
        # Run Flask-SocketIO app (blocks until stopped)
        # This is the main event loop
        try:
            self.dashboard.socketio.run(
                self.dashboard.app,
                host='0.0.0.0',
                port=5000,
                debug=False,
                use_reloader=False
            )
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"[System] Server error: {e}")
            self.stop()
    
    def stop(self):
        """Stop all system components"""
        print("\n[System] Shutting down...")
        self.running = False
        
        self.packet_sniffer.stop()
        self.honeypot.stop()
        self.dashboard.stop()
        self.attack_simulator.stop_all()
        
        print("[System] All components stopped")
    
    def trigger_attack(self, attack_type):
        """Trigger a simulated attack"""
        print(f"[System] Triggering {attack_type} attack...")
        
        if attack_type == 'port_scan':
            self.attack_simulator.port_scan(duration=10)
        elif attack_type == 'sql_injection':
            self.attack_simulator.sql_injection(duration=5)
        elif attack_type == 'ddos':
            self.attack_simulator.ddos_attack(duration=10, intensity=10)
        elif attack_type == 'malware_c2':
            self.attack_simulator.malware_c2(duration=10)
        else:
            print(f"[System] Unknown attack type: {attack_type}")
            return False
        return True

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[System] Interrupt received, shutting down...")
    if 'system' in globals():
        system.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start system
    system = IDSSystem()
    
    try:
        system.start()
    except Exception as e:
        print(f"[System] Fatal error: {e}")
        system.stop()
        sys.exit(1)

