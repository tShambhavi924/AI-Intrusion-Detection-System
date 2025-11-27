"""
ML Detector Module - Entropy, heuristic, and statistical anomaly detection
"""
import numpy as np
from collections import deque, defaultdict
import time
import math

class MLDetector:
    def __init__(self, callback=None):
        self.callback = callback
        self.packet_history = deque(maxlen=1000)
        self.entropy_history = deque(maxlen=100)
        self.ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'port_count': set(),
            'protocol_count': defaultdict(int),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'bytes_sent': 0,
            'bytes_received': 0
        })
        self.port_stats = defaultdict(lambda: {
            'connection_count': 0,
            'unique_ips': set(),
            'last_activity': time.time()
        })
        self.baseline_entropy = 0.0
        self.entropy_samples = deque(maxlen=100)
        
        # Rolling statistics for anomaly detection
        self.size_samples = deque(maxlen=100)
        self.entropy_samples_stats = deque(maxlen=100)
        self.packet_rate_samples = deque(maxlen=100)
        self.size_mean = 0.0
        self.size_std = 0.0
        self.entropy_mean = 0.0
        self.entropy_std = 0.0
        self.rate_mean = 0.0
        self.rate_std = 0.0
        self.last_packet_time = time.time()
        
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data or len(data) == 0:
            return 0.0
        
        # Convert to bytes if string
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')
        
        # Calculate byte frequency
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_anomalies(self, packet_info):
        """Detect anomalies using multiple methods. Returns dict with threat_score (0..1), classification, entropy, features"""
        anomalies = []
        threat_score_raw = 0.0
        
        # Add to history
        self.packet_history.append(packet_info)
        
        # Update rolling statistics
        self._update_rolling_stats(packet_info)
        
        # Update IP statistics
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        if src_ip:
            self._update_ip_stats(src_ip, packet_info, is_source=True)
        if dst_ip:
            self._update_ip_stats(dst_ip, packet_info, is_source=False)
        
        # 1. Entropy-based detection
        entropy_anomaly = self._detect_entropy_anomaly(packet_info)
        if entropy_anomaly:
            anomalies.append(entropy_anomaly)
            threat_score_raw += 0.3
        
        # 2. Port scan detection (heuristic)
        port_scan = self._detect_port_scan(packet_info)
        if port_scan:
            anomalies.append(port_scan)
            threat_score_raw += 0.5
        
        # 3. Statistical anomaly detection
        stat_anomaly = self._detect_statistical_anomaly(packet_info)
        if stat_anomaly:
            anomalies.append(stat_anomaly)
            threat_score_raw += 0.4
        
        # 4. Protocol anomaly
        protocol_anomaly = self._detect_protocol_anomaly(packet_info)
        if protocol_anomaly:
            anomalies.append(protocol_anomaly)
            threat_score_raw += 0.25
        
        # 5. Payload analysis (heuristic)
        payload_anomaly = self._detect_payload_anomaly(packet_info)
        if payload_anomaly:
            anomalies.append(payload_anomaly)
            threat_score_raw += 0.35
        
        # 6. Rate-based anomaly
        rate_anomaly = self._detect_rate_anomaly(packet_info)
        if rate_anomaly:
            anomalies.append(rate_anomaly)
            threat_score_raw += 0.45
        
        # Normalize threat score to 0..1 range
        threat_score = min(1.0, threat_score_raw)
        
        # Calculate entropy
        current_entropy = self.entropy_history[-1] if self.entropy_history else 0.0
        
        # Determine classification
        if threat_score < 0.3:
            classification = "Normal"
        elif threat_score < 0.7:
            classification = "Suspicious Traffic"
        else:
            classification = "Malware/C2 Activity"
        
        # Build features dict
        features = {
            'packet_size': packet_info.get('size', 0),
            'payload_size': packet_info.get('payload_size', 0),
            'entropy': current_entropy,
            'protocol': packet_info.get('protocol', 'unknown'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'anomaly_count': len(anomalies)
        }
        
        # Always return detection dict, even for normal traffic
        detection = {
            'timestamp': time.time(),
            'packet_info': packet_info,
            'anomalies': anomalies,
            'threat_score': threat_score,
            'classification': classification,
            'entropy': current_entropy,
            'features': features
        }
        
        # Only call callback if threat score is significant
        if threat_score >= 0.3 and self.callback:
            self.callback(detection)
        
        return detection
    
    def _update_rolling_stats(self, packet_info):
        """Update rolling statistics for size, entropy, and packet rate"""
        # Update size statistics
        packet_size = packet_info.get('size', 0)
        self.size_samples.append(packet_size)
        if len(self.size_samples) >= 10:
            self.size_mean = np.mean(list(self.size_samples))
            self.size_std = np.std(list(self.size_samples))
        
        # Update entropy statistics (already maintained in entropy_samples)
        if len(self.entropy_samples) >= 10:
            self.entropy_mean = np.mean(list(self.entropy_samples))
            self.entropy_std = np.std(list(self.entropy_samples))
        
        # Update packet rate statistics
        current_time = time.time()
        time_delta = current_time - self.last_packet_time
        if time_delta > 0:
            rate = 1.0 / time_delta
            self.packet_rate_samples.append(rate)
            if len(self.packet_rate_samples) >= 10:
                self.rate_mean = np.mean(list(self.packet_rate_samples))
                self.rate_std = np.std(list(self.packet_rate_samples))
        self.last_packet_time = current_time
    
    def _update_ip_stats(self, ip, packet_info, is_source=True):
        """Update statistics for an IP address"""
        stats = self.ip_stats[ip]
        stats['packet_count'] += 1
        stats['last_seen'] = time.time()
        
        if packet_info.get('src_port'):
            stats['port_count'].add(packet_info['src_port'])
        if packet_info.get('dst_port'):
            stats['port_count'].add(packet_info['dst_port'])
        
        protocol = packet_info.get('protocol', 'unknown')
        stats['protocol_count'][protocol] += 1
        
        if is_source:
            stats['bytes_sent'] += packet_info.get('size', 0)
        else:
            stats['bytes_received'] += packet_info.get('size', 0)
    
    def _detect_entropy_anomaly(self, packet_info):
        """Detect anomalies based on payload entropy"""
        payload = packet_info.get('raw_data', '')
        if not payload:
            return None
        
        entropy = self.calculate_entropy(payload)
        self.entropy_history.append(entropy)
        self.entropy_samples.append(entropy)
        
        # Calculate baseline if we have enough samples
        if len(self.entropy_samples) >= 20:
            self.baseline_entropy = np.mean(list(self.entropy_samples))
            std_dev = np.std(list(self.entropy_samples))
            
            # High entropy (encrypted/compressed) or very low entropy (repetitive)
            if entropy > self.baseline_entropy + 2 * std_dev:
                return {
                    'type': 'high_entropy',
                    'severity': 'medium',
                    'entropy': entropy,
                    'baseline': self.baseline_entropy,
                    'description': f'Unusually high entropy detected ({entropy:.2f}) - possible encryption or obfuscation'
                }
            elif entropy < self.baseline_entropy - 2 * std_dev and entropy < 2.0:
                return {
                    'type': 'low_entropy',
                    'severity': 'low',
                    'entropy': entropy,
                    'baseline': self.baseline_entropy,
                    'description': f'Unusually low entropy detected ({entropy:.2f}) - possible repetitive pattern'
                }
        
        return None
    
    def _detect_port_scan(self, packet_info):
        """Detect port scanning behavior"""
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return None
        
        stats = self.ip_stats[src_ip]
        
        # Check if IP is scanning multiple ports
        unique_ports = len(stats['port_count'])
        packet_count = stats['packet_count']
        time_window = time.time() - stats['first_seen']
        
        # Heuristic: Many unique ports in short time
        if time_window > 0:
            ports_per_second = unique_ports / time_window
            if unique_ports >= 5 and ports_per_second > 2:
                return {
                    'type': 'port_scan',
                    'severity': 'high',
                    'unique_ports': unique_ports,
                    'ports_per_second': ports_per_second,
                    'description': f'Possible port scan: {unique_ports} unique ports scanned in {time_window:.1f}s'
                }
        
        return None
    
    def _detect_statistical_anomaly(self, packet_info):
        """Detect statistical anomalies"""
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return None
        
        stats = self.ip_stats[src_ip]
        packet_count = stats['packet_count']
        time_window = time.time() - stats['first_seen']
        
        if time_window > 0:
            packets_per_second = packet_count / time_window
            
            # High packet rate
            if packets_per_second > 50:
                return {
                    'type': 'high_packet_rate',
                    'severity': 'high',
                    'packets_per_second': packets_per_second,
                    'description': f'Unusually high packet rate: {packets_per_second:.1f} packets/second'
                }
            
            # Many different protocols
            if len(stats['protocol_count']) > 5:
                return {
                    'type': 'protocol_diversity',
                    'severity': 'medium',
                    'protocols': dict(stats['protocol_count']),
                    'description': f'Unusual protocol diversity: {len(stats["protocol_count"])} different protocols'
                }
        
        return None
    
    def _detect_protocol_anomaly(self, packet_info):
        """Detect protocol-specific anomalies"""
        protocol = packet_info.get('protocol')
        flags = packet_info.get('flags')
        
        # TCP flag anomalies
        if flags is not None:
            # SYN flood (many SYN without ACK)
            # This is simplified - real detection needs more context
            pass
        
        # Unusual port usage
        dst_port = packet_info.get('dst_port')
        if dst_port:
            if dst_port < 1024 and dst_port not in [22, 23, 25, 53, 80, 443, 8080]:
                return {
                    'type': 'unusual_port',
                    'severity': 'low',
                    'port': dst_port,
                    'description': f'Connection to unusual port: {dst_port}'
                }
        
        return None
    
    def _detect_payload_anomaly(self, packet_info):
        """Detect anomalies in packet payload"""
        payload = packet_info.get('raw_data', '')
        if not payload:
            return None
        
        payload_lower = payload.lower()
        
        # SQL injection patterns
        sql_patterns = ["' or '1'='1", "union select", "drop table", "'; --", "exec("]
        for pattern in sql_patterns:
            if pattern in payload_lower:
                return {
                    'type': 'sql_injection_pattern',
                    'severity': 'high',
                    'pattern': pattern,
                    'description': f'SQL injection pattern detected: {pattern}'
                }
        
        # XSS patterns
        xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "alert("]
        for pattern in xss_patterns:
            if pattern in payload_lower:
                return {
                    'type': 'xss_pattern',
                    'severity': 'high',
                    'pattern': pattern,
                    'description': f'XSS pattern detected: {pattern}'
                }
        
        # Suspicious commands
        cmd_patterns = ["/bin/sh", "cmd.exe", "powershell", "wget", "curl", "nc ", "netcat"]
        for pattern in cmd_patterns:
            if pattern in payload_lower:
                return {
                    'type': 'command_injection',
                    'severity': 'high',
                    'pattern': pattern,
                    'description': f'Command injection pattern detected: {pattern}'
                }
        
        # Unusually large payload
        payload_size = packet_info.get('payload_size', 0)
        if payload_size > 10000:
            return {
                'type': 'large_payload',
                'severity': 'medium',
                'size': payload_size,
                'description': f'Unusually large payload: {payload_size} bytes'
            }
        
        return None
    
    def _detect_rate_anomaly(self, packet_info):
        """Detect rate-based anomalies"""
        # Check recent packet rate
        if len(self.packet_history) < 10:
            return None
        
        recent_packets = list(self.packet_history)[-10:]
        time_span = recent_packets[-1]['timestamp'] - recent_packets[0]['timestamp']
        
        if time_span > 0:
            rate = len(recent_packets) / time_span
            
            # Very high rate (potential DDoS)
            if rate > 100:
                return {
                    'type': 'ddos_pattern',
                    'severity': 'critical',
                    'packets_per_second': rate,
                    'description': f'Potential DDoS: {rate:.1f} packets/second detected'
                }
        
        return None
    
    def get_entropy_history(self, count=100):
        """Get entropy history for visualization"""
        return list(self.entropy_history)[-count:]
    
    def get_statistics(self):
        """Get detection statistics"""
        return {
            'total_packets_analyzed': len(self.packet_history),
            'unique_ips': len(self.ip_stats),
            'baseline_entropy': self.baseline_entropy,
            'current_entropy': self.entropy_history[-1] if self.entropy_history else 0.0
        }

