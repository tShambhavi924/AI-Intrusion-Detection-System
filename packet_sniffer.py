"""
Packet Sniffer Module - Real-time network packet capture using Scapy
"""
import threading
import time
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import socket
import struct

class PacketSniffer:
    def __init__(self, callback=None, max_packets=1000):
        self.callback = callback
        self.max_packets = max_packets
        self.packet_queue = deque(maxlen=max_packets)
        self.running = False
        self.sniffer_thread = None
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'bytes_captured': 0
        }
        
    def _get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _process_packet(self, packet):
        """Process captured packet and extract features"""
        try:
            packet_info = {
                'timestamp': time.time(),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None,
                'size': len(packet),
                'payload_size': 0,
                'payload_bytes': None,
                'flags': None,
                'raw_data': None
            }
            
            # Extract IP layer
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
                # Extract TCP layer
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    packet_info['flags'] = str(packet[TCP].flags)
                    self.stats['tcp_packets'] += 1
                    
                    # Check for HTTP
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        if Raw in packet:
                            try:
                                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                                packet_info['raw_data'] = payload[:500]  # Limit size
                                if 'HTTP' in payload or 'GET' in payload or 'POST' in payload:
                                    self.stats['http_packets'] += 1
                            except:
                                pass
                
                # Extract UDP layer
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    self.stats['udp_packets'] += 1
                
                # Extract ICMP layer
                elif ICMP in packet:
                    self.stats['icmp_packets'] += 1
                
                # Extract payload bytes
                if Raw in packet:
                    payload_bytes = packet[Raw].load
                    packet_info['payload_size'] = len(payload_bytes)
                    packet_info['payload_bytes'] = payload_bytes  # Store raw bytes
                    if not packet_info['raw_data']:
                        try:
                            payload = payload_bytes.decode('utf-8', errors='ignore')
                            packet_info['raw_data'] = payload[:200]
                        except:
                            packet_info['raw_data'] = str(payload_bytes[:100])  # Fallback to hex representation
            
            # Update stats
            self.stats['total_packets'] += 1
            self.stats['bytes_captured'] += packet_info['size']
            
            # Add to queue
            self.packet_queue.append(packet_info)
            
            # Callback for real-time processing
            if self.callback:
                self.callback(packet_info)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start(self, interface=None):
        """Start packet sniffing"""
        if self.running:
            return
        
        self.running = True
        
        def sniff_loop():
            try:
                # Use filter to capture relevant traffic
                filter_str = "tcp or udp or icmp"
                sniff(
                    iface=interface,
                    prn=self._process_packet,
                    filter=filter_str,
                    stop_filter=lambda x: not self.running,
                    store=False
                )
            except Exception as e:
                print(f"Sniffer error: {e}")
                self.running = False
        
        self.sniffer_thread = threading.Thread(target=sniff_loop, daemon=True)
        self.sniffer_thread.start()
        print(f"[Packet Sniffer] Started on interface: {interface or 'default'}")
    
    def stop(self):
        """Stop packet sniffing"""
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        print("[Packet Sniffer] Stopped")
    
    def get_recent_packets(self, count=50):
        """Get recent packets"""
        return list(self.packet_queue)[-count:]
    
    def get_stats(self):
        """Get capture statistics"""
        return self.stats.copy()

