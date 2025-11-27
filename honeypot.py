"""
Honeypot Module - HTTP, SSH, and FTP honeypot services
"""
import socket
import threading
import time
from datetime import datetime

class Honeypot:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback  # For SQLite storage
        self.running = False
        self.servers = {}
        self.connections = []
        self.hit_log = []
        
    def _log_hit(self, service, client_ip, client_port, details, raw_request_text=""):
        """Log honeypot hit and call callbacks"""
        hit = {
            'timestamp': time.time(),
            'service': service,
            'client_ip': client_ip,
            'client_port': client_port,
            'details': details
        }
        self.hit_log.append(hit)
        
        # Call standard callback for dashboard
        if self.callback:
            self.callback(hit)
        
        # Call log_callback for SQLite storage with metadata dict
        if self.log_callback:
            metadata = {
                'service': service,
                'port': self._get_service_port(service),
                'details': details,
                'raw_request': raw_request_text
            }
            message = f"Honeypot hit: {service} from {client_ip}:{client_port}"
            self.log_callback(message, metadata)
        
        print(f"[Honeypot {service}] Hit from {client_ip}:{client_port} - {details}")
        return hit
    
    def _get_service_port(self, service):
        """Get port number for service"""
        port_map = {'HTTP': 8888, 'SSH': 2222, 'FTP': 2121}
        return port_map.get(service, 0)
    
    def _http_honeypot(self, port=8888):
        """HTTP Honeypot Service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(10)
            sock.settimeout(1.0)
            
            print(f"[Honeypot HTTP] Listening on port {port}")
            
            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    client_ip, client_port = addr
                    
                    # Log connection
                    self._log_hit('HTTP', client_ip, client_port, 'Connection established')
                    
                    # Handle request in thread
                    thread = threading.Thread(
                        target=self._handle_http_request,
                        args=(client_sock, client_ip, client_port),
                        daemon=True
                    )
                    thread.start()
                    self.connections.append(thread)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[Honeypot HTTP] Error: {e}")
                    
        except Exception as e:
            print(f"[Honeypot HTTP] Failed to start: {e}")
    
    def _handle_http_request(self, client_sock, client_ip, client_port):
        """Handle HTTP request"""
        try:
            client_sock.settimeout(5.0)
            data = client_sock.recv(4096).decode('utf-8', errors='ignore')
            
            if data:
                # Parse request
                lines = data.split('\n')
                if lines:
                    request_line = lines[0].strip()
                    method = request_line.split()[0] if len(request_line.split()) > 0 else 'UNKNOWN'
                    path = request_line.split()[1] if len(request_line.split()) > 1 else '/'
                    
                    # Extract headers
                    headers = {}
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()
                    
                    # Log request details
                    user_agent = headers.get('User-Agent', 'Unknown')
                    raw_request = data[:500]  # Limit size
                    self._log_hit('HTTP', client_ip, client_port, {
                        'method': method,
                        'path': path,
                        'user_agent': user_agent,
                        'headers': headers
                    }, raw_request_text=raw_request)
                    
                    # Send fake response
                    response = "HTTP/1.1 200 OK\r\n"
                    response += "Content-Type: text/html\r\n"
                    response += "Connection: close\r\n"
                    response += "\r\n"
                    response += "<html><head><title>Welcome</title></head>"
                    response += "<body><h1>Welcome to Server</h1>"
                    response += "<p>This is a secure server.</p>"
                    response += "<form method='POST' action='/login'>"
                    response += "<input type='text' name='username' placeholder='Username'>"
                    response += "<input type='password' name='password' placeholder='Password'>"
                    response += "<input type='submit' value='Login'>"
                    response += "</form></body></html>"
                    
                    client_sock.send(response.encode())
                    
                    # Check for SQL injection or XSS in path/headers
                    suspicious_patterns = ["'", "OR", "UNION", "<script", "javascript:", "../"]
                    for pattern in suspicious_patterns:
                        if pattern.lower() in data.lower():
                            self._log_hit('HTTP', client_ip, client_port, {
                                'suspicious_pattern': pattern,
                                'type': 'potential_attack'
                            }, raw_request_text=raw_request)
            
            client_sock.close()
            
        except Exception as e:
            pass
    
    def _ssh_honeypot(self, port=2222):
        """SSH Honeypot Service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(10)
            sock.settimeout(1.0)
            
            print(f"[Honeypot SSH] Listening on port {port}")
            
            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    client_ip, client_port = addr
                    
                    # Log connection
                    self._log_hit('SSH', client_ip, client_port, 'Connection attempt')
                    
                    # Handle in thread
                    thread = threading.Thread(
                        target=self._handle_ssh_connection,
                        args=(client_sock, client_ip, client_port),
                        daemon=True
                    )
                    thread.start()
                    self.connections.append(thread)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[Honeypot SSH] Error: {e}")
                        
        except Exception as e:
            print(f"[Honeypot SSH] Failed to start: {e}")
    
    def _handle_ssh_connection(self, client_sock, client_ip, client_port):
        """Handle SSH connection"""
        try:
            client_sock.settimeout(10.0)
            
            # Send fake SSH banner
            banner = "SSH-2.0-OpenSSH_7.4\r\n"
            client_sock.send(banner.encode())
            
            # Try to receive data
            data = client_sock.recv(4096)
            
            if data:
                raw_data = data.decode('utf-8', errors='ignore')[:200]
                # Log authentication attempt
                self._log_hit('SSH', client_ip, client_port, {
                    'type': 'authentication_attempt',
                    'data': raw_data
                }, raw_request_text=raw_data)
                
                # Common usernames to detect brute force
                common_users = ['admin', 'root', 'user', 'test', 'guest']
                data_str = raw_data.lower()
                for user in common_users:
                    if user in data_str:
                        self._log_hit('SSH', client_ip, client_port, {
                            'type': 'brute_force_attempt',
                            'username': user
                        }, raw_request_text=raw_data)
            
            # Send fake error and close
            error_msg = "Permission denied (publickey,password).\r\n"
            client_sock.send(error_msg.encode())
            client_sock.close()
            
        except Exception as e:
            pass
    
    def _ftp_honeypot(self, port=2121):
        """FTP Honeypot Service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.listen(10)
            sock.settimeout(1.0)
            
            print(f"[Honeypot FTP] Listening on port {port}")
            
            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    client_ip, client_port = addr
                    
                    # Log connection
                    self._log_hit('FTP', client_ip, client_port, 'Connection attempt')
                    
                    # Handle in thread
                    thread = threading.Thread(
                        target=self._handle_ftp_connection,
                        args=(client_sock, client_ip, client_port),
                        daemon=True
                    )
                    thread.start()
                    self.connections.append(thread)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[Honeypot FTP] Error: {e}")
                        
        except Exception as e:
            print(f"[Honeypot FTP] Failed to start: {e}")
    
    def _handle_ftp_connection(self, client_sock, client_ip, client_port):
        """Handle FTP connection"""
        try:
            client_sock.settimeout(10.0)
            
            # Send FTP welcome banner
            banner = "220 Welcome to FTP Server\r\n"
            client_sock.send(banner.encode())
            
            # Handle FTP commands
            while True:
                try:
                    data = client_sock.recv(1024)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip().upper()
                    raw_command = data.decode('utf-8', errors='ignore')[:200]
                    
                    # Log command
                    self._log_hit('FTP', client_ip, client_port, {
                        'type': 'command',
                        'command': command
                    }, raw_request_text=raw_command)
                    
                    # Handle common commands
                    if command.startswith('USER'):
                        username = command.split()[1] if len(command.split()) > 1 else 'anonymous'
                        self._log_hit('FTP', client_ip, client_port, {
                            'type': 'login_attempt',
                            'username': username
                        }, raw_request_text=raw_command)
                        response = "331 Password required\r\n"
                        client_sock.send(response.encode())
                    
                    elif command.startswith('PASS'):
                        password = command.split()[1] if len(command.split()) > 1 else ''
                        self._log_hit('FTP', client_ip, client_port, {
                            'type': 'password_attempt',
                            'password_length': len(password)
                        }, raw_request_text=raw_command)
                        response = "530 Login incorrect\r\n"
                        client_sock.send(response.encode())
                    
                    elif command.startswith('QUIT'):
                        response = "221 Goodbye\r\n"
                        client_sock.send(response.encode())
                        break
                    
                    elif command.startswith('PASV') or command.startswith('PORT'):
                        response = "200 Command okay\r\n"
                        client_sock.send(response.encode())
                    
                    else:
                        response = "502 Command not implemented\r\n"
                        client_sock.send(response.encode())
                    
                except socket.timeout:
                    break
                except:
                    break
            
            client_sock.close()
            
        except Exception as e:
            pass
    
    def start(self, http_port=8888, ssh_port=2222, ftp_port=2121):
        """Start all honeypot services"""
        if self.running:
            return
        
        self.running = True
        
        # Start HTTP honeypot
        http_thread = threading.Thread(
            target=self._http_honeypot,
            args=(http_port,),
            daemon=True
        )
        http_thread.start()
        self.servers['HTTP'] = http_thread
        
        # Start SSH honeypot
        ssh_thread = threading.Thread(
            target=self._ssh_honeypot,
            args=(ssh_port,),
            daemon=True
        )
        ssh_thread.start()
        self.servers['SSH'] = ssh_thread
        
        # Start FTP honeypot
        ftp_thread = threading.Thread(
            target=self._ftp_honeypot,
            args=(ftp_port,),
            daemon=True
        )
        ftp_thread.start()
        self.servers['FTP'] = ftp_thread
        
        print("[Honeypot] All services started")
    
    def stop(self):
        """Stop all honeypot services"""
        self.running = False
        print("[Honeypot] Stopping all services...")
    
    def get_recent_hits(self, count=50):
        """Get recent honeypot hits"""
        return self.hit_log[-count:]
    
    def get_statistics(self):
        """Get honeypot statistics"""
        stats = {
            'total_hits': len(self.hit_log),
            'http_hits': len([h for h in self.hit_log if h['service'] == 'HTTP']),
            'ssh_hits': len([h for h in self.hit_log if h['service'] == 'SSH']),
            'ftp_hits': len([h for h in self.hit_log if h['service'] == 'FTP']),
            'unique_ips': len(set(h['client_ip'] for h in self.hit_log))
        }
        return stats

