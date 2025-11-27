"""
Threat Engine Module - Threat scoring, IP blocking, and report generation
"""
import sqlite3
import time
import threading
import os
from collections import defaultdict
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch
import platform
import subprocess

class ThreatEngine:
    def __init__(self, db_path="data/security_events.db", block_threshold=0.7):
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)
        
        self.db_path = db_path
        self.block_threshold = block_threshold  # Now 0..1 range
        self.blocked_ips = set()
        self.threat_log = []
        self.ip_threat_scores = defaultdict(float)
        self.lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database with required schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threats table with required schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                threat_score REAL,
                classification TEXT,
                severity TEXT,
                features_text TEXT
            )
        ''')
        
        # Honeypot events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeypot_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                port INTEGER,
                service_name TEXT,
                raw_request_text TEXT
            )
        ''')
        
        # Blocked IPs table (for reference)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                blocked_at REAL,
                reason TEXT,
                threat_score REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def process_detection(self, detection):
        """Process a detection and update threat scores"""
        with self.lock:
            packet_info = detection.get('packet_info', {})
            src_ip = packet_info.get('src_ip')
            threat_score = detection.get('threat_score', 0.0)  # Now 0..1 range
            classification = detection.get('classification', 'Normal')
            features = detection.get('features', {})
            anomalies = detection.get('anomalies', [])
            
            if not src_ip:
                return None
            
            # Update IP threat score (weighted average)
            current_score = self.ip_threat_scores[src_ip]
            self.ip_threat_scores[src_ip] = (current_score * 0.7) + (threat_score * 0.3)
            
            # Determine severity from threat score
            if threat_score >= 0.8:
                severity = 'critical'
            elif threat_score >= 0.6:
                severity = 'high'
            elif threat_score >= 0.4:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Override with anomaly severity if higher
            max_severity = self._get_max_severity(anomalies)
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            if severity_order.get(max_severity, 0) > severity_order.get(severity, 0):
                severity = max_severity
            
            # Log threat
            threat_entry = {
                'timestamp': detection.get('timestamp', time.time()),
                'src_ip': src_ip,
                'dst_ip': packet_info.get('dst_ip'),
                'protocol': packet_info.get('protocol', 'unknown'),
                'threat_score': threat_score,
                'classification': classification,
                'severity': severity,
                'features_text': str(features)
            }
            
            self.threat_log.append(threat_entry)
            
            # Store in database
            self._store_threat(threat_entry)
            
            # Check if IP should be blocked
            if self.ip_threat_scores[src_ip] >= self.block_threshold and src_ip not in self.blocked_ips:
                self.block_ip(src_ip, f"Threat score exceeded threshold: {self.ip_threat_scores[src_ip]:.3f}")
            
            return threat_entry
    
    def _classify_threat(self, anomalies):
        """Classify threat type from anomalies"""
        if not anomalies:
            return "unknown"
        
        # Priority order
        if any(a.get('type') == 'ddos_pattern' for a in anomalies):
            return "DDoS Attack"
        elif any(a.get('type') == 'port_scan' for a in anomalies):
            return "Port Scan"
        elif any(a.get('type') == 'sql_injection_pattern' for a in anomalies):
            return "SQL Injection"
        elif any(a.get('type') == 'xss_pattern' for a in anomalies):
            return "XSS Attack"
        elif any(a.get('type') == 'command_injection' for a in anomalies):
            return "Command Injection"
        elif any(a.get('type') == 'malware_c2' for a in anomalies):
            return "Malware C2"
        elif any(a.get('type') == 'high_packet_rate' for a in anomalies):
            return "Traffic Anomaly"
        else:
            return "Anomaly Detected"
    
    def _get_max_severity(self, anomalies):
        """Get maximum severity from anomalies"""
        if not anomalies:
            return "low"
        
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity = max(anomalies, key=lambda x: severity_order.get(x.get('severity', 'low'), 0))
        return max_severity.get('severity', 'low')
    
    def _generate_description(self, anomalies):
        """Generate human-readable description"""
        if not anomalies:
            return "Anomaly detected"
        
        descriptions = [a.get('description', '') for a in anomalies[:3]]
        return " | ".join(descriptions)
    
    def _store_threat(self, threat_entry):
        """Store threat in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threats 
                (timestamp, src_ip, dst_ip, protocol, threat_score, classification, severity, features_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_entry['timestamp'],
                threat_entry['src_ip'],
                threat_entry.get('dst_ip'),
                threat_entry.get('protocol', 'unknown'),
                threat_entry['threat_score'],
                threat_entry['classification'],
                threat_entry['severity'],
                threat_entry.get('features_text', '')
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error storing threat: {e}")
    
    def block_ip(self, ip, reason):
        """Block an IP address - best-effort firewall blocking"""
        with self.lock:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                
                try:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason, threat_score)
                        VALUES (?, ?, ?, ?)
                    ''', (ip, time.time(), reason, self.ip_threat_scores.get(ip, 0)))
                    
                    conn.commit()
                    conn.close()
                    
                    print(f"[Threat Engine] Blocked IP: {ip} - {reason}")
                    
                    # Attempt firewall blocking (best-effort, safe)
                    self._firewall_block_ip(ip)
                except Exception as e:
                    print(f"Error blocking IP: {e}")
    
    def _firewall_block_ip(self, ip):
        """Attempt to block IP using system firewall (best-effort, safe)"""
        try:
            system = platform.system()
            
            if system == 'Windows':
                # Windows firewall rule (requires admin)
                try:
                    # Block inbound connections from IP
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name=IDS_Block_{ip}',
                        'dir=in',
                        'action=block',
                        f'remoteip={ip}',
                        'enable=yes'
                    ], check=False, timeout=2, capture_output=True)
                except:
                    pass  # Silently fail if not admin or command unavailable
            
            elif system == 'Linux':
                # iptables rule (requires root)
                try:
                    subprocess.run([
                        'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
                    ], check=False, timeout=2, capture_output=True)
                except:
                    pass  # Silently fail if not root or iptables unavailable
            
            elif system == 'Darwin':  # macOS
                # pfctl rule (requires root)
                try:
                    subprocess.run([
                        'pfctl', '-t', 'blocked_ips', '-T', 'add', ip
                    ], check=False, timeout=2, capture_output=True)
                except:
                    pass  # Silently fail if not root or pfctl unavailable
                    
        except Exception as e:
            # Best-effort: don't crash if firewall blocking fails
            pass
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                
                try:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    
                    cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
                    
                    conn.commit()
                    conn.close()
                    
                    print(f"[Threat Engine] Unblocked IP: {ip}")
                except Exception as e:
                    print(f"Error unblocking IP: {e}")
    
    def is_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def get_recent_threats(self, count=50):
        """Get recent threats"""
        return self.threat_log[-count:]
    
    def get_threat_statistics(self):
        """Get threat statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total threats
        cursor.execute('SELECT COUNT(*) FROM threats')
        total_threats = cursor.fetchone()[0]
        
        # Threats by classification
        cursor.execute('''
            SELECT classification, COUNT(*) as count 
            FROM threats 
            GROUP BY classification 
            ORDER BY count DESC
        ''')
        threats_by_classification = dict(cursor.fetchall())
        
        # Threats by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM threats 
            GROUP BY severity 
            ORDER BY count DESC
        ''')
        threats_by_severity = dict(cursor.fetchall())
        
        # Blocked IPs
        cursor.execute('SELECT COUNT(*) FROM blocked_ips')
        blocked_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_threats': total_threats,
            'threats_by_classification': threats_by_classification,
            'threats_by_severity': threats_by_severity,
            'blocked_ips_count': blocked_count,
            'currently_blocked': len(self.blocked_ips)
        }
    
    def store_honeypot_event(self, timestamp, src_ip, port, service_name, raw_request_text):
        """Store honeypot event in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO honeypot_events (timestamp, src_ip, port, service_name, raw_request_text)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, port, service_name, raw_request_text))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error storing honeypot event: {e}")
    
    def generate_report(self, output_path="threat_report.html", hours=24):
        """Generate HTML/Text report from SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get threats from last N hours
            cutoff_time = time.time() - (hours * 3600)
            cursor.execute('''
                SELECT * FROM threats 
                WHERE timestamp >= ? 
                ORDER BY timestamp DESC
            ''', (cutoff_time,))
            threats = cursor.fetchall()
            
            # Get honeypot events
            cursor.execute('''
                SELECT * FROM honeypot_events 
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
            ''', (cutoff_time,))
            honeypot_events = cursor.fetchall()
            
            # Get statistics
            cursor.execute('SELECT COUNT(*) FROM threats WHERE timestamp >= ?', (cutoff_time,))
            total_threats = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT classification, COUNT(*) FROM threats 
                WHERE timestamp >= ? GROUP BY classification
            ''', (cutoff_time,))
            by_classification = dict(cursor.fetchall())
            
            cursor.execute('''
                SELECT src_ip, COUNT(*) as cnt FROM threats 
                WHERE timestamp >= ? GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
            ''', (cutoff_time,))
            top_ips = cursor.fetchall()
            
            conn.close()
            
            # Generate HTML report
            html_content = self._generate_html_report(
                total_threats, by_classification, top_ips, threats[:100], honeypot_events[:50]
            )
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[Threat Engine] HTML report generated: {output_path}")
            
            # Also generate PDF if reportlab available
            try:
                pdf_path = output_path.replace('.html', '.pdf')
                self.generate_pdf_report(pdf_path, hours)
            except:
                pass
            
            return output_path
            
        except Exception as e:
            print(f"Error generating report: {e}")
            return None
    
    def _generate_html_report(self, total_threats, by_classification, top_ips, threats, honeypot_events):
        """Generate HTML report content"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Threat Report</title>
    <style>
        body {{ font-family: monospace; margin: 20px; background: #0a0a0a; color: #00ff41; }}
        h1 {{ color: #00ff41; text-shadow: 0 0 10px #00ff41; }}
        h2 {{ color: #00ffff; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #00ff41; padding: 8px; text-align: left; }}
        th {{ background: #00ff41; color: #000; }}
        .stat {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>AI-Powered Intrusion Detection System - Threat Report</h1>
    <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>Statistics</h2>
    <div class="stat">Total Threats Detected: <strong>{total_threats}</strong></div>
    <div class="stat">Currently Blocked IPs: <strong>{len(self.blocked_ips)}</strong></div>
    
    <h2>Threats by Classification</h2>
    <table>
        <tr><th>Classification</th><th>Count</th></tr>
"""
        for cls, count in by_classification.items():
            html += f"        <tr><td>{cls}</td><td>{count}</td></tr>\n"
        
        html += """    </table>
    
    <h2>Top Attacker IPs</h2>
    <table>
        <tr><th>IP Address</th><th>Threat Count</th></tr>
"""
        for ip, count in top_ips:
            html += f"        <tr><td>{ip}</td><td>{count}</td></tr>\n"
        
        html += """    </table>
    
    <h2>Recent Threats (Last 100)</h2>
    <table>
        <tr><th>Time</th><th>Source IP</th><th>Classification</th><th>Severity</th><th>Score</th></tr>
"""
        for threat in threats:
            timestamp = time.strftime('%H:%M:%S', time.localtime(threat[1]))
            html += f"        <tr><td>{timestamp}</td><td>{threat[2]}</td><td>{threat[6]}</td><td>{threat[7]}</td><td>{threat[5]:.3f}</td></tr>\n"
        
        html += """    </table>
    
    <h2>Honeypot Events (Last 50)</h2>
    <table>
        <tr><th>Time</th><th>Source IP</th><th>Service</th><th>Port</th></tr>
"""
        for event in honeypot_events:
            timestamp = time.strftime('%H:%M:%S', time.localtime(event[1]))
            html += f"        <tr><td>{timestamp}</td><td>{event[2]}</td><td>{event[4]}</td><td>{event[3]}</td></tr>\n"
        
        html += """    </table>
</body>
</html>"""
        return html
    
    def generate_pdf_report(self, filename="threat_report.pdf", hours=24):
        """Generate PDF report of threats"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get threats from last N hours
            cutoff_time = time.time() - (hours * 3600)
            cursor.execute('''
                SELECT * FROM threats 
                WHERE timestamp >= ? 
                ORDER BY timestamp DESC
            ''', (cutoff_time,))
            
            threats = cursor.fetchall()
            
            # Get blocked IPs
            cursor.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC')
            blocked_ips = cursor.fetchall()
            
            conn.close()
            
            # Create PDF
            doc = SimpleDocTemplate(filename, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#00ff41'),
                spaceAfter=30
            )
            
            story.append(Paragraph("AI-Powered Intrusion Detection System", title_style))
            story.append(Paragraph(f"Threat Report - {time.strftime('%Y-%m-%d %H:%M:%S')}", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            # Statistics
            stats = self.get_threat_statistics()
            stats_data = [
                ['Metric', 'Value'],
                ['Total Threats Detected', str(stats['total_threats'])],
                ['Currently Blocked IPs', str(stats['currently_blocked'])],
                ['High Severity Threats', str(stats['threats_by_severity'].get('high', 0))],
                ['Critical Severity Threats', str(stats['threats_by_severity'].get('critical', 0))]
            ]
            
            stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(Paragraph("Statistics", styles['Heading2']))
            story.append(stats_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Threats by Classification
            if stats.get('threats_by_classification'):
                story.append(Paragraph("Threats by Classification", styles['Heading2']))
                type_data = [['Classification', 'Count']]
                for classification, count in stats['threats_by_classification'].items():
                    type_data.append([classification, str(count)])
                
                type_table = Table(type_data, colWidths=[3*inch, 2*inch])
                type_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(type_table)
                story.append(Spacer(1, 0.3*inch))
            
            # Recent Threats
            story.append(Paragraph("Recent Threats", styles['Heading2']))
            
            if threats:
                threat_data = [['Time', 'Type', 'Severity', 'Source IP', 'Score', 'Description']]
                for threat in threats[:50]:  # Limit to 50 most recent
                    timestamp = time.strftime('%H:%M:%S', time.localtime(threat[1]))
                    threat_data.append([
                        timestamp,
                        threat[2][:20],
                        threat[3],
                        threat[4] or 'N/A',
                        f"{threat[6]:.1f}",
                        threat[7][:40] + '...' if len(threat[7]) > 40 else threat[7]
                    ])
                
                threat_table = Table(threat_data, colWidths=[0.8*inch, 1.2*inch, 0.7*inch, 1*inch, 0.6*inch, 2.3*inch])
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 8),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))
                
                story.append(threat_table)
            else:
                story.append(Paragraph("No threats detected in the specified time period.", styles['Normal']))
            
            story.append(PageBreak())
            
            # Blocked IPs
            if blocked_ips:
                story.append(Paragraph("Blocked IP Addresses", styles['Heading2']))
                blocked_data = [['IP Address', 'Blocked At', 'Reason', 'Threat Score']]
                for blocked in blocked_ips[:20]:
                    blocked_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(blocked[2]))
                    blocked_data.append([
                        blocked[1],
                        blocked_time,
                        blocked[3][:40],
                        f"{blocked[4]:.1f}"
                    ])
                
                blocked_table = Table(blocked_data, colWidths=[1.5*inch, 1.5*inch, 2.5*inch, 1.5*inch])
                blocked_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(blocked_table)
            
            # Build PDF
            doc.build(story)
            print(f"[Threat Engine] PDF report generated: {filename}")
            return filename
            
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return None

