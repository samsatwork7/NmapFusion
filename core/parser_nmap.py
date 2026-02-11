"""Parse nmap normal output format (.nmap)"""

import re
from utils.helpers import is_valid_ip

class NMAPParser:
    """Parse nmap normal output files"""
    
    def parse(self, filepath):
        """Parse NMAP file and extract host information"""
        results = []
        current_host = None
        nmap_command = ""
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Extract nmap command
            for line in lines:
                if line.startswith('Nmap scan report for'):
                    if current_host:
                        results.append(current_host)
                    current_host = self._init_host(nmap_command, str(filepath))
                    self._parse_host_line(line, current_host)
                elif line.startswith('PORT') or line.startswith('PORT   STATE SERVICE'):
                    current_host['parsing_ports'] = True
                elif current_host and current_host.get('parsing_ports'):
                    if line.strip() == '':
                        current_host['parsing_ports'] = False
                    else:
                        self._parse_port_line(line, current_host)
                elif line.startswith('Nmap done:'):
                    if current_host:
                        results.append(current_host)
                elif 'nmap' in line.lower() and 'scan initiated' in line.lower():
                    nmap_command = self._extract_command(line)
            
            # Add last host
            if current_host and current_host['ip']:
                results.append(current_host)
                
        except Exception as e:
            print(f"Error parsing NMAP file {filepath}: {e}")
        
        return results
    
    def _init_host(self, nmap_command, filename):
        """Initialize host data structure"""
        return {
            'ip': None,
            'hostname': '',
            'os': 'unknown',
            'ports': [],
            'nse': [],
            'weak_ciphers': [],
            'cves': [],
            'command': nmap_command,
            'source_file': filename,
            'parsing_ports': False
        }
    
    def _parse_host_line(self, line, host_data):
        """Parse host line from nmap output"""
        # Format: Nmap scan report for 192.168.1.1
        # or: Nmap scan report for hostname (192.168.1.1)
        
        line = line.replace('Nmap scan report for', '').strip()
        
        # Check for hostname with IP in parentheses
        ip_match = re.search(r'\(([0-9a-fA-F:.]+)\)', line)
        if ip_match:
            ip = ip_match.group(1)
            if is_valid_ip(ip):
                host_data['ip'] = ip
            hostname = line.replace(f'({ip})', '').strip()
            if hostname:
                host_data['hostname'] = hostname
        else:
            # Just an IP
            if is_valid_ip(line.strip()):
                host_data['ip'] = line.strip()
            else:
                host_data['hostname'] = line.strip()
    
    def _parse_port_line(self, line, host_data):
        """Parse port line from nmap output"""
        # Format: 80/tcp   open  http       Apache httpd 2.4.49
        parts = line.split()
        if len(parts) >= 3:
            port_proto = parts[0]
            state = parts[1]
            service = parts[2] if len(parts) > 2 else 'unknown'
            version = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
            
            # Split port and protocol
            if '/' in port_proto:
                port, protocol = port_proto.split('/')
            else:
                port = port_proto
                protocol = 'tcp'
            
            try:
                port_num = int(port)
                if state == 'open':
                    host_data['ports'].append({
                        'port': port_num,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'version': version,
                        'product': '',
                        'extrainfo': '',
                        'nse': []
                    })
            except ValueError:
                pass
    
    def _extract_command(self, line):
        """Extract nmap command from init line"""
        # Format: # Nmap 7.80 scan initiated Wed Apr  5 10:00:00 2023 as: nmap -sV 192.168.1.1
        cmd_match = re.search(r'as:\s+(.+?)(?:\s+$|$)', line)
        if cmd_match:
            return cmd_match.group(1)
        return ""
