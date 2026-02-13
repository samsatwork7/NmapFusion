"""Parse nmap greppable output format (.gnmap)"""

import re
from utils.helpers import is_valid_ip

class GNMAPParser:
    """Parse nmap greppable output files"""
    
    def parse(self, filepath):
        """Parse GNMAP file and extract host information"""
        results = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract nmap command from first line
            first_line = content.split('\n')[0]
            nmap_command = self._extract_command(first_line)
            
            # Parse each host line
            for line in content.split('\n'):
                if line.startswith('Host:'):
                    host_data = self._parse_host_line(line, nmap_command, str(filepath))
                    if host_data:
                        results.append(host_data)
                        
        except Exception as e:
            print(f"Error parsing GNMAP file {filepath}: {e}")
        
        return results
    
    def _parse_host_line(self, line, nmap_command, filename):
        """Parse a single GNMAP host line"""
        host_data = {
            'ip': None,
            'hostname': '',
            'os': 'unknown',
            'ports': [],
            'nse': [],
            'weak_ciphers': [],
            'cves': [],
            'command': nmap_command,
            'source_file': filename
        }
        
        # Extract IP
        ip_match = re.search(r'Host:\s+([0-9a-fA-F:.]+)', line)
        if ip_match:
            ip = ip_match.group(1)
            if is_valid_ip(ip):
                host_data['ip'] = ip
        
        # Extract hostname
        hostname_match = re.search(r'\(([^)]+)\)', line)
        if hostname_match:
            host_data['hostname'] = hostname_match.group(1)
        
        # Extract ports
        ports_match = re.search(r'Ports:\s+(.+?)(?:\s+Ignored|$)', line)
        if ports_match:
            ports_str = ports_match.group(1)
            host_data['ports'] = self._parse_ports(ports_str)
        
        # Extract OS
        os_match = re.search(r'OS:\s+([^;\n]+)', line)
        if os_match:
            host_data['os'] = os_match.group(1).strip()
        
        return host_data
    
    def _parse_ports(self, ports_str):
        """Parse port string into structured data"""
        ports = []
        port_entries = ports_str.split(',')
        
        for entry in port_entries:
            entry = entry.strip()
            if not entry:
                continue
            
            parts = entry.split('/')
            if len(parts) < 3:
                continue

            try:
                port_num = int(parts[0]) if parts[0].isdigit() else 0

                # GNMAP canonical format:
                #   port/state/protocol/owner/service/sunrpcinfo/version
                # Some tools export a legacy-like variant, so keep a fallback parser.
                if len(parts) >= 3 and parts[1] in ('open', 'closed', 'filtered'):
                    state = parts[1] if parts[1] else 'open'
                    protocol = parts[2] if parts[2] else 'tcp'
                    service = parts[4] if len(parts) > 4 and parts[4] else 'unknown'

                    # Version/product text is typically in trailing fields.
                    version_fields = [p for p in parts[5:] if p and p != 'none' and not p.startswith('conf=')]
                else:
                    # Fallback (legacy): port/protocol/state/service/version
                    protocol = parts[1] if parts[1] else 'tcp'
                    state = parts[2] if parts[2] else 'open'
                    service = parts[3] if len(parts) > 3 and parts[3] else 'unknown'
                    version_fields = [p for p in parts[4:] if p and p != 'none' and not p.startswith('conf=')]

                version = 'unknown'
                if version_fields:
                    version = ' '.join(version_fields).strip()

                if state == 'open':
                    ports.append({
                        'port': port_num,
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'version': version,
                        'product': '',
                        'extrainfo': '',
                        'nse': []
                    })
            except (ValueError, IndexError):
                continue
        
        return ports
    
    def _extract_command(self, first_line):
        """Extract nmap command from first line"""
        # Format: # Nmap 7.80 scan initiated ...
        cmd_match = re.search(r'as:\s+(.+?)(?:\s+$|$)', first_line)
        if cmd_match:
            return cmd_match.group(1)
        return ""
