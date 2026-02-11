"""Parse nmap XML output format"""

import xml.etree.ElementTree as ET
from datetime import datetime
import re
from utils.helpers import parse_timestamp, clean_nse_output

class XMLParser:
    """Parse nmap XML output files"""
    
    def __init__(self):
        self.namespace = {'nmap': 'http://nmap.org/nsmap'}
    
    def parse(self, filepath):
        """Parse XML file and extract host information"""
        results = []
        nmap_command = ""
        scan_info = {}
        
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            # Extract nmap command
            nmap_command = root.get('args', '')
            scanner = root.get('scanner', 'nmap')
            version = root.get('version', '')
            start_time = root.get('start', '')
            
            scan_info = {
                'command': nmap_command,
                'scanner': scanner,
                'version': version,
                'start_time': parse_timestamp(start_time) if start_time else None,
                'filename': str(filepath)
            }
            
            # Parse each host
            for host in root.findall('.//host'):
                host_data = self._parse_host(host, scan_info)
                if host_data:
                    results.append(host_data)
                    
        except ET.ParseError as e:
            print(f"Error parsing XML file {filepath}: {e}")
        except Exception as e:
            print(f"Unexpected error parsing {filepath}: {e}")
        
        return results
    
    def _parse_host(self, host_elem, scan_info):
        """Parse individual host element"""
        host_data = {
            'ip': None,
            'hostname': '',
            'os': 'unknown',
            'ports': [],
            'nse': [],
            'weak_ciphers': [],
            'cves': [],
            'command': scan_info['command'],
            'timestamp': scan_info['start_time'],
            'source_file': scan_info['filename']
        }
        
        # Get IP address
        address = host_elem.find('.//address[@addrtype="ipv4"]')
        if address is None:
            address = host_elem.find('.//address[@addrtype="ipv6"]')
        
        if address is not None:
            host_data['ip'] = address.get('addr', '')
        
        # Get hostname
        hostname = host_elem.find('.//hostname')
        if hostname is not None:
            host_data['hostname'] = hostname.get('name', '')
        
        # Get OS information
        os_elem = host_elem.find('.//os/osmatch')
        if os_elem is not None:
            host_data['os'] = os_elem.get('name', 'unknown')
        else:
            # Try alternative OS matching
            os_class = host_elem.find('.//os/osclass')
            if os_class is not None:
                host_data['os'] = os_class.get('osfamily', 'unknown')
        
        # Parse ports
        ports_elem = host_elem.find('.//ports')
        if ports_elem is not None:
            for port in ports_elem.findall('.//port'):
                port_data = self._parse_port(port, host_data)
                if port_data:
                    host_data['ports'].append(port_data)
        
        # Parse NSE scripts (host scripts)
        host_scripts = host_elem.findall('.//hostscript/script')
        for script in host_scripts:
            nse_data = self._parse_script(script)
            if nse_data:
                host_data['nse'].append(nse_data)
                self._extract_findings(nse_data, host_data)
        
        return host_data
    
    def _parse_port(self, port_elem, host_data):
        """Parse port information"""
        port_id = port_elem.get('portid')
        protocol = port_elem.get('protocol')
        
        state_elem = port_elem.find('state')
        if state_elem is None or state_elem.get('state') != 'open':
            return None
        
        port_data = {
            'port': int(port_id) if port_id else 0,
            'protocol': protocol,
            'state': 'open',
            'service': 'unknown',
            'version': 'unknown',
            'product': '',
            'extrainfo': '',
            'nse': []
        }
        
        # Service information
        service_elem = port_elem.find('service')
        if service_elem is not None:
            port_data['service'] = service_elem.get('name', 'unknown')
            port_data['product'] = service_elem.get('product', '')
            port_data['version'] = service_elem.get('version', 'unknown')
            port_data['extrainfo'] = service_elem.get('extrainfo', '')
            
            # Construct full version string
            if port_data['product']:
                version_str = port_data['product']
                if port_data['version'] != 'unknown':
                    version_str += f" {port_data['version']}"
                if port_data['extrainfo']:
                    version_str += f" ({port_data['extrainfo']})"
                port_data['version'] = version_str
        
        # Port-specific scripts
        for script in port_elem.findall('script'):
            script_data = self._parse_script(script)
            if script_data:
                port_data['nse'].append(script_data)
                host_data['nse'].append(script_data)
                self._extract_findings(script_data, host_data, port_data)
        
        return port_data
    
    def _parse_script(self, script_elem):
        """Parse NSE script output"""
        script_id = script_elem.get('id', '')
        output = script_elem.get('output', '')
        
        if not script_id or not output:
            return None
        
        # Clean the output
        cleaned_output = clean_nse_output(output)
        
        # Extract tables if present
        tables = []
        for table in script_elem.findall('table'):
            table_data = self._parse_table(table)
            if table_data:
                tables.append(table_data)
        
        return {
            'id': script_id,
            'output': cleaned_output,
            'full_output': output,
            'tables': tables
        }
    
    def _parse_table(self, table_elem):
        """Parse nested table elements"""
        table_data = {}
        key = table_elem.get('key', '')
        
        for elem in table_elem:
            if elem.tag == 'elem':
                elem_key = elem.get('key', '')
                if elem_key:
                    table_data[elem_key] = elem.text
            elif elem.tag == 'table':
                table_data.update(self._parse_table(elem))
        
        return {key: table_data} if key else table_data
    
    def _extract_findings(self, script_data, host_data, port_data=None):
        """Extract CVEs, weak ciphers, and other findings from NSE output"""
        output = script_data.get('output', '')
        script_id = script_data.get('id', '')
        
        # Extract CVEs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, output, re.IGNORECASE)
        for cve in cves:
            if cve not in host_data['cves']:
                host_data['cves'].append({
                    'id': cve,
                    'script': script_id,
                    'port': port_data['port'] if port_data else None
                })
        
        # Extract weak SSL/TLS ciphers
        if 'ssl-enum-ciphers' in script_id:
            weak_cipher_indicators = ['weak', 'DES', 'RC4', 'MD5', 'export', 'low']
            for indicator in weak_cipher_indicators:
                if indicator.lower() in output.lower():
                    host_data['weak_ciphers'].append({
                        'cipher': indicator,
                        'script': script_id,
                        'port': port_data['port'] if port_data else None
                    })
        
        # Extract SSL certificate issues
        if 'ssl-cert' in script_id:
            if 'expired' in output.lower():
                host_data['weak_ciphers'].append({
                    'cipher': 'expired_certificate',
                    'script': script_id,
                    'port': port_data['port'] if port_data else None
                })
