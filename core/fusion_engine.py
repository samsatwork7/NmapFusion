"""Multi-file fusion engine - merges multiple scans of same IP"""

from collections import defaultdict
from datetime import datetime
from utils.helpers import extract_subnet
import ipaddress

class FusionEngine:
    """Intelligently merge multiple scan results for the same IP"""
    
    def __init__(self, config=None):
        self.hosts = {}  # ip -> FusionRecord
        self.config = config or {}
        self.fusion_stats = {
            'files_processed': 0,
            'unique_ips': 0,
            'total_ports': 0,
            'ports_after_fusion': 0,
            'duplicate_ports_removed': 0,
            'nse_merged': 0
        }
    
    def add_scan(self, parsed_data_list, source_file=None):
        """Add parsed scan data to fusion database"""
        self.fusion_stats['files_processed'] += 1
        
        if isinstance(parsed_data_list, dict):
            parsed_data_list = [parsed_data_list]
        
        for host_data in parsed_data_list:
            if not host_data or 'ip' not in host_data or not host_data['ip']:
                continue
            
            ip = host_data['ip']
            if ip not in self.hosts:
                self.hosts[ip] = FusionRecord(ip, self.config)
                self.fusion_stats['unique_ips'] += 1
            
            self.hosts[ip].merge(host_data)
            self.fusion_stats['total_ports'] += len(host_data.get('ports', []))
    
    def resolve_conflicts(self):
        """Apply conflict resolution rules to all hosts"""
        for host in self.hosts.values():
            host.finalize()
            self.fusion_stats['ports_after_fusion'] += len(host.final_ports)
            self.fusion_stats['nse_merged'] += len(host.nse_results)
    
    def get_unified_hosts(self):
        """Return list of unified host objects"""
        return [host.to_dict() for host in self.hosts.values()]
    
    def get_fusion_summary(self):
        """Get summary of fusion operations"""
        self.fusion_stats['duplicate_ports_removed'] = (
            self.fusion_stats['total_ports'] - self.fusion_stats['ports_after_fusion']
        )
        return self.fusion_stats


class FusionRecord:
    """Fusion record for a single IP"""
    
    def __init__(self, ip, config=None):
        self.ip = ip
        self.config = config or {}
        self.hostname = ''
        self.os_candidates = []
        self.ports = {}  # key: f"{port}/{protocol}"
        self.nse_results = []
        self.commands = set()
        self.timestamps = []
        self.source_files = set()
        self.cves = []
        self.weak_ciphers = []
        self.final_ports = []
        self.best_os = 'unknown'
        self.subnet = extract_subnet(ip)
    
    def merge(self, host_data):
        """Intelligently merge new scan data"""
        
        # Merge hostname (prefer non-empty)
        if host_data.get('hostname') and not self.hostname:
            self.hostname = host_data['hostname']
        
        # Merge OS info (collect all candidates)
        if host_data.get('os') and host_data['os'] != 'unknown':
            self.os_candidates.append(host_data['os'])
        
        # Merge ports
        for port in host_data.get('ports', []):
            key = f"{port['port']}/{port['protocol']}"
            
            if key not in self.ports:
                self.ports[key] = PortInfo(port)
            else:
                self.ports[key].merge(port)
        
        # Merge NSE findings (deduplicate)
        for nse in host_data.get('nse', []):
            if not self._nse_exists(nse):
                self.nse_results.append(nse)
        
        # Merge CVEs
        for cve in host_data.get('cves', []):
            if cve not in self.cves:
                self.cves.append(cve)
        
        # Merge weak ciphers
        for cipher in host_data.get('weak_ciphers', []):
            if cipher not in self.weak_ciphers:
                self.weak_ciphers.append(cipher)
        
        # Store command
        if host_data.get('command'):
            self.commands.add(host_data['command'])
        
        # Store timestamp
        if host_data.get('timestamp'):
            self.timestamps.append(host_data['timestamp'])
        
        # Store source file
        if host_data.get('source_file'):
            self.source_files.add(host_data['source_file'])
    
    def _nse_exists(self, nse):
        """Check if NSE result already exists"""
        for existing in self.nse_results:
            if existing.get('id') == nse.get('id'):
                # If same script ID, merge outputs
                if existing.get('output') != nse.get('output'):
                    existing['output'] += "; " + nse.get('output', '')
                return True
        return False
    
    def finalize(self):
        """Produce final unified record"""
        
        # Select best OS (most frequent or most specific)
        self.best_os = self._select_best_os()
        
        # Finalize ports
        self.final_ports = []
        for port_info in self.ports.values():
            port_info.finalize()
            self.final_ports.append(port_info.to_dict())
        
        # Sort ports numerically
        self.final_ports.sort(key=lambda x: (x['port'], x['protocol']))
        
        # Deduplicate CVEs
        unique_cves = {}
        for cve in self.cves:
            if isinstance(cve, dict):
                cve_id = cve.get('id', '')
                unique_cves[cve_id] = cve
        self.cves = list(unique_cves.values())
    
    def _select_best_os(self):
        """Select the best OS from candidates"""
        if not self.os_candidates:
            return 'unknown'
        
        # Count frequency
        from collections import Counter
        os_count = Counter(self.os_candidates)
        
        # Get most common
        most_common = os_count.most_common(1)[0][0]
        
        # Look for more specific version
        for os_candidate in self.os_candidates:
            if len(os_candidate) > len(most_common):
                most_common = os_candidate
        
        return most_common
    
    def to_dict(self):
        """Convert to dictionary for output"""
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'os': self.best_os,
            'ports': self.final_ports,
            'nse': self.nse_results,
            'weak_ciphers': self.weak_ciphers,
            'cves': self.cves,
            'subnet': self.subnet,
            'commands': list(self.commands),
            'source_files': list(self.source_files),
            'port_count': len(self.final_ports)
        }


class PortInfo:
    """Port information with merge capabilities"""
    
    def __init__(self, port_data):
        self.port = port_data['port']
        self.protocol = port_data['protocol']
        self.state = port_data.get('state', 'open')
        self.service = port_data.get('service', 'unknown')
        self.version = port_data.get('version', 'unknown')
        self.product = port_data.get('product', '')
        self.extrainfo = port_data.get('extrainfo', '')
        self.nse = port_data.get('nse', [])
        self.detailed_version = None
        self.has_version = False
        
        # Track if we have detailed version info
        if self.version != 'unknown' and self.version:
            self.has_version = True
            self.detailed_version = self.version
    
    def merge(self, new_port_data):
        """Merge new port data, keeping the best version"""
        
        # Keep most detailed service name
        new_service = new_port_data.get('service', 'unknown')
        if len(new_service) > len(self.service) and new_service != 'unknown':
            self.service = new_service
        
        # Keep most detailed version
        new_version = new_port_data.get('version', 'unknown')
        if new_version != 'unknown' and len(new_version) > len(self.version):
            self.version = new_version
            self.has_version = True
            self.detailed_version = new_version
        
        # Keep product info
        new_product = new_port_data.get('product', '')
        if new_product and not self.product:
            self.product = new_product
        
        # Merge NSE scripts
        for nse in new_port_data.get('nse', []):
            if not self._nse_exists(nse):
                self.nse.append(nse)
    
    def _nse_exists(self, nse):
        """Check if NSE script already exists"""
        for existing in self.nse:
            if existing.get('id') == nse.get('id'):
                return True
        return False
    
    def finalize(self):
        """Finalize port information"""
        # Construct full version string if needed
        if self.product and self.version == 'unknown':
            self.version = self.product
        elif self.product and self.version != 'unknown':
            self.version = f"{self.product} {self.version}"
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'version': self.version,
            'product': self.product,
            'extrainfo': self.extrainfo,
            'nse': self.nse
        }
