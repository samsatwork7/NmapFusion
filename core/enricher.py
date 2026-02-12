"""Enrich host data with subnet info - NO RISK SCORING"""

import json
from pathlib import Path
from utils.helpers import extract_subnet
from utils.subnet_utils import SubnetSorter

class Enricher:
    """Enrich host data with subnet grouping - NO RISK SCORING"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.business_ports = self._load_json('business_ports.json', {})
    
    def _load_json(self, filename, default):
        """Load JSON file from utils directory"""
        try:
            utils_dir = Path(__file__).parent.parent / 'utils'
            filepath = utils_dir / filename
            
            if filepath.exists():
                with open(filepath, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return default
    
    def enrich_hosts(self, hosts):
        """Enrich hosts with subnet info only - NO RISK"""
        enriched_hosts = []
        
        for host in hosts:
            # Add subnet only
            host['subnet'] = extract_subnet(host['ip'])
            
            # Add business function for ports
            for port in host.get('ports', []):
                port['business_function'] = self._get_business_function(port['port'])
            
            enriched_hosts.append(host)
        
        return enriched_hosts
    
    def _get_business_function(self, port):
        """Map port to business function"""
        for function, ports in self.business_ports.items():
            if port in ports:
                return function
        return 'other'
    
    def get_subnet_summary(self, hosts):
        """Generate subnet summary"""
        sorter = SubnetSorter()
        sorter.add_hosts(hosts)
        return sorter.get_subnet_summary()
