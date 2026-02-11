"""Enrich host data with risk scores, subnet info, and vulnerability mapping"""

import json
import os
from pathlib import Path
from utils.helpers import extract_subnet
from utils.subnet_utils import SubnetSorter

class Enricher:
    """Add risk scores, subnet grouping, and vulnerability info"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.risk_ports = self._load_json('risk_ports.json', {})
        self.version_risks = self._load_json('version_risks.json', {})
        self.business_ports = self._load_json('business_ports.json', {})
        
        # Risk weights
        self.weights = {
            'port': 3.0,
            'cve': 5.0,
            'outdated_version': 3.0,
            'weak_cipher': 2.5,
            'nse_finding': 2.0
        }
        
        # Update weights from config
        if config and 'risk_weights' in config:
            self.weights.update(config['risk_weights'])
    
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
        """Enrich all hosts with additional data"""
        enriched_hosts = []
        
        for host in hosts:
            # Add subnet
            host['subnet'] = extract_subnet(host['ip'])
            
            # Calculate risk score for each port
            for port in host.get('ports', []):
                port['risk'] = self._calculate_port_risk(port, host)
            
            # Calculate overall host risk
            host['risk_score'] = self._calculate_host_risk(host)
            host['risk_level'] = self._score_to_level(host['risk_score'])
            
            # Add business function if applicable
            for port in host.get('ports', []):
                port['business_function'] = self._get_business_function(port['port'])
            
            enriched_hosts.append(host)
        
        return enriched_hosts
    
    def _calculate_port_risk(self, port, host):
        """Calculate risk level for a specific port"""
        risk_score = 0
        findings = []
        
        # Check if port is in high-risk list
        port_num = port['port']
        
        for level, ports in self.risk_ports.items():
            if port_num in ports:
                risk_score += self.weights['port'] * self._level_multiplier(level)
                findings.append(f"High-risk port: {port_num}")
        
        # Check version risks
        service = port.get('service', '').lower()
        version = port.get('version', '').lower()
        
        for vuln_service, versions in self.version_risks.items():
            if vuln_service in service:
                for ver_pattern, risk_info in versions.items():
                    if ver_pattern.replace('*', '') in version:
                        risk_score += self.weights['outdated_version'] * self._level_multiplier(risk_info['risk'])
                        findings.append(f"Outdated {service}: {version}")
                        break
        
        # Check CVEs for this port
        for cve in host.get('cves', []):
            if cve.get('port') == port['port']:
                risk_score += self.weights['cve']
                findings.append(f"CVE: {cve.get('id')}")
        
        # Check weak ciphers
        for cipher in host.get('weak_ciphers', []):
            if cipher.get('port') == port['port']:
                risk_score += self.weights['weak_cipher']
                findings.append(f"Weak cipher: {cipher.get('cipher')}")
        
        # Determine risk level
        risk_level = self._score_to_level(risk_score)
        
        return {
            'level': risk_level,
            'score': round(risk_score, 2),
            'findings': findings[:3]  # Top 3 findings
        }
    
    def _calculate_host_risk(self, host):
        """Calculate overall risk score for host"""
        total_score = 0
        
        # Sum port risks
        for port in host.get('ports', []):
            total_score += port.get('risk', {}).get('score', 0)
        
        # Add host-level findings
        total_score += len(host.get('cves', [])) * self.weights['cve'] * 0.5
        total_score += len(host.get('weak_ciphers', [])) * self.weights['weak_cipher'] * 0.3
        
        return round(total_score, 2)
    
    def _level_multiplier(self, level):
        """Convert risk level to multiplier"""
        multipliers = {
            'critical': 1.5,
            'high': 1.2,
            'medium': 1.0,
            'low': 0.7
        }
        return multipliers.get(level.lower(), 1.0)
    
    def _score_to_level(self, score):
        """Convert numeric score to risk level"""
        thresholds = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 1.0
        }
        
        if score >= thresholds['critical']:
            return 'critical'
        elif score >= thresholds['high']:
            return 'high'
        elif score >= thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
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
