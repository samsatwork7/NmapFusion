"""Subnet grouping and IP sorting utilities"""

import ipaddress
from collections import defaultdict
from .helpers import extract_subnet

class SubnetSorter:
    """Group and sort IPs by subnet"""
    
    def __init__(self):
        self.subnets = defaultdict(list)
    
    def add_host(self, host):
        """Add host to subnet group"""
        subnet = host.get('subnet', extract_subnet(host['ip']))
        self.subnets[subnet].append(host)
    
    def add_hosts(self, hosts):
        """Add multiple hosts"""
        for host in hosts:
            self.add_host(host)
    
    def sort_ips_in_subnets(self):
        """Sort IPs within each subnet"""
        for subnet in self.subnets:
            self.subnets[subnet] = sorted(
                self.subnets[subnet],
                key=lambda x: ipaddress.ip_address(x['ip'])
            )
    
    def get_sorted_hosts(self):
        """Get all hosts sorted by subnet then IP"""
        self.sort_ips_in_subnets()
        
        # Sort subnets themselves
        sorted_hosts = []
        for subnet in sorted(self.subnets.keys()):
            sorted_hosts.extend(self.subnets[subnet])
        
        return sorted_hosts
    
    def get_subnet_summary(self):
        """Get summary of subnets"""
        summary = []
        for subnet, hosts in sorted(self.subnets.items()):
            summary.append({
                'subnet': subnet,
                'host_count': len(hosts),
                'ip_range': f"{hosts[0]['ip']} - {hosts[-1]['ip']}" if hosts else 'N/A'
            })
        return summary

def sort_ports(ports):
    """Sort ports numerically"""
    return sorted(ports, key=lambda x: x['port'])

def sort_hosts_by_ip(hosts):
    """Sort hosts by IP address"""
    return sorted(
        hosts,
        key=lambda x: ipaddress.ip_address(x['ip'])
    )
