"""Sorting and subnet grouping module"""

from utils.subnet_utils import SubnetSorter, sort_hosts_by_ip
import ipaddress

class Sorter:
    """Handle all sorting operations for consistent output"""
    
    def __init__(self):
        self.subnet_sorter = SubnetSorter()
    
    def sort_hosts_by_subnet(self, hosts):
        """Group hosts by subnet and sort IPs within"""
        self.subnet_sorter = SubnetSorter()
        self.subnet_sorter.add_hosts(hosts)
        return self.subnet_sorter.get_sorted_hosts()
    
    def sort_ports(self, ports):
        """Sort ports numerically"""
        return sorted(ports, key=lambda x: (x['port'], x.get('protocol', 'tcp')))
    
    def sort_port_frequencies(self, port_freqs):
        """Sort ports by frequency (descending) then port number"""
        return sorted(
            port_freqs,
            key=lambda x: (-x['count'], x['port'])
        )
    
    def sort_hosts_by_risk(self, hosts, reverse=True):
        """Sort hosts by risk score"""
        return sorted(
            hosts,
            key=lambda x: x.get('risk_score', 0),
            reverse=reverse
        )
    
    def get_subnet_summary(self, hosts):
        """Get subnet summary from hosts"""
        return self.subnet_sorter.get_subnet_summary()
