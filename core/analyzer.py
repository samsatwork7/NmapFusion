"""Analyze fused host data and generate table structures - WITH PROPER SORTING"""

from collections import defaultdict
import ipaddress
from utils.subnet_utils import SubnetSorter, sort_ports

class Analyzer:
    """Build data structures for all 4 table types - WITH PROPER SORTING"""
    
    def __init__(self):
        self.hosts = []
        self.sorted_hosts = []
        
        # Table data structures
        self.table1_data = []  # Per-IP Overview
        self.table2_data = {}  # Per-IP Detailed
        self.table3_data = []  # Port Frequency - SORTED BY PORT
        self.table4_data = {}  # Per-Port Detailed - SORTED BY PORT
        
        # Mappings
        self.port_to_ips = defaultdict(list)
        self.port_to_hosts = defaultdict(list)
    
    def analyze(self, hosts):
        """Analyze hosts and build all table structures"""
        self.hosts = hosts
        
        # Sort hosts first
        sorter = SubnetSorter()
        sorter.add_hosts(hosts)
        self.sorted_hosts = sorter.get_sorted_hosts()
        
        # Build mappings
        self._build_port_mappings()
        
        # Build tables
        self._build_table1()
        self._build_table2()
        self._build_table3()
        self._build_table4()
        
        return {
            'table1': self.table1_data,
            'table2': self.table2_data,
            'table3': self.table3_data,
            'table4': self.table4_data,
            'sorted_hosts': self.sorted_hosts
        }
    
    def _build_port_mappings(self):
        """Build port -> IP and port -> host mappings with IP sorting"""
        for host in self.hosts:
            ip = host['ip']
            for port in host.get('ports', []):
                key = f"{port['port']}/{port['protocol']}"
                self.port_to_ips[key].append(ip)
                self.port_to_hosts[key].append(host)
        
        # Sort IPs in each port mapping
        for key in self.port_to_ips:
            self.port_to_ips[key] = sorted(
                self.port_to_ips[key],
                key=lambda x: ipaddress.ip_address(x)
            )
        
        # Sort hosts in each port mapping by IP
        for key in self.port_to_hosts:
            self.port_to_hosts[key] = sorted(
                self.port_to_hosts[key],
                key=lambda x: ipaddress.ip_address(x['ip'])
            )
    
    def _build_table1(self):
        """Build Table 1: Host Summary Overview"""
        self.table1_data = []
        
        for host in self.sorted_hosts:
            ports = host.get('ports', [])
            tcp_ports = [p for p in ports if p['protocol'] == 'tcp']
            udp_ports = [p for p in ports if p['protocol'] == 'udp']
            
            row = {
                'ip': host['ip'],
                'hostname': host.get('hostname', ''),
                'total_ports': len(ports),
                'tcp_ports': len(tcp_ports),
                'udp_ports': len(udp_ports),
                'total_services': len(set([p['service'] for p in ports if p['service'] != 'unknown'])),
                'os': host.get('os', 'unknown')
            }
            self.table1_data.append(row)
    
    def _build_table2(self):
        """Build Table 2: Host Detailed Analysis"""
        self.table2_data = {}
        
        for host in self.sorted_hosts:
            ip = host['ip']
            ports = sort_ports(host.get('ports', []))
            
            port_details = []
            for port in ports:
                port_details.append({
                    'port': port['port'],
                    'protocol': port['protocol'],
                    'service': port['service'],
                    'version': port['version'],
                    'nse_summary': self._get_port_nse_summary(port, host),
                    'business_function': port.get('business_function', 'other')
                })
            
            self.table2_data[ip] = {
                'ip': ip,
                'hostname': host.get('hostname', ''),
                'os': host.get('os', 'unknown'),
                'ports': port_details,
                'cves': host.get('cves', []),
                'weak_ciphers': host.get('weak_ciphers', [])
            }
    
    def _build_table3(self):
        """Build Table 3: Port Frequency Distribution - SORTED BY PORT NUMBER"""
        self.table3_data = []
        
        # Build port frequency data
        for port_key, ips in self.port_to_ips.items():
            port, protocol = port_key.split('/')
            
            row = {
                'port': int(port),
                'protocol': protocol,
                'count': len(ips),
                'ip_list': ips.copy(),  # Already sorted by IP
                'ip_count_total': len(ips),
                'service': self._get_common_service(port_key)
            }
            self.table3_data.append(row)
        
        # SORT TABLE 3 BY PORT NUMBER (ascending)
        self.table3_data.sort(key=lambda x: x['port'])
    
    def _build_table4(self):
        """Build Table 4: Service Exposure Matrix - SORTED BY PORT NUMBER"""
        self.table4_data = {}
        
        for port_key, hosts in self.port_to_hosts.items():
            port, protocol = port_key.split('/')
            
            host_details = []
            for host in hosts:  # Hosts already sorted by IP from _build_port_mappings
                for port_info in host.get('ports', []):
                    if f"{port_info['port']}/{port_info['protocol']}" == port_key:
                        host_details.append({
                            'ip': host['ip'],
                            'hostname': host.get('hostname', ''),
                            'os': host.get('os', 'unknown'),
                            'service': port_info['service'],
                            'version': port_info['version'],
                            'business_function': port_info.get('business_function', 'other')
                        })
                        break
            
            self.table4_data[port_key] = {
                'port': int(port),
                'protocol': protocol,
                'host_count': len(host_details),
                'hosts': host_details,  # Already sorted by IP
                'service': self._get_common_service(port_key)
            }
        
        # No need to sort table4_data dict - we'll sort during display/rendering
        # This preserves the structure but we'll sort keys when iterating
    
    def _get_port_nse_summary(self, port, host):
        """Get NSE summary for a specific port"""
        summaries = []
        
        # Port-specific NSE
        for nse in port.get('nse', []):
            summaries.append(f"{nse.get('id')}: {nse.get('output', '')[:50]}")
        
        # Host NSE related to this port
        for nse in host.get('nse', []):
            if f"port {port['port']}" in nse.get('output', '').lower():
                summaries.append(f"{nse.get('id')}: {nse.get('output', '')[:50]}")
        
        return summaries[:3]
    
    def _get_common_service(self, port_key):
        """Get most common service for a port"""
        services = {}
        
        for host in self.port_to_hosts[port_key]:
            for port in host.get('ports', []):
                if f"{port['port']}/{port['protocol']}" == port_key:
                    service = port.get('service', 'unknown')
                    services[service] = services.get(service, 0) + 1
        
        if services:
            return max(services.items(), key=lambda x: x[1])[0]
        return 'unknown'
