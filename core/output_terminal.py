"""Terminal output rendering with color and tables"""

from tabulate import tabulate
from colorama import Fore, Back, Style, init
from utils.helpers import colorize_risk
import sys

# Initialize colorama for Windows
if sys.platform == 'win32':
    init(autoreset=True)

class TerminalOutput:
    """Render NmapFusion analysis results in terminal"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
    
    def display(self, analysis_results, fusion_summary, selected_tables, nmap_commands):
        """Display selected tables in terminal with enforced order"""
        
        # Always show Nmap commands
        self._display_nmap_commands(nmap_commands)
        
        # Show fusion summary if verbose
        if self.verbose:
            self._display_fusion_summary(fusion_summary)
        
        # Display selected tables IN THE CORRECT ORDER
        for table in selected_tables:  # Now maintains order from main.py
            if table == 'table1':
                self.display_table1(analysis_results['table1'])
            elif table == 'table2':
                self.display_table2(analysis_results['table2'])
            elif table == 'table3':
                self.display_table3(analysis_results['table3'])
            elif table == 'table4':
                self.display_table4(analysis_results['table4'])
        
        # Show summary
        self._display_summary(analysis_results)
    
    def _display_nmap_commands(self, commands):
        """Display Nmap command(s) used"""
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                          NmapFusion SCAN CONFIGURATION                         ║")
        print(f"╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not commands:
            print(f"{Fore.YELLOW}  ⚠ No commands found in scan files{Style.RESET_ALL}")
        else:
            for i, cmd in enumerate(commands, 1):
                print(f"  {Fore.CYAN}❯{Style.RESET_ALL} {cmd}")
        
        print("=" * 80 + "\n")
    
    def _display_fusion_summary(self, summary):
        """Display fusion engine statistics"""
        print(f"{Fore.MAGENTA}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                         FUSION ENGINE STATISTICS                         ║")
        print(f"╠════════════════════════════════════════════════════════════════════════════╣")
        print(f"║  • Files processed     : {summary.get('files_processed', 0):<48}║")
        print(f"║  • Unique IPs found    : {summary.get('unique_ips', 0):<48}║")
        print(f"║  • Total ports scanned : {summary.get('total_ports', 0):<48}║")
        print(f"║  • Ports after fusion  : {summary.get('ports_after_fusion', 0):<48}║")
        print(f"║  • Duplicates removed  : {summary.get('duplicate_ports_removed', 0):<48}║")
        print(f"║  • NSE scripts merged  : {summary.get('nse_merged', 0):<48}║")
        print(f"╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    def display_table1(self, table1_data):
        """Display Table 1: Host Summary Overview"""
        print(f"{Fore.BLUE}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                         TABLE 1: HOST SUMMARY OVERVIEW                    ║")
        print(f"╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not table1_data:
            print(f"{Fore.YELLOW}  ⚠ No host data available{Style.RESET_ALL}\n")
            return
        
        headers = [
            f"{Fore.CYAN}IP Address{Style.RESET_ALL}",
            f"{Fore.CYAN}Hostname{Style.RESET_ALL}",
            f"{Fore.CYAN}Ports{Style.RESET_ALL}",
            f"{Fore.CYAN}TCP{Style.RESET_ALL}",
            f"{Fore.CYAN}UDP{Style.RESET_ALL}",
            f"{Fore.CYAN}Services{Style.RESET_ALL}",
            f"{Fore.CYAN}OS{Style.RESET_ALL}",
            f"{Fore.CYAN}Risk{Style.RESET_ALL}"
        ]
        
        table_data = []
        for row in table1_data:
            table_data.append([
                row['ip'],
                row['hostname'][:25] if row['hostname'] else '—',
                row['total_ports'],
                row['tcp_ports'],
                row['udp_ports'],
                row['total_services'],
                row['os'][:20] if row['os'] != 'unknown' else '—',
                colorize_risk(row['risk_level'])
            ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"{Fore.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Total Hosts: {len(table1_data)} | Total Open Ports: {sum(r['total_ports'] for r in table1_data)}{Style.RESET_ALL}\n")
    
    def display_table2(self, table2_data):
        """Display Table 2: Host Detailed Analysis"""
        print(f"{Fore.GREEN}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                       TABLE 2: HOST DETAILED ANALYSIS                     ║")
        print(f"╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not table2_data:
            print(f"{Fore.YELLOW}  ⚠ No detailed host data available{Style.RESET_ALL}\n")
            return
        
        for ip, data in table2_data.items():
            # Host header with professional formatting
            risk_color = self._get_risk_color(data['risk_level'])
            print(f"\n{Fore.CYAN}{Style.BRIGHT}┌─ HOST: {ip} {Style.RESET_ALL}", end='')
            if data['hostname']:
                print(f"{Fore.WHITE}({data['hostname']}){Style.RESET_ALL} ", end='')
            print(f"│ OS: {Fore.YELLOW}{data['os'][:30]}{Style.RESET_ALL} ", end='')
            print(f"│ RISK: {risk_color}{data['risk_level'].upper()}{Style.RESET_ALL} ")
            print(f"{Fore.CYAN}└{'─' * 78}{Style.RESET_ALL}")
            
            if not data['ports']:
                print(f"  {Fore.YELLOW}⚠ No open ports detected{Style.RESET_ALL}\n")
                continue
            
            # Ports table with professional headers
            headers = [
                f"{Fore.CYAN}Port{Style.RESET_ALL}",
                f"{Fore.CYAN}Proto{Style.RESET_ALL}",
                f"{Fore.CYAN}Service{Style.RESET_ALL}",
                f"{Fore.CYAN}Version{Style.RESET_ALL}",
                f"{Fore.CYAN}Risk{Style.RESET_ALL}",
                f"{Fore.CYAN}NSE Findings{Style.RESET_ALL}"
            ]
            
            port_table = []
            for port in data['ports']:
                nse_summary = '; '.join(port['nse_summary'][:2]) if port['nse_summary'] else '—'
                port_table.append([
                    f"{Fore.WHITE}{port['port']}{Style.RESET_ALL}",
                    port['protocol'],
                    port['service'],
                    port['version'][:35] if port['version'] != 'unknown' else '—',
                    colorize_risk(port['risk']),
                    nse_summary[:45] + '…' if len(nse_summary) > 45 else nse_summary
                ])
            
            print(tabulate(port_table, headers=headers, tablefmt="simple"))
            
            # Show CVEs if any
            if data['cves'] and self.verbose:
                print(f"\n  {Fore.RED}▸ VULNERABILITIES DETECTED:{Style.RESET_ALL}")
                for cve in data['cves'][:5]:
                    print(f"    • {Fore.RED}{cve.get('id', '')}{Style.RESET_ALL}")
            
            # Show weak ciphers if any
            if data['weak_ciphers'] and self.verbose:
                print(f"\n  {Fore.YELLOW}▸ WEAK CRYPTOGRAPHIC CONFIGURATIONS:{Style.RESET_ALL}")
                for cipher in data['weak_ciphers'][:3]:
                    print(f"    • {Fore.YELLOW}{cipher.get('cipher', '')}{Style.RESET_ALL}")
        
        print("\n" + "═" * 80 + "\n")
    
    def display_table3(self, table3_data):
        """Display Table 3: Port Frequency Distribution"""
        print(f"{Fore.YELLOW}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                    TABLE 3: PORT FREQUENCY DISTRIBUTION                  ║")
        print(f"╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not table3_data:
            print(f"{Fore.YELLOW}  ⚠ No port frequency data available{Style.RESET_ALL}\n")
            return
        
        headers = [
            f"{Fore.CYAN}Port{Style.RESET_ALL}",
            f"{Fore.CYAN}Protocol{Style.RESET_ALL}",
            f"{Fore.CYAN}Host Count{Style.RESET_ALL}",
            f"{Fore.CYAN}Service{Style.RESET_ALL}",
            f"{Fore.CYAN}Sample Hosts{Style.RESET_ALL}"
        ]
        
        table_data = []
        for row in table3_data[:20]:  # Top 20 ports
            ip_list = ', '.join(row['ip_list'][:5]) if row['ip_list'] else '—'
            if len(row['ip_list']) > 5:
                ip_list += f" +{len(row['ip_list'])-5} more"
            
            # Color code based on frequency
            count = row['count']
            if count >= 10:
                port_display = f"{Fore.RED}{row['port']}{Style.RESET_ALL}"
            elif count >= 5:
                port_display = f"{Fore.YELLOW}{row['port']}{Style.RESET_ALL}"
            else:
                port_display = f"{Fore.GREEN}{row['port']}{Style.RESET_ALL}"
            
            table_data.append([
                port_display,
                row['protocol'],
                f"{Fore.WHITE}{row['count']}{Style.RESET_ALL}",
                row['service'],
                ip_list[:50] + '…' if len(ip_list) > 50 else ip_list
            ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"{Fore.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Total Unique Ports: {len(table3_data)} | Most Frequent: {table3_data[0]['port']}/{table3_data[0]['protocol']} ({table3_data[0]['count']} hosts){Style.RESET_ALL}\n")
    
    def display_table4(self, table4_data):
        """Display Table 4: Service Exposure Matrix"""
        print(f"{Fore.MAGENTA}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                     TABLE 4: SERVICE EXPOSURE MATRIX                     ║")
        print(f"╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not table4_data:
            print(f"{Fore.YELLOW}  ⚠ No service exposure data available{Style.RESET_ALL}\n")
            return
        
        for port_key, data in list(table4_data.items())[:10]:  # Limit to top 10 ports
            # Port header with professional formatting
            print(f"\n{Fore.CYAN}{Style.BRIGHT}┌─ PORT: {data['port']}/{data['protocol']}{Style.RESET_ALL} ", end='')
            print(f"│ Exposure: {Fore.YELLOW}{data['host_count']} hosts{Style.RESET_ALL} ", end='')
            print(f"│ Service: {Fore.WHITE}{data['service']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└{'─' * 78}{Style.RESET_ALL}")
            
            if not data['hosts']:
                print(f"  {Fore.YELLOW}⚠ No host data available{Style.RESET_ALL}\n")
                continue
            
            # Hosts table with professional headers
            headers = [
                f"{Fore.CYAN}IP Address{Style.RESET_ALL}",
                f"{Fore.CYAN}Hostname{Style.RESET_ALL}",
                f"{Fore.CYAN}OS{Style.RESET_ALL}",
                f"{Fore.CYAN}Service Version{Style.RESET_ALL}",
                f"{Fore.CYAN}Risk{Style.RESET_ALL}"
            ]
            
            host_table = []
            for host in data['hosts'][:15]:  # Limit to 15 hosts per port
                risk_color = self._get_risk_color(host['risk'])
                host_table.append([
                    host['ip'],
                    host.get('hostname', '—')[:20],
                    host.get('os', 'unknown')[:15],
                    host['version'][:35] if host['version'] != 'unknown' else '—',
                    risk_color + host['risk'].upper() + Style.RESET_ALL
                ])
            
            print(tabulate(host_table, headers=headers, tablefmt="simple"))
            
            if len(data['hosts']) > 15:
                print(f"  {Fore.WHITE}... and {len(data['hosts']) - 15} additional hosts{Style.RESET_ALL}")
        
        if len(table4_data) > 10:
            print(f"\n  {Fore.WHITE}... and {len(table4_data) - 10} additional ports{Style.RESET_ALL}")
        
        print("\n" + "═" * 80 + "\n")
    
    def _display_summary(self, analysis_results):
        """Display executive summary"""
        hosts = analysis_results.get('sorted_hosts', [])
        total_ports = sum(len(h.get('ports', [])) for h in hosts)
        total_cves = sum(len(h.get('cves', [])) for h in hosts)
        total_weak_ciphers = sum(len(h.get('weak_ciphers', [])) for h in hosts)
        
        print(f"{Fore.CYAN}{Style.BRIGHT}╔════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                         EXECUTIVE SUMMARY REPORT                        ║")
        print(f"╠════════════════════════════════════════════════════════════════════════════╣")
        print(f"║  • Total Hosts Analyzed  : {len(hosts):<48}║")
        print(f"║  • Total Open Ports      : {total_ports:<48}║")
        print(f"║  • Total CVEs Found      : {total_cves:<48}║")
        print(f"║  • Weak Cipher Suites    : {total_weak_ciphers:<48}║")
        print(f"╠════════════════════════════════════════════════════════════════════════════╣")
        
        # Risk distribution
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for host in hosts:
            level = host.get('risk_level', 'low')
            risk_counts[level] = risk_counts.get(level, 0) + 1
        
        print(f"║  • CRITICAL Risk Hosts   : {risk_counts['critical']:<48}║")
        print(f"║  • HIGH Risk Hosts       : {risk_counts['high']:<48}║")
        print(f"║  • MEDIUM Risk Hosts     : {risk_counts['medium']:<48}║")
        print(f"║  • LOW Risk Hosts        : {risk_counts['low']:<48}║")
        print(f"╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    def _get_risk_color(self, level):
        """Get color for risk level"""
        colors = {
            'critical': Fore.RED + Style.BRIGHT,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.GREEN,
            'unknown': Fore.WHITE
        }
        return colors.get(level.lower(), '')
