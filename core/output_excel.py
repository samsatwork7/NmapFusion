"""Excel report generation for NmapFusion - NO RISK"""

from pathlib import Path
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

class ExcelOutput:
    """Generate Excel compliance reports - NO RISK"""
    
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.wb = Workbook()
        
        # Styles - NO RISK COLORS
        self.header_font = Font(bold=True, color="FFFFFF")
        self.header_fill = PatternFill(start_color="00bcd4", end_color="00bcd4", fill_type="solid")
        self.border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
    
    def generate(self, analysis_results, fusion_summary, nmap_commands, selected_tables):
        """Generate Excel report with NmapFusion branding - NO RISK"""
        
        # Remove default sheet
        self.wb.remove(self.wb.active)
        
        # Enforce correct table order
        table_order = ['table1', 'table2', 'table3', 'table4']
        
        for table in table_order:
            if table in selected_tables:
                if table == 'table1':
                    self._create_table1_sheet(analysis_results['table1'])
                elif table == 'table2':
                    self._create_table2_sheet(analysis_results['table2'])
                elif table == 'table3':
                    self._create_table3_sheet(analysis_results['table3'])
                elif table == 'table4':
                    self._create_table4_sheet(analysis_results['table4'])
        
        # Always generate these sheets
        self._create_nmap_command_sheet(nmap_commands)
        self._create_nse_findings_sheet(analysis_results['sorted_hosts'])
        self._create_subnets_sheet(analysis_results['sorted_hosts'])
        self._create_raw_data_sheet(analysis_results['sorted_hosts'])
        self._create_executive_summary_sheet(analysis_results['sorted_hosts'], fusion_summary)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'nmapfusion_report_{timestamp}.xlsx'
        output_file = self.output_dir / filename
        
        # Save workbook
        self.wb.save(output_file)
        
        return output_file
    
    def _create_table1_sheet(self, table1_data):
        """Create Table 1: Host Summary Overview - NO RISK"""
        ws = self.wb.create_sheet("1_Host_Summary_Overview")
        
        headers = ["IP Address", "Hostname", "Total Ports", "TCP", "UDP", "Services", "OS"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.alignment = Alignment(horizontal='center')
            cell.border = self.border
        
        # Add data
        for row in table1_data:
            ws.append([
                row['ip'],
                row['hostname'] or '-',
                row['total_ports'],
                row['tcp_ports'],
                row['udp_ports'],
                row['total_services'],
                row['os'][:30] if row['os'] != 'unknown' else '-'
            ])
        
        self._adjust_column_widths(ws)
    
    def _create_table2_sheet(self, table2_data):
        """Create Table 2: Host Detailed Analysis - NO RISK"""
        ws = self.wb.create_sheet("2_Host_Detailed_Analysis")
        
        headers = ["IP Address", "Hostname", "OS", "Port", "Protocol", "Service", 
                  "Version", "NSE Findings", "Business Function"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.alignment = Alignment(horizontal='center')
            cell.border = self.border
        
        # Add data
        for ip, data in table2_data.items():
            if not data['ports']:
                ws.append([
                    ip,
                    data['hostname'] or '-',
                    data['os'],
                    '-', '-', '-', '-', '-', '-'
                ])
            else:
                for port in data['ports']:
                    nse_summary = '; '.join(port['nse_summary'][:2]) if port['nse_summary'] else '-'
                    ws.append([
                        ip,
                        data['hostname'] or '-',
                        data['os'],
                        port['port'],
                        port['protocol'],
                        port['service'],
                        port['version'][:50] if port['version'] != 'unknown' else '-',
                        nse_summary,
                        port['business_function'].replace('_', ' ').title()
                    ])
        
        self._adjust_column_widths(ws)
    
    def _create_table3_sheet(self, table3_data):
        """Create Table 3: Port Frequency Distribution"""
        ws = self.wb.create_sheet("3_Port_Frequency_Distribution")
        
        headers = ["Port", "Protocol", "Host Count", "Service", "Sample IPs"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.alignment = Alignment(horizontal='center')
            cell.border = self.border
        
        # Add data
        for row in table3_data:
            ip_sample = ', '.join(row['ip_list'][:5])
            if len(row['ip_list']) > 5:
                ip_sample += f" +{len(row['ip_list'])-5} more"
            
            ws.append([
                row['port'],
                row['protocol'],
                row['count'],
                row['service'],
                ip_sample
            ])
        
        self._adjust_column_widths(ws)
    
    def _create_table4_sheet(self, table4_data):
        """Create Table 4: Service Exposure Matrix - NO RISK"""
        ws = self.wb.create_sheet("4_Service_Exposure_Matrix")
        
        headers = ["Port", "Protocol", "Exposed Hosts", "IP Address", "Hostname", "OS", 
                  "Service Version", "Business Function"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.alignment = Alignment(horizontal='center')
            cell.border = self.border
        
        # Add data
        for port_key, data in table4_data.items():
            for host in data['hosts']:
                ws.append([
                    data['port'],
                    data['protocol'],
                    data['host_count'],
                    host['ip'],
                    host.get('hostname', '-'),
                    host.get('os', 'unknown')[:20],
                    host.get('version', '-')[:50],
                    host.get('business_function', 'other').replace('_', ' ').title()
                ])
        
        self._adjust_column_widths(ws)
    
    def _create_nmap_command_sheet(self, nmap_commands):
        """Create Nmap Command sheet"""
        ws = self.wb.create_sheet("Scan_Configuration")
        
        ws['A1'] = "Nmap Command(s) Used"
        ws['A1'].font = Font(bold=True, size=14)
        ws['A1'].fill = self.header_fill
        
        for i, cmd in enumerate(nmap_commands, 2):
            ws[f'A{i}'] = cmd
            ws[f'A{i}'].font = Font(name='Courier New')
        
        ws.column_dimensions['A'].width = 100
    
    def _create_nse_findings_sheet(self, hosts):
        """Create NSE Findings sheet"""
        ws = self.wb.create_sheet("NSE_Findings")
        
        headers = ["IP Address", "Hostname", "Script", "Output", "Port"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.border = self.border
        
        # Add NSE findings
        for host in hosts:
            for nse in host.get('nse', []):
                ws.append([
                    host['ip'],
                    host.get('hostname', '-'),
                    nse.get('id', ''),
                    nse.get('output', '')[:200],
                    '-'
                ])
        
        self._adjust_column_widths(ws)
    
    def _create_subnets_sheet(self, hosts):
        """Create Subnets sheet"""
        ws = self.wb.create_sheet("Subnet_Summary")
        
        from collections import defaultdict
        subnets = defaultdict(list)
        for host in hosts:
            subnet = host.get('subnet', 'unknown')
            subnets[subnet].append(host['ip'])
        
        headers = ["Subnet", "Host Count", "IP Range"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.border = self.border
        
        # Add subnet data
        for subnet, ips in sorted(subnets.items()):
            ws.append([
                subnet,
                len(ips),
                f"{ips[0]} - {ips[-1]}" if ips else '-'
            ])
        
        self._adjust_column_widths(ws)
    
    def _create_raw_data_sheet(self, hosts):
        """Create Raw Data sheet - NO RISK"""
        ws = self.wb.create_sheet("Raw_Data")
        
        headers = ["IP Address", "Hostname", "OS", "Port", "Protocol", "Service", 
                  "Version", "CVEs", "Source Files"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.border = self.border
        
        # Add raw data
        for host in hosts:
            cve_list = ', '.join([c.get('id', '') for c in host.get('cves', [])[:3]])
            source_files = ', '.join([Path(f).name for f in host.get('source_files', [])[:2]])
            
            if not host.get('ports'):
                ws.append([
                    host['ip'],
                    host.get('hostname', '-'),
                    host.get('os', 'unknown'),
                    '-', '-', '-', '-',
                    cve_list,
                    source_files
                ])
            else:
                for port in host.get('ports', []):
                    ws.append([
                        host['ip'],
                        host.get('hostname', '-'),
                        host.get('os', 'unknown'),
                        port['port'],
                        port['protocol'],
                        port['service'],
                        port.get('version', 'unknown')[:50],
                        cve_list,
                        source_files
                    ])
        
        self._adjust_column_widths(ws)
    
    def _create_executive_summary_sheet(self, hosts, fusion_summary):
        """Create Executive Summary sheet - NO RISK"""
        ws = self.wb.create_sheet("0_Executive_Summary")
        
        # Title
        ws['A1'] = 'NmapFusion - NETWORK ASSESSMENT SUMMARY'
        ws['A1'].font = Font(bold=True, size=16, color='00bcd4')
        ws.merge_cells('A1:F1')
        
        ws['A2'] = 'Enterprise Network Assessment Report'
        ws['A2'].font = Font(size=12, color='8899aa')
        ws.merge_cells('A2:F2')
        
        # Report Info
        ws['A4'] = 'Report Generated:'
        ws['B4'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ws['A4'].font = Font(bold=True)
        ws['B4'].font = Font(name='Courier New')
        
        ws['A5'] = 'Tool Version:'
        ws['B5'] = 'NmapFusion v1.0'
        ws['A5'].font = Font(bold=True)
        
        ws['A6'] = 'Files Analyzed:'
        ws['B6'] = fusion_summary.get('files_processed', 0)
        ws['A6'].font = Font(bold=True)
        
        # Statistics
        ws['A8'] = 'ASSESSMENT STATISTICS'
        ws['A8'].font = Font(bold=True, size=12, color='00bcd4')
        
        total_ports = sum(len(h.get('ports', [])) for h in hosts)
        total_cves = sum(len(h.get('cves', [])) for h in hosts)
        total_weak = sum(len(h.get('weak_ciphers', [])) for h in hosts)
        
        stats = [
            ['Total Hosts Analyzed:', len(hosts)],
            ['Total Open Ports:', total_ports],
            ['Total CVEs Found:', total_cves],
            ['Weak Cipher Suites:', total_weak],
            ['Total NSE Scripts:', fusion_summary.get('nse_merged', 0)]
        ]
        
        for i, stat in enumerate(stats, 10):
            ws[f'A{i}'] = stat[0]
            ws[f'B{i}'] = stat[1]
            ws[f'A{i}'].font = Font(bold=True)
        
        self._adjust_column_widths(ws)
    
    def _adjust_column_widths(self, worksheet):
        """Auto-adjust column widths"""
        for column in worksheet.columns:
            max_length = 0
            column_letter = get_column_letter(column[0].column)
            
            for cell in column:
                try:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                except:
                    pass
            
            adjusted_width = min(max_length + 2, 60)
            worksheet.column_dimensions[column_letter].width = adjusted_width
