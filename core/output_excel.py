"""Excel report generation"""

from pathlib import Path
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

class ExcelOutput:
    """Generate Excel report with multiple sheets in correct order"""
    
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.wb = Workbook()
        
        # Styles
        self.header_font = Font(bold=True, color="FFFFFF")
        self.header_fill = PatternFill(start_color="00bcd4", end_color="00bcd4", fill_type="solid")
        self.risk_fills = {
            'critical': PatternFill(start_color="FF4444", end_color="FF4444", fill_type="solid"),
            'high': PatternFill(start_color="FF8800", end_color="FF8800", fill_type="solid"),
            'medium': PatternFill(start_color="FFBB33", end_color="FFBB33", fill_type="solid"),
            'low': PatternFill(start_color="00C851", end_color="00C851", fill_type="solid")
        }
        self.border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
    
    def generate(self, analysis_results, fusion_summary, nmap_commands, selected_tables):
        """Generate Excel report with tables in CORRECT ORDER (1,2,3,4)"""
        
        # Remove default sheet
        self.wb.remove(self.wb.active)
        
        # ENFORCE THE CORRECT TABLE ORDER
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
        
        # Always generate these sheets (after tables)
        self._create_nmap_command_sheet(nmap_commands)
        self._create_nse_findings_sheet(analysis_results['sorted_hosts'])
        self._create_risks_sheet(analysis_results['sorted_hosts'])
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
        """Create Table 1: Host Summary Overview sheet"""
        ws = self.wb.create_sheet("1_Host_Summary_Overview")
        
        headers = ["IP Address", "Hostname", "Total Ports", "TCP", "UDP", "Services", "OS", "Risk Level"]
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
                row['os'][:30] if row['os'] != 'unknown' else '-',
                row['risk_level'].upper()
            ])
        
        # Format risk column
        for row_idx in range(2, len(table1_data) + 2):
            risk_cell = ws.cell(row=row_idx, column=8)
            risk_level = ws.cell(row=row_idx, column=8).value.lower()
            if risk_level in self.risk_fills:
                risk_cell.fill = self.risk_fills[risk_level]
        
        self._adjust_column_widths(ws)
    
    def _create_table2_sheet(self, table2_data):
        """Create Table 2: Host Detailed Analysis sheet"""
        ws = self.wb.create_sheet("2_Host_Detailed_Analysis")
        
        headers = ["IP Address", "Hostname", "OS", "Port", "Protocol", "Service", 
                  "Version", "Risk", "NSE Findings", "Business Function"]
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
                    '-', '-', '-', '-', '-', '-', '-'
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
                        port['risk'].upper(),
                        nse_summary,
                        port['business_function'].replace('_', ' ').title()
                    ])
        
        # Format risk column
        for row_idx in range(2, ws.max_row + 1):
            risk_cell = ws.cell(row=row_idx, column=8)
            if risk_cell.value and risk_cell.value != '-':
                risk_level = risk_cell.value.lower()
                if risk_level in self.risk_fills:
                    risk_cell.fill = self.risk_fills[risk_level]
        
        self._adjust_column_widths(ws)
    
    def _create_table3_sheet(self, table3_data):
        """Create Table 3: Port Frequency Distribution sheet"""
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
        """Create Table 4: Service Exposure Matrix sheet"""
        ws = self.wb.create_sheet("4_Service_Exposure_Matrix")
        
        headers = ["Port", "Protocol", "Exposed Hosts", "IP Address", "Hostname", "OS", 
                  "Service Version", "Risk", "Business Function"]
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
                    host.get('risk', 'unknown').upper(),
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
    
    def _create_risks_sheet(self, hosts):
        """Create Risks sheet"""
        ws = self.wb.create_sheet("Risk_Assessment")
        
        headers = ["IP Address", "Risk Level", "Risk Score", "CVEs", "Weak Ciphers", "High Risk Ports"]
        ws.append(headers)
        
        # Format headers
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col)
            cell.font = self.header_font
            cell.fill = self.header_fill
            cell.border = self.border
        
        # Add risk data
        for host in hosts:
            high_risk_ports = [str(p['port']) for p in host.get('ports', []) 
                             if p.get('risk', {}).get('level') in ['critical', 'high']]
            
            ws.append([
                host['ip'],
                host.get('risk_level', 'unknown').upper(),
                host.get('risk_score', 0),
                len(host.get('cves', [])),
                len(host.get('weak_ciphers', [])),
                ', '.join(high_risk_ports[:5])
            ])
        
        # Format risk column
        for row_idx in range(2, len(hosts) + 2):
            risk_cell = ws.cell(row=row_idx, column=2)
            if risk_cell.value:
                risk_level = risk_cell.value.lower()
                if risk_level in self.risk_fills:
                    risk_cell.fill = self.risk_fills[risk_level]
        
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
        """Create Raw Data sheet"""
        ws = self.wb.create_sheet("Raw_Data")
        
        headers = ["IP Address", "Hostname", "OS", "Port", "Protocol", "Service", 
                  "Version", "Risk Level", "Risk Score", "CVEs", "Source Files"]
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
                    host.get('risk_level', 'unknown').upper(),
                    host.get('risk_score', 0),
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
                        port.get('risk', {}).get('level', 'unknown').upper(),
                        port.get('risk', {}).get('score', 0),
                        cve_list,
                        source_files
                    ])
        
        self._adjust_column_widths(ws)
    
    def _create_executive_summary_sheet(self, hosts, fusion_summary):
        """Create Executive Summary sheet"""
        ws = self.wb.create_sheet("0_Executive_Summary")
        
        # Title
        ws['A1'] = 'EXECUTIVE SUMMARY - NETWORK SECURITY ASSESSMENT'
        ws['A1'].font = Font(bold=True, size=16, color='00bcd4')
        ws.merge_cells('A1:F1')
        
        # Report Info
        ws['A3'] = 'Report Generated:'
        ws['B3'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ws['A3'].font = Font(bold=True)
        ws['B3'].font = Font(name='Courier New')
        
        ws['A4'] = 'Files Analyzed:'
        ws['B4'] = fusion_summary.get('files_processed', 0)
        ws['A4'].font = Font(bold=True)
        
        # Statistics
        ws['A6'] = 'STATISTICS'
        ws['A6'].font = Font(bold=True, size=12, color='00bcd4')
        
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_ports = 0
        total_cves = 0
        
        for host in hosts:
            level = host.get('risk_level', 'low')
            risk_counts[level] = risk_counts.get(level, 0) + 1
            total_ports += len(host.get('ports', []))
            total_cves += len(host.get('cves', []))
        
        stats = [
            ['Total Hosts:', len(hosts)],
            ['Total Open Ports:', total_ports],
            ['Total CVEs Found:', total_cves],
            ['Critical Risk Hosts:', risk_counts['critical']],
            ['High Risk Hosts:', risk_counts['high']],
            ['Medium Risk Hosts:', risk_counts['medium']],
            ['Low Risk Hosts:', risk_counts['low']]
        ]
        
        for i, stat in enumerate(stats, 7):
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
