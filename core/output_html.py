"""HTML dashboard generation"""

import json
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from utils.helpers import colorize_risk

class HTMLOutput:
    """Generate HTML dashboard from analysis results with enforced table order"""
    
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup Jinja2 template environment
        template_dir = Path(__file__).parent.parent / 'templates'
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True
        )
    
    def generate(self, analysis_results, fusion_summary, nmap_commands, selected_tables):
        """Generate HTML dashboard with tables in CORRECT ORDER (1,2,3,4)"""
        
        # ENFORCE THE CORRECT TABLE ORDER (Table 1, 2, 3, 4)
        ordered_tables = []
        table_order = ['table1', 'table2', 'table3', 'table4']
        
        for table in table_order:
            if table in selected_tables:
                ordered_tables.append(table)
        
        # Prepare template data
        template_data = {
            'nmap_commands': nmap_commands,
            'fusion_summary': fusion_summary,
            'table1': analysis_results.get('table1', []),
            'table2': analysis_results.get('table2', {}),
            'table3': analysis_results.get('table3', []),
            'table4': analysis_results.get('table4', {}),
            'hosts': analysis_results.get('sorted_hosts', []),
            'selected_tables': ordered_tables,  # USE ORDERED LIST
            'timestamp': self._get_timestamp(),
            'stats': self._calculate_stats(analysis_results)
        }
        
        # Load and render template
        template = self.env.get_template('report.html')
        html_content = template.render(**template_data)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'nmapfusion_report_{timestamp}.html'
        output_file = self.output_dir / filename
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def _get_timestamp(self):
        """Get current timestamp for display"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def _calculate_stats(self, analysis_results):
        """Calculate statistics for dashboard"""
        hosts = analysis_results.get('sorted_hosts', [])
        
        stats = {
            'total_hosts': len(hosts),
            'total_ports': sum(len(h.get('ports', [])) for h in hosts),
            'total_cves': sum(len(h.get('cves', [])) for h in hosts),
            'total_weak_ciphers': sum(len(h.get('weak_ciphers', [])) for h in hosts),
            'risk_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        for host in hosts:
            level = host.get('risk_level', 'low')
            stats['risk_counts'][level] = stats['risk_counts'].get(level, 0) + 1
        
        return stats
