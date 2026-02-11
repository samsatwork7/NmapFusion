#!/usr/bin/env python3
"""NmapFusion - Multi-File Fusion Tool for Network Assessment"""

import sys
import argparse
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.aggregator import Aggregator
from core.analyzer import Analyzer
from core.enricher import Enricher
from core.output_terminal import TerminalOutput
from core.output_html import HTMLOutput
from core.output_excel import ExcelOutput

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='🚀 NmapFusion - Enterprise Network Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════╗
║                    NmapFusion v1.0                       ║
║              Multi-File Network Fusion Tool              ║
╠══════════════════════════════════════════════════════════╣
║  FLAGS REFERENCE:                                        ║
║                                                          ║
║  📊 TABLES:                                             ║
║    -1     : Table 1 - Host Summary Overview             ║
║    -2     : Table 2 - Host Detailed Analysis            ║
║    -3     : Table 3 - Port Frequency Distribution       ║
║    -4     : Table 4 - Service Exposure Matrix           ║
║    -a     : ALL tables                                  ║
║                                                          ║
║  📤 OUTPUT:                                             ║
║    --html  : Generate HTML Security Dashboard           ║
║    --excel : Generate Excel Compliance Report           ║
║                                                          ║
║  ⚙️  OTHER:                                             ║
║    -i     : Input file/folder (REQUIRED)                ║
║    -o     : Output directory (default: ./output/)       ║
║    -v     : Verbose mode (fusion details)               ║
║    -d     : Debug mode                                  ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  📌 EXAMPLES:                                           ║
║    python nmapfusion.py -i ./scans/ -a                  ║
║    python nmapfusion.py -i ./scans/ -2 -4 --html        ║
║    python nmapfusion.py -i ./scans/ -1 -v -o ./reports/ ║
╚══════════════════════════════════════════════════════════╝
        """
    )
    
    # Input/Output
    parser.add_argument('-i', '--input', required=True, 
                       help='Input nmap file or directory')
    parser.add_argument('-o', '--output', 
                       help='Output directory (default: ./output/)')
    
    # Table selection
    table_group = parser.add_argument_group('Table Selection')
    table_group.add_argument('-1', '--table1', action='store_true',
                           help='Table 1: Host Summary Overview')
    table_group.add_argument('-2', '--table2', action='store_true',
                           help='Table 2: Host Detailed Analysis')
    table_group.add_argument('-3', '--table3', action='store_true',
                           help='Table 3: Port Frequency Distribution')
    table_group.add_argument('-4', '--table4', action='store_true',
                           help='Table 4: Service Exposure Matrix')
    table_group.add_argument('-a', '--all', action='store_true',
                           help='Show ALL tables')
    
    # Output formats
    output_group = parser.add_argument_group('Output Formats')
    output_group.add_argument('--html', action='store_true',
                            help='Generate HTML Security Dashboard')
    output_group.add_argument('--excel', action='store_true',
                            help='Generate Excel Compliance Report')
    
    # Other options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (show fusion details)')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Debug mode')
    parser.add_argument('--config', 
                       help='Configuration file (JSON)')
    
    args = parser.parse_args()
    
    # If no tables specified, show all
    if not any([args.table1, args.table2, args.table3, args.table4, args.all]):
        args.all = True
    
    return args

def load_config(config_path):
    """Load configuration from JSON file"""
    if config_path:
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    return {}

def main():
    """Main entry point for NmapFusion"""
    args = parse_arguments()
    
    # Setup output directory
    output_dir = Path(args.output) if args.output else Path.cwd() / 'output'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load configuration
    config = load_config(args.config)
    
    print("""
╔══════════════════════════════════════════════════════════╗
║                    🚀 NmapFusion v1.0                    ║
║              Enterprise Network Fusion Tool              ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    # Step 1: Parse and fuse all files
    print(f"[1/5] 📂 Processing input: {args.input}")
    aggregator = Aggregator(config)
    hosts = aggregator.process_input(args.input)
    fusion_summary = aggregator.get_fusion_summary()
    
    if not hosts:
        print("❌ No hosts found in the input files.")
        sys.exit(1)
    
    print(f"[2/5] 🔀 Fusion complete: {fusion_summary['unique_ips']} unique IPs from {fusion_summary['files_processed']} files")
    
    # Step 2: Enrich with risk scores and subnet info
    print("[3/5] ⚠️  Enriching data with risk scores...")
    enricher = Enricher(config)
    hosts = enricher.enrich_hosts(hosts)
    
    # Step 3: Analyze and build tables
    print("[4/5] 📊 Analyzing and building tables...")
    analyzer = Analyzer()
    analysis_results = analyzer.analyze(hosts)
    
    # Collect all unique nmap commands
    all_commands = set()
    for host in hosts:
        all_commands.update(host.get('commands', []))
    nmap_commands = sorted(list(all_commands))
    
    # Determine selected tables - MAINTAIN ORDER
    table_order = ['table1', 'table2', 'table3', 'table4']
    selected_tables = []
    if args.all:
        selected_tables = table_order.copy()
    else:
        if args.table1:
            selected_tables.append('table1')
        if args.table2:
            selected_tables.append('table2')
        if args.table3:
            selected_tables.append('table3')
        if args.table4:
            selected_tables.append('table4')
    
    # Step 4: Generate outputs
    print("[5/5] 📤 Generating outputs...")
    
    # Terminal output
    terminal = TerminalOutput(verbose=args.verbose)
    terminal.display(analysis_results, fusion_summary, selected_tables, nmap_commands)
    
    # HTML output
    if args.html:
        print("\n[+] Generating HTML Security Dashboard...")
        html_output = HTMLOutput(output_dir)
        html_file = html_output.generate(analysis_results, fusion_summary, nmap_commands, selected_tables)
        print(f"    📁 HTML report: {html_file}")
    
    # Excel output
    if args.excel:
        print("[+] Generating Excel Compliance Report...")
        excel_output = ExcelOutput(output_dir)
        excel_file = excel_output.generate(analysis_results, fusion_summary, nmap_commands, selected_tables)
        print(f"    📁 Excel report: {excel_file}")
    
    print("\n✅ NmapFusion analysis complete!")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if '--debug' in sys.argv or '-d' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
