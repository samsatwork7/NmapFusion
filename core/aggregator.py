"""Aggregate all parsed data and feed to fusion engine"""

from core.parser_xml import XMLParser
from core.parser_gnmap import GNMAPParser
from core.parser_nmap import NMAPParser
from core.fusion_engine import FusionEngine
from utils.file_scanner import find_nmap_files

class Aggregator:
    """Aggregate and parse all nmap files"""
    
    def __init__(self, config=None):
        self.xml_parser = XMLParser()
        self.gnmap_parser = GNMAPParser()
        self.nmap_parser = NMAPParser()
        self.fusion_engine = FusionEngine(config)
        self.config = config
    
    def process_input(self, input_path):
        """Process input path (file or directory)"""
        
        # Find all nmap files
        files = find_nmap_files(input_path)
        
        # Parse each file type
        for xml_file in files['xml']:
            results = self.xml_parser.parse(xml_file)
            self.fusion_engine.add_scan(results, xml_file)
        
        for gnmap_file in files['gnmap']:
            results = self.gnmap_parser.parse(gnmap_file)
            self.fusion_engine.add_scan(results, gnmap_file)
        
        for nmap_file in files['nmap']:
            results = self.nmap_parser.parse(nmap_file)
            self.fusion_engine.add_scan(results, nmap_file)
        
        # Resolve conflicts and finalize fusion
        self.fusion_engine.resolve_conflicts()
        
        return self.fusion_engine.get_unified_hosts()
    
    def get_fusion_summary(self):
        """Get fusion engine statistics"""
        return self.fusion_engine.get_fusion_summary()
