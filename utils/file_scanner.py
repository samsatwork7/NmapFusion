"""Auto-detect and categorize nmap output files"""

import os
import re
from pathlib import Path
from collections import defaultdict

class FileScanner:
    """Scan directory for nmap output files and detect their types"""
    
    def __init__(self):
        self.files = {
            'xml': [],
            'gnmap': [],
            'nmap': []
        }
    
    def scan_directory(self, directory_path):
        """Recursively scan directory for nmap files"""
        base_path = Path(directory_path)
        
        if not base_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if base_path.is_file():
            # Single file
            self._classify_file(base_path)
        else:
            # Directory - scan all files
            for file_path in base_path.rglob('*'):
                if file_path.is_file():
                    self._classify_file(file_path)
        
        return self.files
    
    def _classify_file(self, file_path):
        """Classify file type based on extension and content"""
        ext = file_path.suffix.lower()
        name = file_path.name.lower()
        
        # Check extension first
        if ext == '.xml' or name.endswith('.xml'):
            self.files['xml'].append(file_path)
        elif ext == '.gnmap' or name.endswith('.gnmap') or '.gnmap' in name:
            self.files['gnmap'].append(file_path)
        elif ext == '.nmap' or name.endswith('.nmap') or '.nmap' in name:
            self.files['nmap'].append(file_path)
        else:
            # Try to detect by content
            self._detect_by_content(file_path)
    
    def _detect_by_content(self, file_path):
        """Try to detect nmap output format by reading file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = ''.join([f.readline() for _ in range(5)])
                
                # XML detection
                if '<?xml' in first_lines and 'nmaprun' in first_lines:
                    self.files['xml'].append(file_path)
                
                # GNMAP detection
                elif 'Host:' in first_lines and 'Ports:' in first_lines:
                    self.files['gnmap'].append(file_path)
                
                # NMAP detection
                elif 'Nmap scan report for' in first_lines:
                    self.files['nmap'].append(file_path)
                    
        except Exception:
            pass  # If can't read, skip
    
    def get_summary(self):
        """Get summary of found files"""
        summary = {
            'total': sum(len(files) for files in self.files.values()),
            'xml': len(self.files['xml']),
            'gnmap': len(self.files['gnmap']),
            'nmap': len(self.files['nmap'])
        }
        return summary

def find_nmap_files(input_path):
    """Convenience function to find all nmap files"""
    scanner = FileScanner()
    return scanner.scan_directory(input_path)
