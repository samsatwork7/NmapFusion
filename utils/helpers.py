"""Helper utilities for cross-platform compatibility"""

import os
import sys
import re
from pathlib import Path
from datetime import datetime
import ipaddress
from colorama import Fore, Style, init

# Initialize colorama for Windows
if sys.platform == 'win32':
    init(autoreset=True)

def safe_path(path):
    """Convert string to Path object safely"""
    return Path(str(path))

def ensure_dir(path):
    """Ensure directory exists"""
    Path(path).mkdir(parents=True, exist_ok=True)
    return path

def read_file_safe(filepath):
    """Read file with automatic encoding detection"""
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except Exception as e:
            raise e
    
    # Fallback: read as binary and decode ignoring errors
    with open(filepath, 'rb') as f:
        return f.read().decode('utf-8', errors='ignore')

def parse_timestamp(timestamp_str):
    """Parse various timestamp formats"""
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S%z',
        '%a %b %d %H:%M:%S %Y',
        '%Y-%m-%d %H:%M:%S %z'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(str(timestamp_str)[:25], fmt[:25])
        except (ValueError, TypeError):
            continue
    return datetime.now()

def colorize_risk(risk_level):
    """Return colorized risk level string"""
    colors = {
        'critical': Fore.RED + Style.BRIGHT,
        'high': Fore.RED,
        'medium': Fore.YELLOW,
        'low': Fore.GREEN,
        'info': Fore.CYAN
    }
    return f"{colors.get(risk_level.lower(), '')}{risk_level}{Style.RESET_ALL}"

def is_valid_ip(ip):
    """Validate IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def extract_subnet(ip):
    """Extract /24 subnet from IP"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return f"{'.'.join(ip.split('.')[:3])}.0/24"
        else:
            # IPv6 /64 subnet
            parts = ip.split(':')[:4]
            return ':'.join(parts) + '::/64'
    except:
        return 'unknown/24'

def clean_nse_output(output):
    """Clean NSE output by removing excessive whitespace and clutter"""
    if not output:
        return ""
    
    # Remove excessive newlines
    lines = [line.strip() for line in output.split('\n') if line.strip()]
    
    # Remove NSE metadata lines
    lines = [line for line in lines if not line.startswith('|_')]
    
    # Clean up common clutter
    cleaned = '; '.join(lines)
    cleaned = re.sub(r'\s+', ' ', cleaned)
    
    return cleaned[:200] + '...' if len(cleaned) > 200 else cleaned
