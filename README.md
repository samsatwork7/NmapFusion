# 🚀 NmapFusion - Enterprise Network Assessment Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-enterprise-red.svg)](https://github.com/)

**NmapFusion** is a professional-grade network assessment tool that intelligently fuses multiple Nmap scans into comprehensive security reports. Designed for penetration testers, security auditors, and network administrators.

---

## ✨ Enterprise Features

| Feature | Description |
|---------|-------------|
| 🔀 **Multi-File Fusion** | Intelligently merges multiple scan files (XML, GNMAP, NMAP) into unified host profiles |
| 🧠 **Smart Conflict Resolution** | Keeps most detailed version info, merges NSE findings, deduplicates ports |
| 📊 **Four Analytical Views** | Host Summary, Detailed Analysis, Port Distribution, Service Exposure Matrix |
| ⚠️ **Risk Intelligence** | CVEs, weak ciphers, outdated versions, high-risk port detection |
| 📈 **Executive Reporting** | HTML dashboards, Excel compliance reports, color-coded terminal output |
| 🔒 **Enterprise Ready** | Timestamped reports, subnet grouping, sorted outputs, no data loss |

---

## 🚀 Quick Start

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/samsatwork7/nmapfusion.git
cd nmapfusion

# 2. Create and activate a Python virtual environment
python3 -m venv env
source env/bin/activate     # For Linux/Kali/macOS

# (Windows PowerShell equivalent)
# .\env\Scripts\activate

# 3. Install dependencies inside the virtual environment
pip install -r requirements.txt

# 4. Run your first NmapFusion analysis
python nmapfusion.py -i ./nmap_scans/ --all --html --excel

