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
# 1. Clone repository
git clone https://github.com/samsatwork7/nmapfusion.git
cd nmapfusion

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run your first analysis
python nmapfusion.py -i ./nmap_scans/ -a --html --excel
