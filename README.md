# 🚨 Multi-Threaded DNS Spoofing Detector & Network Analyzer

A powerful desktop graphical user interface (GUI) application built in Python designed to audit network integrity and detect DNS spoofing anomalies. The tool validates records simultaneously across multiple global DNS servers, verifies security extensions, and performs direct IP reputation checks.

## 🛠️ Key Technical Features
- **Custom DNS Resolution:** Crafts low-level binary DNS queries and parses responses using raw network sockets.
- **Cross-Server Consistency Auditing:** Compares domain resolution outputs across multiple custom target DNS servers (e.g., Google, Cloudflare) simultaneously to flag mismatch anomalies.
- **Asynchronous Multi-Threading:** Utilizes Python's `ThreadPoolExecutor` and `threading` modules to run network scans in the background without freezing the responsive Tkinter interface.
- **Cryptographic Trust Verification:** Fetches DNSKEY arrays and runs localized `DNSSEC` cryptographic signature verification.
- **Comprehensive Threat Intel:** Built-in automatic secondary validation including GeoIP lookup, website port availability checks, and multi-feed DNSBL (DNS Blacklist/Spamhaus) reputation auditing.
- **Premium UI Theme:** Native cross-platform dark mode powered by the industry-standard **Dracula Color Scheme**.

## 🧰 Built With
- **Language:** Python 3
- **GUI Engine:** Tkinter + Custom CSS-style ToolTips & Loading Animation Spinners.
- **Core Networking:** `socket`, `dnspython`, `ipaddress`, `requests`.

## 🚀 Installation & Usage

### Prerequisites
- Python 3.10+ installed
- Npcap (Windows) or libpcap (Linux/Mac) required for raw network socket access

### Setup

1. Clone this repository:
```bash
git clone https://github.com/Ash-Hackz/dns-spoof-detector-tool.git
cd dns-spoof-detector-tool
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Execute the tool:
```bash
python app.py
```

## 📄 License
This project is licensed under the MIT License.
