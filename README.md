# 🚨 Multi-Threaded DNS Spoofing Detector & Network Analyzer

A powerful desktop graphical user interface (GUI) application built in Python designed to audit network integrity and detect DNS spoofing anomalies[cite: 2]. The tool validates records simultaneously across multiple global DNS servers, verifies security extensions, and performs direct IP reputation checks[cite: 2].

## 🛠️ Key Technical Features
- **Custom DNS Resolution:** Crafts low-level binary DNS queries and parses responses using raw network sockets[cite: 2].
- **Cross-Server Consistency Auditing:** Compares domain resolution outputs across multiple custom target DNS servers simultaneously to flag mismatch anomalies[cite: 2].
- **Asynchronous Multi-Threading:** Utilizes Python's `ThreadPoolExecutor` and `threading` modules to run network scans in the background without freezing the responsive Tkinter interface[cite: 2].
- **Cryptographic Trust Verification:** Fetches DNSKEY arrays and runs localized `DNSSEC` cryptographic signature verification[cite: 2].
- **Comprehensive Threat Intel:** Built-in automatic secondary validation including GeoIP lookup, website port availability checks, and multi-feed DNSBL (DNS Blacklist/Spamhaus) reputation auditing[cite: 2].
- **Premium UI Theme:** Native cross-platform dark mode powered by the industry-standard **Dracula Color Scheme**[cite: 2].

## 🧰 Built With
- **Language:** Python 3[cite: 2]
- **GUI Engine:** Tkinter + Custom CSS-style ToolTips & Loading Animation Spinners[cite: 2].
- **Core Networking:** `socket`, `dnspython`, `ipaddress`, `requests`[cite: 2].

## 🚀 Installation & Usage

### Prerequisites
- Python 3.10+ installed
- Npcap (Windows) or libpcap (Linux/Mac) required for raw network socket access

### Setup
1. Clone this repository:
### Setup
1. Clone this repository:
```bash
git clone [https://github.com/Ash-Hackz/dns-spoof-detector-tool.git](https://github.com/Ash-Hackz/dns-spoof-detector-tool.git)
cd dns-spoof-detector-tool
