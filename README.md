PrinterGhost - Network Printer Security Auditor
### **🔥 What Problem Does This Solve?**
PrinterGhost addresses a critical enterprise security gap: malicious printer impersonation attacks (PrintJacking). Most organizations overlook network printers as potential attack vectors, leaving them vulnerable to:

1. Data exfiltration through fake print servers

2. Lateral movement within corporate networks

3. Man-in-the-middle attacks on print jobs

4. Credential theft via SMB relay attacks

5. Ransomware deployment through printer vulnerabilities

### **🚀 Quick Start**
**Prerequisites**
```
# Install required tools
sudo apt update && sudo apt install nmap

# Clone the repository
git clone https://github.com/whitegertsok/PrinterGhost.git
cd PrinterGhost
```
**Basic Usage**
```
# Make script executable
chmod +x printer_audit.sh

# Run with default settings
sudo ./printer_audit.sh
```
**Advanced Scanning**
```
# Scan specific network
sudo NETWORK="10.0.0.0/24" ./printer_audit.sh

# Custom interface and log location
sudo INTERFACE="eth1" LOG_DIR="/var/log/printer_audit" ./printer_audit.sh
```
### **📋 Comprehensive Guide**
**Configuration Options**
```
# Network settings
NETWORK="192.168.1.0/24"          # Your network range
INTERFACE="eth0"                  # Network interface
SCAN_DELAY="1s"                   # Scan timing

# Brand whitelist (ADD YOUR PRINTER BRANDS HERE)
PRINTER_BRANDS="HP|Canon|Xerox|Epson|Brother|Ricoh|Kyocera"

# Blacklist (suspicious brands)
BLACKLIST_BRANDS="Unknown|Generic|Fake"
```
Let's try for your SOC system! :) **In code EN - English transcription / RU - Russian transcription!**
