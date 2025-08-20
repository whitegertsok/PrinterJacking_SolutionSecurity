#!/bin/bash

# ==================== CONFIGURATION ====================
# Customize these settings for your network 
NETWORK="192.168.1.0/24"          # Your network (e.g.: 192.168.0.0/24)
INTERFACE="eth0"                  # Your network interface (check: ip a)
SCAN_DELAY="1s"                   # Delay between requests (to not break the network)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)  # Current time for filenames
LOG_DIR="/tmp/printer_audit"       # Log folder (can be changed to /var/log/)
SUSPECT_FILE="${LOG_DIR}/suspicious_activity_${TIMESTAMP}.log"
ALIVE_HOSTS="${LOG_DIR}/alive_hosts_${TIMESTAMP}.txt"
PRINT_HOSTS="${LOG_DIR}/print_hosts_${TIMESTAMP}.txt"
DETAILED_SCAN="${LOG_DIR}/detailed_scan_${TIMESTAMP}"

# ==================== PRINTER BRANDS WHITELIST ====================
# 🔧 CONFIGURATION: Add ALL printer brands that exist in your scanned network here
# 📝 Format: "HP|Canon|Xerox|Epson" - separated by | without spaces
# 💡 Example: "HP|Canon|Xerox|RICOH|KYOCERA|Epson|Brother|Lexmark"
PRINTER_BRANDS="HP|Canon|Xerox|RICOH|KYOCERA|Epson|Brother|Lexmark|Konica|Minolta|OKI|Samsung|Sharp|Toshiba"

# ==================== BLACKLIST (OPTIONAL) ====================
# ⚠️ Exclude specific brands, add them here
# ❗ Example: "Unknown|Generic|Fake" - devices with such brands will be suspicious
BLACKLIST_BRANDS="Unknown|Generic|Fake"

# ==================== SECURITY SETTINGS ====================
set -euo pipefail  # Automatically stop script on errors
export LANG=C.UTF-8  # Correct encoding for Russian letters

# ==================== PRE-LAUNCH CHECKS ====================
echo "🔍 [PRINTER AUDIT LAUNCH]"
echo "⏰ Time: $(date)"
echo "📁 Logs will be here: $LOG_DIR"
echo "🔧 Whitelist brands: $PRINTER_BRANDS"
if [ -n "$BLACKLIST_BRANDS" ]; then
    echo "⚫ Blacklist brands: $BLACKLIST_BRANDS"
fi
echo "=========================================================="

# Check if nmap is installed
if ! command -v nmap >/dev/null 2>&1; then
    echo "❌ ERROR: Nmap is not installed!"
    echo "💻 Install it: sudo apt install nmap"
    exit 1
fi

# Check permissions (root needed for some scans)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Script launched without root rights"
    echo "   Some checks may not work"
    sleep 2
fi

# Create log folder
mkdir -p "$LOG_DIR" || {
    echo "❌ Cannot create folder: $LOG_DIR"
    exit 1
}

# ==================== FUNCTIONS ====================
# Function for logging suspicious events
log_suspicious() {
    local message=$1    # What happened
    local ip=$2         # IP address
    local details=$3    # Details
    
    echo "🚨 SUSPICIOUS ACTIVITY: $message" | tee -a "$SUSPECT_FILE"
    echo "   📍 IP: $ip" | tee -a "$SUSPECT_FILE"
    echo "   📝 Details: $details" | tee -a "$SUSPECT_FILE"
    echo "   ⏰ Time: $(date)" | tee -a "$SUSPECT_FILE"
    echo "----------------------------------------" | tee -a "$SUSPECT_FILE"
}

# ==================== STEP 1: FINDING LIVE DEVICES ====================
echo "📡 STEP 1: Searching for all devices in network..."
echo "   Network: $NETWORK"
echo "   This will take 1-2 minutes..."

if ! nmap -sn -T4 --max-retries 1 --host-timeout 30s "$NETWORK" -oG "$ALIVE_HOSTS" > /dev/null 2>&1; then
    echo "❌ Network scanning error!"
    exit 1
fi

# Extract only IP addresses of live devices
grep "Up" "$ALIVE_HOSTS" | awk '{print $2}' > "${ALIVE_HOSTS}.ips"

# Check if there are live devices
if [ ! -s "${ALIVE_HOSTS}.ips" ]; then
    echo "😴 No active devices in network. Exiting."
    exit 0
fi

LIVE_COUNT=$(wc -l < "${ALIVE_HOSTS}.ips")
echo "✅ Devices found: $LIVE_COUNT"

# ==================== STEP 2: FINDING PRINTER PORTS ====================
echo "🖨️  STEP 2: Searching for printers (ports 9100, 515, 631)..."
echo "   Scanning $LIVE_COUNT devices..."

if ! nmap -p 9100,515,631 --open --max-retries 1 --host-timeout 30s -T4 \
    -iL "${ALIVE_HOSTS}.ips" -oG "$PRINT_HOSTS" > /dev/null 2>&1; then
    echo "❌ Port scanning error!"
    exit 1
fi

# Count found printers
PRINT_COUNT=$(grep -c "open" "$PRINT_HOSTS" || true)
echo "✅ Devices with printer ports found: $PRINT_COUNT"

# Save IP addresses of suspicious devices
grep "open" "$PRINT_HOSTS" | awk '{print $2}' > "${PRINT_HOSTS}.ips"

# ==================== STEP 3: CHECKING SUSPICIOUS DEVICES ====================
if [ -s "${PRINT_HOSTS}.ips" ]; then
    echo "🔍 STEP 3: Checking found devices..."
    echo "   ⚠️  Attention: this will take 3-10 minutes!"
    echo "   Scanning $PRINT_COUNT devices..."
    
    # Deep scan of each suspicious device
    if ! nmap -O -sV -T4 --osscan-guess --max-retries 1 --host-timeout 2m \
        --script="ipp-enum,printer-info,smb2-security-mode" \
        -iL "${PRINT_HOSTS}.ips" -oA "$DETAILED_SCAN" > /dev/null 2>&1; then
        echo "⚠️  There were scanning errors, but continuing..."
    fi
    
    # Check each device
    while IFS= read -r TARGET_IP; do
        echo "   🔎 Checking: $TARGET_IP"
        
        # Extract information from nmap results
        OS_INFO=$(grep -A 15 "Nmap scan report for $TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                 grep -E "Running|OS details|Aggressive OS guesses" | head -3 || echo "Not defined")
        
        SERVICE_INFO=$(grep -A 20 "Nmap scan report for $TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                      grep -E "9100|515|631|445|135" | grep -E "open|filtered" || echo "No information")
        
        SCRIPT_INFO=$(grep -A 10 -B 2 "$TARGET_IP" "${DETAILED_SCAN}.nmap" 2>/dev/null | \
                     grep -E "printer-info|ipp-enum|message_signing" | head -5 || echo "No data")
        
        # ===== CHECKING FOR HACKING SIGNS =====
        SUSPICIOUS=false
        REASONS=()
        
        # 1. Windows\|Linux\|Mac\|macOS\|Apple\|Darwin on printer ports - MAIN SIGN!
        if echo "$OS_INFO" | grep -qi "Windows\|Linux\|Mac\|macOS\|Apple\|Darwin" && \
           echo "$SERVICE_INFO" | grep -q "9100/open\|631/open"; then
            SUSPICIOUS=true
            REASONS+=("Computer pretending to be printer")
        fi
        
        # 2. SMB signing disabled - vulnerability for attacks
        if echo "$SCRIPT_INFO" | grep -q "message_signing: disabled"; then
            SUSPICIOUS=true
            REASONS+=("SMB signing disabled - vulnerability")
        fi
        
        # 3. Windows services on "printer"
        if echo "$SERVICE_INFO" | grep -q "445/open.*microsoft-ds\|135/open.*msrpc"; then
            SUSPICIOUS=true
            REASONS+=("Windows server found instead of printer")
        fi
        
        # 4. 🔧 WHITELIST AND BLACKLIST BRAND CHECKING
        # 📝 Logic: If there is printer information but no known brands OR there are forbidden brands
        if echo "$SCRIPT_INFO" | grep -q "printer-info"; then
            # 🟢 Whitelist check: if brand NOT in whitelist
            if ! echo "$SCRIPT_INFO" | grep -qi "$PRINTER_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Device not from whitelist brands")
            fi
            
            # 🔴 Blacklist check: if brand in blacklist
            if echo "$SCRIPT_INFO" | grep -qi "$BLACKLIST_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Brand from blacklist detected")
            fi
        fi
        
        # ===== ACTIONS IF SUSPICIOUS DEVICE FOUND =====
        if [ "$SUSPICIOUS" = true ]; then
            REASON_STR=$(IFS='; '; echo "${REASONS[*]}")
            log_suspicious "POSSIBLE PRINTER IMPERSONATION" "$TARGET_IP" "$REASON_STR"
            echo "      ❗ ATTENTION: Threat detected!"
            echo "      🖥️  OS: $OS_INFO"
            echo "      🛠️  Services: $SERVICE_INFO"
            echo "      📊 Scripts: $SCRIPT_INFO"
        else
            echo "      ✅ Device is OK (real printer)"
        fi
        
    done < "${PRINT_HOSTS}.ips"
else
    echo "✅ No suspicious printers found"
fi

# ==================== STEP 4: NETWORK PROTOCOL CHECKING ====================
echo ""
read -p "❓ Check network for LLMNR/NBNS vulnerabilities? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📡 STEP 4: Network protocol checking (60 seconds)..."
    
    if command -v timeout >/dev/null 2>&1; then
        BROADCAST_CHECK=$(timeout 60 nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>&1 || true)
    else
        echo "⚠️  Timeout utility not found, scanning may take longer"
        BROADCAST_CHECK=$(nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>&1 | head -50 || true)
    fi
    
    if echo "$BROADCAST_CHECK" | grep -q "discovered"; then
        echo "⚠️  LLMNR/NBNS network activity detected"
        echo "$BROADCAST_CHECK" | grep "discovered" | while read -r line; do
            log_suspicious "NETWORK ACTIVITY" "N/A" "$line"
        done
    else
        echo "✅ Network protocols are OK"
    fi
fi

# ==================== FINAL REPORT ====================
echo ""
echo "=========================================================="
echo "🎉 AUDIT COMPLETED: $(date)"
echo "=========================================================="

if [ -f "$SUSPECT_FILE" ] && [ -s "$SUSPECT_FILE" ]; then
    SUSPECT_COUNT=$(grep -c "SUSPICIOUS ACTIVITY" "$SUSPECT_FILE")
    echo "🚨 THREATS FOUND: $SUSPECT_COUNT"
    echo "📄 Details in file: $SUSPECT_FILE"
    echo ""
    echo "⚡ RECOMMENDATIONS:"
    echo "   1. Check IP addresses from report"
    echo "   2. Isolate suspicious devices from network"
    echo "   3. Check logs on these devices"
    echo "   4. 🔧 Update whitelist brands if needed"
else
    echo "✅ NO THREATS detected! Network secured."
fi

echo ""
echo "📊 All scan files: $LOG_DIR"
echo "🔍 Main details file: ${DETAILED_SCAN}.nmap"
echo "🔧 Whitelist brands: $PRINTER_BRANDS"
if [ -n "$BLACKLIST_BRANDS" ]; then
    echo "⚫ Blacklist brands: $BLACKLIST_BRANDS"
fi
echo "💡 To modify lists, edit PRINTER_BRANDS and BLACKLIST_BRANDS variables"
echo "=========================================================="

# Copy logs to convenient location
cp "$SUSPECT_FILE" "/tmp/last_printer_audit.log" 2>/dev/null || true
echo "📋 Short report also saved: /tmp/last_printer_audit.log"
