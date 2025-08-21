#!/bin/bash

# ==================== CONFIGURATION ====================
# Network settings for your network 
NETWORK="192.168.1.0/24"          # Your network (e.g.: 192.168.0.0/24)
INTERFACE="eth0"                  # Your network interface (check: ip a)
SCAN_DELAY="1s"                   # Delay between requests (to not break the network)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)  # Current time for filenames
LOG_DIR="/tmp/printer_audit"       # Folder for logs (can be changed to /var/log/)
SUSPECT_FILE="${LOG_DIR}/suspicious_activity_${TIMESTAMP}.log"
ALIVE_HOSTS="${LOG_DIR}/alive_hosts_${TIMESTAMP}.txt"
PRINT_HOSTS="${LOG_DIR}/print_hosts_${TIMESTAMP}.txt"
DETAILED_SCAN="${LOG_DIR}/detailed_scan_${TIMESTAMP}"

# ==================== PRINTER BRANDS WHITELIST ====================
# 🔧 CONFIGURATION: Add ALL printer brands that are in the scanned network here
# 📝 Format: "HP|Canon|Xerox|Epson" - via | without spaces
# 💡 Example: "HP|Canon|Xerox|RICOH|KYOCERA|Epson|Brother|Lexmark"
PRINTER_BRANDS="HP|Canon|Xerox|RICOH|KYOCERA|Epson|Brother|Lexmark|Konica|Minolta|OKI|Samsung|Sharp|Toshiba"

# ==================== BLACKLIST (OPTIONAL) ====================
# ⚠️ Exclude certain brands, add them here
# ❗ Example: "Unknown|Generic|Fake" - devices with such brands will be suspicious
BLACKLIST_BRANDS="Unknown|Generic|Fake"

# ==================== SECURITY SETTINGS ====================
set -euo pipefail  # Automatically stop the script on errors
export LANG=C.UTF-8  # Correct encoding for Russian letters

# ==================== PRE-RUN CHECKS ====================
echo "🔍 [PRINTER AUDIT START]"
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

# Check privileges (need root for some scans)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Script started without root rights"
    echo "   Some checks might not work"
    sleep 2
fi

# Create log folder
mkdir -p "$LOG_DIR" || {
    echo "❌ Cannot create folder: $LOG_DIR"
    exit 1
}

# ==================== FUNCTIONS ====================
# Function to log suspicious events
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
echo "📡 STEP 1: Searching for all devices in the network..."
echo "   Network: $NETWORK"
echo "   This will take 1-2 minutes..."

if ! nmap -sn -T4 --max-retries 1 --host-timeout 30s "$NETWORK" -oG "$ALIVE_HOSTS" > /dev/null 2>&1; then
    echo "❌ Network scan error!"
    exit 1
fi

# Extract only IP addresses of live devices
grep "Up" "$ALIVE_HOSTS" | awk '{print $2}' > "${ALIVE_HOSTS}.ips"

# Check if there are live devices
if [ ! -s "${ALIVE_HOSTS}.ips" ]; then
    echo "😴 No active devices in the network. Exiting."
    exit 0
fi

LIVE_COUNT=$(wc -l < "${ALIVE_HOSTS}.ips")
echo "✅ Devices found: $LIVE_COUNT"

# ==================== STEP 2: SEARCHING FOR PRINTER PORTS ====================
echo "🖨️  STEP 2: Searching for printers (ports 9100, 515, 631)..."
echo "   Scanning $LIVE_COUNT devices..."

if ! nmap -p 9100,515,631 --open --max-retries 1 --host-timeout 30s -T4 \
    -iL "${ALIVE_HOSTS}.ips" -oG "$PRINT_HOSTS" > /dev/null 2>&1; then
    echo "❌ Port scan error!"
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
        echo "⚠️  There were errors during scanning, but continuing..."
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
            REASONS+=("Computer is pretending to be a printer")
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
        
        # 4. 🔧 CHECKING BY WHITE AND BLACK BRAND LISTS
        # 📝 Logic: If there is printer information but no known brands OR there are forbidden brands
        if echo "$SCRIPT_INFO" | grep -q "printer-info"; then
            # 🟢 Whitelist check: if brand is NOT in the whitelist
            if ! echo "$SCRIPT_INFO" | grep -qi "$PRINTER_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Device not from whitelist brands")
            fi
            
            # 🔴 Blacklist check: if brand is in the blacklist
            if echo "$SCRIPT_INFO" | grep -qi "$BLACKLIST_BRANDS"; then
                SUSPICIOUS=true
                REASONS+=("Brand from blacklist detected")
            fi
        fi
        
                # ===== FINAL PJL VERIFICATION (INCREASING RELIABILITY) =====
        # Check if port 9100 is open and device is still suspicious
        if [ "$SUSPICIOUS" = true ] && echo "$SERVICE_INFO" | grep -q "9100/open"; then
            echo "      🔬 Checking authenticity via PJL..."
            log_suspicious "PJL_VERIFICATION_START" "$TARGET_IP" "Starting PJL verification for suspicious device"
            
            # Try to get device ID via PJL
            PJL_RESPONSE=$(timeout 5 echo "@PJL INFO ID" | nc -w 3 "$TARGET_IP" 9100 2>/dev/null | tr -d '\0' | head -1 || true)
            
            # Log the fact of the check and the received response
            log_suspicious "PJL_VERIFICATION_ATTEMPT" "$TARGET_IP" "Command sent: @PJL INFO ID"
            
            # If response is not empty and contains printer keywords - lower threat level
            if [[ -n "$PJL_RESPONSE" ]]; then
                echo "      📨 Response received: $PJL_RESPONSE"
                log_suspicious "PJL_RESPONSE_RECEIVED" "$TARGET_IP" "Response received: $PJL_RESPONSE"
                
                if echo "$PJL_RESPONSE" | grep -qi "PJL\|@PJL\|HP\|Canon\|Xerox\|Epson\|Brother"; then
                    echo "      ✅ PJL Check: Device responded as a real printer. Lowering threat level."
                    log_suspicious "PJL_VERIFICATION_PASSED" "$TARGET_IP" "Device responded as printer: $PJL_RESPONSE"
                    SUSPICIOUS=false
                    REASONS=("Printer signs detected (PJL response: $PJL_RESPONSE)")  # Overwrite reasons
                else
                    echo "      ⚠️ PJL Check: Non-standard response received. Confirming threat."
                    log_suspicious "PJL_VERIFICATION_FAILED" "$TARGET_IP" "Non-standard PJL response: $PJL_RESPONSE"
                    REASONS+=("Failed PJL verification. Response: $PJL_RESPONSE")
                fi
            else
                echo "      ❗ PJL Check: Device did not respond to PJL request. Confirming threat."
                log_suspicious "PJL_VERIFICATION_TIMEOUT" "$TARGET_IP" "Device did not respond to PJL INFO ID"
                REASONS+=("Did not respond to PJL INFO ID (timeout or no response)")
            fi
        fi
        
        # ===== ACTIONS IF SUSPICIOUS DEVICE FOUND =====
        if [ "$SUSPICIOUS" = true ]; then
            REASON_STR=$(IFS='; '; echo "${REASONS[*]}")
            log_suspicious "POSSIBLE PRINTER SPOOFING" "$TARGET_IP" "$REASON_STR"
            echo "      ❗ ATTENTION: Threat detected!"
            echo "      🖥️  OS: $OS_INFO"
            echo "      🛠️  Services: $SERVICE_INFO"
            echo "      📊 Scripts: $SCRIPT_INFO"
        else
            echo "      ✅ Device is OK (real printer or false positive)"
            log_suspicious "DEVICE_VERIFIED" "$TARGET_IP" "Device verified as printer via PJL"
        fi

# ==================== STEP 4: NETWORK PROTOCOL CHECK ====================
echo ""
read -p "❓ Check network for LLMNR/NBNS vulnerabilities? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📡 STEP 4: Checking network protocols (60 seconds)..."
    
    if command -v timeout >/dev/null 2>&1; then
        BROADCAST_CHECK=$(timeout 60 nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>/dev/null || true)
    else
        echo "⚠️  Timeout utility not found, scan might take longer"
        BROADCAST_CHECK=$(nmap --script broadcast-llmnr-discover,broadcast-nbns-discover -e "$INTERFACE" 2>/dev/null | head -50 || true)
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
    echo "   1. Check IP addresses from the report"
    echo "   2. Isolate suspicious devices from the network"
    echo "   3. Check logs on these devices"
    echo "   4. 🔧 Update the whitelist if needed"
else
    echo "✅ NO THREATS detected! Network is protected."
fi

echo ""
echo "📊 All scan files: $LOG_DIR"
echo "🔍 Main details file: ${DETAILED_SCAN}.nmap"
echo "🔧 Whitelist brands: $PRINTER_BRANDS"
if [ -n "$BLACKLIST_BRANDS" ]; then
    echo "⚫ Blacklist brands: $BLACKLIST_BRANDS"
fi
echo "💡 To change lists, edit the PRINTER_BRANDS and BLACKLIST_BRANDS variables"
echo "=========================================================="

# Copy logs to a convenient location
cp "$SUSPECT_FILE" "/tmp/last_printer_audit.log" 2>/dev/null || true
echo "📋 Short report also saved: /tmp/last_printer_audit.log"
