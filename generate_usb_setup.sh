#!/bin/bash
# =============================================================================
# MakerMate WiFi Setup Script for Elegoo Neptune 4 Series
# Version: 4.0
# 
# Creates a USB package that automatically configures persistent WiFi
# on Elegoo Neptune 4 / 4 Pro / 4 Plus / 4 Max printers.
#
# Usage: sudo ./generate_usb_setup.sh
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
  echo -e "${BLUE}"
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║          MakerMate WiFi Setup for Elegoo Neptune 4            ║"
  echo "║                      Version 4.0                              ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
  log_error "This script must be run as root"
  echo "Execute with: sudo $0"
  exit 1
fi

# Configuration
USB_MOUNT="/media/usb"
UPDATE_DIR="$USB_MOUNT/ELEGOO_UPDATE_DIR"
PKG_DIR="/tmp/makermate_pkg"
DEB_PATH="$UPDATE_DIR/ELEGOO_FIX_BAG.deb"

log_info "Cleaning up previous installations..."

# Cleanup previous installations (local machine)
systemctl stop makermate-wifi.service 2>/dev/null || true
systemctl disable makermate-wifi.service 2>/dev/null || true
rm -rf /etc/systemd/system/makermate-wifi.service 2>/dev/null || true
rm -rf "$PKG_DIR" /tmp/makermate_pkg 2>/dev/null || true
umount "$USB_MOUNT" 2>/dev/null || true

# Create directories
mkdir -p "$USB_MOUNT" "$PKG_DIR"/{DEBIAN,usr/local/bin}

log_info "Mounting USB drive..."

# Mount USB - try common device paths
USB_DEVICE=""
for dev in /dev/sda1 /dev/sdb1 /dev/sdc1; do
  if [ -b "$dev" ]; then
    USB_DEVICE="$dev"
    break
  fi
done

if [ -z "$USB_DEVICE" ]; then
  log_error "No USB drive found. Please insert a FAT32 formatted USB drive."
  exit 1
fi

mount "$USB_DEVICE" "$USB_MOUNT" || { 
  log_error "Failed to mount $USB_DEVICE. Is it FAT32 formatted?"
  exit 1
}

log_success "Mounted $USB_DEVICE to $USB_MOUNT"

# Create package control file
cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: makermate-wifi
Version: 4.0
Architecture: all
Maintainer: MakerMate
Description: Persistent WiFi Connection for Elegoo Neptune 4 Series
 Automatically connects your Elegoo Neptune 4 printer to WiFi
 and maintains the connection across reboots.
EOF

# Create the main post-installation script
cat > "$PKG_DIR/DEBIAN/postinst" <<'POSTINST_EOF'
#!/bin/bash
set -e

# =============================================================================
# MakerMate WiFi Post-Installation Script
# This runs automatically when the printer processes the .deb package
# =============================================================================

LOG_FILE="/var/log/makermate-wifi.log"
UPDATE_PATH="/home/mks/gcode_files/sda1/ELEGOO_UPDATE_DIR"
CREDS_PATH="$UPDATE_PATH/wifi_credentials.txt"
WPA_CONF="/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
WATCHDOG_SCRIPT="/usr/local/bin/wifi-watchdog.sh"
STATUS_SCRIPT="/usr/local/bin/wifi-status.sh"
STATE_DIR="/var/lib/makermate"
DEFAULT_HOSTNAME="makermate"

# Initialize log
mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR"
touch "$LOG_FILE"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=============================================="
log "MakerMate WiFi Installation Started (v4.0)"
log "=============================================="

# =============================================================================
# CLEANUP OLD VERSIONS (makermate-wifi)
# =============================================================================
log "Cleaning up any previous installations..."

# Stop old services
systemctl stop makermate-wifi.service 2>/dev/null || true
systemctl stop wpa_supplicant@wlan0.service 2>/dev/null || true

# Disable old services
systemctl disable makermate-wifi.service 2>/dev/null || true

# Kill any running WiFi processes
pkill -9 wpa_supplicant 2>/dev/null || true
pkill -9 dhclient 2>/dev/null || true
pkill -f wifi-watchdog 2>/dev/null || true

# Remove old service files
rm -f /etc/systemd/system/makermate-wifi.service 2>/dev/null || true

# Remove old scripts
rm -f /usr/local/bin/wifi-watchdog.sh 2>/dev/null || true
rm -f /usr/local/bin/wifi-status.sh 2>/dev/null || true

# Remove old wpa configs
rm -f /etc/wpa_supplicant/wpa_supplicant-wlan0.conf 2>/dev/null || true
rm -f /etc/wpa_supplicant.conf 2>/dev/null || true

# Remove old log rotation
rm -f /etc/logrotate.d/makermate-wifi 2>/dev/null || true

# Clean up wpa_supplicant runtime files
rm -rf /var/run/wpa_supplicant 2>/dev/null || true
mkdir -p /var/run/wpa_supplicant

# Reload systemd
systemctl daemon-reload

log "Old installations cleaned up"
sleep 2

# =============================================================================
# Create the WiFi Watchdog Script
# =============================================================================
log "Creating WiFi watchdog script..."

cat > "$WATCHDOG_SCRIPT" <<'WATCHDOG_EOF'
#!/bin/bash
# =============================================================================
# MakerMate WiFi Watchdog
# Monitors and maintains WiFi connection
# =============================================================================

LOG_FILE="/var/log/makermate-wifi.log"
WPA_CONF="/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
MAX_RETRIES=5
RETRY_COUNT=0
CHECK_INTERVAL=30
COOLDOWN_TIME=300
STATE_DIR="/var/lib/makermate"
MDNS_SETUP_FLAG="$STATE_DIR/mdns-setup.done"
MDNS_LAST_ATTEMPT="$STATE_DIR/mdns-last-attempt"
MDNS_RETRY_SECONDS=900

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WATCHDOG] $1" >> "$LOG_FILE"
}

cleanup_wifi() {
  log "Cleaning up WiFi processes..."
  pkill -9 wpa_supplicant 2>/dev/null || true
  pkill -9 dhclient 2>/dev/null || true
  ip addr flush dev wlan0 2>/dev/null || true
  ip link set wlan0 down 2>/dev/null || true
  rm -f /var/run/wpa_supplicant/wlan0 2>/dev/null || true
  sleep 3
}

wait_for_interface() {
  log "Waiting for wlan0 interface..."
  local attempts=0
  local max_attempts=30
  
  while [ $attempts -lt $max_attempts ]; do
    if ip link show wlan0 &>/dev/null; then
      log "wlan0 interface detected"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 2
  done
  
  log "ERROR: wlan0 interface not found after $((max_attempts * 2)) seconds"
  return 1
}

check_wifi_associated() {
  # Check if wpa_supplicant reports connected/completed state
  local state=$(wpa_cli -i wlan0 status 2>/dev/null | grep "wpa_state=" | cut -d= -f2)
  if [ "$state" = "COMPLETED" ]; then
    return 0
  fi
  return 1
}

check_has_ip() {
  # Check if we have a valid IP address (not link-local)
  if ip addr show wlan0 2>/dev/null | grep -q "inet [0-9]" | grep -v "169.254"; then
    return 0
  fi
  return 1
}

get_current_ip() {
  ip addr show wlan0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 | head -1
}

get_ssid() {
  wpa_cli -i wlan0 status 2>/dev/null | grep "^ssid=" | cut -d= -f2
}

maybe_install_mdns() {
  mkdir -p "$STATE_DIR"

  if [ -f "$MDNS_SETUP_FLAG" ]; then
    return 0
  fi

  local now
  now=$(date +%s)

  if [ -f "$MDNS_LAST_ATTEMPT" ]; then
    local last
    last=$(cat "$MDNS_LAST_ATTEMPT")
    if [ "$((now - last))" -lt "$MDNS_RETRY_SECONDS" ]; then
      return 0
    fi
  fi

  echo "$now" > "$MDNS_LAST_ATTEMPT"

  if ! check_has_ip; then
    log "Skipping mDNS install; wlan0 has no IP yet"
    return 1
  fi

  if ! command -v apt-get >/dev/null 2>&1; then
    log "Skipping mDNS install; apt-get not available"
    return 1
  fi

  # Point old buster repos to archive to avoid 404s
  if grep -q "buster" /etc/apt/sources.list 2>/dev/null; then
    sed -i 's|deb http://deb.debian.org/debian buster|deb http://archive.debian.org/debian buster|g' /etc/apt/sources.list || true
    sed -i 's|deb http://security.debian.org|deb http://archive.debian.org/debian-security|g' /etc/apt/sources.list || true
  fi

  local connectivity_target
  connectivity_target=$(ip route | awk '/default/ {print $3; exit}')
  [ -z "$connectivity_target" ] && connectivity_target="8.8.8.8"

  if ! ping -c1 -W2 "$connectivity_target" >/dev/null 2>&1 && ! ping -c1 -W2 8.8.8.8 >/dev/null 2>&1; then
    log "Skipping mDNS install; no internet connectivity detected"
    return 1
  fi

  # Remove conflicting vendor packages if present
  dpkg --remove --force-depends makermate-avahi makermate-setup 2>/dev/null || true

  log "Installing mDNS support (avahi-daemon, avahi-utils, libnss-mdns)..."
  export DEBIAN_FRONTEND=noninteractive
  if apt-get -o Acquire::Check-Valid-Until=false update >> "$LOG_FILE" 2>&1 && \
     apt-get -o Dpkg::Options::="--force-overwrite" -o Acquire::Check-Valid-Until=false install -y avahi-daemon avahi-utils libnss-mdns >> "$LOG_FILE" 2>&1; then
    if grep -q '^hosts:.*mdns' /etc/nsswitch.conf; then
      true
    else
      sed -i 's/^hosts:.*/hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4/' /etc/nsswitch.conf || log "nsswitch.conf update for mDNS failed"
    fi

    systemctl enable avahi-daemon >> "$LOG_FILE" 2>&1 || log "Could not enable avahi-daemon"
    systemctl restart avahi-daemon >> "$LOG_FILE" 2>&1 || log "Could not restart avahi-daemon"
    touch "$MDNS_SETUP_FLAG"

    local host_name
    host_name=$(cat /etc/hostname 2>/dev/null || echo "printer")
    log "mDNS ready. Reachable as ${host_name}.local (after network caches refresh)"
  else
    log "mDNS package install failed; will retry later"
  fi
}

connect_wifi() {
  log "Initiating WiFi connection..."
  
  cleanup_wifi
  
  # Bring interface up
  log "Bringing wlan0 interface up..."
  ip link set wlan0 up
  sleep 2
  
  # Verify interface is up
  if ! ip link show wlan0 | grep -q "UP"; then
    log "ERROR: Failed to bring wlan0 up"
    return 1
  fi
  
  # Start wpa_supplicant
  log "Starting wpa_supplicant..."
  wpa_supplicant -B -i wlan0 -c "$WPA_CONF" -D nl80211,wext 2>&1 | while read line; do
    log "wpa_supplicant: $line"
  done
  
  # Wait for association (up to 30 seconds)
  log "Waiting for WiFi association..."
  local assoc_attempts=0
  while [ $assoc_attempts -lt 15 ]; do
    if check_wifi_associated; then
      local ssid=$(get_ssid)
      log "Successfully associated with SSID: $ssid"
      break
    fi
    assoc_attempts=$((assoc_attempts + 1))
    sleep 2
  done
  
  if ! check_wifi_associated; then
    log "ERROR: Failed to associate with WiFi network"
    return 1
  fi
  
  # Get IP via DHCP
  log "Requesting IP address via DHCP..."
  # Older dhclient on the printer image does not support -timeout; use -1 (single attempt) instead
  dhclient -v -1 wlan0 2>&1 | while read line; do
    log "dhclient: $line"
  done
  
  sleep 3
  
  # Verify we got an IP
  if check_has_ip; then
    local ip=$(get_current_ip)
    log "SUCCESS: Connected with IP address $ip"
    return 0
  else
    log "ERROR: Failed to obtain IP address"
    return 1
  fi
}

# =============================================================================
# Main Execution
# =============================================================================

log "=============================================="
log "MakerMate WiFi Watchdog Started"
log "=============================================="

mkdir -p "$STATE_DIR"

# Initial boot delay - wait for system and USB WiFi dongle to initialize
log "Waiting 15 seconds for system initialization..."
sleep 15

# Wait for WiFi interface to appear
if ! wait_for_interface; then
  log "FATAL: No WiFi interface found. Is the WiFi dongle connected?"
  log "Will keep trying every 60 seconds..."
  
  while true; do
    sleep 60
    if wait_for_interface; then
      break
    fi
  done
fi

# Initial connection attempt
log "Attempting initial WiFi connection..."
if connect_wifi; then
  log "Initial connection successful"
  RETRY_COUNT=0
  maybe_install_mdns &
else
  log "Initial connection failed, will retry..."
  RETRY_COUNT=1
fi

# =============================================================================
# Monitoring Loop
# =============================================================================
log "Entering monitoring loop (check interval: ${CHECK_INTERVAL}s)..."

while true; do
  sleep $CHECK_INTERVAL
  
  # Check connection status
  if check_wifi_associated && check_has_ip; then
    # Connection is healthy
    if [ $RETRY_COUNT -gt 0 ]; then
      log "Connection restored after $RETRY_COUNT retries"
      RETRY_COUNT=0
    fi

    maybe_install_mdns &
  else
    # Connection lost
    RETRY_COUNT=$((RETRY_COUNT + 1))
    
    if check_wifi_associated; then
      log "WiFi associated but no IP (attempt $RETRY_COUNT/$MAX_RETRIES)"
    else
      log "WiFi connection lost (attempt $RETRY_COUNT/$MAX_RETRIES)"
    fi
    
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
      log "Max retries ($MAX_RETRIES) reached. Entering cooldown for ${COOLDOWN_TIME}s..."
      sleep $COOLDOWN_TIME
      RETRY_COUNT=0
      log "Cooldown complete, resuming connection attempts..."
    fi
    
    connect_wifi
  fi
done
WATCHDOG_EOF

chmod +x "$WATCHDOG_SCRIPT"
log "Watchdog script created"

# =============================================================================
# Create Status Script (for debugging)
# =============================================================================
cat > "$STATUS_SCRIPT" <<'STATUS_EOF'
#!/bin/bash
# MakerMate WiFi Status Script

echo "========================================"
echo "  MakerMate WiFi Status"
echo "========================================"
echo ""

# Service status
echo "Service Status:"
if systemctl is-active --quiet makermate-wifi.service; then
  echo "  Running: YES"
else
  echo "  Running: NO"
fi
echo ""

# Interface status
echo "Interface Status:"
if ip link show wlan0 &>/dev/null; then
  echo "  wlan0: EXISTS"
  ip link show wlan0 | grep -o "state [A-Z]*" | sed 's/^/  /'
else
  echo "  wlan0: NOT FOUND"
fi
echo ""

# Connection status
echo "Connection Status:"
if command -v wpa_cli &>/dev/null; then
  wpa_cli -i wlan0 status 2>/dev/null | grep -E "^(wpa_state|ssid|ip_address)=" | sed 's/^/  /'
fi
echo ""

# IP Address
echo "IP Configuration:"
ip addr show wlan0 2>/dev/null | grep "inet " | sed 's/^/  /'
echo ""

# Recent logs
echo "Recent Logs (last 20 lines):"
echo "----------------------------------------"
tail -20 /var/log/makermate-wifi.log 2>/dev/null || echo "  No logs found"
echo ""
STATUS_EOF

chmod +x "$STATUS_SCRIPT"
log "Status script created at $STATUS_SCRIPT"

# =============================================================================
# Parse and Validate Credentials
# =============================================================================
log "Looking for credentials at: $CREDS_PATH"

if [ ! -f "$CREDS_PATH" ]; then
  log "ERROR: wifi_credentials.txt not found!"
  log "Expected location: $CREDS_PATH"
  exit 1
fi

log "Reading WiFi credentials..."

# Parse credentials (handles special characters properly)
SSID=$(grep -E '^SSID=' "$CREDS_PATH" | head -1 | cut -d= -f2-)
PASSWORD=$(grep -E '^PASSWORD=' "$CREDS_PATH" | head -1 | cut -d= -f2-)
COUNTRY=$(grep -E '^COUNTRY=' "$CREDS_PATH" | head -1 | cut -d= -f2- || echo "US")
HOSTNAME_RAW=$(grep -E '^HOSTNAME=' "$CREDS_PATH" | head -1 | cut -d= -f2-)

# Default country if not specified
[ -z "$COUNTRY" ] && COUNTRY="US"

# Validate credentials
if [ -z "$SSID" ]; then
  log "ERROR: SSID is empty or not found in credentials file"
  exit 1
fi

if [ -z "$PASSWORD" ]; then
  log "ERROR: PASSWORD is empty or not found in credentials file"
  exit 1
fi

log "SSID: $SSID"
log "Country: $COUNTRY"
log "Password: [HIDDEN - ${#PASSWORD} characters]"

# =============================================================================
# Set Hostname (used for mDNS: <hostname>.local)
# =============================================================================
HOSTNAME_VALUE="$HOSTNAME_RAW"
[ -z "$HOSTNAME_VALUE" ] && HOSTNAME_VALUE="$DEFAULT_HOSTNAME"

# Sanitize: lowercase, alphanumeric + dash, trim leading/trailing dashes, max 63 chars
HOSTNAME_VALUE=$(echo "$HOSTNAME_VALUE" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')
HOSTNAME_VALUE=$(echo "$HOSTNAME_VALUE" | sed 's/^-*//' | sed 's/-*$//')
[ -z "$HOSTNAME_VALUE" ] && HOSTNAME_VALUE="$DEFAULT_HOSTNAME"
HOSTNAME_VALUE=${HOSTNAME_VALUE:0:63}

log "Hostname: $HOSTNAME_VALUE (edit HOSTNAME= in wifi_credentials.txt to change)"
echo "$HOSTNAME_VALUE" > /etc/hostname

if grep -q '^127\.0\.1\.1' /etc/hosts; then
  sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$HOSTNAME_VALUE/" /etc/hosts
else
  echo -e "127.0.1.1\t$HOSTNAME_VALUE" >> /etc/hosts
fi

hostname "$HOSTNAME_VALUE" 2>/dev/null || true

# =============================================================================
# Create wpa_supplicant Configuration
# =============================================================================
log "Creating wpa_supplicant configuration..."

mkdir -p /etc/wpa_supplicant

cat > "$WPA_CONF" <<WPAEOF
# MakerMate WiFi Configuration
# Generated: $(date)

ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=$COUNTRY

network={
    ssid="$SSID"
    psk="$PASSWORD"
    key_mgmt=WPA-PSK
    scan_ssid=1
    priority=1
}
WPAEOF

chmod 600 "$WPA_CONF"
log "wpa_supplicant configuration created"

# =============================================================================
# Create Systemd Service
# =============================================================================
log "Creating systemd service..."

cat > /etc/systemd/system/makermate-wifi.service <<'SERVICE_EOF'
[Unit]
Description=MakerMate WiFi Persistent Connection
Documentation=
After=network-pre.target systemd-udevd.service
Wants=network-pre.target
Before=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wifi-watchdog.sh
ExecStop=/bin/bash -c 'pkill -f wifi-watchdog; pkill wpa_supplicant; pkill dhclient'
Restart=always
RestartSec=30
StandardOutput=append:/var/log/makermate-wifi.log
StandardError=append:/var/log/makermate-wifi.log

# Security hardening
NoNewPrivileges=no
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
SERVICE_EOF

log "Systemd service created"

# =============================================================================
# Setup Log Rotation
# =============================================================================
log "Setting up log rotation..."

cat > /etc/logrotate.d/makermate-wifi <<'LOGROTATE_EOF'
/var/log/makermate-wifi.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 644 root root
}
LOGROTATE_EOF

log "Log rotation configured"

# =============================================================================
# Enable and Start Service
# =============================================================================
log "Enabling and starting service..."

systemctl daemon-reload
systemctl enable makermate-wifi.service
systemctl start makermate-wifi.service

log "=============================================="
log "MakerMate WiFi Installation Complete!"
log "=============================================="
log ""
log "Useful commands:"
log "  Check status:  wifi-status.sh"
log "  View logs:     tail -f /var/log/makermate-wifi.log"
log "  Restart:       sudo systemctl restart makermate-wifi"
log ""

exit 0
POSTINST_EOF

chmod 755 "$PKG_DIR/DEBIAN/postinst"

# =============================================================================
# Create Uninstall Script
# =============================================================================
log_info "Creating uninstall script..."

cat > "$PKG_DIR/DEBIAN/prerm" <<'PRERM_EOF'
#!/bin/bash
# MakerMate WiFi Uninstall Script

echo "Uninstalling MakerMate WiFi..."

# Stop services
systemctl stop makermate-wifi.service 2>/dev/null || true
systemctl disable makermate-wifi.service 2>/dev/null || true
systemctl stop avahi-daemon 2>/dev/null || true
systemctl disable avahi-daemon 2>/dev/null || true

# Remove avahi/mdns packages installed by this package (best-effort)
apt-get -y purge avahi-daemon avahi-utils libnss-mdns 2>/dev/null || true
dpkg --purge makermate-avahi makermate-setup 2>/dev/null || true

# Restore nsswitch hosts line to a safe default
if grep -q '^hosts:.*mdns' /etc/nsswitch.conf 2>/dev/null; then
  sed -i 's/^hosts:.*/hosts:          files mymachines dns myhostname/' /etc/nsswitch.conf || true
fi

# Kill any running processes
pkill -f wifi-watchdog.sh 2>/dev/null || true
pkill wpa_supplicant 2>/dev/null || true
pkill dhclient 2>/dev/null || true

# Remove files
rm -f /etc/systemd/system/makermate-wifi.service
rm -f /usr/local/bin/wifi-watchdog.sh
rm -f /usr/local/bin/wifi-status.sh
rm -f /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
rm -f /etc/logrotate.d/makermate-wifi

# Reload systemd
systemctl daemon-reload

echo "MakerMate WiFi has been uninstalled."
echo "Note: Log file preserved at /var/log/makermate-wifi.log"

exit 0
PRERM_EOF

chmod 755 "$PKG_DIR/DEBIAN/prerm"

# =============================================================================
# Build the .deb Package
# =============================================================================
log_info "Building .deb package..."

mkdir -p "$UPDATE_DIR"
dpkg-deb --build "$PKG_DIR" "$DEB_PATH"

if [ -f "$DEB_PATH" ]; then
  log_success "Package created: $DEB_PATH"
else
  log_error "Failed to create package"
  exit 1
fi

# =============================================================================
# Create Template Credentials File
# =============================================================================
log_info "Creating credentials template..."

cat > "$UPDATE_DIR/wifi_credentials.txt" <<'CREDS_EOF'
# MakerMate WiFi Credentials
# Edit this file with your WiFi network details
# 
# SSID: Your WiFi network name (case-sensitive)
# PASSWORD: Your WiFi password
# COUNTRY: Your 2-letter country code (US, GB, DE, FR, etc.)
#          This ensures proper WiFi channel compliance
# HOSTNAME: Optional; mDNS name becomes <hostname>.local (defaults to makermate)

SSID=YourWiFiNetworkName
PASSWORD=YourWiFiPassword
COUNTRY=US
HOSTNAME=makermate
CREDS_EOF

log_success "Credentials template created"

# =============================================================================
# Cleanup and Finish
# =============================================================================
log_info "Finalizing..."

umount "$USB_MOUNT"
sync

# Cleanup temp files
rm -rf "$PKG_DIR"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              USB Package Created Successfully!                ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo ""
echo "  1. ${BLUE}Edit WiFi credentials${NC}"
echo "     Open the USB drive and edit:"
echo "     ELEGOO_UPDATE_DIR/wifi_credentials.txt"
echo ""
echo "  2. ${BLUE}Safely eject the USB drive${NC}"
echo ""
echo "  3. ${BLUE}Insert USB into your Elegoo Neptune 4${NC}"
echo ""
echo "  4. ${BLUE}Power cycle the printer${NC}"
echo "     Turn it off, wait 5 seconds, turn it back on"
echo ""
echo "  5. ${BLUE}Wait 2-3 minutes${NC}"
echo "     The printer will automatically install the WiFi package"
echo ""
echo "  6. ${BLUE}Connect your WiFi dongle${NC}"
echo "     If not already connected, insert it now"
echo ""
echo -e "${YELLOW}Troubleshooting:${NC}"
echo ""
echo "  SSH into your printer:"
echo "    ssh mks@<printer-ip>"
echo "    Password: makerbase"
echo ""
echo "  Check WiFi status:"
echo "    wifi-status.sh"
echo ""
echo "  View live logs:"
echo "    tail -f /var/log/makermate-wifi.log"
echo ""
echo "  Restart WiFi service:"
echo "    sudo systemctl restart makermate-wifi"
echo ""
