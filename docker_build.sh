#!/bin/bash
# =============================================================================
# MakerMate WiFi - Docker Build Script
# 
# This script runs the package builder inside Docker on macOS.
# Requires Docker Desktop to be installed and running.
#
# Usage: ./docker_build.sh
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Makermate WiFi - Docker Package Builder               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if Docker is running
if ! docker info &>/dev/null; then
  echo -e "${RED}[ERROR]${NC} Docker is not running!"
  echo ""
  echo "Please start Docker Desktop and try again."
  echo ""
  exit 1
fi

echo -e "${GREEN}[OK]${NC} Docker is running"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}[INFO]${NC} Building package in Docker container..."
echo ""

# Run the build script inside an Ubuntu container
docker run --rm \
  -v "$SCRIPT_DIR:/work" \
  -w /work \
  ubuntu:22.04 \
  bash -c "apt-get update -qq && apt-get install -y -qq dpkg-dev > /dev/null 2>&1 && chmod +x build_package.sh && ./build_package.sh"

# Check if build was successful
if [ -d "$SCRIPT_DIR/output/ELEGOO_UPDATE_DIR" ]; then
  echo ""
  echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║                    BUILD SUCCESSFUL!                          ║${NC}"
  echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${YELLOW}Your files are ready at:${NC}"
  echo "  $SCRIPT_DIR/output/ELEGOO_UPDATE_DIR/"
  echo ""
  echo -e "${YELLOW}Files created:${NC}"
  ls -la "$SCRIPT_DIR/output/ELEGOO_UPDATE_DIR/"
  echo ""
  echo -e "${YELLOW}=== NEXT STEPS ===${NC}"
  echo ""
  echo "  1. ${BLUE}Edit your WiFi credentials:${NC}"
  echo "     nano $SCRIPT_DIR/output/ELEGOO_UPDATE_DIR/wifi_credentials.txt"
  echo ""
  echo "     Or open in Finder:"
  echo "     open $SCRIPT_DIR/output/ELEGOO_UPDATE_DIR/"
  echo ""
  echo "  2. ${BLUE}Insert your FAT32 USB drive${NC}"
  echo ""
  echo "  3. ${BLUE}Copy the folder to USB:${NC}"
  echo "     cp -r $SCRIPT_DIR/output/ELEGOO_UPDATE_DIR /Volumes/YOUR_USB_NAME/"
  echo ""
  echo "  4. ${BLUE}Eject USB, insert into printer, power cycle${NC}"
  echo ""
else
  echo ""
  echo -e "${RED}[ERROR]${NC} Build failed! Check the output above for errors."
  exit 1
fi

