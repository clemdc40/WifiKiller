#!/bin/bash
# ============================================================
#  WifiKiller - Installation Script
#  Installs all required dependencies on Kali/Debian/Ubuntu
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║           WifiKiller - Installer                 ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Ce script doit être lancé en root (sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Mise à jour des paquets...${NC}"
apt-get update -qq

echo -e "${YELLOW}[*] Installation des dépendances système...${NC}"
apt-get install -y -qq \
    aircrack-ng \
    hcxtools \
    python3 \
    python3-pip \
    python3-venv \
    net-tools \
    wireless-tools \
    iw \
    procps \
    > /dev/null 2>&1

echo -e "${YELLOW}[*] Installation des dépendances Python...${NC}"
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo -e "${YELLOW}[*] Configuration des permissions...${NC}"
chmod +x wifikiller.py

echo ""
echo -e "${GREEN}[✓] Installation terminée avec succès !${NC}"
echo -e "${CYAN}[i] Utilisation : sudo python3 wifikiller.py${NC}"
echo ""
