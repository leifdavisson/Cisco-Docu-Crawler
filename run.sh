#!/usr/bin/env bash
# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Colors for menu
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
BLUE='\033[0;34m'
YELLOW='\033[1;33m'

# Clear screen initially
clear

# Project root path helper
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

show_header() {
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${GREEN}          Cisco Switch Docu-Crawler - Operator Shell            ${NC}"
    echo -e "${BLUE}================================================================${NC}"
}

check_system_requirements() {
    echo -e "\n${BLUE}[*] Checking system requirements...${NC}"
    
    # Check Python 3
    if command -v python3 &>/dev/null; then
        echo -e "  - Python 3: ${GREEN}Installed${NC} ($(python3 --version))"
    else
        echo -e "  - Python 3: ${RED}Not Installed${NC} (Please install python3 first)"
    fi
    
    # Check Pip
    if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
        echo -e "  - Pip: ${GREEN}Installed${NC}"
    else
        echo -e "  - Pip: ${YELLOW}Not Installed${NC} (Required to install netmiko/netaddr)"
    fi
    
    # Check Nmap
    if command -v nmap &>/dev/null; then
        echo -e "  - Nmap: ${GREEN}Installed${NC}"
    else
        echo -e "  - Nmap: ${YELLOW}Not Installed${NC} (Crawler will automatically fall back to Python scanner)"
    fi
}

install_dependencies() {
    echo -e "\n${BLUE}[*] Installing dependencies from requirements.txt...${NC}"
    
    PIP_CMD=""
    if command -v pip3 &>/dev/null; then
        PIP_CMD="pip3"
    elif command -v pip &>/dev/null; then
        PIP_CMD="pip"
    fi
    
    if [ -z "$PIP_CMD" ]; then
        echo -e "${RED}[!] Error: pip or pip3 not found. Please install pip or run dependencies manually.${NC}"
        return 1
    fi
    
    echo -e "Running: $PIP_CMD install -r requirements.txt"
    $PIP_CMD install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}[+] All dependencies installed successfully!${NC}"
    else
        echo -e "\n${RED}[!] Dependencies installation failed. Check permissions or network access.${NC}"
    fi
}

run_discovery() {
    echo -e "\n${BLUE}[*] Starting New Network Discovery Scan...${NC}"
    python3 cisco_crawler.py
}

retry_scan() {
    if [ -f "failed_hosts.json" ]; then
        echo -e "\n${BLUE}[*] Resuming scan for failed hosts...${NC}"
        python3 cisco_crawler.py --retry failed_hosts.json
    else
        echo -e "\n${YELLOW}[!] No failed_hosts.json file found. No previous failed scans to retry.${NC}"
    fi
}

list_backups() {
    echo -e "\n${BLUE}[*] Available Configuration Backups:${NC}"
    if [ -d "backups" ] && [ "$(ls -A backups)" ]; then
        echo -e "----------------------------------------------------------------"
        ls -la backups/*.cfg 2>/dev/null | awk '{print $9, "("$5, "bytes)"}'
        echo -e "----------------------------------------------------------------"
        echo -e "Backups are stored locally in the '${GREEN}backups/${NC}' folder."
    else
        echo -e "${YELLOW}[!] No backups have been generated yet. Run a successful scan first.${NC}"
    fi
}

# Main loop
while true; do
    show_header
    check_system_requirements
    
    echo -e "\n${BLUE}Operations Menu:${NC}"
    echo -e "  1) ${GREEN}Initialize Environment${NC} (Install Python packages)"
    echo -e "  2) ${GREEN}Run a New Discovery Scan${NC}"
    echo -e "  3) ${GREEN}Retry/Resume Failed Devices${NC} (Loads failed_hosts.json)"
    echo -e "  4) ${GREEN}List Current Backups${NC}"
    echo -e "  5) ${RED}Exit${NC}"
    echo -e "----------------------------------------------------------------"
    
    read -p "Select option (1-5): " opt
    
    case $opt in
        1)
            install_dependencies
            ;;
        2)
            run_discovery
            ;;
        3)
            retry_scan
            ;;
        4)
            list_backups
            ;;
        5)
            echo -e "\n${GREEN}Exiting Operator Shell. Goodbye!${NC}\n"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid option. Please select between 1 and 5.${NC}"
            ;;
    esac
    
    echo -e "\nPress [Enter] to return to the menu..."
    read
    clear
done
