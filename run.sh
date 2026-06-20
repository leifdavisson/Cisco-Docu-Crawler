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

# Default crawler settings (advanced settings hidden from junior engineers)
DISABLE_TELNET=false
THREADS=10
TIMEOUT=10

get_advanced_flags() {
    local flags=""
    if [ "$DISABLE_TELNET" = true ]; then
        flags="$flags --disable-telnet"
    fi
    flags="$flags --threads $THREADS --timeout $TIMEOUT"
    echo "$flags"
}

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
    if ! read -p "Enable verbose logging? (y/N): " verbose_opt; then
        exit 0
    fi
    local verbose_flag=""
    if [[ "$verbose_opt" =~ ^[Yy]$ ]]; then
        verbose_flag="--verbose"
    fi
    local adv_flags=$(get_advanced_flags)
    echo -e "\n${BLUE}[*] Starting New Network Discovery Scan...${NC}"
    python3 cisco_crawler.py $verbose_flag $adv_flags
}

run_simulation() {
    if ! read -p "Enable verbose logging? (y/N): " verbose_opt; then
        exit 0
    fi
    local verbose_flag=""
    if [[ "$verbose_opt" =~ ^[Yy]$ ]]; then
        verbose_flag="--verbose"
    fi
    local adv_flags=$(get_advanced_flags)
    echo -e "\n${BLUE}[*] Starting Simulated Network Discovery Scan (Demo Mode)...${NC}"
    python3 cisco_crawler.py --simulate $verbose_flag $adv_flags
}

run_baseline() {
    if ! read -p "Enter filename to save baseline to (e.g. baseline.json): " baseline_file; then
        exit 0
    fi
    if [ -z "$baseline_file" ]; then
        echo -e "${RED}[!] Error: Baseline filename cannot be empty.${NC}"
        return 1
    fi
    if ! read -p "Enable verbose logging? (y/N): " verbose_opt; then
        exit 0
    fi
    local verbose_flag=""
    if [[ "$verbose_opt" =~ ^[Yy]$ ]]; then
        verbose_flag="--verbose"
    fi
    local adv_flags=$(get_advanced_flags)
    echo -e "\n${BLUE}[*] Starting Baseline Scan...${NC}"
    python3 cisco_crawler.py --baseline "$baseline_file" $verbose_flag $adv_flags
}

run_compare() {
    if ! read -p "Enter baseline file to compare against (e.g. baseline.json): " baseline_file; then
        exit 0
    fi
    if [ ! -f "$baseline_file" ]; then
        echo -e "${RED}[!] Error: Baseline file '$baseline_file' not found.${NC}"
        return 1
    fi
    if ! read -p "Enable verbose logging? (y/N): " verbose_opt; then
        exit 0
    fi
    local verbose_flag=""
    if [[ "$verbose_opt" =~ ^[Yy]$ ]]; then
        verbose_flag="--verbose"
    fi
    local adv_flags=$(get_advanced_flags)
    echo -e "\n${BLUE}[*] Starting Compare Scan against $baseline_file...${NC}"
    python3 cisco_crawler.py --compare "$baseline_file" $verbose_flag $adv_flags
}

retry_scan() {
    if [ -f "failed_hosts.json" ]; then
        if ! read -p "Enable verbose logging? (y/N): " verbose_opt; then
            exit 0
        fi
        local verbose_flag=""
        if [[ "$verbose_opt" =~ ^[Yy]$ ]]; then
            verbose_flag="--verbose"
        fi
        local adv_flags=$(get_advanced_flags)
        echo -e "\n${BLUE}[*] Resuming scan for failed hosts...${NC}"
        python3 cisco_crawler.py --retry failed_hosts.json $verbose_flag $adv_flags
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

toggle_telnet() {
    if [ "$DISABLE_TELNET" = true ]; then
        DISABLE_TELNET=false
        echo -e "\n${GREEN}[+] Telnet Fallback enabled.${NC}"
    else
        DISABLE_TELNET=true
        echo -e "\n${GREEN}[+] Telnet Fallback disabled.${NC}"
    fi
}

change_threads() {
    if ! read -p "Enter concurrent thread count (1-50) [Current: $THREADS]: " val; then
        exit 0
    fi
    if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge 1 ] && [ "$val" -le 50 ]; then
        THREADS=$val
        echo -e "\n${GREEN}[+] Concurrent threads set to $THREADS.${NC}"
    else
        echo -e "\n${RED}[!] Invalid thread count. Must be an integer between 1 and 50.${NC}"
    fi
}

change_timeout() {
    if ! read -p "Enter connection timeout in seconds (1-120) [Current: $TIMEOUT]: " val; then
        exit 0
    fi
    if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge 1 ] && [ "$val" -le 120 ]; then
        TIMEOUT=$val
        echo -e "\n${GREEN}[+] Connection timeout set to $TIMEOUT seconds.${NC}"
    else
        echo -e "\n${RED}[!] Invalid timeout value. Must be an integer between 1 and 120.${NC}"
    fi
}

show_advanced_menu() {
    while true; do
        clear
        echo -e "${BLUE}================================================================${NC}"
        echo -e "${GREEN}          Cisco Switch Docu-Crawler - Advanced Options          ${NC}"
        echo -e "${BLUE}================================================================${NC}"
        
        local telnet_status="${GREEN}ENABLED${NC}"
        if [ "$DISABLE_TELNET" = true ]; then
            telnet_status="${RED}DISABLED${NC}"
        fi
        
        echo -e "Current Settings:"
        echo -e "  - Telnet Fallback: $telnet_status"
        echo -e "  - Concurrent Threads: ${GREEN}$THREADS${NC}"
        echo -e "  - Connection Timeout: ${GREEN}$TIMEOUT seconds${NC}"
        echo -e "----------------------------------------------------------------"
        echo -e "\n${BLUE}Advanced Operations Menu:${NC}"
        echo -e "  1) ${GREEN}Save Network State as Baseline${NC}"
        echo -e "  2) ${GREEN}Compare Current State against Baseline${NC}"
        echo -e "  3) ${GREEN}Retry/Resume Failed Devices${NC} (Loads failed_hosts.json)"
        echo -e "  4) ${GREEN}Toggle Telnet Fallback${NC}"
        echo -e "  5) ${GREEN}Change Thread Count${NC}"
        echo -e "  6) ${GREEN}Change Connection Timeout${NC}"
        echo -e "  7) ${RED}Return to Main Menu${NC}"
        echo -e "----------------------------------------------------------------"
        
        if ! read -p "Select option (1-7): " adv_opt; then
            exit 0
        fi
        
        case $adv_opt in
            1)
                run_baseline
                ;;
            2)
                run_compare
                ;;
            3)
                retry_scan
                ;;
            4)
                toggle_telnet
                ;;
            5)
                change_threads
                ;;
            6)
                change_timeout
                ;;
            7)
                return 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option. Please select between 1 and 7.${NC}"
                ;;
        esac
        
        echo -e "\nPress [Enter] to return to the Advanced Menu..."
        if ! read; then
            exit 0
        fi
    done
}

# Main loop
while true; do
    show_header
    check_system_requirements
    
    echo -e "\n${BLUE}Operations Menu:${NC}"
    echo -e "  1) ${GREEN}Initialize Environment${NC} (Install Python packages)"
    echo -e "  2) ${GREEN}Run a New Discovery Scan${NC}"
    echo -e "  3) ${GREEN}Run Simulated Discovery (Demo Mode)${NC}"
    echo -e "  4) ${GREEN}List Current Backups${NC}"
    echo -e "  5) ${GREEN}Advanced Options Menu${NC}"
    echo -e "  6) ${RED}Exit${NC}"
    echo -e "----------------------------------------------------------------"
    
    if ! read -p "Select option (1-6): " opt; then
        echo -e "\nExiting."
        exit 0
    fi
    
    case $opt in
        1)
            install_dependencies
            ;;
        2)
            run_discovery
            ;;
        3)
            run_simulation
            ;;
        4)
            list_backups
            ;;
        5)
            show_advanced_menu
            ;;
        6)
            echo -e "\n${GREEN}Exiting Operator Shell. Goodbye!${NC}\n"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid option. Please select between 1 and 6.${NC}"
            ;;
    esac
    
    echo -e "\nPress [Enter] to return to the menu..."
    if ! read; then
        exit 0
    fi
    clear
done
