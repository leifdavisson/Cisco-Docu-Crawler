#!/usr/bin/env python3
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

import os
import sys
import json
import argparse
import getpass
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPNetwork, IPSet
import time

# Import local modules
import oui_lookup
import parser
import report_generator

# Ensure directories exist
RAW_LOGS_DIR = "raw_logs"
BACKUPS_DIR = "backups"
os.makedirs(RAW_LOGS_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

def get_local_ip_subnet():
    """Gets the default local IP and guesses the /24 subnet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
        subnet = ".".join(local_ip.split('.')[:3]) + ".0/24"
    except Exception:
        local_ip = "127.0.0.1"
        subnet = "192.168.1.0/24"
    finally:
        s.close()
    return local_ip, subnet

def check_nmap_installed():
    """Checks if nmap is available in the system path."""
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def run_nmap_scan(subnets):
    """
    Runs Nmap to scan subnets for ports 22 (SSH) and 23 (Telnet).
    Falls back to TCP Connect scan if not root.
    """
    targets = " ".join(subnets)
    xml_output = "nmap_results.xml"
    
    # Try SYN stealth scan first, fallback to TCP connect scan if non-root
    print(f"Running Nmap scan on target subnets: {targets}")
    cmd = ["nmap", "-sS", "-p", "22,23", "-Pn", "-oX", xml_output] + subnets
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "You must be root" in result.stderr or result.returncode != 0:
            print("Non-root environment detected. Falling back to Nmap TCP Connect scan (-sT)...")
            cmd = ["nmap", "-sT", "-p", "22,23", "-Pn", "-oX", xml_output] + subnets
            subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed: {e}")
        return []

    return parse_nmap_xml(xml_output)

def parse_nmap_xml(xml_file):
    """Parses Nmap XML output to extract hosts with open port 22 or 23."""
    hosts = []
    if not os.path.exists(xml_file):
        return hosts
        
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall('host'):
            ip = ""
            mac = ""
            ports = []
            
            # Extract IP and MAC
            for addr in host.findall('address'):
                addr_type = addr.get('addrtype')
                if addr_type == 'ipv4':
                    ip = addr.get('addr')
                elif addr_type == 'mac':
                    mac = addr.get('addr')
                    
            # Extract ports
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        ports.append(int(port.get('portid')))
                        
            if ip and ports:
                hosts.append({
                    "ip": ip,
                    "mac": mac,
                    "ports": ports
                })
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
        
    return hosts

def python_port_scan_worker(ip, ports):
    """Worker thread to scan ports 22 and 23 on a single IP."""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    if open_ports:
        return {"ip": ip, "mac": "", "ports": open_ports}
    return None

def run_python_port_scan(subnets):
    """Fallback multi-threaded Python TCP port scanner if Nmap is not installed."""
    print("Nmap not found. Falling back to internal Python multi-threaded port scanner...")
    discovered = []
    ips_to_scan = []
    
    for subnet in subnets:
        try:
            net = IPNetwork(subnet)
            # Skip network and broadcast IPs for scanning
            if net.prefixlen < 31:
                ips_to_scan.extend([str(ip) for ip in list(net)[1:-1]])
            else:
                ips_to_scan.extend([str(ip) for ip in list(net)])
        except Exception as e:
            print(f"Invalid subnet range ignored: {subnet} ({e})")
            
    print(f"Scanning {len(ips_to_scan)} IP addresses on ports 22 and 23...")
    
    # Run scan with thread pool
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(python_port_scan_worker, ip, [22, 23]): ip for ip in ips_to_scan}
        for future in as_completed(futures):
            res = future.result()
            if res:
                discovered.append(res)
                print(f"  Discovered active host: {res['ip']} (Open ports: {res['ports']})")
                
    return discovered

def connect_and_detect(ip, username, password, secret, conn_type="ssh"):
    """
    Connects to the switch and detects the specific Cisco OS type.
    Returns the active netmiko connection object and the detected OS string.
    """
    from netmiko import ConnectHandler
    
    device_type = 'cisco_ios' if conn_type == 'ssh' else 'cisco_ios_telnet'
    
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': username,
        'password': password,
        'secret': secret,
        'global_delay_factor': 2,
    }
    
    # Establish connection
    net_connect = ConnectHandler(**device)
    
    # Send commands to verify OS type
    version_output = net_connect.send_command('show version')
    
    detected_os = 'cisco_ios'
    if 'NX-OS' in version_output or 'Nexus' in version_output:
        detected_os = 'cisco_nxos'
    elif 'IOS-XR' in version_output or 'IOS XR' in version_output:
        detected_os = 'cisco_xr'
        
    # If the detected OS isn't standard IOS, reconnect with the matching driver
    if detected_os != 'cisco_ios':
        net_connect.disconnect()
        device['device_type'] = detected_os + ('_telnet' if conn_type == 'telnet' else '')
        # XR doesn't use enable secret
        if detected_os == 'cisco_xr' and 'secret' in device:
            del device['secret']
        net_connect = ConnectHandler(**device)
        
    return net_connect, detected_os

def crawl_device(ip, ports, username, password, secret):
    """
    Performs discovery commands on a single switch.
    Tries SSH first, falls back to Telnet.
    """
    conn = None
    os_type = None
    mgmt_method = None
    
    # Try SSH first if port 22 is open
    if 22 in ports:
        try:
            print(f"[{ip}] Attempting SSH connection...")
            conn, os_type = connect_and_detect(ip, username, password, secret, conn_type="ssh")
            mgmt_method = "SSH"
        except Exception as e:
            print(f"[{ip}] SSH connection failed: {e}")
            
    # Try Telnet fallback if SSH failed or only port 23 is open
    if not conn and 23 in ports:
        try:
            print(f"[{ip}] Attempting Telnet fallback connection...")
            conn, os_type = connect_and_detect(ip, username, password, secret, conn_type="telnet")
            mgmt_method = "Telnet"
        except Exception as e:
            print(f"[{ip}] Telnet connection failed: {e}")
            
    if not conn:
        return {"ip": ip, "status": "failed", "reason": "Connection failed (both SSH and Telnet)"}
        
    # Device connected! Execute read-only discovery commands
    device_data = {
        "ip": ip,
        "status": "success",
        "mgmt_method": mgmt_method,
        "os_type": os_type,
        "hostname": "",
        "model": "",
        "serial": "",
        "firmware": "",
        "mac_address": "",
        "neighbors": [],
        "l3_interfaces": [],
        "interfaces_detail": {},
        "stp": {},
        "routes": [],
        "services": {},
        "raw_config": ""
    }
    
    try:
        # Enter enable mode if secret is provided and device is IOS/NX-OS
        if secret and os_type != 'cisco_xr':
            try:
                conn.enable()
            except Exception:
                pass
                
        # 1. Version information
        sh_ver = conn.send_command('show version')
        with open(os.path.join(RAW_LOGS_DIR, f"{ip}_show_version.log"), "w") as f:
            f.write(sh_ver)
            
        ver_data = parser.parse_show_version(sh_ver, os_type)
        device_data.update(ver_data)
        
        # 2. Inventory check (highly reliable model/serial)
        try:
            sh_inv = conn.send_command('show inventory')
            with open(os.path.join(RAW_LOGS_DIR, f"{ip}_show_inventory.log"), "w") as f:
                f.write(sh_inv)
            inv_items = parser.parse_show_inventory(sh_inv)
            # Find chassis module for primary model/serial
            for item in inv_items:
                if "chassis" in item["name"].lower() or "chassis" in item["descr"].lower():
                    if item["pid"]:
                        device_data["model"] = item["pid"]
                    if item["sn"] and item["sn"] != "N/A":
                        device_data["serial"] = item["sn"]
                    break
            if not device_data["serial"] and inv_items:
                # Fallback to first inventory item with a serial number
                for item in inv_items:
                    if item["sn"] and item["sn"] != "N/A":
                        device_data["serial"] = item["sn"]
                        if item["pid"]:
                            device_data["model"] = item["pid"]
                        break
        except Exception:
            pass
            
        # Ensure we clean hostname from prompt if still empty
        if not device_data["hostname"]:
            device_data["hostname"] = conn.find_prompt().replace('#', '').replace('>', '').strip()
            
        # 3. Interfaces L3 list
        sh_ip_int_cmd = 'show ipv4 interface brief' if os_type == 'cisco_xr' else 'show ip interface brief'
        sh_ip_int = conn.send_command(sh_ip_int_cmd)
        device_data["l3_interfaces"] = parser.parse_ip_interface_brief(sh_ip_int, os_type)
        
        # 4. Interfaces physical details
        sh_ints = conn.send_command('show interfaces')
        device_data["interfaces_detail"] = parser.parse_show_interfaces(sh_ints, os_type)
        
        # Try to locate base MAC address from interfaces if show version failed
        if not device_data["mac_address"]:
            # Find first interface MAC address
            for intf_name, intf_data in device_data["interfaces_detail"].items():
                if intf_data.get("mac_address"):
                    device_data["mac_address"] = oui_lookup.normalize_mac(intf_data["mac_address"])
                    break
                    
        # 5. CDP & LLDP Neighbors
        neighbors = []
        # CDP
        if os_type != 'cisco_xr':
            try:
                sh_cdp = conn.send_command('show cdp neighbors detail')
                neighbors.extend(parser.parse_cdp_neighbors_detail(sh_cdp))
            except Exception:
                pass
        # LLDP
        try:
            sh_lldp_cmd = 'show lldp neighbors' if os_type == 'cisco_xr' else 'show lldp neighbors detail'
            sh_lldp = conn.send_command(sh_lldp_cmd)
            neighbors.extend(parser.parse_lldp_neighbors_detail(sh_lldp))
        except Exception:
            pass
            
        # De-duplicate neighbors
        unique_neighbors = {}
        for n in neighbors:
            key = (n["local_port"], n["remote_device"])
            unique_neighbors[key] = n
        device_data["neighbors"] = list(unique_neighbors.values())
        
        # 6. Spanning Tree (STP)
        if os_type != 'cisco_xr':
            try:
                sh_stp = conn.send_command('show spanning-tree')
                device_data["stp"] = parser.parse_spanning_tree(sh_stp, os_type)
            except Exception:
                device_data["stp"] = {"enabled": False, "vlans": {}}
        else:
            device_data["stp"] = {"enabled": False, "vlans": {}}
            
        # 7. Routing table
        sh_route_cmd = 'show route' if os_type == 'cisco_xr' else 'show ip route'
        sh_route = conn.send_command(sh_route_cmd)
        device_data["routes"] = parser.parse_show_ip_route(sh_route, os_type)
        
        # 8. Services config from running-config
        try:
            sh_run = conn.send_command('show running-config')
            device_data["raw_config"] = sh_run
            device_data["services"] = parser.parse_services(sh_run)
            
            # Save raw config to raw logs
            with open(os.path.join(RAW_LOGS_DIR, f"{ip}_running_config.cfg"), "w") as f:
                f.write(sh_run)
                
            # Save clean configuration backup with hostname and timestamp
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename_hostname = device_data["hostname"] or ip
            backup_filename = f"{filename_hostname}_backup_{timestamp}.cfg"
            with open(os.path.join(BACKUPS_DIR, backup_filename), "w") as f:
                f.write(sh_run)
            print(f"[{ip}] Saved backup to {BACKUPS_DIR}/{backup_filename}")
        except Exception as e:
            print(f"[{ip}] Failed to get running-config: {e}")
            device_data["services"] = {"dns_servers": [], "ntp_servers": [], "radius_servers": [], "tacacs_servers": []}
            
        print(f"[{ip}] Scanned successfully. Hostname: {device_data['hostname']}, Model: {device_data['model']}")
        
    except Exception as e:
        print(f"[{ip}] Error executing discovery commands: {e}")
        device_data["status"] = "partial"
        device_data["reason"] = f"CLI Command execution failed: {e}"
    finally:
        conn.disconnect()
        
    return device_data

def main():
    parser_arg = argparse.ArgumentParser(description="Cisco Switch Discovery & Documentation Engine")
    parser_arg.add_argument("--subnets", help="Comma-separated target subnets (e.g. 192.168.1.0/24)")
    parser_arg.add_argument("--retry", help="Retry failed scan IPs using a JSON failure log file")
    parser_arg.add_argument("--baseline", help="Save the scanned network state as a baseline JSON file")
    parser_arg.add_argument("--compare", help="Compare current network state against a baseline JSON file")
    args = parser_arg.parse_args()
    
    # Download OUI registry if not found
    if not os.path.exists(oui_lookup.OUI_FILE):
        oui_lookup.download_oui_db()
        
    targets = []
    
    if args.retry:
        if not os.path.exists(args.retry):
            print(f"Error: Retry file {args.retry} does not exist.")
            sys.exit(1)
        try:
            with open(args.retry, 'r') as f:
                failed_data = json.load(f)
                targets_ips = failed_data.get("failed_ips", [])
                print(f"Loaded {len(targets_ips)} failed hosts from {args.retry} for retry.")
                # We format them as mock scan discoveries
                for ip in targets_ips:
                    targets.append({"ip": ip, "mac": "", "ports": [22, 23]})
        except Exception as e:
            print(f"Error reading retry file: {e}")
            sys.exit(1)
            
    else:
        # Prompt for target subnets if not passed
        local_ip, local_subnet = get_local_ip_subnet()
        subnets_input = args.subnets
        if not subnets_input:
            subnets_input = input(f"Enter target subnets to scan (comma separated) [Default: {local_subnet}]: ").strip()
            if not subnets_input:
                subnets_input = local_subnet
                
        subnets = [s.strip() for s in subnets_input.split(',')]
        
        # Check subnets validity
        valid_subnets = []
        for s in subnets:
            try:
                IPNetwork(s)
                valid_subnets.append(s)
            except Exception:
                print(f"Skipping invalid subnet input: {s}")
                
        if not valid_subnets:
            print("No valid target subnets to scan. Exiting.")
            sys.exit(1)
            
        print("\n--- Phase 1: Subnet Discovery ---")
        if check_nmap_installed():
            targets = run_nmap_scan(valid_subnets)
        else:
            targets = run_python_port_scan(valid_subnets)
            
        print(f"Discovered {len(targets)} active hosts with open SSH/Telnet ports.")
        if not targets:
            print("No switch management ports (22/23) found. Exiting.")
            sys.exit(1)
            
    # Prompt for credentials
    print("\n--- Phase 2: Credentials Input ---")
    username = input("Enter SSH/Telnet username: ").strip()
    password = getpass.getpass("Enter password: ")
    secret = getpass.getpass("Enter enable secret (press Enter if none): ")
    
    print("\n--- Phase 3: Switch Discovery Crawl ---")
    scanned_devices = {}
    failed_devices = []
    
    # Thread pool for concurrency
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(
                crawl_device, 
                t["ip"], 
                t["ports"], 
                username, 
                password, 
                secret
            ): t for t in targets
        }
        
        for future in as_completed(futures):
            res = future.result()
            ip = res["ip"]
            if res["status"] == "success":
                scanned_devices[ip] = res
            elif res["status"] == "partial":
                scanned_devices[ip] = res
                failed_devices.append({"ip": ip, "reason": res["reason"], "status": "partial"})
            else:
                failed_devices.append({"ip": ip, "reason": res["reason"], "status": "failed"})
                
    # Update MAC address vendors using OUI lookup
    for ip, dev in scanned_devices.items():
        mac = dev.get("mac_address")
        if mac:
            # Check OUI vendor
            vendor = oui_lookup.get_vendor(mac)
            # If not Cisco, log it
            if "Cisco" not in vendor and vendor != "Unknown":
                print(f"[{ip}] Non-Cisco vendor detected: {vendor} ({mac})")
                
    # Generate Deliverables
    print("\n--- Phase 4: Generating Deliverables ---")
    if scanned_devices:
        report_generator.generate_asset_inventory(scanned_devices)
        report_generator.generate_l2_diagram(scanned_devices)
        report_generator.generate_l3_diagram(scanned_devices)
        report_generator.generate_network_analysis_report(scanned_devices)
        report_generator.generate_best_practices_report(scanned_devices)
        report_generator.generate_cabling_matrix(scanned_devices)
        report_generator.generate_protocol_translation(scanned_devices)
        report_generator.generate_config_variables(scanned_devices)
        
        if args.baseline:
            report_generator.save_baseline_state(scanned_devices, args.baseline)
        if args.compare:
            report_generator.compare_baseline_state(scanned_devices, args.compare)
    else:
        print("No devices were successfully scanned. Skipping reports generation.")
        
    # Handle failures & re-run lists
    failed_ips_list = [f["ip"] for f in failed_devices]
    if failed_ips_list:
        failed_log = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "failed_ips": failed_ips_list,
            "details": failed_devices
        }
        with open("failed_hosts.json", "w") as f:
            json.dump(failed_log, f, indent=4)
        print(f"\nWARNING: {len(failed_ips_list)} devices failed or partial-scanned. Details saved to failed_hosts.json")
        print("You can re-run the script to retry only these hosts using: python3 cisco_crawler.py --retry failed_hosts.json")
        
    print("\nNetwork Discovery Complete!")
    print(f"Successfully Scanned: {len(scanned_devices)}")
    print(f"Failed/Partial Scanned: {len(failed_ips_list)}")

if __name__ == "__main__":
    main()
