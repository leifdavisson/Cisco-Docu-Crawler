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
import queue
import threading
import re

# Import local modules
import oui_lookup
import parser
import report_generator

# Ensure directories exist
RAW_LOGS_DIR = "raw_logs"
BACKUPS_DIR = "backups"
os.makedirs(RAW_LOGS_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

VERBOSE = False
DISABLE_TELNET = False
TIMEOUT = 10

def log_debug(msg):
    if VERBOSE:
        print(f"[DEBUG] {msg}")

def send_command_paced(conn, command, mgmt_method):
    """Sends a CLI command to the connection, pacing executions if Telnet is used to protect legacy CPU."""
    if mgmt_method == "Telnet":
        log_debug(f"Pacing Telnet: sleeping 1.0 second before executing '{command}'...")
        time.sleep(1.0)
    res = conn.send_command(command)
    if mgmt_method == "Telnet":
        log_debug(f"Pacing Telnet: sleeping 0.5 seconds after executing '{command}'...")
        time.sleep(0.5)
    return res

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

def validate_credentials(ip, ports, username, password, secret, simulate=False):
    """
    Validates credentials by attempting to connect to a single host.
    Returns True if connection succeeds, False otherwise.
    """
    if simulate:
        print(f"[*] Simulated credential verification succeeded for host {ip}.")
        return True
    if 22 in ports:
        try:
            conn, _ = connect_and_detect(ip, username, password, secret, conn_type="ssh", timeout=TIMEOUT)
            conn.disconnect()
            return True
        except Exception as e:
            print(f"[*] Credential validation failed on {ip} via SSH: {e}")
    if 23 in ports and not DISABLE_TELNET:
        try:
            conn, _ = connect_and_detect(ip, username, password, secret, conn_type="telnet", timeout=TIMEOUT)
            conn.disconnect()
            return True
        except Exception as e:
            print(f"[*] Credential validation failed on {ip} via Telnet: {e}")
    return False

def parse_nmap_grepable_line(line):
    """Parses a single line of Nmap grepable output (-oG) to extract a host with open ports 22/23."""
    if not line.startswith("Host:"):
        return None
    
    parts = line.split("\t")
    if len(parts) < 2:
        return None
    
    host_part = parts[0]
    ports_part = parts[1]
    
    if not ports_part.startswith("Ports:"):
        return None
        
    ip_match = re.search(r"Host:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", host_part)
    if not ip_match:
        return None
    ip = ip_match.group(1)
    
    open_ports = []
    for port_info in ports_part.replace("Ports:", "").split(","):
        port_info = port_info.strip()
        if "/open/" in port_info:
            port_num = port_info.split("/")[0]
            try:
                open_ports.append(int(port_num))
            except ValueError:
                pass
                
    if open_ports:
        return {"ip": ip, "mac": "", "ports": open_ports}
    return None

def run_nmap_scan(subnets):
    """
    Runs Nmap to scan subnets for ports 22 (SSH) and 23 (Telnet).
    Falls back to TCP Connect scan if not root.
    Yields discovered hosts in real-time.
    """
    targets = subnets
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    xml_output = os.path.join(RAW_LOGS_DIR, f"nmap_results_{timestamp}.xml")
    
    ports_str = "22" if DISABLE_TELNET else "22,23"
    print(f"\nRunning Nmap scan on target subnets: {targets}")
    print(f"[*] Saving XML output to: {xml_output}")
    cmd = ["nmap", "-sS", "-p", ports_str, "-Pn", "-oG", "-", "-oX", xml_output] + targets
    
    try:
        print("[*] Starting Nmap SYN scan... (this may take a few minutes)")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        
        # Give Nmap a moment to start and check if it failed immediately (e.g. non-root error)
        time.sleep(0.5)
        if process.poll() is not None:
            stderr_content = process.stderr.read()
            if "You must be root" in stderr_content or "privileges" in stderr_content:
                print("[*] Non-root environment/permissions detected. Falling back to Nmap TCP Connect scan (-sT)...")
                cmd = ["nmap", "-sT", "-p", ports_str, "-Pn", "-oG", "-", "-oX", xml_output] + targets
                print("[*] Starting Nmap TCP Connect scan... (this may take a few minutes)")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            else:
                print(f"[!] Nmap failed to start: {stderr_content}")
                return
        
        # Read stdout in real-time
        for line in process.stdout:
            res = parse_nmap_grepable_line(line)
            if res:
                yield res
                
        process.stdout.close()
        process.wait()
        print("[+] Nmap scan completed successfully.")
    except Exception as e:
        print(f"[!] Nmap scan error: {e}")

def python_port_scan_worker(ip, ports, timeout=0.5):
    """Worker thread to scan ports on a single IP."""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
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
    """Fallback multi-threaded Python TCP port scanner if Nmap is not installed. Yields discovered hosts in real-time."""
    print("Nmap not found. Falling back to internal Python multi-threaded port scanner...")
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
            
    total_ips = len(ips_to_scan)
    ports_to_scan = [22] if DISABLE_TELNET else [22, 23]
    ports_str = "port 22" if DISABLE_TELNET else "ports 22 and 23"
    print(f"Scanning {total_ips} IP addresses on {ports_str}...")
    
    completed = 0
    # Run scan with thread pool and yield results as they finish
    scan_timeout = max(0.5, TIMEOUT / 10.0)
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(python_port_scan_worker, ip, ports_to_scan, scan_timeout): ip for ip in ips_to_scan}
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            if res:
                print(f"\n[+] Discovered active host: {res['ip']} (Open ports: {res['ports']})")
                yield res
            if completed % 10 == 0 or completed == total_ips:
                sys.stdout.write(f"\r[*] Scan progress: {completed}/{total_ips} IPs checked...")
                sys.stdout.flush()
    print()

def run_simulation_scan(subnets):
    """
    Simulates discovery of active switch IPs in target subnets.
    Yields discovered hosts in real-time.
    """
    print("[*] Running simulated subnet discovery...")
    for subnet in subnets:
        try:
            net = IPNetwork(subnet)
            # Pick a few sample IP addresses from the network to "discover"
            ips = []
            if len(net) > 50:
                # E.g. pick indices 10, 20, 30, 100
                ips = [str(net[10]), str(net[20]), str(net[30]), str(net[100])]
            elif len(net) > 5:
                ips = [str(net[i]) for i in range(1, min(5, len(net) - 1))]
            else:
                ips = [str(ip) for ip in list(net)]
                
            print(f"  Simulating scan of subnet {subnet} ({len(net)} IPs). Yielding {len(ips)} simulated active hosts...")
            sim_ports = [22] if DISABLE_TELNET else [22, 23]
            for ip in ips:
                time.sleep(0.1) # Simulate real-time discovery delay
                print(f"  Discovered active host (simulated): {ip} (Open ports: {sim_ports})")
                yield {"ip": ip, "mac": f"00:11:22:33:44:{hash(ip) & 0xff:02x}", "ports": sim_ports}
        except Exception as e:
            print(f"Invalid subnet range ignored in simulation: {subnet} ({e})")

def crawl_device_simulated(ip):
    """
    Simulates performing switch discovery commands on a switch.
    Returns simulated switch data and saves mock config files.
    """
    print(f"[{ip}] Simulating Switch discovery crawl...")
    time.sleep(0.5) # Simulate CLI delay
    
    # Generate stable mock data using hash of IP
    h = hash(ip)
    last_octet = h & 0xff
    mac = f"00:1a:a1:b2:c3:{last_octet:02x}"
    
    # Generate mock neighbor IP addresses
    ip_parts = ip.split('.')
    neigh_ip_1 = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{int(ip_parts[3])+1}"
    neigh_ip_2 = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{int(ip_parts[3])+2}"
    
    os_choices = ['cisco_ios', 'cisco_nxos', 'cisco_xr']
    os_type = os_choices[last_octet % len(os_choices)]
    
    model_choices = ['WS-C3850-24T', 'N9K-C93180YC-FX', 'ISR4431/K9', 'WS-C2960X-48FPS-L']
    model = model_choices[last_octet % len(model_choices)]
    
    firmware_choices = ['16.12.5b', '9.3(5)', '15.5(3)S', '15.2(2)E6']
    firmware = firmware_choices[last_octet % len(firmware_choices)]
    
    hostname = f"sim-switch-{last_octet}"
    serial = f"FDO{last_octet:03d}X{last_octet:02d}Y"
    
    device_data = {
        "ip": ip,
        "status": "success",
        "mgmt_method": "SSH" if (last_octet % 2 == 0) else "Telnet",
        "os_type": os_type,
        "hostname": hostname,
        "model": model,
        "serial": serial,
        "firmware": firmware,
        "mac_address": mac,
        "neighbors": [
            {
                "local_port": "GigabitEthernet1/0/1",
                "remote_device": f"sim-switch-{last_octet + 1}",
                "remote_port": "GigabitEthernet1/0/2",
                "remote_ip": neigh_ip_1,
                "remote_platform": "cisco_ios"
            },
            {
                "local_port": "GigabitEthernet1/0/2",
                "remote_device": f"sim-switch-{last_octet + 2}",
                "remote_port": "GigabitEthernet1/0/1",
                "remote_ip": neigh_ip_2,
                "remote_platform": "cisco_nxos"
            }
        ],
        "l3_interfaces": [
            {"interface": "Vlan10", "ip_address": ip, "status": "up", "protocol": "up"},
            {"interface": "Loopback0", "ip_address": f"10.255.255.{last_octet}", "status": "up", "protocol": "up"}
        ],
        "interfaces_detail": {
            "GigabitEthernet1/0/1": {"status": "up", "protocol": "up", "description": "Uplink to Core", "mac_address": mac, "speed": "1Gb/s", "duplex": "Full-duplex"},
            "GigabitEthernet1/0/2": {"status": "up", "protocol": "up", "description": "Downlink", "mac_address": mac, "speed": "1Gb/s", "duplex": "Full-duplex"}
        },
        "stp": {
            "enabled": True,
            "vlans": {
                "10": {
                    "GigabitEthernet1/0/1": {"role": "Root", "state": "FWD"},
                    "GigabitEthernet1/0/2": {"role": "Desg", "state": "FWD" if last_octet % 4 != 0 else "BLK"}
                }
            }
        },
        "routes": [
            {"protocol": "C", "network": f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0", "mask": "24", "nexthop": "Directly Connected", "interface": "Vlan10"},
            {"protocol": "O", "network": "0.0.0.0", "mask": "0", "nexthop": f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1", "interface": "Vlan10"}
        ],
        "services": {
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "ntp_servers": ["pool.ntp.org"],
            "radius_servers": ["192.168.100.50"],
            "tacacs_servers": ["192.168.100.60"]
        },
        "raw_config": f"! Simulated Config\nhostname {hostname}\n!"
    }
    
    # Save simulated running-config to raw logs & backups
    try:
        with open(os.path.join(RAW_LOGS_DIR, f"{ip}_running_config.cfg"), "w") as f:
            f.write(device_data["raw_config"])
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{hostname}_backup_{timestamp}.cfg"
        with open(os.path.join(BACKUPS_DIR, backup_filename), "w") as f:
            f.write(device_data["raw_config"])
        print(f"[{ip}] Saved backup to {BACKUPS_DIR}/{backup_filename}")
    except Exception as e:
        print(f"[{ip}] Error saving simulated config: {e}")
        
    print(f"[{ip}] Scanned successfully (simulated). Hostname: {hostname}, Model: {model}")
    return device_data

def connect_and_detect(ip, username, password, secret, conn_type="ssh", timeout=None):
    """
    Connects to the switch and detects the specific Cisco OS type.
    Returns the active netmiko connection object and the detected OS string.
    """
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    
    device_type = 'cisco_ios' if conn_type == 'ssh' else 'cisco_ios_telnet'
    
    device = {
        'device_type': device_type,
        'ip': ip,
        'username': username,
        'password': password,
        'secret': secret,
        'global_delay_factor': 2,
    }
    
    if timeout is not None:
        device['timeout'] = timeout
        device['auth_timeout'] = timeout
    
    if conn_type == 'telnet':
        # Optimize for slower/older Telnet connections and enable logging for troubleshooting
        if timeout is None:
            device['auth_timeout'] = 60
        device['fast_cli'] = False
        device['session_log'] = os.path.join(RAW_LOGS_DIR, f"{ip}_telnet_session.log")
        device['global_delay_factor'] = 4  # Increase delay factor for old/slow Telnet devices
        
    max_retries = 3
    retry_delay = 2.0  # Base delay in seconds
    net_connect = None
    
    # Connect with exponential backoff
    for attempt in range(1, max_retries + 1):
        try:
            log_debug(f"[{ip}] Initializing Netmiko ConnectHandler with device_type={device_type} (Attempt {attempt}/{max_retries})...")
            net_connect = ConnectHandler(**device)
            log_debug(f"[{ip}] Connection established. Prompt detected: {net_connect.find_prompt()}")
            break
        except NetmikoAuthenticationException as e:
            # Do NOT retry authentication failures to avoid locking accounts in enterprise environments
            print(f"[{ip}] Authentication failed. Bypassing retries to prevent account lockout.")
            raise e
        except (NetmikoTimeoutException, ConnectionError, socket.timeout) as e:
            if attempt == max_retries:
                print(f"[!] [{ip}] Connection failed after {max_retries} attempts: {e}")
                raise e
            sleep_time = retry_delay * (2 ** (attempt - 1))
            print(f"[*] [{ip}] Connection timeout or socket issue: {e}. Retrying in {sleep_time}s...")
            time.sleep(sleep_time)
        except Exception as e:
            err_msg = str(e).lower()
            if "timeout" in err_msg or "conn" in err_msg or "reset" in err_msg or "refused" in err_msg:
                if attempt == max_retries:
                    print(f"[!] [{ip}] Connection failed after {max_retries} attempts: {e}")
                    raise e
                sleep_time = retry_delay * (2 ** (attempt - 1))
                print(f"[*] [{ip}] Connection exception: {e}. Retrying in {sleep_time}s...")
                time.sleep(sleep_time)
            else:
                raise e

    # Send commands to verify OS type
    log_debug(f"[{ip}] Sending 'show version' to detect OS...")
    if conn_type == 'telnet':
        time.sleep(1.0)
    version_output = net_connect.send_command('show version')
    if conn_type == 'telnet':
        time.sleep(0.5)
    
    detected_os = 'cisco_ios'
    if 'NX-OS' in version_output or 'Nexus' in version_output:
        detected_os = 'cisco_nxos'
    elif 'IOS-XR' in version_output or 'IOS XR' in version_output:
        detected_os = 'cisco_xr'
        
    log_debug(f"[{ip}] Detected OS type: {detected_os}")
    # If the detected OS isn't standard IOS, reconnect with the matching driver
    if detected_os != 'cisco_ios':
        log_debug(f"[{ip}] Re-connecting with detected driver: {detected_os}...")
        net_connect.disconnect()
        device['device_type'] = detected_os + ('_telnet' if conn_type == 'telnet' else '')
        # XR doesn't use enable secret
        if detected_os == 'cisco_xr' and 'secret' in device:
            del device['secret']
            
        # Reconnect with backoff
        for attempt in range(1, max_retries + 1):
            try:
                net_connect = ConnectHandler(**device)
                log_debug(f"[{ip}] Connection re-established with driver: {device['device_type']}")
                break
            except NetmikoAuthenticationException as e:
                raise e
            except Exception as e:
                if attempt == max_retries:
                    raise e
                sleep_time = retry_delay * (2 ** (attempt - 1))
                print(f"[*] [{ip}] Driver re-connection failed. Retrying in {sleep_time}s...")
                time.sleep(sleep_time)
        
    return net_connect, detected_os

def crawl_device(ip, ports, username, password, secret):
    """
    Performs discovery commands on a single switch.
    Tries SSH first, falls back to Telnet if enabled.
    """
    conn = None
    os_type = None
    mgmt_method = None
    
    # Try SSH first if port 22 is open
    if 22 in ports:
        try:
            print(f"[{ip}] Attempting SSH connection...")
            conn, os_type = connect_and_detect(ip, username, password, secret, conn_type="ssh", timeout=TIMEOUT)
            mgmt_method = "SSH"
        except Exception as e:
            err_type = type(e).__name__
            err_msg = str(e).split('\n')[0]
            if VERBOSE:
                import traceback
                print(f"[{ip}] SSH connection failed with full traceback:\n{traceback.format_exc()}")
            else:
                if "Authentication" in err_type or "auth" in err_msg.lower():
                    print(f"[{ip}] SSH connection failed: Authentication failed.")
                elif "Timeout" in err_type or "timed out" in err_msg.lower():
                    print(f"[{ip}] SSH connection failed: Connection timed out.")
                elif "ConnectionRefused" in err_type or "refused" in err_msg.lower():
                    print(f"[{ip}] SSH connection failed: Connection refused.")
                else:
                    print(f"[{ip}] SSH connection failed: {err_msg}")
            
    # Try Telnet fallback if SSH failed or only port 23 is open and Telnet is not disabled
    if not conn and 23 in ports:
        if DISABLE_TELNET:
            log_debug(f"[{ip}] Telnet port is open but Telnet connections are disabled via policy.")
        else:
            try:
                print(f"[{ip}] Attempting Telnet fallback connection...")
                conn, os_type = connect_and_detect(ip, username, password, secret, conn_type="telnet", timeout=TIMEOUT)
                mgmt_method = "Telnet"
            except Exception as e:
                err_type = type(e).__name__
                err_msg = str(e).split('\n')[0]
                if VERBOSE:
                    import traceback
                    print(f"[{ip}] Telnet connection failed with full traceback:\n{traceback.format_exc()}")
                else:
                    if "Authentication" in err_type or "auth" in err_msg.lower():
                        print(f"[{ip}] Telnet connection failed: Authentication failed.")
                    elif "Timeout" in err_type or "timed out" in err_msg.lower():
                        print(f"[{ip}] Telnet connection failed: Connection timed out.")
                    elif "ConnectionRefused" in err_type or "refused" in err_msg.lower():
                        print(f"[{ip}] Telnet connection failed: Connection refused.")
                    else:
                        print(f"[{ip}] Telnet connection failed: {err_msg}")
            
    if not conn:
        reason = "Connection failed (both SSH and Telnet)" if not DISABLE_TELNET else "Connection failed (SSH failed and Telnet is disabled)"
        return {"ip": ip, "status": "failed", "reason": reason}
        
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
                log_debug(f"[{ip}] Entering enable mode...")
                conn.enable()
                log_debug(f"[{ip}] Successfully entered enable mode.")
                if mgmt_method == "Telnet":
                    time.sleep(1.0)
            except Exception as e:
                log_debug(f"[{ip}] Failed to enter enable mode: {e}")
                pass
                
        # 1. Version information
        log_debug(f"[{ip}] Executing 'show version'...")
        sh_ver = send_command_paced(conn, 'show version', mgmt_method)
        log_debug(f"[{ip}] Saving show version response ({len(sh_ver)} chars) to raw logs...")
        with open(os.path.join(RAW_LOGS_DIR, f"{ip}_show_version.log"), "w") as f:
            f.write(sh_ver)
            
        ver_data = parser.parse_show_version(sh_ver, os_type)
        device_data.update(ver_data)
        log_debug(f"[{ip}] Detected Hostname: {device_data.get('hostname')}, OS/Firmware: {device_data.get('firmware')}")
        
        # 2. Inventory check (highly reliable model/serial)
        try:
            log_debug(f"[{ip}] Executing 'show inventory'...")
            sh_inv = send_command_paced(conn, 'show inventory', mgmt_method)
            log_debug(f"[{ip}] Saving show inventory response ({len(sh_inv)} chars) to raw logs...")
            with open(os.path.join(RAW_LOGS_DIR, f"{ip}_show_inventory.log"), "w") as f:
                f.write(sh_inv)
            inv_items = parser.parse_show_inventory(sh_inv)
            log_debug(f"[{ip}] Parsed {len(inv_items)} inventory items.")
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
            log_debug(f"[{ip}] Extracted Model: {device_data.get('model')}, Serial: {device_data.get('serial')}")
        except Exception as e:
            log_debug(f"[{ip}] Show inventory query failed: {e}")
            pass
            
        # Ensure we clean hostname from prompt if still empty
        if not device_data["hostname"]:
            device_data["hostname"] = conn.find_prompt().replace('#', '').replace('>', '').strip()
            log_debug(f"[{ip}] Hostname defaulted from prompt: {device_data['hostname']}")
            
        # 3. Interfaces L3 list
        sh_ip_int_cmd = 'show ipv4 interface brief' if os_type == 'cisco_xr' else 'show ip interface brief'
        log_debug(f"[{ip}] Executing '{sh_ip_int_cmd}'...")
        sh_ip_int = send_command_paced(conn, sh_ip_int_cmd, mgmt_method)
        device_data["l3_interfaces"] = parser.parse_ip_interface_brief(sh_ip_int, os_type)
        log_debug(f"[{ip}] Parsed {len(device_data['l3_interfaces'])} L3 interface entries.")
        
        # 4. Interfaces physical details
        log_debug(f"[{ip}] Executing 'show interfaces'...")
        sh_ints = send_command_paced(conn, 'show interfaces', mgmt_method)
        device_data["interfaces_detail"] = parser.parse_show_interfaces(sh_ints, os_type)
        log_debug(f"[{ip}] Parsed detailed info for {len(device_data['interfaces_detail'])} physical interfaces.")
        
        # Try to locate base MAC address from interfaces if show version failed
        if not device_data["mac_address"]:
            # Find first interface MAC address
            for intf_name, intf_data in device_data["interfaces_detail"].items():
                if intf_data.get("mac_address"):
                    device_data["mac_address"] = oui_lookup.normalize_mac(intf_data["mac_address"])
                    log_debug(f"[{ip}] Base MAC address extracted from interface {intf_name}: {device_data['mac_address']}")
                    break
                    
        # 5. CDP & LLDP Neighbors
        neighbors = []
        # CDP
        if os_type != 'cisco_xr':
            try:
                log_debug(f"[{ip}] Executing 'show cdp neighbors detail'...")
                sh_cdp = send_command_paced(conn, 'show cdp neighbors detail', mgmt_method)
                neighbors.extend(parser.parse_cdp_neighbors_detail(sh_cdp))
            except Exception as e:
                log_debug(f"[{ip}] CDP neighbor query failed: {e}")
                pass
        # LLDP
        try:
            sh_lldp_cmd = 'show lldp neighbors' if os_type == 'cisco_xr' else 'show lldp neighbors detail'
            log_debug(f"[{ip}] Executing '{sh_lldp_cmd}'...")
            sh_lldp = send_command_paced(conn, sh_lldp_cmd, mgmt_method)
            neighbors.extend(parser.parse_lldp_neighbors_detail(sh_lldp))
        except Exception as e:
            log_debug(f"[{ip}] LLDP neighbor query failed: {e}")
            pass
            
        # De-duplicate neighbors
        unique_neighbors = {}
        for n in neighbors:
            key = (n["local_port"], n["remote_device"])
            unique_neighbors[key] = n
        device_data["neighbors"] = list(unique_neighbors.values())
        log_debug(f"[{ip}] Total unique neighbors parsed: {len(device_data['neighbors'])}")
        
        # 6. Spanning Tree (STP)
        if os_type != 'cisco_xr':
            try:
                log_debug(f"[{ip}] Executing 'show spanning-tree'...")
                sh_stp = send_command_paced(conn, 'show spanning-tree', mgmt_method)
                device_data["stp"] = parser.parse_spanning_tree(sh_stp, os_type)
            except Exception as e:
                log_debug(f"[{ip}] Spanning-tree query failed: {e}")
                device_data["stp"] = {"enabled": False, "vlans": {}}
        else:
            device_data["stp"] = {"enabled": False, "vlans": {}}
            
        # 7. Routing table
        sh_route_cmd = 'show route' if os_type == 'cisco_xr' else 'show ip route'
        log_debug(f"[{ip}] Executing '{sh_route_cmd}'...")
        sh_route = send_command_paced(conn, sh_route_cmd, mgmt_method)
        device_data["routes"] = parser.parse_show_ip_route(sh_route, os_type)
        log_debug(f"[{ip}] Parsed {len(device_data['routes'])} routes.")
        
        # 8. Services config from running-config
        try:
            log_debug(f"[{ip}] Executing 'show running-config'...")
            sh_run = send_command_paced(conn, 'show running-config', mgmt_method)
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
    parser_arg.add_argument("--simulate", action="store_true", help="Simulate/mock network scan and switch crawling")
    parser_arg.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging / debug output")
    parser_arg.add_argument("--disable-telnet", action="store_true", help="Disable Telnet connection fallback completely")
    parser_arg.add_argument("--threads", type=int, default=10, help="Number of concurrent crawler threads (default: 10)")
    parser_arg.add_argument("--timeout", type=int, default=10, help="Timeout in seconds for scanning and connections (default: 10)")
    args = parser_arg.parse_args()
    
    global VERBOSE, DISABLE_TELNET, TIMEOUT
    VERBOSE = args.verbose
    DISABLE_TELNET = args.disable_telnet
    TIMEOUT = args.timeout
    
    if VERBOSE:
        print("[*] Verbose logging / debug output is ENABLED.")
    if DISABLE_TELNET:
        print("[*] Telnet connections are DISABLED.")
    print(f"[*] Thread count set to {args.threads}.")
    print(f"[*] Timeout set to {args.timeout} seconds.")
    
    # Download OUI registry if not found
    if not os.path.exists(oui_lookup.OUI_FILE):
        oui_lookup.download_oui_db()
        
    host_generator = None
    
    if args.retry:
        if not os.path.exists(args.retry):
            print(f"Error: Retry file {args.retry} does not exist.")
            sys.exit(1)
        try:
            with open(args.retry, 'r') as f:
                failed_data = json.load(f)
                targets_ips = failed_data.get("failed_ips", [])
                print(f"Loaded {len(targets_ips)} failed hosts from {args.retry} for retry.")
                
                def retry_generator():
                    for ip in targets_ips:
                        yield {"ip": ip, "mac": "", "ports": [22] if DISABLE_TELNET else [22, 23]}
                host_generator = retry_generator()
        except Exception as e:
            print(f"Error reading retry file: {e}")
            sys.exit(1)
            
    else:
        # Prompt for target subnets if not passed
        local_ip, local_subnet = get_local_ip_subnet()
        subnets_input = args.subnets
        if not subnets_input:
            default_sub = "192.168.1.0/24" if args.simulate else local_subnet
            try:
                subnets_input = input(f"Enter target subnets to scan (comma separated) [Default: {default_sub}]: ").strip()
            except (EOFError, OSError):
                subnets_input = ""
            if not subnets_input:
                subnets_input = default_sub
                
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
            
    # Prompt for credentials first
    print("\n--- Phase 1: Credentials Input ---")
    if args.simulate:
        print("[*] Simulation mode enabled. Using default mock credentials.")
        username = "admin"
        password = "password"
        secret = "secret"
    else:
        # Try environment variables first
        username = os.environ.get("CRAWLER_USER") or os.environ.get("CRAWLER_USERNAME") or ""
        username = username.strip()
        
        password = os.environ.get("CRAWLER_PASSWORD") or ""
        password = password.strip()
        
        secret = os.environ.get("CRAWLER_SECRET") or os.environ.get("CRAWLER_ENABLE_SECRET") or ""
        secret = secret.strip()
        
        try:
            if username:
                print(f"[*] Loaded username from environment: {username}")
            else:
                username = input("Enter SSH/Telnet username: ").strip()
                
            if password:
                print("[*] Loaded password from environment.")
            else:
                if sys.stdin.isatty():
                    password = getpass.getpass("Enter password: ")
                else:
                    password = input("Enter password: ").strip()
                    
            if secret:
                print("[*] Loaded enable secret from environment.")
            elif not os.environ.get("CRAWLER_USER") and not os.environ.get("CRAWLER_USERNAME"):
                # Only prompt for optional enable secret in interactive runs
                if sys.stdin.isatty():
                    secret = getpass.getpass("Enter enable secret (press Enter if none): ")
                else:
                    secret = input("Enter enable secret (press Enter if none): ").strip()
        except (EOFError, OSError):
            print("\n[!] EOF or interruption detected while reading credentials.")
            if not username:
                username = ""
            if not password:
                password = ""
            if not secret:
                secret = ""

    if not args.retry:
        print("\n--- Phase 2: Subnet Discovery ---")
        if args.simulate:
            host_generator = run_simulation_scan(valid_subnets)
        elif check_nmap_installed():
            host_generator = run_nmap_scan(valid_subnets)
        else:
            host_generator = run_python_port_scan(valid_subnets)
            
    # Set up generator iterator
    iterator = iter(host_generator)
    first_host = None
    try:
        first_host = next(iterator)
    except StopIteration:
        pass
        
    if not first_host:
        print("No switch management ports (22/23) found. Exiting.")
        sys.exit(1)
        
    print(f"\n[+] Discovered first active host: {first_host['ip']} (Open ports: {first_host['ports']})")
            
    # Validate the credentials entered earlier
    print("\n--- Phase 3: Credentials Validation ---")
    
    discovered_hosts = [first_host]
    validated = False
    
    while not validated:
        # Check validation on all hosts we currently have
        for idx in range(len(discovered_hosts)):
            host = discovered_hosts[idx]
            print(f"[*] Validating credentials on {host['ip']}...")
            if validate_credentials(host["ip"], host["ports"], username, password, secret, simulate=args.simulate):
                print(f"[+] Credentials verified successfully on {host['ip']}!")
                validated = True
                break
            else:
                print(f"[-] Credential validation failed on {host['ip']}.")
        
        if validated:
            break
            
        # Try to pull remaining hosts from iterator to validate on them
        try:
            for host in iterator:
                discovered_hosts.append(host)
                print(f"[+] Discovered additional active host: {host['ip']} (Open ports: {host['ports']})")
                print(f"[*] Validating credentials on {host['ip']}...")
                if validate_credentials(host["ip"], host["ports"], username, password, secret, simulate=args.simulate):
                    print(f"[+] Credentials verified successfully on {host['ip']}!")
                    validated = True
                    break
                else:
                    print(f"[-] Credential validation failed on {host['ip']}.")
        except Exception as e:
            print(f"[!] Error during additional host discovery: {e}")
            
        if validated:
            break
            
        print("[!] Credentials validation failed on all discovered hosts.")
        print("This could be due to invalid credentials, or because you are connecting to the wrong device (e.g., home gateway).")
        if not sys.stdin.isatty():
            print("[!] Terminal is non-interactive and credentials validation failed. Exiting.")
            sys.exit(1)
            
        try:
            username = input("Enter SSH/Telnet username (or type 'skip' to bypass validation): ").strip()
            if username.lower() == 'skip':
                print("[*] Bypassing credentials validation. Proceeding to scan all discovered hosts...")
                break
                
            if sys.stdin.isatty():
                password = getpass.getpass("Enter password: ")
                secret = getpass.getpass("Enter enable secret (press Enter if none): ")
            else:
                password = input("Enter password: ").strip()
                secret = input("Enter enable secret (press Enter if none): ").strip()
        except (EOFError, OSError):
            print("\n[!] EOF or interruption detected while reading credentials. Exiting.")
            sys.exit(1)
            
    print("[+] Credentials phase completed.")
    
    print("\n--- Phase 4: Switch Discovery Crawl (Concurrent Scan & Crawl) ---")
    scanned_devices = {}
    failed_devices = []
    devices_lock = threading.Lock()
    crawl_queue = queue.Queue()
    
    def crawler_worker():
        while True:
            item = crawl_queue.get()
            if item is None:
                crawl_queue.task_done()
                break
                
            ip = item["ip"]
            try:
                if args.simulate:
                    res = crawl_device_simulated(ip)
                else:
                    res = crawl_device(ip, item["ports"], username, password, secret)
                with devices_lock:
                    if res["status"] == "success":
                         scanned_devices[ip] = res
                    elif res["status"] == "partial":
                         scanned_devices[ip] = res
                         failed_devices.append({"ip": ip, "reason": res["reason"], "status": "partial"})
                    else:
                         failed_devices.append({"ip": ip, "reason": res["reason"], "status": "failed"})
            except Exception as e:
                print(f"[{ip}] Unexpected error in crawler worker: {e}")
                with devices_lock:
                    failed_devices.append({"ip": ip, "reason": str(e), "status": "failed"})
            finally:
                crawl_queue.task_done()
 
    # Thread pool for concurrency
    num_workers = args.threads
    workers = []
    for _ in range(num_workers):
        t = threading.Thread(target=crawler_worker)
        t.daemon = True
        t.start()
        workers.append(t)
        
    # Queue all hosts that have been discovered so far
    for host in discovered_hosts:
        crawl_queue.put(host)
        
    # Feed remaining hosts to queue as they are discovered (if any)
    try:
        for host in iterator:
            crawl_queue.put(host)
    except Exception as e:
        print(f"[!] Error during discovery: {e}")
        
    # Wait for all crawling to complete
    crawl_queue.join()
    
    # Stop workers
    for _ in range(num_workers):
        crawl_queue.put(None)
    for t in workers:
        t.join()
                
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
    # Generate Deliverables
    print("\n--- Phase 5: Generating Deliverables ---")
    if scanned_devices:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        deliv_dir = os.path.join("deliverables", f"run_{timestamp}")
        inv_dir = os.path.join(deliv_dir, "inventory")
        diag_dir = os.path.join(deliv_dir, "diagrams")
        analysis_dir = os.path.join(deliv_dir, "analysis")
        mig_dir = os.path.join(deliv_dir, "migration")
        
        os.makedirs(inv_dir, exist_ok=True)
        os.makedirs(diag_dir, exist_ok=True)
        os.makedirs(analysis_dir, exist_ok=True)
        os.makedirs(mig_dir, exist_ok=True)

        print(f"[+] Output directory created: {deliv_dir}")

        asset_file = os.path.join(inv_dir, "asset_inventory.csv")
        report_generator.generate_asset_inventory(scanned_devices, asset_file)
        print(f"  - Asset Inventory: {asset_file}")

        l2_diag = os.path.join(diag_dir, "L2_network_diagrams.md")
        report_generator.generate_l2_diagram(scanned_devices, l2_diag)
        print(f"  - L2 Network Diagrams: {l2_diag}")

        l3_diag = os.path.join(diag_dir, "L3_network_diagrams.md")
        report_generator.generate_l3_diagram(scanned_devices, l3_diag)
        print(f"  - L3 Network Diagrams: {l3_diag}")

        analysis_report = os.path.join(analysis_dir, "network_analysis_report.md")
        report_generator.generate_network_analysis_report(scanned_devices, analysis_report)
        print(f"  - Network Analysis Report: {analysis_report}")

        best_practices = os.path.join(analysis_dir, "Cisco_Best_Practices.md")
        report_generator.generate_best_practices_report(scanned_devices, best_practices)
        print(f"  - Cisco Best Practices: {best_practices}")

        cable_matrix = os.path.join(mig_dir, "migration_cabling_matrix.csv")
        report_generator.generate_cabling_matrix(scanned_devices, cable_matrix)
        print(f"  - Migration Cabling Matrix: {cable_matrix}")

        protocol_trans = os.path.join(mig_dir, "cisco_to_target_translation.md")
        report_generator.generate_protocol_translation(scanned_devices, protocol_trans)
        print(f"  - Protocol Translation Guide: {protocol_trans}")

        config_vars = os.path.join(mig_dir, "migration_config_variables.json")
        report_generator.generate_config_variables(scanned_devices, config_vars)
        print(f"  - Configuration Variables: {config_vars}")
        
        if args.baseline:
            report_generator.save_baseline_state(scanned_devices, args.baseline)
            print(f"  - Saved network baseline state to: {args.baseline}")
        if args.compare:
            report_generator.compare_baseline_state(scanned_devices, args.compare)
            print(f"  - Compared current state against baseline: {args.compare}")
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
