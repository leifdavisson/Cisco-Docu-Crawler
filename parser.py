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

import re
import sys

def parse_show_version(output, os_type):
    """
    Parses 'show version' output.
    Returns a dict with: hostname, firmware, model, serial
    """
    data = {
        "hostname": "",
        "firmware": "",
        "model": "",
        "serial": ""
    }
    
    # Clean up backspaces or paging characters
    output = re.sub(r'[\b]', '', output)
    
    if os_type == "cisco_ios":
        # Firmware Version
        fw_match = re.search(r'Version\s+([^,]+)', output)
        if fw_match:
            data["firmware"] = fw_match.group(1).strip()
            
        # Hostname (usually derived from uptime prompt like "hostname uptime is...")
        hn_match = re.search(r'(\S+)\s+uptime\s+is', output)
        if hn_match:
            data["hostname"] = hn_match.group(1).strip()
            
        # Model & Serial
        # Often: "cisco WS-C2960S-48TS-L (PowerPC) processor"
        model_match = re.search(r'[Cc]isco\s+([A-Za-z0-9-]+)\s+\([^)]+\)\s+processor', output)
        if model_match:
            data["model"] = model_match.group(1).strip()
            
        serial_match = re.search(r'Processor\s+board\s+ID\s+(\S+)', output)
        if serial_match:
            data["serial"] = serial_match.group(1).strip()
            
    elif os_type == "cisco_nxos":
        # Firmware Version
        fw_match = re.search(r'NXOS:\s+version\s+(\S+)', output)
        if not fw_match:
            fw_match = re.search(r'system:\s+version\s+(\S+)', output)
        if fw_match:
            data["firmware"] = fw_match.group(1).strip()
            
        # Model
        # "cisco Nexus9000 C9396PX Chassis"
        model_match = re.search(r'Chassis\s*\n\s*cisco\s+([A-Za-z0-9-]+)', output)
        if not model_match:
            model_match = re.search(r'Hardware\s*\n\s*cisco\s+([A-Za-z0-9-]+)', output)
        if model_match:
            data["model"] = model_match.group(1).strip()
            
        # Serial
        serial_match = re.search(r'Processor\s+Board\s+ID\s+(\S+)', output)
        if serial_match:
            data["serial"] = serial_match.group(1).strip()
            
    elif os_type == "cisco_xr":
        # Firmware Version
        fw_match = re.search(r'Version\s+(\S+)', output)
        if fw_match:
            data["firmware"] = fw_match.group(1).strip()
            
        # Model
        model_match = re.search(r'cisco\s+([A-Za-z0-9-]+)\s+Series\s+\([^)]+\)\s+processor', output)
        if not model_match:
            model_match = re.search(r'cisco\s+([A-Za-z0-9-]+)\s+\([^)]+\)\s+processor', output)
        if model_match:
            data["model"] = model_match.group(1).strip()
            
        # Serial
        serial_match = re.search(r'Chassis\s+Serial\s+Number:\s*(\S+)', output)
        if serial_match:
            data["serial"] = serial_match.group(1).strip()
            
    return data

def parse_show_inventory(output):
    """
    Parses 'show inventory' output which is highly standard.
    Returns list of dicts: {"name": ..., "descr": ..., "pid": ..., "sn": ...}
    We can use this to enrich the Version Model/Serial if missing.
    """
    items = []
    # Standard format:
    # NAME: "Chassis", DESCR: "Cisco ASR-9001 Chassis"
    # PID: ASR-9001            , VID: V01, SN: FOX16123XYZ
    pattern = re.compile(
        r'NAME:\s*"([^"]*)"\s*,\s*DESCR:\s*"([^"]*)"\s*\r?\nPID:\s*(\S*)\s*,\s*VID:\s*\S*\s*,\s*SN:\s*(\S*)',
        re.IGNORECASE
    )
    for match in pattern.finditer(output):
        items.append({
            "name": match.group(1).strip(),
            "descr": match.group(2).strip(),
            "pid": match.group(3).strip(),
            "sn": match.group(4).strip()
        })
    return items

def parse_ip_interface_brief(output, os_type):
    """
    Parses 'show ip interface brief' or 'show ipv4 interface brief' output.
    Returns list of dicts: {"interface": ..., "ip_address": ..., "status": ..., "protocol": ...}
    """
    interfaces = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or "Interface" in line or "IP-Address" in line or "OK?" in line:
            continue
        # Format: Interface IP-Address OK? Method Status Protocol
        # Or XR: Interface IP-Address State Active
        parts = line.split()
        if len(parts) >= 4:
            interface = parts[0]
            ip_addr = parts[1]
            if os_type == "cisco_xr":
                # XR format: Loopback0 192.168.1.1 Up Is-Up ...
                status = parts[2]
                protocol = parts[3]
            else:
                # IOS/NX-OS format: Vlan1 10.1.1.1 YES NVRAM up up
                status = parts[-2]
                protocol = parts[-1]
                
            interfaces.append({
                "interface": interface,
                "ip_address": ip_addr,
                "status": status.lower(),
                "protocol": protocol.lower()
            })
    return interfaces

def parse_show_interfaces_status(output):
    """
    Parses 'show interface status' (IOS / NX-OS).
    Returns list of dicts: {"port": ..., "name": ..., "status": ..., "vlan": ..., "duplex": ..., "speed": ..., "type": ...}
    """
    ports = []
    # Columns usually: Port Name Status Vlan Duplex Speed Type
    # Match rows. Headers: Port      Name               Status       Vlan       Duplex  Speed Type
    lines = output.splitlines()
    header_found = False
    for line in lines:
        if "Port" in line and "Status" in line:
            header_found = True
            continue
        if not header_found or not line.strip() or line.startswith("---") or line.startswith("Port"):
            continue
        
        # Split by fixed width or regex spacing since Name column can have spaces.
        # Often easier to match: (Interface) (Name/Description - optional) (connected/notconnect/disabled/err-disabled) (Vlan) (duplex) (speed) (Type)
        # Port name regex: e.g. "Gi1/0/1" or "Fa0/1" or "Po1" or "Eth1/1"
        match = re.match(r'^(\S+)\s+(.*?)\s+(connected|notconnect|disabled|err-disabled|up|down|monitoring)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$', line.strip())
        if match:
            ports.append({
                "port": match.group(1),
                "name": match.group(2).strip(),
                "status": match.group(3),
                "vlan": match.group(4),
                "duplex": match.group(5),
                "speed": match.group(6),
                "type": match.group(7).strip() if match.group(7) else ""
            })
    return ports

def parse_show_interfaces(output, os_type):
    """
    Parses 'show interfaces' (full detail).
    Looks for packet counters, CRC/input errors, duplex/speed settings.
    Returns dict mapping interface name -> stats dict:
    {"mac_address": ..., "speed": ..., "duplex": ..., "input_errors": ..., "crc": ..., "output_errors": ..., "description": ...}
    """
    interfaces = {}
    current_int = None
    
    # We split output by double newline or by line starting with non-whitespace interface
    lines = output.splitlines()
    for line in lines:
        # Check if line starts an interface definition
        # e.g., "GigabitEthernet1/0/1 is up, line protocol is up"
        # or "GigabitEthernet1/0/1 is down (disabled)"
        # or "Bundle-Ether1 is up, line protocol is up"
        int_start = re.match(r'^(\S+)\s+is\s+(up|down|administratively down)', line)
        if int_start:
            current_int = int_start.group(1)
            interfaces[current_int] = {
                "status": int_start.group(2),
                "mac_address": "",
                "speed": "",
                "duplex": "",
                "input_errors": 0,
                "crc": 0,
                "output_errors": 0,
                "description": ""
            }
            continue
            
        if not current_int:
            continue
            
        # Description
        desc_match = re.search(r'[Dd]escription:\s*(.+)$', line)
        if desc_match:
            interfaces[current_int]["description"] = desc_match.group(1).strip()
            
        # MAC Address
        # "Hardware is ..., address is 0011.2233.4455 (bia 0011.2233.4455)"
        # "Hardware: Ethernet, address: 0011.2233.4455 (bia 0011.2233.4455)"
        mac_match = re.search(r'address\s*(?:is|:)\s*([0-9a-fA-F.-]+)', line)
        if mac_match:
            interfaces[current_int]["mac_address"] = mac_match.group(1).replace('-', '').replace('.', '').replace(':', '')
            
        # Speed/Duplex
        # "Full-duplex, 1000Mb/s, link type is auto, media type is 10/100/1000BaseTX"
        # "Full-duplex, 10Gbps"
        # "Auto-duplex, Auto-speed"
        sd_match = re.search(r'(\S+-duplex),\s*(\S+b/s|\S+bps|Auto-speed)', line, re.IGNORECASE)
        if sd_match:
            interfaces[current_int]["duplex"] = sd_match.group(1).strip()
            interfaces[current_int]["speed"] = sd_match.group(2).strip()
            
        # Input Errors & CRCs
        # "0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored"
        ie_match = re.search(r'(\d+)\s+input\s+errors,\s*(\d+)\s+CRC', line)
        if ie_match:
            interfaces[current_int]["input_errors"] = int(ie_match.group(1))
            interfaces[current_int]["crc"] = int(ie_match.group(2))
            
        # Output Errors
        # "0 output errors, 0 collisions, 0 interface resets"
        oe_match = re.search(r'(\d+)\s+output\s+errors', line)
        if oe_match:
            interfaces[current_int]["output_errors"] = int(oe_match.group(1))
            
    return interfaces

def parse_cdp_neighbors_detail(output):
    """
    Parses 'show cdp neighbors detail' output.
    Returns list of neighbor dicts:
    {"local_port": ..., "remote_device": ..., "remote_port": ..., "remote_ip": ..., "platform": ...}
    """
    neighbors = []
    current = {}
    
    # We parse block by block. A block starts with "-------------------------" or "Device ID:"
    # Note: Device ID is the start of a block.
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Start of neighbor block
        device_match = re.match(r'^Device ID:\s*(\S+)', line)
        if device_match:
            if current and "local_port" in current:
                neighbors.append(current)
            current = {
                "remote_device": device_match.group(1).split('.')[0], # strip domain
                "remote_ip": "",
                "local_port": "",
                "remote_port": "",
                "platform": ""
            }
            continue
            
        if not current:
            continue
            
        # IP Address
        ip_match = re.search(r'IP\s+address:\s*([0-9.]+)', line)
        if ip_match:
            current["remote_ip"] = ip_match.group(1)
            continue
        # Sometimes IP is on the next line or formatted differently:
        # "IPv4 Address: 10.1.1.2"
        ipv4_match = re.search(r'IPv4\s+Address:\s*([0-9.]+)', line)
        if ipv4_match:
            current["remote_ip"] = ipv4_match.group(1)
            continue
            
        # Platform
        plat_match = re.search(r'Platform:\s*([^,]+)', line)
        if plat_match:
            current["platform"] = plat_match.group(1).strip()
            continue
            
        # Interface ports (Local and Remote)
        # "Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24"
        ports_match = re.search(r'Interface:\s*([^,]+),\s*Port\s+ID\s+\(outgoing\s+port\):\s*(\S+)', line, re.IGNORECASE)
        if ports_match:
            current["local_port"] = ports_match.group(1).strip()
            current["remote_port"] = ports_match.group(2).strip()
            continue
            
    # Append the last neighbor
    if current and "local_port" in current:
        neighbors.append(current)
        
    return neighbors

def parse_lldp_neighbors_detail(output):
    """
    Parses 'show lldp neighbors detail' output.
    Returns list of neighbor dicts:
    {"local_port": ..., "remote_device": ..., "remote_port": ..., "remote_ip": ..., "platform": ...}
    """
    neighbors = []
    current = {}
    
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # LLDP Block start differs between IOS/NX-OS and XR
        # IOS/NX-OS: "Chassis id: ..." or "Local Interface: ..."
        # Let's check for Local Interface as block start
        local_int_match = re.match(r'^Local\s+Interface:\s*(\S+)', line, re.IGNORECASE)
        if local_int_match:
            if current and "local_port" in current:
                neighbors.append(current)
            current = {
                "local_port": local_int_match.group(1),
                "remote_device": "",
                "remote_port": "",
                "remote_ip": "",
                "platform": ""
            }
            continue
            
        if not current:
            # Maybe XR style: it lists neighbors in tables or different blocks
            # Let's handle XR lldp block
            # Device ID: ..., Local Interface: ...
            xr_dev_match = re.match(r'^System\s+Name:\s*(\S+)', line, re.IGNORECASE)
            if xr_dev_match:
                current = {
                    "local_port": "",
                    "remote_device": xr_dev_match.group(1).split('.')[0],
                    "remote_port": "",
                    "remote_ip": "",
                    "platform": ""
                }
            continue
            
        # System Name (Remote Device)
        sys_name_match = re.match(r'^System\s+Name:\s*(\S+)', line, re.IGNORECASE)
        if sys_name_match:
            current["remote_device"] = sys_name_match.group(1).split('.')[0]
            continue
            
        # Port id (Remote Port)
        port_id_match = re.match(r'^Port\s+id:\s*(\S+)', line, re.IGNORECASE)
        if port_id_match:
            current["remote_port"] = port_id_match.group(1)
            continue
            
        # IP Address / Management Address
        # "IP: 10.1.1.2" or "IPv4 Address: 10.1.1.2" or under Management Addresses:
        ip_match = re.match(r'^(?:IPv4\s+)?Address:\s*([0-9.]+)', line, re.IGNORECASE)
        if not ip_match:
            ip_match = re.match(r'^IP:\s*([0-9.]+)', line, re.IGNORECASE)
        if ip_match:
            current["remote_ip"] = ip_match.group(1)
            continue
            
        # System Description (can contain platform)
        sys_desc_match = re.match(r'^System\s+Description:\s*(.+)', line, re.IGNORECASE)
        if sys_desc_match:
            desc = sys_desc_match.group(1)
            # Try to extract platform from description
            platform_match = re.search(r'(cisco\s+\S+|WS-\S+)', desc, re.IGNORECASE)
            if platform_match:
                current["platform"] = platform_match.group(1)
            continue
            
    if current and "local_port" in current:
        neighbors.append(current)
        
    return neighbors

def parse_spanning_tree(output, os_type):
    """
    Parses 'show spanning-tree' or 'show spanning-tree summary'.
    Returns a dict with:
    {"enabled": True/False, "root_bridge": "Hostname/MAC of Root", "is_root": True/False, "vlans": {...}}
    where vlans is mapping VLAN_ID -> {"role": ..., "status": ...} for interfaces
    """
    data = {
        "enabled": False,
        "root_bridge": "",
        "is_root": False,
        "vlans": {}
    }
    
    if not output or "Spanning tree enabled protocol" not in output:
        # If it doesn't run STP (like IOS-XR or disabled)
        if "Spanning tree" in output or "MST" in output:
            data["enabled"] = True
        return data
        
    data["enabled"] = True
    
    # Check if this switch is root
    # "This bridge is the root"
    if "This bridge is the root" in output:
        data["is_root"] = True
        
    # Root bridge MAC
    # "Root ID    Priority    32769\n             Address     0011.2233.4455"
    root_mac_match = re.search(r'Root\s+ID.*?Address\s+([0-9a-fA-F.]+)', output, re.DOTALL | re.IGNORECASE)
    if root_mac_match:
        data["root_bridge"] = root_mac_match.group(1).replace('.', '')
        
    # Parse interfaces and their STP states
    # Interface           Role Sts Cost      Prio.Nbr Type
    # ------------------- ---- --- --------- -------- --------------------------------
    # Gi1/0/1             Desg FWD 4         128.1    P2p
    # Gi1/0/2             Altn BLK 4         128.2    P2p
    lines = output.splitlines()
    current_vlan = "1"
    
    for line in lines:
        vlan_match = re.search(r'VLAN(\d+)', line, re.IGNORECASE)
        if vlan_match:
            current_vlan = vlan_match.group(1)
            if current_vlan not in data["vlans"]:
                data["vlans"][current_vlan] = {}
            continue
            
        # Parse port state
        port_match = re.match(r'^([A-Za-z0-9/.-]+)\s+(Root|Desg|Altn|Back)\s+(FWD|BLK|LRN|LIS|DSB)\s+(\d+)', line.strip())
        if port_match:
            port = port_match.group(1)
            role = port_match.group(2)
            state = port_match.group(3)
            if current_vlan not in data["vlans"]:
                data["vlans"][current_vlan] = {}
            data["vlans"][current_vlan][port] = {
                "role": role,
                "state": state
            }
            
    return data

def parse_show_ip_route(output, os_type):
    """
    Parses routing table.
    Returns list of dicts: {"subnet": ..., "protocol": ..., "next_hop": ..., "interface": ...}
    """
    routes = []
    lines = output.splitlines()
    
    # We look for lines containing subnets and gateways
    # IOS: "D    192.168.10.0/24 [90/156160] via 10.1.1.2, 00:02:15, GigabitEthernet1/0/24"
    # IOS: "C    192.168.1.0/24 is directly connected, Vlan1"
    # XR:  "D    192.168.10.0/24 [90/156160] via 10.1.1.2, 00:02:15, GigabitEthernet0/0/0/1"
    
    # Simple regexes to catch connected and routed networks
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Connected route
        conn_match = re.match(r'^([C|L])\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+is\s+directly\s+connected,\s*(\S+)', line)
        if conn_match:
            routes.append({
                "subnet": conn_match.group(2),
                "protocol": "Connected" if conn_match.group(1) == 'C' else "Local",
                "next_hop": "Directly Connected",
                "interface": conn_match.group(3)
            })
            continue
            
        # Routed via gateway
        route_match = re.match(r'^([O|D|B|R|S|*])\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+\[\d+/\d+\]\s+via\s+([0-9.]+)(?:,\s*(\S+))?', line)
        if route_match:
            proto_map = {'O': 'OSPF', 'D': 'EIGRP', 'B': 'BGP', 'R': 'RIP', 'S': 'Static', '*': 'Default'}
            routes.append({
                "subnet": route_match.group(2),
                "protocol": proto_map.get(route_match.group(1), "Other"),
                "next_hop": route_match.group(3),
                "interface": route_match.group(4) if route_match.group(4) else ""
            })
            continue
            
        # NX-OS or slightly different IOS formats:
        # "192.168.1.0/24, ubest/mbest: 1/0, attached"
        # "* via 10.1.1.2, Eth1/1, [1/0]"
        nx_conn_match = re.match(r'^(\d+\.\d+\.\d+\.\d+/\d+),\s*ubest/mbest', line)
        if nx_conn_match:
            # Next line usually has details. For simplicity, we parse basic subnets
            routes.append({
                "subnet": nx_conn_match.group(1),
                "protocol": "RoutingEntry",
                "next_hop": "Unknown",
                "interface": ""
            })
            
    return routes

def parse_services(running_config):
    """
    Parses running config to extract Layer 4-7 services configuration.
    Returns dict:
    {"dns_servers": [...], "ntp_servers": [...], "radius_servers": [...], "tacacs_servers": [...]}
    """
    services = {
        "dns_servers": [],
        "ntp_servers": [],
        "radius_servers": [],
        "tacacs_servers": []
    }
    
    lines = running_config.splitlines()
    for line in lines:
        line = line.strip()
        
        # DNS Name Servers
        # "ip name-server 8.8.8.8 8.8.4.4"
        dns_match = re.match(r'^ip\s+name-server\s+(.+)$', line)
        if dns_match:
            servers = dns_match.group(1).split()
            services["dns_servers"].extend([s for s in servers if re.match(r'^[0-9.]+$', s)])
            
        # NTP Servers
        # "ntp server 10.1.1.100"
        ntp_match = re.match(r'^ntp\s+server\s+(\S+)', line)
        if ntp_match:
            services["ntp_servers"].append(ntp_match.group(1))
            
        # RADIUS Servers
        # "radius-server host 10.1.1.50"
        # "radius server Group1..."
        rad_match = re.search(r'radius-server\s+host\s+(\S+)', line)
        if not rad_match:
            rad_match = re.search(r'radius\s+server\s+host\s+(\S+)', line)
        if rad_match:
            services["radius_servers"].append(rad_match.group(1))
            
        # TACACS Servers
        tac_match = re.search(r'tacacs-server\s+host\s+(\S+)', line)
        if not tac_match:
            tac_match = re.search(r'tacacs\s+server\s+host\s+(\S+)', line)
        if tac_match:
            services["tacacs_servers"].append(tac_match.group(1))
            
    # De-duplicate
    for key in services:
        services[key] = list(set(services[key]))
        
    return services
