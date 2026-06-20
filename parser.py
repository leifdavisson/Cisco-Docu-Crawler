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

try:
    from netmiko.utilities import get_structured_data
except ImportError:
    get_structured_data = None

def clean_cli_output(output):
    """
    Cleans up terminal escape sequences, backspaces, paging markers (--More--),
    and paging prompt lines from the raw output.
    """
    if not output:
        return ""
    # Strip backspaces and carriage returns that overwrite text
    output = re.sub(r'.\x08', '', output)  # Remove backspaced characters
    output = re.sub(r'[\b]', '', output)
    
    # Strip common paging prompts
    output = re.sub(r'.*--\s*[Mm]ore\s*--.*', '', output, flags=re.IGNORECASE)
    output = re.sub(r'.*-\s*[Mm]ore\s*-.*', '', output, flags=re.IGNORECASE)
    
    # Remove terminal escape codes (ANSI sequences)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    output = ansi_escape.sub('', output)
    
    return output

def parse_show_version(output, os_type):
    """
    Parses 'show version' output.
    Returns a dict with: hostname, firmware, model, serial
    """
    output = clean_cli_output(output)
    
    data = {
        "hostname": "",
        "firmware": "",
        "model": "",
        "serial": ""
    }
    
    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data("show version", output, platform=os_type)
            if isinstance(structured, list) and len(structured) > 0:
                entry = structured[0]
                fw = entry.get("VERSION") or entry.get("os") or entry.get("software_image") or entry.get("version") or ""
                hn = entry.get("HOSTNAME") or entry.get("device_name") or entry.get("hostname") or ""
                
                model = entry.get("HARDWARE") or entry.get("platform") or entry.get("model") or ""
                if isinstance(model, list) and len(model) > 0:
                    model = model[0]
                    
                serial = entry.get("SERIAL") or entry.get("serial_number") or entry.get("serial") or ""
                if isinstance(serial, list) and len(serial) > 0:
                    serial = serial[0]
                    
                if fw:
                    data["firmware"] = str(fw).strip()
                if hn:
                    data["hostname"] = str(hn).strip()
                if model:
                    data["model"] = str(model).strip()
                if serial:
                    data["serial"] = str(serial).strip()
                    
                if data["firmware"] or data["hostname"] or data["model"] or data["serial"]:
                    return data
        except Exception:
            pass

    # Regex Fallback
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
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data("show inventory", output, platform="cisco_ios")
            if isinstance(structured, list):
                items = []
                for entry in structured:
                    items.append({
                        "name": str(entry.get("NAME") or entry.get("name") or "").strip(),
                        "descr": str(entry.get("DESCR") or entry.get("descr") or "").strip(),
                        "pid": str(entry.get("PID") or entry.get("pid") or "").strip(),
                        "sn": str(entry.get("SN") or entry.get("sn") or "").strip()
                    })
                if items:
                    return items
        except Exception:
            pass

    # Regex Fallback
    items = []
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
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            cmd = "show ipv4 interface brief" if os_type == "cisco_xr" else "show ip interface brief"
            structured = get_structured_data(cmd, output, platform=os_type)
            if isinstance(structured, list):
                interfaces = []
                for entry in structured:
                    intf = entry.get("INTERFACE") or entry.get("interface") or ""
                    ip = entry.get("IPADDR") or entry.get("ip_address") or ""
                    status = entry.get("STATUS") or entry.get("status") or ""
                    proto = entry.get("PROTO") or entry.get("PROTOCOL") or entry.get("protocol") or ""
                    if intf:
                        interfaces.append({
                            "interface": intf.strip(),
                            "ip_address": ip.strip(),
                            "status": status.strip().lower(),
                            "protocol": proto.strip().lower()
                        })
                if interfaces:
                    return interfaces
        except Exception:
            pass

    # Regex Fallback
    interfaces = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or "Interface" in line or "IP-Address" in line or "OK?" in line:
            continue
        parts = line.split()
        if len(parts) >= 4:
            interface = parts[0]
            ip_addr = parts[1]
            if os_type == "cisco_xr":
                status = parts[2]
                protocol = parts[3]
            else:
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
    output = clean_cli_output(output)
    
    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data("show interface status", output, platform="cisco_ios")
            if isinstance(structured, list):
                ports = []
                for entry in structured:
                    port = entry.get("PORT") or entry.get("port") or ""
                    if port:
                        ports.append({
                            "port": port.strip(),
                            "name": str(entry.get("NAME") or entry.get("name") or "").strip(),
                            "status": str(entry.get("STATUS") or entry.get("status") or "").strip(),
                            "vlan": str(entry.get("VLAN") or entry.get("vlan") or "").strip(),
                            "duplex": str(entry.get("DUPLEX") or entry.get("duplex") or "").strip(),
                            "speed": str(entry.get("SPEED") or entry.get("speed") or "").strip(),
                            "type": str(entry.get("TYPE") or entry.get("type") or "").strip()
                        })
                if ports:
                    return ports
        except Exception:
            pass

    # Regex Fallback
    ports = []
    lines = output.splitlines()
    header_found = False
    for line in lines:
        if "Port" in line and "Status" in line:
            header_found = True
            continue
        if not header_found or not line.strip() or line.startswith("---") or line.startswith("Port"):
            continue
        
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
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data("show interfaces", output, platform=os_type)
            if isinstance(structured, list):
                interfaces = {}
                for entry in structured:
                    intf = entry.get("INTERFACE") or entry.get("interface") or ""
                    if not intf:
                        continue
                    
                    # Address matches MAC
                    mac = entry.get("ADDRESS") or entry.get("mac_address") or entry.get("mac") or ""
                    mac = mac.replace('-', '').replace('.', '').replace(':', '')
                    
                    speed = entry.get("SPEED") or entry.get("speed") or ""
                    duplex = entry.get("DUPLEX") or entry.get("duplex") or ""
                    desc = entry.get("DESCRIPTION") or entry.get("description") or ""
                    
                    try:
                        input_err = int(entry.get("INPUT_ERRORS") or entry.get("input_errors") or 0)
                    except ValueError:
                        input_err = 0
                        
                    try:
                        crc = int(entry.get("CRC") or entry.get("crc") or 0)
                    except ValueError:
                        crc = 0
                        
                    try:
                        output_err = int(entry.get("OUTPUT_ERRORS") or entry.get("output_errors") or 0)
                    except ValueError:
                        output_err = 0
                        
                    interfaces[intf] = {
                        "status": entry.get("LINK_STATUS") or entry.get("status") or "down",
                        "mac_address": mac,
                        "speed": speed,
                        "duplex": duplex,
                        "input_errors": input_err,
                        "crc": crc,
                        "output_errors": output_err,
                        "description": desc
                    }
                if interfaces:
                    return interfaces
        except Exception:
            pass

    # Regex Fallback
    interfaces = {}
    current_int = None
    
    lines = output.splitlines()
    for line in lines:
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
            
        desc_match = re.search(r'[Dd]escription:\s*(.+)$', line)
        if desc_match:
            interfaces[current_int]["description"] = desc_match.group(1).strip()
            
        mac_match = re.search(r'address\s*(?:is|:)\s*([0-9a-fA-F.-]+)', line)
        if mac_match:
            interfaces[current_int]["mac_address"] = mac_match.group(1).replace('-', '').replace('.', '').replace(':', '')
            
        sd_match = re.search(r'(\S+-duplex),\s*(\S+b/s|\S+bps|Auto-speed)', line, re.IGNORECASE)
        if sd_match:
            interfaces[current_int]["duplex"] = sd_match.group(1).strip()
            interfaces[current_int]["speed"] = sd_match.group(2).strip()
            
        ie_match = re.search(r'(\d+)\s+input\s+errors,\s*(\d+)\s+CRC', line)
        if ie_match:
            interfaces[current_int]["input_errors"] = int(ie_match.group(1))
            interfaces[current_int]["crc"] = int(ie_match.group(2))
            
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
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data("show cdp neighbors detail", output, platform="cisco_ios")
            if isinstance(structured, list):
                neighbors = []
                for entry in structured:
                    local_port = entry.get("LOCAL_PORT") or entry.get("local_port") or ""
                    dest_host = entry.get("DESTINATION_HOST") or entry.get("destination_host") or entry.get("device_id") or ""
                    remote_port = entry.get("REMOTE_PORT") or entry.get("remote_port") or entry.get("port_id") or ""
                    remote_ip = entry.get("MANAGEMENT_IP") or entry.get("management_ip") or entry.get("entry_address") or ""
                    platform = entry.get("PLATFORM") or entry.get("platform") or ""
                    
                    if local_port:
                        neighbors.append({
                            "remote_device": dest_host.split('.')[0],
                            "remote_ip": remote_ip,
                            "local_port": local_port,
                            "remote_port": remote_port,
                            "platform": platform
                        })
                if neighbors:
                    return neighbors
        except Exception:
            pass

    # Regex Fallback
    neighbors = []
    current = {}
    
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        device_match = re.match(r'^Device ID:\s*(\S+)', line)
        if device_match:
            if current and "local_port" in current:
                neighbors.append(current)
            current = {
                "remote_device": device_match.group(1).split('.')[0],
                "remote_ip": "",
                "local_port": "",
                "remote_port": "",
                "platform": ""
            }
            continue
            
        if not current:
            continue
            
        ip_match = re.search(r'IP\s+address:\s*([0-9.]+)', line)
        if ip_match:
            current["remote_ip"] = ip_match.group(1)
            continue
        ipv4_match = re.search(r'IPv4\s+Address:\s*([0-9.]+)', line)
        if ipv4_match:
            current["remote_ip"] = ipv4_match.group(1)
            continue
            
        plat_match = re.search(r'Platform:\s*([^,]+)', line)
        if plat_match:
            current["platform"] = plat_match.group(1).strip()
            continue
            
        ports_match = re.search(r'Interface:\s*([^,]+),\s*Port\s+ID\s+\(outgoing\s+port\):\s*(\S+)', line, re.IGNORECASE)
        if ports_match:
            current["local_port"] = ports_match.group(1).strip()
            current["remote_port"] = ports_match.group(2).strip()
            continue
            
    if current and "local_port" in current:
        neighbors.append(current)
        
    return neighbors

def parse_lldp_neighbors_detail(output):
    """
    Parses 'show lldp neighbors detail' output.
    Returns list of neighbor dicts:
    {"local_port": ..., "remote_device": ..., "remote_port": ..., "remote_ip": ..., "platform": ...}
    """
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data("show lldp neighbors detail", output, platform="cisco_ios")
            if isinstance(structured, list):
                neighbors = []
                for entry in structured:
                    local_port = entry.get("LOCAL_INTERFACE") or entry.get("local_port") or ""
                    sys_name = entry.get("SYSTEM_NAME") or entry.get("neighbor") or entry.get("device_id") or ""
                    remote_port = entry.get("NEIGHBOR_PORT") or entry.get("port_id") or ""
                    remote_ip = entry.get("MANAGEMENT_ADDRESS") or entry.get("management_ip") or ""
                    desc = entry.get("SYSTEM_DESCRIPTION") or entry.get("platform") or ""
                    
                    platform = ""
                    platform_match = re.search(r'(cisco\s+\S+|WS-\S+)', desc, re.IGNORECASE)
                    if platform_match:
                        platform = platform_match.group(1)
                        
                    if local_port:
                        neighbors.append({
                            "local_port": local_port,
                            "remote_device": sys_name.split('.')[0],
                            "remote_port": remote_port,
                            "remote_ip": remote_ip,
                            "platform": platform
                        })
                if neighbors:
                    return neighbors
        except Exception:
            pass

    # Regex Fallback
    neighbors = []
    current = {}
    
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
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
            
        sys_name_match = re.match(r'^System\s+Name:\s*(\S+)', line, re.IGNORECASE)
        if sys_name_match:
            current["remote_device"] = sys_name_match.group(1).split('.')[0]
            continue
            
        port_id_match = re.match(r'^Port\s+id:\s*(\S+)', line, re.IGNORECASE)
        if port_id_match:
            current["remote_port"] = port_id_match.group(1)
            continue
            
        ip_match = re.match(r'^(?:IPv4\s+)?Address:\s*([0-9.]+)', line, re.IGNORECASE)
        if not ip_match:
            ip_match = re.match(r'^IP:\s*([0-9.]+)', line, re.IGNORECASE)
        if ip_match:
            current["remote_ip"] = ip_match.group(1)
            continue
            
        sys_desc_match = re.match(r'^System\s+Description:\s*(.+)', line, re.IGNORECASE)
        if sys_desc_match:
            desc = sys_desc_match.group(1)
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
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data("show spanning-tree", output, platform=os_type)
            if isinstance(structured, list):
                data = {
                    "enabled": True,
                    "root_bridge": "",
                    "is_root": False,
                    "vlans": {}
                }
                for entry in structured:
                    vlan_id = entry.get("VLAN_ID") or entry.get("vlan") or "1"
                    if vlan_id not in data["vlans"]:
                        data["vlans"][vlan_id] = {}
                        
                    root_mac = entry.get("ROOT_BRIDGE") or entry.get("root_mac") or ""
                    if root_mac:
                        data["root_bridge"] = root_mac.replace('.', '').replace(':', '')
                        
                    port = entry.get("INTERFACE") or entry.get("interface") or ""
                    role = entry.get("ROLE") or entry.get("role") or ""
                    state = entry.get("STATUS") or entry.get("state") or ""
                    
                    if port:
                        data["vlans"][vlan_id][port] = {
                            "role": role,
                            "state": state
                        }
                output_lower = output.lower()
                if "this bridge is the root" in output_lower or "we are the root" in output_lower:
                    data["is_root"] = True
                if data["vlans"]:
                    return data
        except Exception:
            pass

    # Regex Fallback
    data = {
        "enabled": False,
        "root_bridge": "",
        "is_root": False,
        "vlans": {}
    }
    
    if not output:
        return data
        
    output_lower = output.lower()
    if "spanning-tree" in output_lower or "spanning tree" in output_lower or "mst" in output_lower:
        data["enabled"] = True
        
    if not data["enabled"]:
        return data
        
    if "this bridge is the root" in output_lower or "we are the root" in output_lower:
        data["is_root"] = True
        
    root_mac_match = re.search(r'Root\s+ID.*?Address\s+([0-9a-fA-F.]+)', output, re.DOTALL | re.IGNORECASE)
    if root_mac_match:
        data["root_bridge"] = root_mac_match.group(1).replace('.', '')
        
    lines = output.splitlines()
    current_vlan = "1"
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue
            
        vlan_match = re.search(r'^(?:vlan|mst)\s*(\d+)\b', line_stripped, re.IGNORECASE)
        if vlan_match:
            current_vlan = vlan_match.group(1)
            if current_vlan not in data["vlans"]:
                data["vlans"][current_vlan] = {}
            continue
            
        # 1. Detailed/Router format: " Port 2 (FastEthernet1) of VLAN1 is forwarding"
        det_match = re.search(r'Port\s+\d+\s+\(([^)]+)\)\s+of\s+VLAN\s*(\d+)\s+is\s+(\w+)', line_stripped, re.IGNORECASE)
        if det_match:
            port = det_match.group(1)
            vlan_id = det_match.group(2)
            state_str = det_match.group(3).lower()
            
            state = "FWD"
            if "forward" in state_str:
                state = "FWD"
            elif "block" in state_str:
                state = "BLK"
            elif "learn" in state_str:
                state = "LRN"
            elif "listen" in state_str:
                state = "LIS"
            elif "disable" in state_str:
                state = "DSB"
                
            role = "Desg"
            if vlan_id not in data["vlans"]:
                data["vlans"][vlan_id] = {}
            data["vlans"][vlan_id][port] = {
                "role": role,
                "state": state
            }
            continue
            
        # 2. Tabular format
        port_match = re.match(r'^([A-Za-z0-9/.-]+)\s+(Root|Desg|Altn|Back)\s+(FWD|BLK|LRN|LIS|DSB)\s+(\d+)', line_stripped)
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
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            cmd = "show route" if os_type == "cisco_xr" else "show ip route"
            structured = get_structured_data(cmd, output, platform=os_type)
            if isinstance(structured, list):
                routes = []
                for entry in structured:
                    network = entry.get("NETWORK") or ""
                    mask = entry.get("NETMASK") or entry.get("mask") or ""
                    prefix = network
                    if mask and "/" not in prefix:
                        prefix = f"{network}/{mask}"
                    
                    proto = entry.get("PROTOCOL") or entry.get("protocol") or ""
                    nexthop = entry.get("NEXTHOP_IP") or entry.get("nexthop") or ""
                    interface = entry.get("NEXTHOP_IF") or entry.get("interface") or ""
                    
                    if prefix:
                        routes.append({
                            "subnet": prefix,
                            "protocol": proto,
                            "next_hop": nexthop or "Directly Connected",
                            "interface": interface
                        })
                if routes:
                    return routes
        except Exception:
            pass

    # Regex Fallback
    routes = []
    lines = output.splitlines()
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        conn_match = re.match(r'^([C|L])\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+is\s+directly\s+connected,\s*(\S+)', line)
        if conn_match:
            routes.append({
                "subnet": conn_match.group(2),
                "protocol": "Connected" if conn_match.group(1) == 'C' else "Local",
                "next_hop": "Directly Connected",
                "interface": conn_match.group(3)
            })
            continue
            
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
            
        nx_conn_match = re.match(r'^(\d+\.\d+\.\d+\.\d+/\d+),\s*ubest/mbest', line)
        if nx_conn_match:
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
        
        dns_match = re.match(r'^ip\s+name-server\s+(.+)$', line)
        if dns_match:
            servers = dns_match.group(1).split()
            services["dns_servers"].extend([s for s in servers if re.match(r'^[0-9.]+$', s)])
            
        ntp_match = re.match(r'^ntp\s+server\s+(\S+)', line)
        if ntp_match:
            services["ntp_servers"].append(ntp_match.group(1))
            
        rad_match = re.search(r'radius-server\s+host\s+(\S+)', line)
        if not rad_match:
            rad_match = re.search(r'radius\s+server\s+host\s+(\S+)', line)
        if rad_match:
            services["radius_servers"].append(rad_match.group(1))
            
        tac_match = re.search(r'tacacs-server\s+host\s+(\S+)', line)
        if not tac_match:
            tac_match = re.search(r'tacacs\s+server\s+host\s+(\S+)', line)
        if tac_match:
            services["tacacs_servers"].append(tac_match.group(1))
            
    for key in services:
        services[key] = list(set(services[key]))
        
    return services
