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

import csv
import os
import json
import re
from netaddr import IPNetwork, IPSet

def normalize_interface_name(name):
    if not name:
        return ""
    name = name.lower().strip()
    replacements = {
        "gigabitethernet": "gi",
        "tengigabitethernet": "te",
        "fastethernet": "fa",
        "ethernet": "et",
        "fortygigabitethernet": "fo",
        "hundredgige": "hu",
        "hundredgigabitethernet": "hu",
        "fivegigabitethernet": "fi",
        "twopointfivegigabitethernet": "tw",
        "port-channel": "po",
        "bundle-ether": "be"
    }
    for full, short in replacements.items():
        if name.startswith(full):
            return name.replace(full, short)
    return name

def get_link_speed(local_port, interfaces_detail):
    norm_local = normalize_interface_name(local_port)
    
    # 1. Try to find in interfaces_detail
    for name, stats in interfaces_detail.items():
        if normalize_interface_name(name) == norm_local:
            speed_str = stats.get("speed", "").lower()
            if speed_str:
                if "100g" in speed_str or "100000" in speed_str:
                    return "100G"
                elif "40g" in speed_str or "40000" in speed_str:
                    return "40G"
                elif "10g" in speed_str or "10000" in speed_str:
                    return "10G"
                elif "5g" in speed_str or "5000" in speed_str:
                    return "5G"
                elif "2.5g" in speed_str or "2500" in speed_str:
                    return "2.5G"
                elif "1000m" in speed_str or "1g" in speed_str or "1000" in speed_str:
                    return "1G"
                elif "100m" in speed_str or "100" in speed_str:
                    return "100M"
                elif "10m" in speed_str or "10" in speed_str:
                    return "10M"
    
    # 2. Fallback to guessing from interface name
    if "hu" in norm_local or "hundred" in norm_local:
        return "100G"
    elif "fo" in norm_local or "forty" in norm_local:
        return "40G"
    elif "te" in norm_local or "ten" in norm_local:
        return "10G"
    elif "fi" in norm_local or "five" in norm_local:
        return "5G"
    elif "tw" in norm_local or "twopointfive" in norm_local:
        return "2.5G"
    elif "gi" in norm_local or "gig" in norm_local:
        return "1G"
    elif "fa" in norm_local or "fast" in norm_local:
        return "100M"
    elif "et" in norm_local or "eth" in norm_local:
        return "10M"
        
    return "1G" # Default to 1G if unknown


def get_route_details(route):
    """
    Extracts subnet, protocol, next_hop, and interface from a route dict,
    handling different formats (e.g. parsed vs simulated).
    """
    # Subnet extraction
    subnet = route.get("subnet")
    if not subnet:
        network = route.get("network")
        mask = route.get("mask")
        if network:
            if mask:
                subnet = f"{network}/{mask}"
            else:
                subnet = network
        else:
            subnet = "Unknown"
            
    # Protocol extraction
    protocol = route.get("protocol", "Unknown")
    proto_map = {'C': 'Connected', 'L': 'Local', 'O': 'OSPF', 'D': 'EIGRP', 'B': 'BGP', 'R': 'RIP', 'S': 'Static', '*': 'Default'}
    if len(protocol) == 1 and protocol in proto_map:
        protocol = proto_map[protocol]
        
    # Next hop extraction
    next_hop = route.get("next_hop") or route.get("nexthop") or "Unknown"
    
    # Interface extraction
    interface = route.get("interface") or ""
    
    return {
        "subnet": subnet,
        "protocol": protocol,
        "next_hop": next_hop,
        "interface": interface
    }


def get_unique_devices(devices):
    """
    De-duplicates devices based on Serial Number (primary) and Hostname (fallback).
    If a device was discovered/crawled via multiple SVIs, it only keeps one primary instance.
    """
    if not devices:
        return {}
        
    unique_devices = {}
    seen_serials = set()
    seen_hostnames = set()
    
    # Sort IPs so that we prioritize:
    # 1. Successful crawls over failed ones
    # 2. SSH over Telnet
    # 3. Alphabetical/numerical ordering of IP for determinism
    def ip_sort_key_internal(ip):
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return [int(x) for x in ip.split('.')]
        return [0]
        
    sorted_ips = sorted(
        devices.keys(),
        key=lambda ip: (
            devices[ip].get("status") == "success",
            devices[ip].get("mgmt_method") == "SSH",
            ip_sort_key_internal(ip)
        ),
        reverse=True
    )
    
    duplicates_info = []
    
    for ip in sorted_ips:
        dev = devices[ip]
        serial = dev.get("serial")
        hostname = dev.get("hostname")
        
        is_duplicate = False
        duplicate_reason = ""
        
        # Check Serial number uniqueness
        if serial and serial != "Unknown" and serial.strip():
            serial_clean = serial.strip().upper()
            if serial_clean in seen_serials:
                is_duplicate = True
                duplicate_reason = f"duplicate serial {serial_clean}"
            else:
                seen_serials.add(serial_clean)
                
        # Check Hostname uniqueness as fallback
        if not is_duplicate and hostname and hostname != "Unknown" and hostname.strip():
            host_clean = hostname.strip().lower()
            if host_clean in seen_hostnames:
                is_duplicate = True
                duplicate_reason = f"duplicate hostname {host_clean}"
            else:
                seen_hostnames.add(host_clean)
                
        if not is_duplicate:
            unique_devices[ip] = dev
        else:
            duplicates_info.append(f"Discovered duplicate IP {ip} ({hostname}) via {duplicate_reason}. Excluding from deliverables.")
            
    if duplicates_info:
        print("\n--- Duplicate Device Detection (Multiple SVIs) ---")
        for info in duplicates_info:
            print(f"  [!] {info}")
        print(f"  [+] Retained {len(unique_devices)} unique physical devices out of {len(devices)} discovered SVI endpoints.\n")
        
    # Return unique devices sorted by IP for consistency
    def ip_sort_key(ip):
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return [int(x) for x in ip.split('.')]
        return [0]
    return {ip: unique_devices[ip] for ip in sorted(unique_devices.keys(), key=ip_sort_key)}


def generate_asset_inventory(devices, output_path="asset_inventory.csv"):
    """
    Generates the authoritative Asset Inventory CSV.
    Fields: Hostname, IP Address, MAC Address, Device Type, Model + Firmware, Serial Number, Role, Mgmt Method
    """
    fields = [
        "Hostname", 
        "IP Address", 
        "MAC Address", 
        "Device Type", 
        "Model", 
        "Firmware", 
        "Serial Number", 
        "Role", 
        "Management Method"
    ]
    
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ip, dev in devices.items():
                # Determine role based on model/hostname/LLDP neighbors
                role = "Access"
                model_lower = dev.get("model", "").lower()
                hostname_lower = dev.get("hostname", "").lower()
                
                if "core" in hostname_lower or "c9500" in model_lower or "4500" in model_lower:
                    role = "Core"
                elif "dist" in hostname_lower or "c3850" in model_lower or "c9300" in model_lower:
                    role = "Distribution"
                elif "edge" in hostname_lower or "asr" in model_lower or "isr" in model_lower:
                    role = "Edge/Router"
                
                # Determine device type
                dev_type = "Switch"
                if "asr" in model_lower or "isr" in model_lower or "router" in hostname_lower:
                    dev_type = "Router"
                elif "ap" in model_lower or "wlc" in model_lower:
                    dev_type = "Wireless AP/Controller"
                
                writer.writerow({
                    "Hostname": dev.get("hostname") or "Unknown",
                    "IP Address": ip,
                    "MAC Address": dev.get("mac_address") or "Unknown",
                    "Device Type": dev_type,
                    "Model": dev.get("model") or "Unknown",
                    "Firmware": dev.get("firmware") or "Unknown",
                    "Serial Number": dev.get("serial") or "Unknown",
                    "Role": role,
                    "Management Method": dev.get("mgmt_method") or "SSH"
                })
        print(f"Asset inventory successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating asset inventory CSV: {e}")

def generate_l2_diagram(devices, output_path="L2_network_diagrams.md"):
    """
    Generates the L2/Physical Network Diagram using Mermaid.js.
    Shows switch stacks, APs, uplinks, fiber paths, and STP states.
    """
    lines = [
        "# Layer 2 & Physical Network Diagrams",
        "",
        "This file contains physical topologies, switch-to-switch uplinks, and wireless AP connections discovered via CDP/LLDP and local port statuses.",
        "",
        "## Physical Connectivity Diagram",
        "```mermaid",
        "graph TD",
        "  %% Style configurations",
        "  classDef core fill:#3399ff,stroke:#0066cc,stroke-width:2px,color:#fff;",
        "  classDef dist fill:#85c1e9,stroke:#2e86c1,stroke-width:2px;",
        "  classDef access fill:#d5dbdb,stroke:#7f8c8d,stroke-width:1px;",
        "  classDef ap fill:#f9e79f,stroke:#f1c40f,stroke-width:1px;",
        "  classDef root fill:#2ecc71,stroke:#27ae60,stroke-width:3px,color:#fff;",
        ""
    ]
    
    # Track link duplicates: we only want to draw links once (e.g. A->B and B->A is one link)
    seen_links = set()
    link_idx = 0
    link_styles = []
    
    # Safe alphanumeric IDs mapping for L2 graph to avoid syntax errors with special characters
    node_ids = {}
    sw_counter = 0
    
    # Pre-populate IDs for all scanned devices
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        node_ids[hostname] = f"sw_{sw_counter}"
        sw_counter += 1
        
    # 1. Define nodes and their styles
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        model = dev.get("model") or "Unknown"
        is_root = dev.get("stp", {}).get("is_root", False)
        
        node_id = node_ids[hostname]
        # Node label with Model
        safe_hostname = hostname.replace('"', '\\"')
        safe_model = model.replace('"', '\\"')
        label = f'["{safe_hostname}<br/>({safe_model})"]'
        lines.append(f"  {node_id}{label}")
        
        # Apply classes
        model_lower = model.lower()
        hn_lower = hostname.lower()
        if is_root:
            lines.append(f"  class {node_id} root;")
        elif "core" in hn_lower or "c9500" in model_lower:
            lines.append(f"  class {node_id} core;")
        elif "dist" in hn_lower or "c3850" in model_lower or "c9300" in model_lower:
            lines.append(f"  class {node_id} dist;")
        else:
            lines.append(f"  class {node_id} access;")
            
    lines.append("")
    lines.append("  %% Topology links")
    
    # 2. Draw connections from neighbors
    connections = {}
    external_nodes_defined = set()
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        neighbors = dev.get("neighbors", [])
        
        # Parse channel groups from raw config
        channel_map = {}
        cfg = dev.get("raw_config", "")
        if cfg:
            blocks = cfg.split("interface ")
            for block in blocks[1:]:
                block_lines = block.splitlines()
                if not block_lines:
                    continue
                intf_name = block_lines[0].split()[0].strip()
                for bl in block_lines[1:]:
                    if bl.strip() == "!":
                        break
                    cg_match = re.search(r'channel-group\s+(\d+)', bl)
                    if cg_match:
                        channel_map[intf_name] = f"Po{cg_match.group(1)}"
                        break
                        
        for n in neighbors:
            remote_host = n.get("remote_device")
            if not remote_host:
                continue
            remote_host = remote_host.split('.')[0]
            
            matched_remote = None
            for rip, rdev in devices.items():
                rhn = rdev.get("hostname", "")
                if rhn and rhn.split('.')[0].lower() == remote_host.lower():
                    matched_remote = rhn
                    break
                    
            node_b = matched_remote or remote_host
            
            # Ensure safe ID exists for node_b
            if node_b not in node_ids:
                node_ids[node_b] = f"ext_{len(node_ids)}"
                
            node_a_id = node_ids[hostname]
            node_b_id = node_ids[node_b]
            
            # If external and not defined yet, define it
            if node_b not in devices and node_b not in external_nodes_defined:
                safe_nb = node_b.replace('"', '\\"')
                lines.append(f'  {node_b_id}["{safe_nb}"]')
                lines.append(f'  class {node_b_id} access;') # default class
                external_nodes_defined.add(node_b)
            
            # Sort names for link key to prevent duplicates
            if node_a_id < node_b_id:
                key = (node_a_id, node_b_id)
            else:
                key = (node_b_id, node_a_id)
                
            if key not in connections:
                connections[key] = []
                
            local_port = n.get("local_port", "")
            remote_port = n.get("remote_port", "")
            
            is_blocked = False
            stp_vlans = dev.get("stp", {}).get("vlans", {})
            for vlan_id, ports in stp_vlans.items():
                if local_port in ports and ports[local_port].get("state") == "BLK":
                    is_blocked = True
                    break
                    
            speed_val = get_link_speed(local_port, dev.get("interfaces_detail", {}))
            po_name = channel_map.get(local_port, "")
            
            connections[key].append({
                "local_port": local_port,
                "remote_port": remote_port,
                "is_blocked": is_blocked,
                "speed": speed_val,
                "port_channel": po_name
            })
            
    for (id_a, id_b), links in connections.items():
        # Determine stp status: blocked if any link in bundle is blocked
        is_blocked = any(lk["is_blocked"] for lk in links)
        
        # Sort and select speeds
        def speed_key(s):
            return {"100G": 8, "40G": 7, "10G": 6, "5G": 5, "2.5G": 4, "1G": 3, "100M": 2, "10M": 1}.get(s, 0)
        speeds = [lk["speed"] for lk in links]
        max_speed = max(speeds, key=speed_key) if speeds else "1G"
        
        thickness = {
            "10M": "1px",
            "100M": "2px",
            "1G": "3.5px",
            "2.5G": "5px",
            "5G": "6px",
            "10G": "7.5px",
            "40G": "9px",
            "100G": "11px"
        }.get(max_speed, "3.5px")
        
        # Build logical label for the connection
        pos = sorted(list(set([lk["port_channel"] for lk in links if lk["port_channel"]])))
        if pos:
            # Combined under port channel
            local_ports_str = ", ".join(sorted(list(set([lk["local_port"] for lk in links]))))
            label = f"{pos[0]} ({local_ports_str})"
        else:
            # Physical ports only
            label = ", ".join(sorted(list(set([lk["local_port"] for lk in links]))))
            
        clean_label = label.replace('"', '\\"')
        
        if is_blocked:
            # Dotted red line for blocked paths
            lines.append(f'  {id_a} -.->|"{clean_label}"| {id_b}')
            link_styles.append(f"  linkStyle {link_idx} stroke:#ff3333,stroke-width:{thickness},stroke-dasharray: 5 5;")
        else:
            # Thick line with port labels
            lines.append(f'  {id_a} ==>|"{clean_label}"| {id_b}')
            link_styles.append(f"  linkStyle {link_idx} stroke:#333,stroke-width:{thickness};")
            
        link_idx += 1

    # 3. Add link styles
    if link_styles:
        lines.append("")
        lines.append("  %% Link Styles (thickness based on link speed)")
        lines.extend(link_styles)
        
    lines.extend([
        "```",
        "",
        "### Legend",
        "* **Green Highlighted Node**: STP Root Bridge.",
        "* **Blue Node**: Core / Distribution switches.",
        "* **Grey Node**: Access switches.",
        "* **Dashed Red Lines**: STP Blocking (`BLK`) links.",
        "* **Double Solid Lines**: Active forwarding links (line thickness indicates speed).",
        "",

        "## Wireless Overlay Layout",
        "Discovered Wireless Access Points connected to switches:"
    ])
    
    # Extract AP neighbors
    ap_count = 0
    ap_table = ["| Switch Hostname | Local Port | AP Hostname/MAC | AP IP | AP Model |", "| --- | --- | --- | --- | --- |"]
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        for n in dev.get("neighbors", []):
            platform = n.get("platform", "").lower()
            if "ap" in platform or "air-" in platform or "access point" in platform:
                ap_count += 1
                ap_table.append(f"| {hostname} | {n.get('local_port')} | {n.get('remote_device')} | {n.get('remote_ip') or 'N/A'} | {n.get('platform')} |")
                
    if ap_count > 0:
        lines.append(f"\nTotal Discovered Access Points: **{ap_count}**\n")
        lines.extend(ap_table)
    else:
        lines.append("\nNo wireless access points were directly discovered via LLDP/CDP neighbor tables.")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"L2 Diagrams successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating L2 diagram file: {e}")

def generate_l3_diagram(devices, output_path="L3_network_diagrams.md"):
    """
    Generates L3 logical and routing topologies using Mermaid.js mindmap.
    Lists subnets, SVIs, VLANs, and VRFs.
    """
    # 1. Build adjacency list of the bipartite graph
    adj = {} # node -> set of neighbors
    subnets = set()
    device_nodes = set()
    subnet_vlan_names = {} # subnet_cidr -> set of vlan names
    
    # Pre-parse VLAN names for all devices
    device_vlan_maps = {}
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        vlan_names = {}
        if cfg:
            matches = re.finditer(r'^vlan\s+(\d+)\s*[\r\n]+(?:\s+name\s+(\S+))?', cfg, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                vlan_id = match.group(1)
                name = match.group(2)
                if name:
                    vlan_names[vlan_id] = name.strip()
        device_vlan_maps[hostname] = vlan_names

    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        device_nodes.add(hostname)
        if hostname not in adj:
            adj[hostname] = set()
            
        l3_ints = dev.get("l3_interfaces", [])
        vlan_names = device_vlan_maps.get(hostname, {})
        for intf in l3_ints:
            intf_ip = intf.get("ip_address")
            if not intf_ip or intf_ip in ["unassigned", "down", "up", "unset"]:
                continue
            
            # Simple assumption of subnet for SVI / routing interface
            clean_ip_base = ".".join(intf_ip.split('.')[:3]) + ".0/24"
            subnets.add(clean_ip_base)
            
            if clean_ip_base not in adj:
                adj[clean_ip_base] = set()
                
            adj[hostname].add(clean_ip_base)
            adj[clean_ip_base].add(hostname)
            
            # Extract VLAN ID to map name
            intf_name = intf.get("interface", "")
            vlan_match = re.search(r'(?:vlan|vl)\s*(\d+)', intf_name, re.IGNORECASE)
            if vlan_match:
                vlan_id = vlan_match.group(1)
                vname = vlan_names.get(vlan_id)
                if vname:
                    if clean_ip_base not in subnet_vlan_names:
                        subnet_vlan_names[clean_ip_base] = set()
                    subnet_vlan_names[clean_ip_base].add(vname)
            
    diagram_lines = []
    if not adj:
        diagram_lines.append("graph TD")
        diagram_lines.append("  root[\"No L3 Interfaces Discovered\"]")
    else:
        diagram_lines.append("graph TD")
        diagram_lines.append("  %% Style configurations")
        diagram_lines.append("  classDef device fill:#f5f5f5,stroke:#333,stroke-width:2px;")
        diagram_lines.append("  classDef subnet fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;")
        diagram_lines.append("")
        
        # Pre-populate safe IDs for all nodes
        node_ids = {}
        counter = 0
        for sub in sorted(list(subnets)):
            node_ids[sub] = f"sub_{counter}"
            counter += 1
        for dev in sorted(list(device_nodes)):
            node_ids[dev] = f"dev_{counter}"
            counter += 1
            
        # Define Subnets (stadium oval: ([...]))
        diagram_lines.append("  %% Subnets (Ovals)")
        for sub in sorted(list(subnets)):
            node_id = node_ids[sub]
            vnames = subnet_vlan_names.get(sub, set())
            vname_suffix = f" ({'/'.join(sorted(vnames))})" if vnames else ""
            label = f"{sub}{vname_suffix}"
            safe_label = label.replace('"', '\\"')
            diagram_lines.append(f'  {node_id}(["{safe_label}"])')
            diagram_lines.append(f'  class {node_id} subnet;')
            
        # Define Devices (square: [...])
        diagram_lines.append("\n  %% Devices (Squares)")
        for dev in sorted(list(device_nodes)):
            node_id = node_ids[dev]
            safe_dev = dev.replace('"', '\\"')
            diagram_lines.append(f'  {node_id}["{safe_dev}"]')
            diagram_lines.append(f'  class {node_id} device;')
            
        # Draw Links
        diagram_lines.append("\n  %% Connectivity Links")
        for dev in sorted(list(device_nodes)):
            dev_id = node_ids[dev]
            for sub in sorted(list(adj.get(dev, []))):
                sub_id = node_ids[sub]
                diagram_lines.append(f"  {dev_id} --- {sub_id}")

    lines = [
        "# Layer 3 & Logical Network Diagrams",
        "",
        "This file documents Layer 3 boundaries, Switch Virtual Interfaces (SVIs), VLAN maps, and routing domains/VRFs.",
        "",
        "## Logical Routing Boundary Diagram",
        "```mermaid",
        "\n".join(diagram_lines),
        "```",
        "",
        "## Authoritative VLAN, Subnet & SVI Map",
        "",
        "| Switch Hostname | Interface / VLAN | VLAN Name | Description | SVI IP Address | Subnet Range | Interface Status |",
        "| --- | --- | --- | --- | --- | --- | --- |"
    ]
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        l3_ints = dev.get("l3_interfaces", [])
        ints_detail = dev.get("interfaces_detail", {})
        for intf in l3_ints:
            intf_name = intf.get("interface")
            ip_addr = intf.get("ip_address")
            status = intf.get("status")
            
            # Match SVI name to interfaces_detail to get description
            desc = ""
            norm_name = normalize_interface_name(intf_name)
            for name, stats in ints_detail.items():
                if normalize_interface_name(name) == norm_name:
                    desc = stats.get("description", "")
                    break
                    
            # Get VLAN name
            vlan_name = "N/A"
            vlan_match = re.search(r'(?:vlan|vl)\s*(\d+)', intf_name, re.IGNORECASE)
            if vlan_match:
                vlan_id = vlan_match.group(1)
                vlan_name = device_vlan_maps.get(hostname, {}).get(vlan_id, "N/A")
                    
            subnet_range = '.'.join(ip_addr.split('.')[:3]) + '.0/24' if (ip_addr and '.' in ip_addr) else 'N/A'
            lines.append(f"| {hostname} | {intf_name} | {vlan_name} | {desc or 'N/A'} | {ip_addr} | {subnet_range} | {status} |")
            
    lines.extend([
        "",
        "## VRF Routing Instances & Boundaries",
        "Discovered VRF routing instances and their associated interfaces:"
    ])
    
    # Search running config for VRFs
    vrf_found = False
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        # Look for "vrf definition X" or "ip vrf X"
        vrfs = list(set(re.findall(r'(?:ip vrf|vrf definition)\s+(\S+)', cfg)))
        if vrfs:
            vrf_found = True
            lines.append(f"\n### {hostname} VRF Instances:")
            for vrf in vrfs:
                lines.append(f"* **VRF Name:** `{vrf}`")
                
    if not vrf_found:
        lines.append("\nNo virtual routing and forwarding (VRF) instances were detected in active device configurations (standard global table only).")
        
    # Complete Routing Tables
    lines.extend([
        "",
        "## Discovered Routing Tables",
        "The following table lists the active routing entries parsed from each device's routing table:"
    ])
    
    has_routes = False
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        routes = dev.get("routes", [])
        if routes:
            if not has_routes:
                lines.append("")
                lines.append("| Switch Hostname | Route Prefix / Subnet | Protocol | Next Hop IP | Outgoing Interface |")
                lines.append("| --- | --- | --- | --- | --- |")
                has_routes = True
            
            sorted_routes = []
            for r in routes:
                sorted_routes.append(get_route_details(r))
                
            def route_sort_key(rt):
                sub = rt["subnet"]
                if sub == "0.0.0.0/0" or sub.startswith("0.0.0.0"):
                    return (0, "")
                try:
                    ip_net = IPNetwork(sub)
                    return (1, ip_net)
                except Exception:
                    return (2, sub)
                    
            sorted_routes.sort(key=route_sort_key)
            
            for rt in sorted_routes:
                lines.append(f"| {hostname} | `{rt['subnet']}` | {rt['protocol']} | {rt['next_hop']} | {rt['interface'] or 'N/A'} |")
                
    if not has_routes:
        lines.append("\nNo routing table entries were parsed or simulated for the scanned devices.")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"L3 Diagrams successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating L3 diagram file: {e}")

def parse_interface_ips_from_config(raw_config):
    """
    Parses interface IP addresses and subnet masks from Cisco IOS/XE/XR running-config.
    Returns a dict mapping normalized interface name -> (ip_address, subnet_mask_or_prefix)
    """
    if not raw_config:
        return {}
    
    intf_ips = {}
    current_intf = None
    
    for line in raw_config.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
            
        # Match interface line
        intf_match = re.match(r'^interface\s+(\S+)', line_stripped, re.IGNORECASE)
        if intf_match:
            current_intf = normalize_interface_name(intf_match.group(1))
            continue
            
        if current_intf:
            # Check for end of interface block (e.g. '!' or exit)
            if line_stripped == '!' or line_stripped.lower().startswith('exit'):
                current_intf = None
                continue
                
            # Match ip address/ipv4 address
            ip_match = re.match(
                r'^(?:ipv4|ip)\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|/(\d+))',
                line_stripped,
                re.IGNORECASE
            )
            if ip_match:
                ip = ip_match.group(1)
                mask_or_prefix = ip_match.group(2) or ip_match.group(3)
                intf_ips[current_intf] = (ip, mask_or_prefix)
                
    return intf_ips

def generate_network_analysis_report(devices, output_path="network_analysis_report.md"):
    """
    Generates a structured Layer 1-7 network analysis report.
    Details cabling errors, speed mismatches, STP loop risks, subnets, and L4-L7 services.
    """
    lines = [
        "# Layered Network Analysis Report (OSI-Oriented)",
        "",
        "This report evaluates network behavior, health indicators, configuration consistency, and security gaps parsed from active switch running-states.",
        "",
        "## 1. Layer 1/2 (Physical & Data Link) Analysis",
        ""
    ]
    
    # A. Cabling & Speed Mismatches
    lines.append("### Cabling Issues & Speed/Duplex Mismatches")
    mismatches = []
    errors_found = []
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        ints_detail = dev.get("interfaces_detail", {})
        
        for name, stats in ints_detail.items():
            desc = stats.get("description", "")
            speed = stats.get("speed", "")
            duplex = stats.get("duplex", "")
            in_err = stats.get("input_errors", 0)
            crc = stats.get("crc", 0)
            out_err = stats.get("output_errors", 0)
            
            # Check half duplex (often a mismatch indicator on switchports)
            if duplex and "half" in duplex.lower():
                mismatches.append(f"* **{hostname}** Interface `{name}` (`{desc}`): Operating at **{duplex}** / **{speed}** (Potential mismatch).")
                
            # Speed constraints
            if speed and "10Mb/s" in speed:
                mismatches.append(f"* **{hostname}** Interface `{name}` (`{desc}`): Speed restricted to **10 Mbps**.")
                
            # Errors
            if in_err > 0 or crc > 0 or out_err > 0:
                desc_str = f" (`{desc}`)" if desc else ""
                errors_found.append(f"* **{hostname}** Interface `{name}`{desc_str}: Input Errors: `{in_err}`, CRCs: `{crc}`, Output Errors: `{out_err}`.")
                
    if mismatches:
        lines.extend(mismatches)
    else:
        lines.append("  * No active speed/duplex mismatches or half-duplex anomalies detected.")
        
    lines.append("\n### Interface Packet & CRC Errors")
    if errors_found:
        lines.extend(errors_found)
    else:
        lines.append("  * No packet errors or CRC checksum failures detected on active interfaces (clean physical paths).")
        
    # B. Port Utilization
    lines.append("\n### Interface Port Utilization Summary")
    lines.append("| Switch Hostname | Connected Ports | Total Ports | Utilization % |")
    lines.append("| --- | --- | --- | --- |")
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        ints_detail = dev.get("interfaces_detail", {})
        total = len(ints_detail)
        connected = 0
        for name, stats in ints_detail.items():
            if stats.get("status") == "up":
                connected += 1
                
        pct = (connected / total * 100) if total > 0 else 0
        lines.append(f"| {hostname} | {connected} | {total} | {pct:.1f}% |")
        
    # C. Spanning Tree State
    lines.append("\n### Loop Risks & Spanning Tree (STP) Audit")
    stp_issues = []
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        stp = dev.get("stp", {})
        
        if not stp.get("enabled"):
            stp_issues.append(f"* **{hostname}**: **Spanning Tree is DISABLED** (Extreme loop risk if redundant links exist).")
            continue
            
        # Count blocked interfaces
        blocked_ports = []
        for vlan_id, ports in stp.get("vlans", {}).items():
            for port_name, state_dict in ports.items():
                if state_dict.get("state") == "BLK":
                    blocked_ports.append(f"`{port_name}` (VLAN {vlan_id})")
                    
        if blocked_ports:
            lines.append(f"* **{hostname}**: Currently blocking loops on {len(set(blocked_ports))} ports: {', '.join(list(set(blocked_ports)))}")
            
    if stp_issues:
        lines.extend(stp_issues)
        
    # D. Interface Descriptions & Port Naming
    lines.append("\n### Configured Interface Descriptions & Port Naming")
    desc_found = False
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        ints_detail = dev.get("interfaces_detail", {})
        
        has_local_desc = False
        device_lines = []
        for name, stats in ints_detail.items():
            desc = stats.get("description", "")
            if desc:
                if not has_local_desc:
                    device_lines.append(f"\n#### {hostname} Port Naming Mappings:")
                    device_lines.append("| Port Interface | Speed | Status | Configured Description / Name |")
                    device_lines.append("| --- | --- | --- | --- |")
                    has_local_desc = True
                    desc_found = True
                status = stats.get("status", "unknown")
                speed = stats.get("speed", "unknown")
                device_lines.append(f"| `{name}` | {speed} | {status} | {desc} |")
                
        if has_local_desc:
            lines.extend(device_lines)
            
    if not desc_found:
        lines.append("  * No interface descriptions or port names were found configured on scanned devices.")
        
    # 2. Layer 3 (Routing) Analysis
    lines.extend([
        "",
        "## 2. Layer 3 (Routing) Analysis",
        ""
    ])
    
    # Subnet overlaps
    lines.append("### Overlapping Subnets & IP Space Conflicts")
    ip_subnets = []
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        raw_config = dev.get("raw_config", "")
        config_ips = parse_interface_ips_from_config(raw_config) if raw_config else {}
        
        l3_ints = dev.get("l3_interfaces", [])
        for intf in l3_ints:
            intf_name = intf.get("interface")
            intf_ip = intf.get("ip_address")
            if intf_ip and intf_ip not in ["unassigned", "down", "up", "unset"]:
                norm_name = normalize_interface_name(intf_name)
                ip_from_cfg, mask_from_cfg = config_ips.get(norm_name, (None, None))
                
                net = None
                if ip_from_cfg == intf_ip and mask_from_cfg:
                    try:
                        if '/' in mask_from_cfg or mask_from_cfg.isdigit():
                            net = IPNetwork(f"{intf_ip}/{mask_from_cfg}")
                        else:
                            net = IPNetwork(f"{intf_ip}/{mask_from_cfg}")
                    except Exception:
                        pass
                
                if net is None:
                    try:
                        # Guess /24 if not specified/parseable
                        net = IPNetwork(f"{intf_ip}/24")
                    except Exception:
                        pass
                        
                if net:
                    ip_subnets.append((hostname, intf_name, intf_ip, net))

    ip_conflicts = []
    subnet_overlaps = []
    
    # Compare each subnet for overlaps and IP conflicts
    for i in range(len(ip_subnets)):
        for j in range(i+1, len(ip_subnets)):
            h1, int1, ip1, net1 = ip_subnets[i]
            h2, int2, ip2, net2 = ip_subnets[j]
            
            if h1 == h2:
                continue
                
            # 1. Check exact IP conflict
            if ip1 == ip2:
                ip_conflicts.append((h1, int1, ip1, h2, int2, ip2))
            # 2. Check subnet address space overlaps using netaddr CIDR boundaries
            elif net1 in net2 or net2 in net1:
                subnet_overlaps.append((h1, int1, net1, h2, int2, net2))
                
    overlap_found = False
    
    if ip_conflicts:
        overlap_found = True
        lines.append("#### Critical IP Address Conflicts")
        for h1, int1, ip1, h2, int2, ip2 in ip_conflicts:
            lines.append(f"* **CRITICAL IP CONFLICT:** IP address `{ip1}` is configured on **{h1}** (`{int1}`) and **{h2}** (`{int2}`).")
        lines.append("")
        
    if subnet_overlaps:
        overlap_found = True
        lines.append("#### Subnet Address Space Overlaps")
        for h1, int1, net1, h2, int2, net2 in subnet_overlaps:
            if net1 == net2:
                lines.append(f"* **Overlap Warning:** Identical subnet range `{net1.network}/{net1.prefixlen}` configured on **{h1}** (`{int1}`) and **{h2}** (`{int2}`).")
            else:
                lines.append(f"* **Overlap Warning:** Overlapping subnets: `{net1}` on **{h1}** (`{int1}`) and `{net2}` on **{h2}** (`{int2}`).")
        lines.append("")
        
    if not overlap_found:
        lines.append("  * No overlapping subnets or IP address space collisions detected.")
        
    # Routing protocols
    lines.append("\n### Active Routing Protocols")
    routes_summary = {}
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        routes = dev.get("routes", [])
        protocols = list(set([get_route_details(r)["protocol"] for r in routes]))
        protocols = [p for p in protocols if p and p != "Unknown"]
        if protocols:
            routes_summary[hostname] = protocols
            
    if routes_summary:
        for host, protos in routes_summary.items():
            lines.append(f"* **{host}**: Running routing protocols: {', '.join(protos)}")
    else:
        lines.append("  * Devices are operating entirely on Static routing or directly connected Layer 3 boundaries.")
        
    # Complete Routing Tables
    lines.append("\n### Complete Routing Tables")
    has_routes_any = False
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        routes = dev.get("routes", [])
        if routes:
            has_routes_any = True
            lines.append(f"\n#### {hostname} Routing Table:")
            lines.append("| Route Prefix | Protocol | Next Hop / Gateway | Outgoing Interface |")
            lines.append("| --- | --- | --- | --- |")
            
            sorted_routes = []
            for r in routes:
                sorted_routes.append(get_route_details(r))
            
            def route_sort_key(rt):
                sub = rt["subnet"]
                if sub == "0.0.0.0/0" or sub.startswith("0.0.0.0"):
                    return (0, "")
                try:
                    ip_net = IPNetwork(sub)
                    return (1, ip_net)
                except Exception:
                    return (2, sub)
                    
            sorted_routes.sort(key=route_sort_key)
            
            for rt in sorted_routes:
                lines.append(f"| `{rt['subnet']}` | {rt['protocol']} | {rt['next_hop']} | {rt['interface'] or 'N/A'} |")
                
    if not has_routes_any:
        lines.append("  * No routing table entries were parsed or simulated for the scanned devices.")
        
    # 3. Layer 4-7 Services Analysis
    lines.extend([
        "",
        "## 3. Layer 4-7 (Services & Security) Analysis",
        ""
    ])
    
    lines.append("### Infrastructure Services Consistency (NTP, DNS, AAA)")
    lines.append("| Switch Hostname | DNS Servers | NTP Servers | RADIUS/TACACS Servers | Management Protocol |")
    lines.append("| --- | --- | --- | --- | --- |")
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        services = dev.get("services", {})
        dns = ", ".join(services.get("dns_servers", [])) or "None"
        ntp = ", ".join(services.get("ntp_servers", [])) or "None"
        aaa = []
        if services.get("radius_servers"):
            aaa.append(f"RADIUS({len(services['radius_servers'])})")
        if services.get("tacacs_servers"):
            aaa.append(f"TACACS({len(services['tacacs_servers'])})")
        aaa_str = ", ".join(aaa) or "None"
        mgmt = dev.get("mgmt_method", "SSH")
        
        lines.append(f"| {hostname} | {dns} | {ntp} | {aaa_str} | {mgmt} |")
        
    # Security/Visibility Gaps
    lines.append("\n### Visibility & Security Gaps")
    gaps = []
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        mgmt = dev.get("mgmt_method", "SSH")
        services = dev.get("services", {})
        
        if mgmt == "Telnet":
            gaps.append(f"* **{hostname}** is using unencrypted **Telnet** for management interface (Security risk).")
        if not services.get("ntp_servers"):
            gaps.append(f"* **{hostname}** has **no NTP servers** configured (Log timestamps may be out of sync).")
        if not services.get("dns_servers"):
            gaps.append(f"* **{hostname}** has **no DNS name-servers** configured (Unable to resolve hostnames).")
        if not services.get("radius_servers") and not services.get("tacacs_servers"):
            gaps.append(f"* **{hostname}** does not use central AAA authentication (Using local fallback users).")
            
    if gaps:
        lines.extend(gaps)
    else:
        lines.append("  * No primary visibility or security gaps found. Central AAA, NTP synchronization, and secure SSH management are properly configured.")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Network analysis report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating network analysis report: {e}")

def generate_best_practices_report(devices, output_path="Cisco Best Practices.md"):
    """
    Generates a Cisco Security and Compatibility Best Practices checklist report.
    Checks running configurations and state parameters against Cisco best practices
    and flags service-impacting remediations.
    """
    lines = [
        "# Cisco Switch Best Practices & Security Audit Report",
        "",
        "This report compares active switch configurations against Cisco Security Hardening and Compatibility Guidelines.",
        "",
        "### ⚠️ Critical Warning on Service Impact Levels",
        "* **Low Impact**: Configuration changes that do not affect active data traffic (e.g. disabling unused protocols).",
        "* **Medium Impact**: Admin session drops or localized traffic shifts (e.g. switching from Telnet to SSH, changing AAA).",
        "* **High / Service Disruptive**: Potential network-wide downtime, routing adjacency drops, or port closures (e.g. Port Security, Spanning Tree changes, LACP mode updates).",
        ""
    ]

    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        mgmt_method = dev.get("mgmt_method", "SSH")
        services = dev.get("services", {})
        
        # Audits
        # 1. SSH vs Telnet
        ssh_ok = (mgmt_method == "SSH")
        
        # 2. Central AAA
        aaa_ok = bool(services.get("radius_servers") or services.get("tacacs_servers"))
        
        # 3. SNMP v3
        snmp_v3 = False
        snmp_v1_2 = False
        if cfg:
            if re.search(r'snmp-server group|snmp-server user', cfg, re.IGNORECASE):
                snmp_v3 = True
            if re.search(r'snmp-server community', cfg, re.IGNORECASE):
                snmp_v1_2 = True
        snmp_ok = snmp_v3 and not snmp_v1_2
        
        # 4. DHCP Snooping
        dhcp_snoop = False
        if cfg and re.search(r'ip dhcp snooping(?!\s+information)', cfg, re.IGNORECASE):
            dhcp_snoop = True
            
        # 5. BPDU Guard
        bpdu_guard = False
        if cfg and re.search(r'bpduguard enable|bpduguard default', cfg, re.IGNORECASE):
            bpdu_guard = True
            
        # 6. Port Security
        port_sec = False
        if cfg and re.search(r'port-security', cfg, re.IGNORECASE):
            port_sec = True
            
        # 7. Static LACP ("mode on") loops
        lacp_static = False
        if cfg and re.search(r'channel-group\s+\d+\s+mode\s+on', cfg, re.IGNORECASE):
            lacp_static = True
            
        # 8. Control Plane Policing (CoPP)
        copp_ok = False
        if cfg and re.search(r'control-plane', cfg, re.IGNORECASE):
            copp_ok = True

        lines.extend([
            f"## Device: {hostname} ({ip})",
            "",
            "| Best Practice Rule | Current Status | Cisco Recommendation | Service Impact of Fix |",
            "| --- | --- | --- | --- |",
            f"| **Secure Management (SSH)** | {'[✓] Compliant' if ssh_ok else '[✗] Non-Compliant'} | Disable Telnet, use SSHv2 only | **Medium**: Will drop current active Telnet sessions. |",
            f"| **Centralized AAA** | {'[✓] Compliant' if aaa_ok else '[✗] Non-Compliant'} | Use RADIUS/TACACS+ instead of local users | **Medium**: Potential admin lockout if AAA servers are unreachable. |",
            f"| **Secure SNMP (v3)** | {'[✓] Compliant' if snmp_ok else '[✗] Non-Compliant'} | Disable SNMP v1/v2c, use encrypted SNMPv3 | **Low**: Requires NMS credential updates. |",
            f"| **DHCP Snooping** | {'[✓] Compliant' if dhcp_snoop else '[✗] Non-Compliant'} | Enable globally and trust uplinks to block rogue servers | **High**: Incorrect trust port configuration blocks valid DHCP leases. |",
            f"| **STP BPDU Guard** | {'[✓] Compliant' if bpdu_guard else '[✗] Non-Compliant'} | Enable on access-ports to shut down rogue switches | **High**: Shuts down ports if rogue STP packets are received. |",
            f"| **Port Security** | {'[✓] Compliant' if port_sec else '[✗] Non-Compliant'} | Limit MACs per access-port to block MAC flooding | **High**: Shuts down port if users connect unapproved hubs/switches. |",
            f"| **Static EtherChannel** | {'[✓] Compliant' if not lacp_static else '[✗] Non-Compliant'} | Avoid static 'mode on'; use dynamic LACP | **Service Disruptive**: Changing mode drops bundle interfaces; incorrect configuration creates loops. |",
            f"| **Control Plane Policing (CoPP)** | {'[✓] Compliant' if copp_ok else '[✗] Non-Compliant'} | Enable CoPP to protect CPU from Denial of Service | **Medium**: Can drop valid protocol packets if rate-limits are too strict. |",
            ""
        ])

    lines.extend([
        "## Detailed Remediation Guide & Risk Mitigations",
        "",
        "### 1. Static EtherChannel to LACP Active Mode",
        "* **Risk**: **Service Disruptive**",
        "* **Impact**: Changing a port-channel group configuration tears down the virtual interface. If traffic is flowing over the port-channel, a temporary outage occurs.",
        "* **Mitigation**: Perform during a maintenance window. Enable LACP on the remote end first (passive or active), then switch the local Cisco switch to `mode active`. Avoid using `mode on` (static) as it cannot detect cabling loops.",
        "",
        "### 2. DHCP Snooping & Dynamic ARP Inspection (DAI)",
        "* **Risk**: **High**",
        "* **Impact**: If you enable DHCP Snooping without marking the uplink ports to the DHCP server as `trusted`, the switch will discard all incoming DHCP Server packets, entirely blocking DHCP addressing.",
        "* **Mitigation**: Always configure interface trust states first: `ip dhcp snooping trust` on uplink interfaces BEFORE enabling DHCP snooping globally.",
        "",
        "### 3. Port Security & MAC Address Limits",
        "* **Risk**: **High**",
        "* **Impact**: If a user plugs in a small unmanaged desktop switch or a device changes its MAC address, the port is put into `err-disabled` (shut down), causing local user outages.",
        "* **Mitigation**: Set a reasonable MAC count limit (e.g. `switchport port-security maximum 3`) and configure violation mode to `restrict` instead of `shutdown` to alert syslog without disabling the interface.",
        "",
        "### 4. AAA Authentication (RADIUS/TACACS+)",
        "* **Risk**: **Medium**",
        "* **Impact**: If centralized servers are unreachable and no local fallback is configured, administrators will be completely locked out of the switch console.",
        "* **Mitigation**: Always ensure a local fallback is defined in the method list: `aaa authentication login default group tacacs+ local` and verify console fallback access before logging out."
    ])

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Best practices report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating best practices report: {e}")

def generate_cabling_matrix(devices, output_path="migration_cabling_matrix.csv"):
    """
    Generates the Physical & Cabling Patching Matrix (Cutover Sheet).
    """
    fields = [
        "Source Hostname",
        "Source Port",
        "Description",
        "Status",
        "VLAN",
        "Speed",
        "Duplex",
        "Neighbor Hostname",
        "Neighbor Port",
        "Neighbor Platform",
        "Target Hostname (Placeholder)",
        "Target Port (Placeholder)",
        "Target Patch Panel (Placeholder)"
    ]
    
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for ip, dev in devices.items():
                hostname = dev.get("hostname") or ip
                ints_detail = dev.get("interfaces_detail", {})
                neighbors = dev.get("neighbors", [])
                
                # Pre-map neighbors by local interface name (normalized)
                neighbor_map = {}
                for n in neighbors:
                    lp = n.get("local_port", "")
                    if lp:
                        neighbor_map[normalize_interface_name(lp)] = n
                        
                for name, stats in ints_detail.items():
                    desc = stats.get("description", "")
                    status = stats.get("status", "down")
                    vlan = stats.get("vlan", "")
                    speed = stats.get("speed", "")
                    duplex = stats.get("duplex", "")
                    
                    # Look up neighbor
                    norm_name = normalize_interface_name(name)
                    neighbor = neighbor_map.get(norm_name)
                    
                    neigh_host = ""
                    neigh_port = ""
                    neigh_plat = ""
                    if neighbor:
                        neigh_host = neighbor.get("remote_device", "")
                        neigh_port = neighbor.get("remote_port", "")
                        neigh_plat = neighbor.get("platform", "")
                        
                    writer.writerow({
                        "Source Hostname": hostname,
                        "Source Port": name,
                        "Description": desc,
                        "Status": status,
                        "VLAN": vlan,
                        "Speed": speed,
                        "Duplex": duplex,
                        "Neighbor Hostname": neigh_host,
                        "Neighbor Port": neigh_port,
                        "Neighbor Platform": neigh_plat,
                        "Target Hostname (Placeholder)": "",
                        "Target Port (Placeholder)": "",
                        "Target Patch Panel (Placeholder)": ""
                    })
        print(f"Cabling patching matrix successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating cabling matrix CSV: {e}")

def generate_protocol_translation(devices, output_path="cisco_to_target_translation.md"):
    """
    Generates Cisco-to-Target Feature Mapping & Protocol Translation Matrix.
    """
    lines = [
        "# Cisco-to-Target Protocol Translation & Mapping Matrix",
        "",
        "This report outlines proprietary or Cisco-specific protocols detected on your network switches, and provides the standard target equivalent features required during migration.",
        ""
    ]
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        
        lines.append(f"## Switch: {hostname} ({ip})")
        lines.append("| Cisco Configured Feature | Target Standard Equivalent | Migration Recommendation / Notes |")
        lines.append("| --- | --- | --- |")
        
        features_found = 0
        
        if cfg:
            # Spanning tree
            if re.search(r'spanning-tree mode\s+(?:pvst|rapid-pvst)', cfg, re.IGNORECASE):
                lines.append("| **Rapid-PVST+ / PVST+** | `MSTP (802.1s)` or `RSTP (802.1w)` | Proprietary multi-instance STP. Map to standard MSTP or single-instance RSTP. |")
                features_found += 1
            # HSRP
            if re.search(r'standby\s+\d+\s+ip', cfg, re.IGNORECASE):
                lines.append("| **HSRP (Hot Standby Router Protocol)** | `VRRP (RFC 5798 / 802.11R)` | Proprietary router redundancy. Transition gateway IP virtual addresses to VRRP groups. |")
                features_found += 1
            # CDP
            if re.search(r'cdp run|cdp enable', cfg, re.IGNORECASE):
                lines.append("| **CDP (Cisco Discovery Protocol)** | `LLDP (802.1AB)` | Proprietary device discovery. Enable LLDP globally and per interface on new vendor switches. |")
                features_found += 1
            # VTP
            if re.search(r'vtp mode|vtp domain', cfg, re.IGNORECASE):
                lines.append("| **VTP (VLAN Trunking Protocol)** | `Manual Config` or `MVRP (802.1ak)` | Proprietary VLAN propagation. Recommend manual provisioning or automation templates instead. |")
                features_found += 1
            # Static EtherChannel
            if re.search(r'channel-group\s+\d+\s+mode\s+on', cfg, re.IGNORECASE):
                lines.append("| **Static EtherChannel** | `LACP (802.3ad) Active` | Hardcoded bundling without control packet validation. Convert to standard dynamic LACP. |")
                features_found += 1
            # Stackwise
            if dev.get("model") and ("c9300" in dev.get("model").lower() or "c3850" in dev.get("model").lower()):
                lines.append("| **StackWise / StackWise-Virtual** | `VPC / MLAG` or Target Virtual Chassis | Stack backplane redundancy. Transition to target Multi-chassis LAG or equivalent backplane stack. |")
                features_found += 1
                
        if features_found == 0:
            lines.append("| *No proprietary Cisco protocols detected.* | Standard-ready configuration | Config is already standard-compliant. |")
            
        lines.append("")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Protocol translation report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating protocol translation report: {e}")

def generate_config_variables(devices, output_path="migration_config_variables.json"):
    """
    Generates configuration variables JSON sheet for Jinja2/Ansible templates.
    """
    variables = {}
    
    # Pre-parse VLAN names for all devices
    device_vlan_maps = {}
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        vlan_names = {}
        if cfg:
            matches = re.finditer(r'^vlan\s+(\d+)\s*[\r\n]+(?:\s+name\s+(\S+))?', cfg, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                vlan_id = match.group(1)
                name = match.group(2)
                if name:
                    vlan_names[vlan_id] = name.strip()
        device_vlan_maps[hostname] = vlan_names

    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        services = dev.get("services", {})
        
        # Build VLAN list
        vlans_list = []
        vlan_names = device_vlan_maps.get(hostname, {})
        for vid, vname in vlan_names.items():
            vlans_list.append({"id": vid, "name": vname})
            
        # Build SVI list
        l3_ints = dev.get("l3_interfaces", [])
        ints_detail = dev.get("interfaces_detail", {})
        svis_list = []
        for intf in l3_ints:
            intf_name = intf.get("interface")
            ip_addr = intf.get("ip_address")
            status = intf.get("status")
            
            desc = ""
            norm_name = normalize_interface_name(intf_name)
            for name, stats in ints_detail.items():
                if normalize_interface_name(name) == norm_name:
                    desc = stats.get("description", "")
                    break
                    
            subnet_range = '.'.join(ip_addr.split('.')[:3]) + '.0/24' if (ip_addr and '.' in ip_addr) else 'N/A'
            svis_list.append({
                "interface": intf_name,
                "ip_address": ip_addr,
                "subnet": subnet_range,
                "status": status,
                "description": desc
            })
            
        # Build physical interfaces list
        interfaces_list = []
        for name, stats in ints_detail.items():
            # Skip SVIs in the physical list
            if "vlan" in name.lower() or "loopback" in name.lower():
                continue
            interfaces_list.append({
                "interface": name,
                "description": stats.get("description", ""),
                "status": stats.get("status", "down"),
                "vlan": stats.get("vlan", ""),
                "speed": stats.get("speed", ""),
                "duplex": stats.get("duplex", "")
            })
            
        variables[hostname] = {
            "management_ip": ip,
            "model": dev.get("model", "Unknown"),
            "firmware": dev.get("firmware", "Unknown"),
            "serial": dev.get("serial", "Unknown"),
            "dns_servers": services.get("dns_servers", []),
            "ntp_servers": services.get("ntp_servers", []),
            "radius_servers": services.get("radius_servers", []),
            "tacacs_servers": services.get("tacacs_servers", []),
            "vlans": vlans_list,
            "l3_interfaces": svis_list,
            "interfaces": interfaces_list,
            "routes": [get_route_details(r) for r in dev.get("routes", [])]
        }
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(variables, f, indent=4)
        print(f"Configuration variables successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating config variables JSON: {e}")

def save_baseline_state(devices, output_path):
    """
    Saves the key operational state parameters (MACs, routes, neighbors, up interfaces)
    as a baseline JSON file for future comparison.
    """
    baseline = {}
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        
        # Up physical interfaces
        up_ints = []
        for name, stats in dev.get("interfaces_detail", {}).items():
            if stats.get("status") == "up":
                up_ints.append(name)
                
        # Neighbor connections
        neighbors = []
        for n in dev.get("neighbors", []):
            neighbors.append({
                "local_port": n.get("local_port", ""),
                "remote_device": n.get("remote_device", ""),
                "remote_port": n.get("remote_port", "")
            })
            
        # Route prefixes
        routes = []
        for r in dev.get("routes", []):
            details = get_route_details(r)
            if details["subnet"] and details["subnet"] != "Unknown":
                routes.append(details["subnet"])
        
        # SVI / L3 Interface states
        svis = {}
        for intf in dev.get("l3_interfaces", []):
            svis[intf.get("interface")] = {
                "ip": intf.get("ip_address"),
                "status": intf.get("status")
            }
            
        baseline[hostname] = {
            "management_ip": ip,
            "up_interfaces": up_ints,
            "neighbors": neighbors,
            "routes": routes,
            "svis": svis
        }
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=4)
        print(f"\n[+] Baseline state successfully saved to {output_path}")
    except Exception as e:
        print(f"Error saving baseline state: {e}")

def compare_baseline_state(devices, baseline_path, output_path="migration_verification_report.md"):
    """
    Compares the current network state against a baseline JSON file.
    Generates a verification report detailing missing elements or state mismatches.
    """
    if not os.path.exists(baseline_path):
        print(f"Error: Baseline file {baseline_path} does not exist.")
        return
        
    try:
        with open(baseline_path, "r") as f:
            baseline = json.load(f)
    except Exception as e:
        print(f"Error reading baseline file: {e}")
        return
        
    lines = [
        "# Post-Migration Verification & Validation Report",
        "",
        f"This report compares the current network state against the baseline file: `{os.path.basename(baseline_path)}`.",
        ""
    ]
    
    total_failures = 0
    
    for host_base, base_state in baseline.items():
        # Find matching device in current devices by IP or hostname
        current_dev = None
        base_ip = base_state.get("management_ip")
        
        for ip, dev in devices.items():
            if ip == base_ip or (dev.get("hostname") and dev.get("hostname").lower() == host_base.lower()):
                current_dev = dev
                break
                
        lines.append(f"## Device: {host_base}")
        if not current_dev:
            lines.append("❌ **CRITICAL: Switch is UNREACHABLE or missing in current scan!**")
            lines.append("")
            total_failures += 1
            continue
            
        device_failures = 0
        
        # 1. Compare UP physical interfaces
        base_up = base_state.get("up_interfaces", [])
        curr_ints = current_dev.get("interfaces_detail", {})
        curr_up = [name for name, stats in curr_ints.items() if stats.get("status") == "up"]
        
        missing_ints = [name for name in base_up if name not in curr_up]
        if missing_ints:
            lines.append(f"❌ **Interface Status Mismatch**: {len(missing_ints)} interfaces that were UP are now DOWN or missing:")
            for name in missing_ints:
                desc = curr_ints.get(name, {}).get("description", "No Description")
                lines.append(f"  * `{name}` (Description: `{desc}`)")
            device_failures += 1
        else:
            lines.append("✓ **Interface Status**: All baseline UP interfaces are currently UP.")
            
        # 2. Compare SVI / L3 Interface states
        base_svis = base_state.get("svis", {})
        curr_svis = {intf.get("interface"): intf for intf in current_dev.get("l3_interfaces", [])}
        
        svi_mismatches = []
        for name, base_svi in base_svis.items():
            curr_svi = curr_svis.get(name)
            if not curr_svi:
                svi_mismatches.append(f"Interface `{name}` is missing entirely.")
            elif curr_svi.get("status") != base_svi.get("status"):
                svi_mismatches.append(f"Interface `{name}` status is `{curr_svi.get('status')}` (Expected: `{base_svi.get('status')}`).")
            elif curr_svi.get("ip_address") != base_svi.get("ip"):
                svi_mismatches.append(f"Interface `{name}` IP is `{curr_svi.get('ip_address')}` (Expected: `{base_svi.get('ip')}`).")
                
        if svi_mismatches:
            lines.append(f"❌ **SVI/L3 Mismatches**:")
            for mismatch in svi_mismatches:
                lines.append(f"  * {mismatch}")
            device_failures += 1
        else:
            lines.append("✓ **SVI/L3 Interfaces**: All baseline L3 interfaces and IPs match.")
            
        # 3. Compare Neighbors (CDP/LLDP)
        base_neighbors = base_state.get("neighbors", [])
        curr_neighbors = current_dev.get("neighbors", [])
        
        missing_neighbors = []
        for bn in base_neighbors:
            match_found = False
            b_remote = bn.get("remote_device", "").split('.')[0].lower()
            b_local_port = normalize_interface_name(bn.get("local_port", ""))
            
            for cn in curr_neighbors:
                c_remote = cn.get("remote_device", "").split('.')[0].lower()
                c_local_port = normalize_interface_name(cn.get("local_port", ""))
                if b_remote == c_remote and b_local_port == c_local_port:
                    match_found = True
                    break
            if not match_found:
                missing_neighbors.append(f"Port `{bn.get('local_port')}` has lost connection to `{bn.get('remote_device')}` (Port: `{bn.get('remote_port')}`).")
                
        if missing_neighbors:
            lines.append(f"❌ **Neighbor/Uplink Mismatches**: Lost neighbor adjacencies on {len(missing_neighbors)} ports:")
            for mismatch in missing_neighbors:
                lines.append(f"  * {mismatch}")
            device_failures += 1
        else:
            lines.append("✓ **CDP/LLDP Neighbor Adjacencies**: All baseline neighbors are present.")
            
        # 4. Compare Routing table prefixes
        base_routes = set(base_state.get("routes", []))
        curr_routes = set()
        for r in current_dev.get("routes", []):
            details = get_route_details(r)
            if details["subnet"] and details["subnet"] != "Unknown":
                curr_routes.add(details["subnet"])
        
        missing_routes = base_routes - curr_routes
        if missing_routes:
            lines.append(f"❌ **Routing Prefix Mismatches**: {len(missing_routes)} routes present in the baseline are missing:")
            for r in sorted(list(missing_routes)):
                lines.append(f"  * Prefix: `{r}`")
            device_failures += 1
        else:
            lines.append("✓ **Routing Table**: All baseline route prefixes are learned.")
            
        if device_failures > 0:
            lines.append(f"\n⚠️ **Verification Summary**: {device_failures} state verification checks failed for switch **{host_base}**.")
            total_failures += 1
        else:
            lines.append(f"\n✓ **Verification Summary**: Switch **{host_base}** passed all state verification checks.")
        lines.append("")
        
    lines.append("---")
    if total_failures > 0:
        lines.append(f"# ❌ Verification Verdict: FAILED ({total_failures} switches failed validation checks)")
    else:
        lines.append("# ✓ Verification Verdict: PASSED (All switches match their baseline states)")
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"\n[+] Post-Migration Verification Report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating verification report: {e}")
