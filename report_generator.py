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
    
    # 1. Define nodes and their styles
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        model = dev.get("model") or "Unknown"
        is_root = dev.get("stp", {}).get("is_root", False)
        
        # Node label with Model
        label = f"[\"{hostname}<br/>({model})\"]"
        lines.append(f"  {hostname}{label}")
        
        # Apply classes
        model_lower = model.lower()
        hn_lower = hostname.lower()
        if is_root:
            lines.append(f"  class {hostname} root;")
        elif "core" in hn_lower or "c9500" in model_lower:
            lines.append(f"  class {hostname} core;")
        elif "dist" in hn_lower or "c3850" in model_lower or "c9300" in model_lower:
            lines.append(f"  class {hostname} dist;")
        else:
            lines.append(f"  class {hostname} access;")
            
    lines.append("")
    lines.append("  %% Topology links")
    
    # 2. Draw connections from neighbors
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        neighbors = dev.get("neighbors", [])
        
        for n in neighbors:
            remote_host = n.get("remote_device")
            if not remote_host:
                continue
                
            # Clean remote hostname
            remote_host = remote_host.split('.')[0]
            
            # Find matching remote node in scanned devices if possible to use IP/Hostname
            matched_remote = None
            for rip, rdev in devices.items():
                rhn = rdev.get("hostname", "")
                if rhn and rhn.split('.')[0].lower() == remote_host.lower():
                    matched_remote = rhn
                    break
            
            # If not in scanned devices, we still add it
            node_b = matched_remote or remote_host
            
            # Sort node names to prevent duplicates
            link_key = tuple(sorted([hostname, node_b]))
            if link_key in seen_links:
                continue
            seen_links.add(link_key)
            
            local_port = n.get("local_port", "")
            remote_port = n.get("remote_port", "")
            
            # Determine link characteristics (e.g., STP blocking)
            is_blocked = False
            stp_vlans = dev.get("stp", {}).get("vlans", {})
            for vlan_id, ports in stp_vlans.items():
                if local_port in ports and ports[local_port].get("state") == "BLK":
                    is_blocked = True
                    break
            
            # Determine link speed and thickness
            speed_val = get_link_speed(local_port, dev.get("interfaces_detail", {}))
            thickness = {
                "10M": "1px",
                "100M": "2px",
                "1G": "3.5px",
                "2.5G": "5px",
                "5G": "6px",
                "10G": "7.5px",
                "40G": "9px",
                "100G": "11px"
            }.get(speed_val, "3.5px")
            
            if is_blocked:
                # Dotted red line for blocked paths
                lines.append(f"  {hostname} -.-> {node_b}")
                link_styles.append(f"  linkStyle {link_idx} stroke:#ff3333,stroke-width:{thickness},stroke-dasharray: 5 5;")
            else:
                lines.append(f"  {hostname} === {node_b}")
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
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        device_nodes.add(hostname)
        if hostname not in adj:
            adj[hostname] = set()
            
        l3_ints = dev.get("l3_interfaces", [])
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
            
    mindmap_lines = []
    if not adj:
        mindmap_lines.append("mindmap")
        mindmap_lines.append("  root((No L3 Interfaces Discovered))")
    else:
        # 2. Find root node (most connected node)
        root_node = max(adj.keys(), key=lambda k: len(adj[k]))
        
        # 3. BFS to build tree hierarchy
        visited = {root_node}
        
        def build_subtree(node):
            subtree = {}
            # Sort neighbors by degree (most connected first)
            neighbors = sorted(adj[node], key=lambda k: len(adj[k]), reverse=True)
            for neighbor in neighbors:
                if neighbor not in visited:
                    visited.add(neighbor)
                    subtree[neighbor] = build_subtree(neighbor)
            return subtree
            
        tree = {root_node: build_subtree(root_node)}
        
        # Add any disconnected components
        for node in adj.keys():
            if node not in visited:
                visited.add(node)
                tree[root_node][node] = build_subtree(node)
                
        # 4. Render tree to Mermaid mindmap syntax
        mindmap_lines.append("mindmap")
        
        def render_node(node, indent_level):
            indent = "  " * indent_level
            safe_text = node.replace('"', '\\"')
            if node == root_node:
                shape = f"(({safe_text}))"
            elif node in device_nodes:
                shape = f"({safe_text})"
            else:
                shape = f"[{safe_text}]"
            mindmap_lines.append(f"{indent}{shape}")
            
        def walk_tree(subtree, indent_level):
            for node, children in subtree.items():
                render_node(node, indent_level)
                walk_tree(children, indent_level + 1)
                
        walk_tree(tree, 1)

    lines = [
        "# Layer 3 & Logical Network Diagrams",
        "",
        "This file documents Layer 3 boundaries, Switch Virtual Interfaces (SVIs), VLAN maps, and routing domains/VRFs.",
        "",
        "## Logical Routing Boundary Diagram",
        "```mermaid",
        "\n".join(mindmap_lines),
        "```",
        "",
        "## Authoritative VLAN, Subnet & SVI Map",
        "",
        "| Switch Hostname | Interface / VLAN | Description | SVI IP Address | Subnet Range | Interface Status |",
        "| --- | --- | --- | --- | --- | --- |"
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
                    
            subnet_range = '.'.join(ip_addr.split('.')[:3]) + '.0/24' if (ip_addr and '.' in ip_addr) else 'N/A'
            lines.append(f"| {hostname} | {intf_name} | {desc or 'N/A'} | {ip_addr} | {subnet_range} | {status} |")
            
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
        
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"L3 Diagrams successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating L3 diagram file: {e}")

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
    overlap_found = False
    
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        l3_ints = dev.get("l3_interfaces", [])
        for intf in l3_ints:
            intf_ip = intf.get("ip_address")
            if intf_ip and intf_ip not in ["unassigned", "down", "up", "unset"]:
                try:
                    # Parse subnet (guess /24 if not specified)
                    net = IPNetwork(f"{intf_ip}/24")
                    ip_subnets.append((hostname, intf.get("interface"), net))
                except Exception:
                    pass
                    
    # Compare each subnet for overlaps
    for i in range(len(ip_subnets)):
        for j in range(i+1, len(ip_subnets)):
            h1, int1, net1 = ip_subnets[i]
            h2, int2, net2 = ip_subnets[j]
            # If subnets are identical but on different devices or interfaces
            if net1.network == net2.network and h1 != h2:
                lines.append(f"* **Overlap Warning:** Same network range `{net1.network}/{net1.prefixlen}` configured on **{h1}** (`{int1}`) and **{h2}** (`{int2}`).")
                overlap_found = True
                
    if not overlap_found:
        lines.append("  * No overlapping subnets or IP address space collisions detected.")
        
    # Routing protocols
    lines.append("\n### Active Routing Protocols")
    routes_summary = {}
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        routes = dev.get("routes", [])
        protocols = list(set([r.get("protocol") for r in routes if r.get("protocol")]))
        if protocols:
            routes_summary[hostname] = protocols
            
    if routes_summary:
        for host, protos in routes_summary.items():
            lines.append(f"* **{host}**: Running routing protocols: {', '.join(protos)}")
    else:
        lines.append("  * Devices are operating entirely on Static routing or directly connected Layer 3 boundaries.")
        
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
