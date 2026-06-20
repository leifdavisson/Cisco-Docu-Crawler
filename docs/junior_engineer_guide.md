# Cisco Switch Docu-Crawler - Junior Network Engineer Quick-Start Guide

Welcome to the **Cisco Switch Docu-Crawler**! This tool is designed to automate the discovery, auditing, configuration backup, and migration mapping of Cisco network switches and routers (supporting Cisco IOS, IOS-XE, NX-OS, and IOS-XR).

This guide is designed to help you get up to speed with running the tool safely and interpreting the generated outputs.

---

## 🚀 Running the Operator Shell

To make execution easy and consistent, the tool provides operator menus for both Unix/Linux and Windows platforms. These scripts check system requirements (like Python 3, pip, and Nmap) and install necessary packages automatically.

### On Unix/Linux/macOS:
Open your terminal and run the shell script bootstrapper:
```bash
./run.sh
```

### On Windows (PowerShell):
Double-click `run.bat` or run it from a PowerShell window:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\run.ps1
```

---

## 📋 Operations Menu: Step-by-Step

When you launch the script, you are presented with the **Operations Menu**:

```
Operations Menu:
  1) Initialize Environment (Install Python packages)
  2) Run a New Discovery Scan
  3) Run Simulated Discovery (Demo Mode)
  4) List Current Backups
  5) Advanced Options Menu
  6) Exit
```

### Step 1: Initialize Environment (Option 1)
Run this the first time you clone the repository or set up a new machine. It ensures that the required Python libraries (like `netmiko` and `netaddr`) are installed and up-to-date.

### Step 2: Run Simulated Discovery (Option 3 - Highly Recommended First Step)
Before scanning a live network, run a simulation. 
* **Safe Dry-Run**: It does not make any real network connections.
* It uses mock switches (spanning different Cisco models like WS-C3850, WS-C2960X, and ISR4431) to generate a full set of deliverables.
* **Purpose**: Allows you to check the report formatting and understand what the tool collects without any risk of affecting production systems.

### Step 3: Run a New Discovery Scan (Option 2)
When you are ready to scan the live network:
1. **Subnets Input**: The script will prompt you for target subnets (e.g. `192.168.1.0/24`). You can enter a single subnet or multiple subnets separated by commas.
2. **Credentials Input**: Provide the SSH/Telnet username and password. 
   * **AAA Lockout Prevention**: The crawler is built to gracefully halt retries if it hits a `NetmikoAuthenticationException` (authentication error). This prevents the crawler from locking out operator credentials in TACACS+/RADIUS AAA servers.
3. **Scan Execution**: The tool will scan the subnets to locate active switches, validate login credentials, and crawl configuration details concurrently.

---

## 🛠️ Advanced Options Menu (Option 5)

Advanced operations are grouped under the **Advanced Options Menu** to prevent accidental misconfigurations:

* **Save/Compare Baselines**: Allows saving the running network state to a JSON file and comparing it later to detect changes (like new routes, modified neighbors, or interfaces going down).
* **Retry/Resume**: Loads `failed_hosts.json` from a previous run to retry only the hosts that failed to connect, saving time.
* **Crawler Customizations**:
  * **Thread Count**: Defaults to `10`. Raising this too high (e.g. `50+`) on older network platforms can saturate switch CPU control planes. Keep it low for safety.
  * **Connection Timeout**: The socket wait duration (default `10` seconds). Useful to raise only when scanning across high-latency WAN links.
  * **Telnet Fallback**: Toggles Telnet fallback. Toggling this off enforces SSH-only connections.

---

## 📁 Understanding the Deliverables

Every successful crawl creates a new folder under `deliverables/run_<timestamp>/`. The contents are organized as follows:

### 1. `inventory/asset_inventory.csv`
A spreadsheet listing every discovered switch and router. It contains the Hostname, IP, MAC address, Hardware Model, Firmware Version, Serial Number, and Management Method.

### 2. `diagrams/L2_network_diagrams.md`
Contains a **Mermaid.js** physical diagram showing how switches connect.
* **Green Highlighted Nodes**: Represent Spanning Tree (STP) Root Bridges.
* **Dashed Red Lines**: Represent active blocking ports (`BLK`) where STP is actively breaking topology loops.
* **Solid Lines**: Forwarding connections (line thickness corresponds to link speed).

### 3. `diagrams/L3_network_diagrams.md`
Contains a logical diagram mapping IP networks, SVIs (Switched Virtual Interfaces), Loopbacks, and default routing boundaries.

### 4. `analysis/network_analysis_report.md`
An audit report highlighting issues:
* Physical Layer: Speed/duplex mismatches, input/output packet errors, and CRC checksum issues.
* Layer 2 Spanning Tree: STP Disabled switches (which present loop risks) and blocking ports list.
* Layer 3 Subnet Conflicts: Flags **IP Address Conflicts** (same IP on two different switches) and **Subnet Overlaps** (overlapping routing ranges).
* Services Audit: Flags missing NTP, DNS, or AAA security configurations.

### 5. `migration/`
Contains configuration mapping variables (`migration_config_variables.json`), physical patching details (`migration_cabling_matrix.csv`), and translation guidelines (`cisco_to_target_translation.md`) to assist in planning migrations.
