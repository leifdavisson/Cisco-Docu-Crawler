# Cisco Switch Docu-Crawler

<p align="center">
  <img src="docs/images/banner.jpg" alt="Cisco Switch Docu-Crawler Banner" width="100%" max-width="800px" style="border-radius: 8px;" />
</p>

<p align="center">
  <a href="https://github.com/leifdavisson/Cisco-Docu-Crawler/actions/workflows/ci.yml">
    <img src="https://github.com/leifdavisson/Cisco-Docu-Crawler/actions/workflows/ci.yml/badge.svg" alt="CI Status" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL v3" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Support" />
  </a>
  <a href="https://github.com/ktbyers/netmiko">
    <img src="https://img.shields.io/badge/dependency-Netmiko%20v4+-orange.svg" alt="Netmiko Dependency" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform Support" />
  </a>
</p>

A portable, self-contained Python 3 CLI tool that performs network discovery, logs into Cisco switches (supporting **IOS / IOS-XE**, **NX-OS**, and **IOS-XR**), runs safe read-only commands, and compiles authoritative network inventory, configuration diffs, and migration documentation reports.

---

## ✨ Features

* **Nmap & Socket Scanner Fallback:** Uses `nmap` via subprocess for scanning. If `nmap` is not installed, it falls back to a built-in multi-threaded Python TCP port scanner.
* **Auto-OS Detection:** Connects initially, detects the Cisco OS (IOS, NX-OS, IOS-XR) via system strings, and dynamically loads the correct Netmiko driver.
* **Safe, Read-Only CLI Commands:** Executes safe status commands (e.g., `show version`, `show running-config`, `show ip interface brief`, `show interfaces`, `show arp`, `show cdp/lldp neighbors`, `show spanning-tree`, `show ip route`).
* **Switch Configuration Benchmarking:** Saves running configurations as standard baselines and provides comparison diffs to track configuration drift over time.
* **Offline OUI Lookup:** Resolves manufacturer MAC addresses using a built-in common vendor database, with automatic fallback to loading or downloading the official IEEE OUI registry.
* **Failure Management / Retry:** Logs failed or partial hosts to `failed_hosts.json`. You can resume/retry scanning just those hosts using new credentials or network configurations.
* **Cross-Platform Operator Shells:** Automated interactive menu wrappers (`run.sh` for Linux/macOS and `run.ps1`/`run.bat` for Windows) streamline setup, prerequisites installation, baseline comparison, and retries.
* **Advanced Options & Security Controls**: Hides advanced operational settings (thread pool scale, timeouts, baseline comparison, retry modes, telnet disabling) in an `Advanced Options Menu` to protect production switches from junior engineers.
* **EOF-Safe Menus & Pipes**: Shell menus support non-interactive pipelines (e.g., piping configuration scripts via stdin) and terminate immediately upon receiving EOF.
* **Accurate Layer 3 Subnet Analysis**: Diagnostics accurately identify overlapping nested IP subnets versus exact IP address conflicts, using standard CIDR boundary parsing.
* **Standard Python Packaging**: Supports PEP 517 structures. Run `pip install .` to install the crawler as a system-wide CLI utility.

---

## 📂 Deliverables Generated

After a successful scan, the crawler compiles and generates the following reports in the current directory:

1. **`asset_inventory.csv`**: The authoritative inventory database including Hostname, IP, MAC Address, Device Type, Model, Firmware, Serial Number, Role, and Management Protocol.
2. **`migration_cabling_matrix.csv`**: A port-by-port cabling patching matrix mapping Cisco interfaces, connected MACs, resolved vendors (OUI), descriptions, link speeds, VLAN numbers, names, and target destination switch ports.
3. **`cisco_to_target_translation.md`**: A detailed command-by-command and feature-by-feature translation map bridging Cisco CLI syntax (IOS/NX-OS/XR) with standard modern target switches.
4. **`migration_config_variables.json`**: An extracted variables database containing hostname, domain name, VLAN names, IP interfaces, routing configurations, NTP, SNMP, AAA, and DNS details.
5. **`L2_network_diagrams.md`**: Physical topologies, switch-to-switch uplinks, switch stacks, wireless AP connections, and STP blocking/forwarding links documented in standard **Mermaid.js** diagrams.
6. **`L3_network_diagrams.md`**: Logical routing boundaries, Switch Virtual Interfaces (SVIs), VLAN mapping tables, and VRF instances mapped out via Mermaid.js.
7. **`network_analysis_report.md`**: Detailed Layer 1-7 behavior analysis highlighting cabling errors, port utilization percentages, loop/STP risks, overlapping subnets, dynamic routing configurations, AAA/RADIUS setups, and security gaps.
8. **`failed_hosts.json`**: List of hosts that failed scanning for follow-up runs.


## 🚀 Getting Started

### Method 1: Interactive Menu (Recommended for Operators)
The easiest way to initialize the environment, install requirements, and run the crawler is using the interactive menu shell:

* **Linux/macOS:**
  ```bash
  chmod +x run.sh
  ./run.sh
  ```
* **Windows (PowerShell):**
  Double click on `run.bat` or run:
  ```powershell
  PowerShell.exe -ExecutionPolicy Bypass -File .\run.ps1
  ```
This shell will guide you through checking requirements, installing dependencies, executing discovery, comparing baselines, retrying failed hosts, and listing backups.

### Method 2: Docker Container (Recommended for Isolated Execution)
A pre-built container package is compiled and hosted on **GitHub Container Registry (GHCR)**. It contains Python, all packages, and system-level `nmap` pre-configured.

To pull and run the crawler image in a container, mounting a local volume to collect the deliverables:
```bash
docker run --rm -it -v "$(pwd)/deliverables:/app/deliverables" ghcr.io/leifdavisson/cisco-docu-crawler --subnets 192.168.1.0/24
```
*(Optionally define `CRAWLER_USER`, `CRAWLER_PASSWORD`, and `CRAWLER_SECRET` environment variables using `-e` flags to skip the credential prompt).*

### Method 3: Standard Python Package (Recommended for Scripting)
You can install the crawler directly on your host machine as a standard, system-wide command-line utility:
```bash
pip install .
```
Once installed, you can invoke the crawler from any directory simply by typing:
```bash
cisco-crawler
```

---

## 📚 Documentation

Detailed guides and manuals are available in the `docs/` directory:
* **[Junior Network Engineer Quick-Start Guide](docs/junior_engineer_guide.md)**: Walks through basic menu operations, using the simulated demo scan mode, and reading generated topology diagrams and reports.
* **[Advanced Scripting & Automation Guide](docs/scripting_guide.md)**: Outlines command-line flags, environment variable parameterization, and integration scripts to run the crawler programmatically in cron jobs or CI/CD pipelines.

---

### Manual CLI Execution (Alternative)

If you prefer to run the scripts manually, follow these steps:

#### 1. Installation
Install the light dependencies:
```bash
pip install -r requirements.txt
```

#### 2. Make Crawler Executable
```bash
chmod +x cisco_crawler.py
```

#### 3. Run the Discovery Scanner
```bash
./cisco_crawler.py
```
*If no subnets are passed, the script automatically detects your machine's local IP and suggests your local `/24` subnet as the default.*

To specify target subnets directly via CLI:
```bash
./cisco_crawler.py --subnets 192.168.1.0/24,10.0.5.0/24
```

#### 4. Baseline Configuration Saving
To save a snapshot of the current configurations:
```bash
./cisco_crawler.py --baseline
```

#### 5. Configuration Drift / Comparison Diffs
To run the crawler and check for changes against the saved baseline:
```bash
./cisco_crawler.py --compare
```

#### 6. Retry Failed/Partial Scans
If any switches fail (due to network timeout, bad credentials, or AAA/enable issues), their details are logged in `failed_hosts.json`. 

You can rerun the crawler to target **only** the failed devices:
```bash
./cisco_crawler.py --retry failed_hosts.json
```
*(The script will scan only those hosts and prompt for credentials again, making it easy to try alternate passwords or troubleshoot connectivity)*

---

## 🛠️ Safe Command Comparison Cheat Sheet

This crawler normalizes command inputs across Cisco platforms based on the following differences:

| Function | IOS / IOS-XE | NX-OS | IOS-XR |
| --- | --- | --- | --- |
| **Interfaces Summary** | `show ip interface brief` | `show ip interface brief` | `show ipv4 interface brief` |
| **MAC Address Table** | `show mac address-table` | `show mac address-table` | Parsed from `show interfaces` / `show arp` |
| **ARP Table** | `show arp` | `show ip arp` | `show arp` |
| **Topology Discovery**| CDP + LLDP detail | CDP + LLDP detail | LLDP only |
| **Spanning Tree** | `show spanning-tree` | `show spanning-tree` | Disabled (Routing platforms) |
| **Routing Table** | `show ip route` | `show ip route` | `show route` |
| **Paging Control** | `terminal length 0` | `terminal length 0` | `terminal length 0` |

---

## 🖥️ How to View the Generated Reports (.md & Mermaid Diagrams)

The generated reports are written in **Markdown (`.md`)** format, which is a clean, readable text format. The physical and logical network diagrams are created using **Mermaid.js**, a text-to-diagram standard.

To view the reports with rich formatting and render the diagrams automatically, we recommend using one of the following tools:

### 1. Obsidian (Recommended & Easiest)
[Obsidian](https://obsidian.md/) is a free, highly-rated note-taking app available for Windows, macOS, and Linux.
* **Why it's best:** It natively supports Markdown and renders Mermaid diagrams instantly out-of-the-box without needing any plugins or setup.
* **How to use:** Install Obsidian, click "Open folder as vault", and select the folder where the crawler generated your reports.

### 2. GitHub (Zero Installation)
If you push these files to a GitHub repository:
* **Why it's best:** GitHub natively parses Markdown and renders Mermaid diagrams directly inside the web browser.
* **How to use:** Simply click on any `.md` file on your GitHub project page to read it.

### 3. Visual Studio Code (VS Code)
For developers and IT administrators already using VS Code:
* **How to use:** Open any `.md` file and open the preview tab (`Ctrl+Shift+V` on Windows/Linux or `Cmd+Shift+V` on macOS).
* **Render Diagrams:** Install the **Markdown Preview Mermaid Support** extension from the Marketplace to render the topologies inside the preview pane.

### 4. Mermaid Live Editor (Web-based)
If you just want to export the diagrams:
* **How to use:** Copy the text block starting with ````mermaid` from your diagram reports and paste it into the [Mermaid Live Editor](https://mermaid.live/). From there, you can customize the layout or export it as a high-resolution PNG, SVG, or PDF.

---

## 🔒 Security & Safety

This script uses **read-only** status commands and does not make configuration changes. All username/password prompting is done securely using Python's standard `getpass` module so that passwords never leak to the terminal logs or bash history.

---

## 📄 License

This project is licensed under the **GNU Affero General Public License Version 3.0 (AGPL-3.0)**. See the [LICENSE](LICENSE) file for the full license text.
