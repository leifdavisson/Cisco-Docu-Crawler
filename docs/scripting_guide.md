# Cisco Switch Docu-Crawler - Advanced Scripting & Integration Guide

The **Cisco Switch Docu-Crawler** is designed to be fully scriptable. This guide explains how to integrate the crawler into automated environments (such as cron jobs, Ansible playbooks, CI/CD pipelines, or custom Python orchestration scripts) by leveraging environment variables, CLI flags, and structured output files.

---

## 🔐 Credentials Automation

To run the crawler non-interactively without prompting for input, you can pass credentials using environment variables:

| Variable | Description |
| --- | --- |
| `CRAWLER_USER` or `CRAWLER_USERNAME` | SSH/Telnet Login Username |
| `CRAWLER_PASSWORD` | SSH/Telnet Login Password |
| `CRAWLER_SECRET` or `CRAWLER_ENABLE_SECRET` | Cisco Privileged EXEC Enable Secret |

### Bash Example:
```bash
export CRAWLER_USER="admin"
export CRAWLER_PASSWORD="SecureLogin123"
export CRAWLER_SECRET="SecureEnable123"

python3 cisco_crawler.py --subnets 10.0.1.0/24,10.0.2.0/24 --disable-telnet
```

---

## ⚙️ CLI Reference Table

The `cisco_crawler.py` command line supports the following flags:

| Argument | Type | Default | Description |
| --- | --- | --- | --- |
| `--subnets` | string | *Local subnet* | Comma-separated target networks to scan (e.g. `10.0.0.0/24,192.168.1.0/24`) |
| `--simulate` | flag | `False` | Run simulated scan & crawl (uses local mock switches without network traffic) |
| `--disable-telnet` | flag | `False` | Disables Telnet connections and restricts connection protocol to SSH-only |
| `--threads` | integer | `10` | Number of concurrent workers for switch scanning and crawls |
| `--timeout` | integer | `10` | Connection and socket read timeout in seconds |
| `--retry` | string | `None` | Path to `failed_hosts.json` to retry only previously failed targets |
| `--baseline` | string | `None` | Filepath to save the collected network operational state (for baseline auditing) |
| `--compare` | string | `None` | Filepath to a baseline JSON to compare the current network state against |
| `--verbose` or `-v` | flag | `False` | Enable detailed debug logs printed to standard output |

---

## 🐍 Custom Python Integration Examples

### Example 1: Nightly Automation Script (subprocess)
This script runs the crawler, automatically passing subnets and credentials via the process environment, and exits with a status code.

```python
import subprocess
import os
import sys

def run_nightly_backup():
    print("[*] Starting scheduled backup run...")
    
    # Configure run environment
    env = os.environ.copy()
    env["CRAWLER_USER"] = "admin"
    env["CRAWLER_PASSWORD"] = "SecurePassword123"
    env["CRAWLER_SECRET"] = "SecureEnableSecret123"
    
    # Call crawler process
    cmd = [
        "python3", "cisco_crawler.py",
        "--subnets", "192.168.1.0/24",
        "--disable-telnet",
        "--threads", "15",
        "--timeout", "8"
    ]
    
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[+] Crawler completed successfully!")
        print(result.stdout)
    else:
        print("[!] Crawler execution failed!", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)

if __name__ == "__main__":
    run_nightly_backup()
```

### Example 2: Parsing Config Variables JSON
You can parse the structured JSON variables output file (`migration_config_variables.json`) inside your own automation scripts to build inventory assets or populate CMDBs.

```python
import json
import glob
import os

def load_latest_device_variables():
    # Locate the most recent run deliverables directory
    runs = glob.glob("deliverables/run_*")
    if not runs:
        print("No crawler runs found.")
        return
        
    latest_run = max(runs, key=os.path.getmtime)
    vars_file = os.path.join(latest_run, "migration", "migration_config_variables.json")
    
    if not os.path.exists(vars_file):
        print(f"Variables JSON not found in: {latest_run}")
        return

    with open(vars_file, "r") as f:
        devices = json.load(f)
        
    print(f"--- Decoupled Configuration Parameters ({latest_run}) ---")
    for hostname, config in devices.items():
        print(f"\nDevice: {hostname}")
        print(f"  Management IP: {config.get('management_ip')}")
        print(f"  Model:         {config.get('model')}")
        print(f"  DNS Servers:   {', '.join(config.get('dns_servers', []))}")
        print(f"  NTP Servers:   {', '.join(config.get('ntp_servers', []))}")
        print(f"  L3 Interfaces:")
        for intf in config.get("l3_interfaces", []):
            print(f"    - {intf.get('interface')}: {intf.get('ip_address')} (Subnet: {intf.get('subnet')})")

if __name__ == "__main__":
    load_latest_device_variables()
```

### Example 3: Running a Configuration State Baseline Audit
This example automates baseline checks, saving the baseline config and raising alerts if the state changes in a future run.

```python
import subprocess
import os
import sys

def check_network_baseline():
    baseline_path = "backups/production_baseline.json"
    env = os.environ.copy()
    env["CRAWLER_USER"] = "admin"
    env["CRAWLER_PASSWORD"] = "SecurePassword123"
    env["CRAWLER_SECRET"] = "SecureEnableSecret123"
    
    # 1. Create baseline if it doesn't exist
    if not os.path.exists(baseline_path):
        print(f"[*] Baseline not found. Generating new baseline file at {baseline_path}...")
        cmd = ["python3", "cisco_crawler.py", "--subnets", "192.168.1.0/24", "--baseline", baseline_path]
        subprocess.run(cmd, env=env, check=True)
        print("[+] Baseline successfully saved.")
        return
        
    # 2. Compare current network state against the baseline
    print("[*] Comparing current network state against baseline...")
    cmd = ["python3", "cisco_crawler.py", "--subnets", "192.168.1.0/24", "--compare", baseline_path]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    
    # Check output for configuration delta drift
    if "State Comparison: CHANGES DETECTED" in result.stdout:
        print("[!] WARNING: Network drift detected!")
        # Print comparison report details
        print(result.stdout)
        # Here you could trigger email notifications or slack webhooks
    else:
        print("[+] Network state is consistent with the baseline.")

if __name__ == "__main__":
    check_network_baseline()
```
