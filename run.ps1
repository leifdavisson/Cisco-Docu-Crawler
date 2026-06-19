<#
.SYNOPSIS
    Cisco Switch Docu-Crawler - Operator Shell for Windows.
.DESCRIPTION
    A pre-req checker and runner for the Cisco Docu-Crawler Python script on Windows 11.
.EXAMPLE
    PowerShell.exe -ExecutionPolicy Bypass -File .\run.ps1
#>

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

# Enable UTF-8 encoding support
$OutputEncoding = [System.Text.Encoding]::UTF8

# Set current location to the directory containing this script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($scriptDir) {
    Set-Location $scriptDir
}

# Define colors
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"
$CYAN = "Cyan"
$WHITE = "White"

function Clear-Console {
    Clear-Host
}

function Show-Header {
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "          Cisco Switch Docu-Crawler - Windows Shell             " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Cyan
}

# Try to find Python if it's not in PATH
function Find-Python {
    # 1. Test if 'python' in path works and is a real Python (not Microsoft Store link)
    try {
        $ver = & python --version 2>&1
        if ($ver -like "*Python 3*") {
            return "python"
        }
    } catch {}

    # 2. Check common Local AppData path
    $localPythonPath = "$env:LocalAppData\Programs\Python"
    if (Test-Path $localPythonPath) {
        $localPythonDirs = Get-ChildItem -Path $localPythonPath -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $localPythonDirs) {
            $pyPath = Join-Path $dir.FullName "python.exe"
            if (Test-Path $pyPath) {
                # Add to path for this session
                $env:PATH += ";$($dir.FullName)"
                $env:PATH += ";$(Join-Path $dir.FullName "Scripts")"
                try {
                    $ver = & python --version 2>&1
                    if ($ver -like "*Python 3*") {
                        return "python"
                    }
                } catch {}
            }
        }
    }

    # 3. Check Program Files
    $programFilesPath = $env:ProgramFiles
    if (Test-Path $programFilesPath) {
        $programPythonDirs = Get-ChildItem -Path "$programFilesPath\Python*" -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $programPythonDirs) {
            $pyPath = Join-Path $dir.FullName "python.exe"
            if (Test-Path $pyPath) {
                # Add to path for this session
                $env:PATH += ";$($dir.FullName)"
                $env:PATH += ";$(Join-Path $dir.FullName "Scripts")"
                try {
                    $ver = & python --version 2>&1
                    if ($ver -like "*Python 3*") {
                        return "python"
                    }
                } catch {}
            }
        }
    }

    return $null
}

function Check-Requirements {
    Write-Host "`n[*] Verifying Windows system requirements..." -ForegroundColor Cyan
    
    # 1. Admin status
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "  - Administrative Privilege: [✓] Yes (Ready for automated updates)" -ForegroundColor Green
    } else {
        Write-Host "  - Administrative Privilege: [!] No (Auto-installing Python or Nmap will request UAC elevation)" -ForegroundColor Yellow
    }

    # 2. Python
    $global:PythonCmd = Find-Python
    if ($global:PythonCmd) {
        $pyVer = & $global:PythonCmd --version 2>&1
        Write-Host "  - Python 3: [✓] Installed ($pyVer)" -ForegroundColor Green
        
        # 3. Pip
        $hasPip = $false
        try {
            $pipVer = & $global:PythonCmd -m pip --version 2>&1
            if ($pipVer -like "*pip*") {
                $hasPip = $true
            }
        } catch {}
        
        if ($hasPip) {
            Write-Host "  - Pip Package Manager: [✓] Installed" -ForegroundColor Green
        } else {
            Write-Host "  - Pip Package Manager: [✗] Missing (Run: python -m ensurepip to install it)" -ForegroundColor Red
        }

        # 4. Libraries
        $hasNetmiko = $false
        $hasNetaddr = $false
        try {
            $null = & $global:PythonCmd -c "import netmiko" 2>&1
            if ($LASTEXITCODE -eq 0) { $hasNetmiko = $true }
        } catch {}
        try {
            $null = & $global:PythonCmd -c "import netaddr" 2>&1
            if ($LASTEXITCODE -eq 0) { $hasNetaddr = $true }
        } catch {}

        if ($hasNetmiko) {
            Write-Host "  - netmiko Library: [✓] Installed" -ForegroundColor Green
        } else {
            Write-Host "  - netmiko Library: [✗] NOT Installed (Required - Choose Option 1 to install)" -ForegroundColor Red
        }

        if ($hasNetaddr) {
            Write-Host "  - netaddr Library: [✓] Installed" -ForegroundColor Green
        } else {
            Write-Host "  - netaddr Library: [✗] NOT Installed (Required - Choose Option 1 to install)" -ForegroundColor Red
        }
        
    } else {
        Write-Host "  - Python 3: [✗] NOT Installed or Not in PATH" -ForegroundColor Red
        Write-Host "    (Please select Option 1 to auto-install Python 3 via Winget)" -ForegroundColor Yellow
    }

    # 5. Nmap
    $hasNmap = $false
    try {
        $nmapVer = & nmap --version 2>&1
        if ($nmapVer[0] -like "*Nmap*") {
            $hasNmap = $true
        }
    } catch {}
    
    if ($hasNmap) {
        Write-Host "  - Nmap Scanner: [✓] Installed" -ForegroundColor Green
    } else {
        Write-Host "  - Nmap Scanner: [!] Not Found (Optional - Crawler will fall back to built-in TCP port scanner)" -ForegroundColor Yellow
    }
}

function Install-Dependencies {
    Write-Host "`n[*] Starting environment initialization..." -ForegroundColor Cyan
    
    if (-not $global:PythonCmd) {
        Write-Host "[!] Python is not installed. Attempting to install Python 3 via Winget..." -ForegroundColor Yellow
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Host "Running: winget install -e --id Python.Python.3" -ForegroundColor Cyan
            winget install -e --id Python.Python.3 --source winget
            Write-Host "[*] Python installation complete. Please close and restart this script/shell to load new environment paths." -ForegroundColor Green
        } else {
            Write-Host "[!] Winget not found. Please download Python 3 manually from: https://www.python.org/downloads/" -ForegroundColor Red
            Write-Host "[!] IMPORTANT: Make sure to check 'Add python.exe to PATH' during installation!" -ForegroundColor Yellow
        }
        return
    }

    Write-Host "Running: python -m pip install --upgrade pip" -ForegroundColor Cyan
    & $global:PythonCmd -m pip install --upgrade pip

    Write-Host "Running: python -m pip install -r requirements.txt" -ForegroundColor Cyan
    & $global:PythonCmd -m pip install -r requirements.txt
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n[+] Dependencies installed successfully!" -ForegroundColor Green
    } else {
        Write-Host "`n[!] Dependency installation failed. Check internet access or permissions." -ForegroundColor Red
    }
}

function Install-Nmap {
    Write-Host "`n[*] Attempting to install Nmap..." -ForegroundColor Cyan
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Running: winget install -e --id Nmap.Nmap" -ForegroundColor Cyan
        winget install -e --id Nmap.Nmap --source winget
        Write-Host "[+] Nmap installation complete. You might need to restart this console/session to use it." -ForegroundColor Green
    } else {
        Write-Host "[!] Winget not found. Please download Nmap manually from: https://nmap.org/download.html" -ForegroundColor Red
    }
}

function Run-Discovery {
    if (-not $global:PythonCmd) {
        Write-Host "[!] Error: Python 3 must be installed to run the discovery scanner." -ForegroundColor Red
        return
    }
    
    # Check dependencies before running
    $hasLibs = $true
    try {
        $null = & $global:PythonCmd -c "import netmiko, netaddr" 2>&1
        if ($LASTEXITCODE -ne 0) { $hasLibs = $false }
    } catch {
        $hasLibs = $false
    }
    
    if (-not $hasLibs) {
        Write-Host "[!] Error: Required libraries (netmiko/netaddr) are missing. Select Option 1 first." -ForegroundColor Red
        return
    }

    $verboseOpt = Read-Host "Enable verbose logging? (y/N)"
    $verboseFlag = ""
    if ($verboseOpt -match "^[Yy]$") {
        $verboseFlag = "--verbose"
    }

    Write-Host "`n[*] Starting Cisco Network Discovery Scan..." -ForegroundColor Cyan
    if ($verboseFlag) {
        & $global:PythonCmd cisco_crawler.py $verboseFlag
    } else {
        & $global:PythonCmd cisco_crawler.py
    }
}

function Run-Simulation {
    if (-not $global:PythonCmd) {
        Write-Host "[!] Error: Python 3 must be installed to run the discovery scanner." -ForegroundColor Red
        return
    }
    
    # Check dependencies before running (in simulation, only netaddr is strictly required)
    $hasLibs = $true
    try {
        $null = & $global:PythonCmd -c "import netaddr" 2>&1
        if ($LASTEXITCODE -ne 0) { $hasLibs = $false }
    } catch {
        $hasLibs = $false
    }
    
    if (-not $hasLibs) {
        Write-Host "[!] Error: Required library (netaddr) is missing. Select Option 1 first." -ForegroundColor Red
        return
    }

    $verboseOpt = Read-Host "Enable verbose logging? (y/N)"
    $verboseFlag = ""
    if ($verboseOpt -match "^[Yy]$") {
        $verboseFlag = "--verbose"
    }

    Write-Host "`n[*] Starting Simulated Network Discovery Scan (Demo Mode)..." -ForegroundColor Cyan
    if ($verboseFlag) {
        & $global:PythonCmd cisco_crawler.py --simulate $verboseFlag
    } else {
        & $global:PythonCmd cisco_crawler.py --simulate
    }
}

function Retry-Scan {
    if (-not $global:PythonCmd) {
        Write-Host "[!] Error: Python 3 is required." -ForegroundColor Red
        return
    }

    if (Test-Path "failed_hosts.json") {
        Write-Host "`n[*] Resuming scan for failed hosts using failed_hosts.json..." -ForegroundColor Cyan
        & $global:PythonCmd cisco_crawler.py --retry failed_hosts.json
    } else {
        Write-Host "`n[!] No failed_hosts.json found. No previous failed scans to resume." -ForegroundColor Yellow
    }
}

function List-Backups {
    Write-Host "`n[*] Checking configuration backups..." -ForegroundColor Cyan
    if (Test-Path "backups") {
        $cfgs = Get-ChildItem -Path "backups\*.cfg" -ErrorAction SilentlyContinue
        if ($cfgs.Count -gt 0) {
            Write-Host "----------------------------------------------------------------"
            foreach ($file in $cfgs) {
                Write-Host ("{0,-40} ({1} bytes)" -f $file.Name, $file.Length) -ForegroundColor Green
            }
            Write-Host "----------------------------------------------------------------"
            Write-Host "Backups are stored locally in the 'backups\' folder." -ForegroundColor Green
        } else {
            Write-Host "[!] No backup configurations (.cfg) found in the backups\ folder." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] The backups\ directory does not exist. Run a successful scan first." -ForegroundColor Yellow
    }
}

# Main Loop
while ($true) {
    Clear-Console
    Show-Header
    Check-Requirements

    Write-Host "`nOperations Menu:" -ForegroundColor Cyan
    Write-Host "  1) " -NoNewline; Write-Host "Initialize Environment" -ForegroundColor Green -NoNewline; Write-Host " (Install Python + Crawler Packages)"
    Write-Host "  2) " -NoNewline; Write-Host "Run New Discovery Scan" -ForegroundColor Green
    Write-Host "  3) " -NoNewline; Write-Host "Run Simulated Discovery (Demo Mode)" -ForegroundColor Green
    Write-Host "  4) " -NoNewline; Write-Host "Retry/Resume Failed Devices" -ForegroundColor Green -NoNewline; Write-Host " (Loads failed_hosts.json)"
    Write-Host "  5) " -NoNewline; Write-Host "List Current Backups" -ForegroundColor Green
    Write-Host "  6) " -NoNewline; Write-Host "Install Nmap Utility" -ForegroundColor Green -NoNewline; Write-Host " (Optional)"
    Write-Host "  7) " -NoNewline; Write-Host "Exit" -ForegroundColor Red
    Write-Host "----------------------------------------------------------------"

    $selection = Read-Host "Select option (1-7)"

    switch ($selection) {
        "1" { Install-Dependencies }
        "2" { Run-Discovery }
        "3" { Run-Simulation }
        "4" { Retry-Scan }
        "5" { List-Backups }
        "6" { Install-Nmap }
        "7" { 
            Write-Host "`nExiting Windows Operator Shell. Goodbye!`n" -ForegroundColor Green
            break
        }
        default {
            Write-Host "[!] Invalid selection. Please choose a number between 1 and 7." -ForegroundColor Red
        }
    }

    if ($selection -eq "7") { break }

    Write-Host "`nPress [Enter] to return to the menu..."
    Read-Host
}
