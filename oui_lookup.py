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
import urllib.request
import os

# Bundled list of common enterprise network equipment vendor OUIs
COMMON_OUIS = {
    # Cisco Systems
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:43": "Cisco Systems",
    "00:01:63": "Cisco Systems",
    "00:01:64": "Cisco Systems",
    "00:01:96": "Cisco Systems",
    "00:01:97": "Cisco Systems",
    "00:02:16": "Cisco Systems",
    "00:02:17": "Cisco Systems",
    "00:02:4A": "Cisco Systems",
    "00:02:4B": "Cisco Systems",
    "00:02:B9": "Cisco Systems",
    "00:02:BA": "Cisco Systems",
    "00:02:FC": "Cisco Systems",
    "00:02:FD": "Cisco Systems",
    "00:03:31": "Cisco Systems",
    "00:03:32": "Cisco Systems",
    "00:03:6B": "Cisco Systems",
    "00:03:6C": "Cisco Systems",
    "00:03:E3": "Cisco Systems",
    "00:03:E4": "Cisco Systems",
    "00:04:4D": "Cisco Systems",
    "00:04:4E": "Cisco Systems",
    "00:04:9A": "Cisco Systems",
    "00:04:9B": "Cisco Systems",
    "00:04:C0": "Cisco Systems",
    "00:04:C1": "Cisco Systems",
    "00:04:DD": "Cisco Systems",
    "00:04:DE": "Cisco Systems",
    "00:05:00": "Cisco Systems",
    "00:05:31": "Cisco Systems",
    "00:05:32": "Cisco Systems",
    "00:05:5E": "Cisco Systems",
    "00:05:5F": "Cisco Systems",
    "00:05:9A": "Cisco Systems",
    "00:05:9B": "Cisco Systems",
    "00:06:28": "Cisco Systems",
    "00:06:29": "Cisco Systems",
    "00:06:52": "Cisco Systems",
    "00:06:53": "Cisco Systems",
    "00:07:0D": "Cisco Systems",
    "00:07:0E": "Cisco Systems",
    "00:07:50": "Cisco Systems",
    "00:07:51": "Cisco Systems",
    "00:07:84": "Cisco Systems",
    "00:07:85": "Cisco Systems",
    "00:07:B3": "Cisco Systems",
    "00:07:B4": "Cisco Systems",
    "00:07:EC": "Cisco Systems",
    "00:07:ED": "Cisco Systems",
    "00:08:20": "Cisco Systems",
    "00:08:21": "Cisco Systems",
    "00:08:7C": "Cisco Systems",
    "00:08:7D": "Cisco Systems",
    "00:08:A3": "Cisco Systems",
    "00:08:A4": "Cisco Systems",
    "00:08:E2": "Cisco Systems",
    "00:08:E3": "Cisco Systems",
    "00:09:43": "Cisco Systems",
    "00:09:44": "Cisco Systems",
    "00:09:7B": "Cisco Systems",
    "00:09:7C": "Cisco Systems",
    "00:09:B6": "Cisco Systems",
    "00:09:B7": "Cisco Systems",
    "00:09:E8": "Cisco Systems",
    "00:09:E9": "Cisco Systems",
    "00:0A:41": "Cisco Systems",
    "00:0A:42": "Cisco Systems",
    "00:0A:8A": "Cisco Systems",
    "00:0A:8B": "Cisco Systems",
    "00:0A:B7": "Cisco Systems",
    "00:0A:B8": "Cisco Systems",
    "00:0A:F3": "Cisco Systems",
    "00:0A:F4": "Cisco Systems",
    "00:0B:45": "Cisco Systems",
    "00:0B:46": "Cisco Systems",
    "00:0B:85": "Cisco Systems",
    "00:0B:86": "Cisco Systems",
    "00:0B:C5": "Cisco Systems",
    "00:0B:C6": "Cisco Systems",
    "00:0B:FC": "Cisco Systems",
    "00:0B:FD": "Cisco Systems",
    "00:0C:30": "Cisco Systems",
    "00:0C:31": "Cisco Systems",
    "00:0C:85": "Cisco Systems",
    "00:0C:86": "Cisco Systems",
    "00:0C:CE": "Cisco Systems",
    "00:0C:CF": "Cisco Systems",
    "00:0D:28": "Cisco Systems",
    "00:0D:29": "Cisco Systems",
    "00:0D:65": "Cisco Systems",
    "00:0D:66": "Cisco Systems",
    "00:0D:9D": "Cisco Systems",
    "00:0D:9E": "Cisco Systems",
    "00:0D:BD": "Cisco Systems",
    "00:0D:BE": "Cisco Systems",
    "00:0D:EC": "Cisco Systems",
    "00:0D:ED": "Cisco Systems",
    "00:0E:38": "Cisco Systems",
    "00:0E:39": "Cisco Systems",
    "00:0E:7F": "Cisco Systems",
    "00:0E:83": "Cisco Systems",
    "00:0E:84": "Cisco Systems",
    "00:0E:D6": "Cisco Systems",
    "00:0E:D7": "Cisco Systems",
    "00:0F:23": "Cisco Systems",
    "00:0F:24": "Cisco Systems",
    "00:0F:8F": "Cisco Systems",
    "00:0F:90": "Cisco Systems",
    "00:0F:C8": "Cisco Systems",
    "00:0F:C9": "Cisco Systems",
    "00:0F:F7": "Cisco Systems",
    "00:0F:F8": "Cisco Systems",
    "00:10:07": "Cisco Systems",
    "00:10:08": "Cisco Systems",
    "00:10:7B": "Cisco Systems",
    "00:10:7C": "Cisco Systems",
    "00:10:A6": "Cisco Systems",
    "00:10:A7": "Cisco Systems",
    "00:10:F3": "Cisco Systems",
    "00:10:F4": "Cisco Systems",
    "00:11:20": "Cisco Systems",
    "00:11:21": "Cisco Systems",
    "00:11:5C": "Cisco Systems",
    "00:11:5D": "Cisco Systems",
    "00:11:92": "Cisco Systems",
    "00:11:93": "Cisco Systems",
    "00:11:BB": "Cisco Systems",
    "00:11:BC": "Cisco Systems",
    "00:12:00": "Cisco Systems",
    "00:12:01": "Cisco Systems",
    "00:12:43": "Cisco Systems",
    "00:12:44": "Cisco Systems",
    "00:12:7F": "Cisco Systems",
    "00:12:80": "Cisco Systems",
    "00:12:D9": "Cisco Systems",
    "00:12:DA": "Cisco Systems",
    "00:13:19": "Cisco Systems",
    "00:13:1A": "Cisco Systems",
    "00:13:60": "Cisco Systems",
    "00:13:61": "Cisco Systems",
    "00:13:7F": "Cisco Systems",
    "00:13:80": "Cisco Systems",
    "00:13:C3": "Cisco Systems",
    "00:13:C4": "Cisco Systems",
    "00:14:1B": "Cisco Systems",
    "00:14:1C": "Cisco Systems",
    "00:14:69": "Cisco Systems",
    "00:14:6A": "Cisco Systems",
    "00:14:A8": "Cisco Systems",
    "00:14:A9": "Cisco Systems",
    "00:14:ED": "Cisco Systems",
    "00:14:EE": "Cisco Systems",
    "00:15:2B": "Cisco Systems",
    "00:15:2C": "Cisco Systems",
    "00:15:62": "Cisco Systems",
    "00:15:63": "Cisco Systems",
    "00:15:C5": "Cisco Systems",
    "00:15:C6": "Cisco Systems",
    "00:15:FA": "Cisco Systems",
    "00:15:FB": "Cisco Systems",
    "00:16:46": "Cisco Systems",
    "00:16:47": "Cisco Systems",
    "00:16:9C": "Cisco Systems",
    "00:16:9D": "Cisco Systems",
    "00:16:C7": "Cisco Systems",
    "00:16:C8": "Cisco Systems",
    "00:17:0E": "Cisco Systems",
    "00:17:0F": "Cisco Systems",
    "00:17:59": "Cisco Systems",
    "00:17:5A": "Cisco Systems",
    "00:17:94": "Cisco Systems",
    "00:17:95": "Cisco Systems",
    "00:17:DF": "Cisco Systems",
    "00:17:E0": "Cisco Systems",
    "00:18:18": "Cisco Systems",
    "00:18:19": "Cisco Systems",
    "00:18:73": "Cisco Systems",
    "00:18:74": "Cisco Systems",
    "00:18:B9": "Cisco Systems",
    "00:18:BA": "Cisco Systems",
    "00:18:F8": "Cisco Systems",
    "00:18:F9": "Cisco Systems",
    "00:19:06": "Cisco Systems",
    "00:19:07": "Cisco Systems",
    "00:19:2F": "Cisco Systems",
    "00:19:30": "Cisco Systems",
    "00:19:55": "Cisco Systems",
    "00:19:56": "Cisco Systems",
    "00:19:A9": "Cisco Systems",
    "00:19:AA": "Cisco Systems",
    "00:19:E7": "Cisco Systems",
    "00:19:E8": "Cisco Systems",
    "00:1A:2F": "Cisco Systems",
    "00:1A:30": "Cisco Systems",
    "00:1A:6B": "Cisco Systems",
    "00:1A:6C": "Cisco Systems",
    "00:1A:A1": "Cisco Systems",
    "00:1A:A2": "Cisco Systems",
    "00:1A:E2": "Cisco Systems",
    "00:1A:E3": "Cisco Systems",
    "00:1B:0C": "Cisco Systems",
    "00:1B:0D": "Cisco Systems",
    "00:1B:2A": "Cisco Systems",
    "00:1B:2B": "Cisco Systems",
    "00:1B:53": "Cisco Systems",
    "00:1B:54": "Cisco Systems",
    "00:1B:90": "Cisco Systems",
    "00:1B:91": "Cisco Systems",
    "00:1B:D4": "Cisco Systems",
    "00:1B:D5": "Cisco Systems",
    "00:1C:0F": "Cisco Systems",
    "00:1C:10": "Cisco Systems",
    "00:1C:57": "Cisco Systems",
    "00:1C:58": "Cisco Systems",
    "00:1C:B0": "Cisco Systems",
    "00:1C:B1": "Cisco Systems",
    "00:1D:45": "Cisco Systems",
    "00:1D:46": "Cisco Systems",
    "00:1D:70": "Cisco Systems",
    "00:1D:71": "Cisco Systems",
    "00:1D:A1": "Cisco Systems",
    "00:1D:A2": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:1E:14": "Cisco Systems",
    "00:1E:49": "Cisco Systems",
    "00:1E:4A": "Cisco Systems",
    "00:1E:7A": "Cisco Systems",
    "00:1E:7B": "Cisco Systems",
    "00:1E:BE": "Cisco Systems",
    "00:1E:BF": "Cisco Systems",
    "00:1F:26": "Cisco Systems",
    "00:1F:27": "Cisco Systems",
    "00:1F:6C": "Cisco Systems",
    "00:1F:6D": "Cisco Systems",
    "00:1F:9D": "Cisco Systems",
    "00:1F:9E": "Cisco Systems",
    "00:1F:CA": "Cisco Systems",
    "00:1F:CB": "Cisco Systems",
    "00:21:1C": "Cisco Systems",
    "00:21:1D": "Cisco Systems",
    "05:EB:1A": "Cisco Systems",
    "08:96:AD": "Cisco Systems",
    "18:8B:9F": "Cisco Systems",
    "2C:33:11": "Cisco Systems",
    "3C:08:F6": "Cisco Systems",
    "4C:4E:35": "Cisco Systems",
    "5C:5B:35": "Cisco Systems",
    "70:38:EE": "Cisco Systems",
    "84:78:AC": "Cisco Systems",
    "A0:3D:6F": "Cisco Systems",
    "B4:14:89": "Cisco Systems",
    "C8:F9:F9": "Cisco Systems",
    "E4:C7:22": "Cisco Systems",

    # Arista Networks
    "00:1C:73": "Arista Networks",
    "74:83:EF": "Arista Networks",
    "98:5A:EB": "Arista Networks",
    "D8:B1:90": "Arista Networks",

    # Juniper Networks
    "00:1F:12": "Juniper Networks",
    "00:26:88": "Juniper Networks",
    "3C:61:04": "Juniper Networks",
    "80:71:1D": "Juniper Networks",
    "D4:04:CD": "Juniper Networks",

    # Hewlett Packard Enterprise (HP/Aruba)
    "00:09:B7": "HP/Aruba",
    "00:0F:20": "HP/Aruba",
    "00:11:0A": "HP/Aruba",
    "00:16:35": "HP/Aruba",
    "00:17:A4": "HP/Aruba",
    "00:1E:0B": "HP/Aruba",
    "00:22:64": "HP/Aruba",
    "00:25:B3": "HP/Aruba",
    "2C:76:8A": "HP/Aruba",
    "70:10:5C": "HP/Aruba",
    "A0:D3:C1": "HP/Aruba",
    "C8:CB:B8": "HP/Aruba",

    # Dell
    "00:14:22": "Dell",
    "00:1D:09": "Dell",
    "00:25:64": "Dell",
    "14:18:77": "Dell",
    "24:B6:FD": "Dell",
    "A4:1F:72": "Dell",
    "F8:DB:88": "Dell",

    # Ubiquiti Networks
    "00:27:22": "Ubiquiti Networks",
    "04:18:D6": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "74:83:C2": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "80:2A:A8": "Ubiquiti Networks",
    "90:17:AC": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "F0:9F:C2": "Ubiquiti Networks",

    # Fortinet
    "00:09:0F": "Fortinet",
    "00:21:07": "Fortinet",
    "70:4C:A5": "Fortinet",
    "84:B1:53": "Fortinet",
    "94:B4:0F": "Fortinet",
    "C0:8A:DE": "Fortinet",

    # Palo Alto Networks
    "00:1B:17": "Palo Alto Networks",
    "08:30:6B": "Palo Alto Networks",
    "D4:1D:71": "Palo Alto Networks",
}

# Offline IEEE OUI database local file path
OUI_FILE = "oui.txt"

def normalize_mac(mac_str):
    """
    Normalizes a MAC address string into AA:BB:CC:DD:EE:FF format.
    Accepts:
    - aabb.ccdd.eeff
    - aa:bb:cc:dd:ee:ff / AA:BB:CC:DD:EE:FF
    - aa-bb-cc-dd-ee-ff
    """
    if not mac_str:
        return ""
    # Remove separators
    cleaned = re.sub(r'[^a-fA-F0-9]', '', mac_str)
    if len(cleaned) != 12:
        return mac_str # Return as-is if malformed
    
    # Format as AA:BB:CC:DD:EE:FF
    octets = [cleaned[i:i+2].upper() for i in range(0, 12, 2)]
    return ":".join(octets)

def get_oui_prefix(mac_str):
    """Extracts the 24-bit OUI prefix (AA:BB:CC) from a MAC address."""
    normalized = normalize_mac(mac_str)
    if len(normalized) >= 8:
        return normalized[:8]
    return ""

# Global cache for dynamic OUI lookups loaded from file
_loaded_ouis = {}

def load_oui_file():
    """Loads a standard IEEE OUI text file if present in the local directory."""
    global _loaded_ouis
    if _loaded_ouis:
        return True
    
    if not os.path.exists(OUI_FILE):
        return False
    
    # Parses format:
    # 00-00-0C   (hex)		CISCO SYSTEMS, INC.
    # 00000C     (base 16)		CISCO SYSTEMS, INC.
    pattern = re.compile(r'^([0-9a-fA-F]{2})[-:]([0-9a-fA-F]{2})[-:]([0-9a-fA-F]{2})\s+\(hex\)\s+(.+)$')
    pattern_flat = re.compile(r'^([0-9a-fA-F]{6})\s+\(base 16\)\s+(.+)$')
    
    try:
        with open(OUI_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = pattern.match(line)
                if match:
                    prefix = f"{match.group(1)}:{match.group(2)}:{match.group(3)}".upper()
                    _loaded_ouis[prefix] = match.group(4).strip()
                    continue
                match_flat = pattern_flat.match(line)
                if match_flat:
                    h = match_flat.group(1)
                    prefix = f"{h[0:2]}:{h[2:4]}:{h[4:6]}".upper()
                    _loaded_ouis[prefix] = match_flat.group(2).strip()
    except Exception as e:
        print(f"Error reading OUI file: {e}")
        return False
    return True

def download_oui_db():
    """Downloads the official IEEE OUI registry for local offline use."""
    url = "http://standards-oui.ieee.org/oui/oui.txt"
    print("Downloading IEEE OUI Registry (approx 5MB)...")
    try:
        urllib.request.urlretrieve(url, OUI_FILE)
        print(f"IEEE OUI database successfully saved to {OUI_FILE}")
        return True
    except Exception as e:
        print(f"Failed to download OUI registry: {e}")
        return False

def get_vendor(mac_str):
    """
    Returns the manufacturer/vendor name for a MAC address.
    First checks the local OUI text database (if present).
    Second checks the bundled common network OUIs.
    Returns 'Unknown' if not found.
    """
    if not mac_str:
        return "Unknown"
    
    prefix = get_oui_prefix(mac_str)
    if not prefix:
        return "Unknown"
    
    # Check loaded IEEE file
    if load_oui_file():
        if prefix in _loaded_ouis:
            return _loaded_ouis[prefix]
    
    # Check built-in fallback dictionary
    if prefix in COMMON_OUIS:
        return COMMON_OUIS[prefix]
        
    return "Unknown"

if __name__ == "__main__":
    # Test script
    test_macs = [
        "00:00:0c:12:34:56",
        "aabb.cc11.2233",
        "00-1C-73-AA-BB-CC",
        "1418.7700.1122",
        "11:22:33:44:55:66"
    ]
    for mac in test_macs:
        print(f"MAC: {mac} -> Normalized: {normalize_mac(mac)} -> Vendor: {get_vendor(mac)}")
