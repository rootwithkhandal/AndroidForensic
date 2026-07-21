#!/usr/bin/env python3
"""
Android Forensic Framework – Device Connectivity & Network History Module
Extracts Wi-Fi network history (`dumpsys wifi`, `WifiConfigStore.xml`), Bluetooth paired/connected
devices (`dumpsys bluetooth_manager`, `bt_config.conf`), USB history (`dumpsys usb`), and live TCP/UDP sockets.

Usage:
  python capture/extract_connectivity.py --output evidence/CASE-CONNECTIVITY
"""

import argparse
import csv
import datetime
import json
import logging
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)-8s │ %(message)s")
log = logging.getLogger("ConnectivityExtractor")

class ConnectivityExtractor:
    def __init__(self, output_dir: Path, adb_path: Path = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir = self.output_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.parsed_dir = self.output_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)
        self.adb_path = adb_path or self._find_adb()

    def _find_adb(self) -> Path:
        local_adb = project_root / "capture" / "components" / "adb-tools" / "windows" / "platform-tools" / "adb.exe"
        if local_adb.exists():
            return local_adb
        return Path("adb")

    def _run_adb(self, args: list[str]) -> tuple[int, str, str]:
        cmd = [str(self.adb_path)] + args
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return 1, "", str(e)

    def extract_all(self) -> dict:
        """Runs full connectivity acquisition across Wi-Fi, Bluetooth, USB, and Live Sockets."""
        log.info("═" * 60)
        log.info(" 🌐 STARTING ANDROID DEVICE CONNECTIVITY EXTRACTION")
        log.info("═" * 60)

        results = {
            "wifi_networks": [],
            "bluetooth_devices": [],
            "live_connections": [],
            "raw_dumps": []
        }

        # 1. Wi-Fi Acquisition
        log.info("🔍 Method 1: Extracting Wi-Fi history (`dumpsys wifi`)...")
        wifi_list, wifi_raw = self._extract_wifi()
        if wifi_list:
            log.info(f"✅ Extracted {len(wifi_list)} configured/historical Wi-Fi networks!")
            results["wifi_networks"] = wifi_list
            self._save_records(wifi_list, "wifi_networks")
        if wifi_raw: results["raw_dumps"].append(str(wifi_raw))

        # 2. Bluetooth Acquisition
        log.info("🔍 Method 2: Extracting Bluetooth paired & connected devices (`dumpsys bluetooth_manager`)...")
        bt_list, bt_raw = self._extract_bluetooth()
        if bt_list:
            log.info(f"✅ Extracted {len(bt_list)} bonded/paired Bluetooth devices!")
            results["bluetooth_devices"] = bt_list
            self._save_records(bt_list, "bluetooth_devices")
        if bt_raw: results["raw_dumps"].append(str(bt_raw))

        # 3. USB Connectivity Dump
        log.info("🔍 Method 3: Dumping USB device & accessory history (`dumpsys usb`)...")
        usb_raw = self._dump_service("usb", "dumpsys_usb")
        if usb_raw: results["raw_dumps"].append(str(usb_raw))

        # 4. Live TCP/UDP Sockets & Connectivity
        log.info("🔍 Method 4: Capturing live TCP/UDP network connections (`netstat / ss`)...")
        conn_list = self._extract_live_sockets()
        if conn_list:
            log.info(f"✅ Captured {len(conn_list)} active network socket connections!")
            results["live_connections"] = conn_list
            self._save_records(conn_list, "live_network_connections")

        # 5. Check Root (`su`) for WifiConfigStore.xml and bt_config.conf
        log.info("🔍 Method 5: Checking for Root (`su`) to pull Wi-Fi passwords & BT configuration...")
        self._try_root_pulls()

        log.info("═" * 60)
        log.info(" 📊 CONNECTIVITY EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Wi-Fi Networks Found:    {len(results['wifi_networks'])}")
        log.info(f"  Bluetooth Devices Found: {len(results['bluetooth_devices'])}")
        log.info(f"  Live Network Sockets:    {len(results['live_connections'])}")
        log.info(f"  Raw Service Dumps Saved: {len(results['raw_dumps'])}")
        log.info(f"  Output Directory:        {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _extract_wifi(self) -> tuple[list[dict], Path | None]:
        dump_file = self._dump_service("wifi", "dumpsys_wifi")
        code, out, _ = self._run_adb(["shell", "dumpsys", "wifi"])
        if code != 0:
            return [], dump_file

        wifi_networks = []
        # Parse ConfiguredNetworks / NetworkList
        # Example pattern in dumpsys wifi: ID: 0 SSID: "Home_WiFi" BSSID: aa:bb:cc... FQDN: null ...
        lines = out.splitlines()
        current_net = {}
        for line in lines:
            line = line.strip()
            if line.startswith("ID: ") or "SSID: " in line:
                if current_net and "ssid" in current_net:
                    wifi_networks.append(current_net)
                current_net = {}
                
                ssid_match = re.search(r'SSID:\s*"?([^"\n]+)"?', line)
                if ssid_match and ssid_match.group(1) != "null":
                    current_net["ssid"] = ssid_match.group(1).strip()
                
                bssid_match = re.search(r'BSSID:\s*([0-9a-fA-F:]+)', line)
                if bssid_match:
                    current_net["bssid"] = bssid_match.group(1).strip()
            
            if current_net and "KeyMgmt:" in line:
                current_net["security"] = line.split("KeyMgmt:")[-1].strip()
            elif current_net and ("lastConnected" in line or "last_seen" in line):
                current_net["last_seen_info"] = line.strip()

        if current_net and "ssid" in current_net:
            wifi_networks.append(current_net)

        # Dedup by SSID
        seen = set()
        deduped = []
        for w in wifi_networks:
            ssid = w.get("ssid")
            if ssid and ssid not in seen:
                seen.add(ssid)
                deduped.append({
                    "ssid": ssid,
                    "bssid": w.get("bssid", "Unknown"),
                    "security": w.get("security", "WPA2/Unknown"),
                    "last_seen_info": w.get("last_seen_info", "Recorded in ConfiguredNetworks"),
                })

        return deduped, dump_file

    def _extract_bluetooth(self) -> tuple[list[dict], Path | None]:
        dump_file = self._dump_service("bluetooth_manager", "dumpsys_bluetooth")
        code, out, _ = self._run_adb(["shell", "dumpsys", "bluetooth_manager"])
        if code != 0:
            return [], dump_file

        bt_devices = []
        # Look for MAC address patterns accompanied by names inside dumpsys bluetooth_manager
        # Pattern: 00:11:22:33:44:55 [Name: Airpods Pro, BondState: BOND_BONDED] or similar
        lines = out.splitlines()
        for line in lines:
            line_str = line.strip()
            mac_match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line_str)
            if mac_match:
                mac = mac_match.group(1).upper()
                if mac == "00:00:00:00:00:00": continue
                
                name = "Unknown Device"
                name_match = re.search(r'(?:Name|name):\s*([^,\n\r]+)', line_str)
                if name_match:
                    name = name_match.group(1).strip()
                elif "(" in line_str and ")" in line_str:
                    name = line_str.split("(")[-1].split("")[0].strip()

                status = "Bonded/Historical"
                if "CONNECTED" in line_str.upper():
                    status = "Currently Connected"
                elif "BONDED" in line_str.upper():
                    status = "Paired / Bonded"

                bt_devices.append({
                    "mac_address": mac,
                    "device_name": name,
                    "status": status,
                    "raw_context": line_str[:120]
                })

        # Dedup by MAC
        seen = set()
        deduped = []
        for b in bt_devices:
            mac = b["mac_address"]
            if mac not in seen:
                seen.add(mac)
                deduped.append(b)

        return deduped, dump_file

    def _extract_live_sockets(self) -> list[dict]:
        """Runs netstat or ss to check active network sockets."""
        code, out, _ = self._run_adb(["shell", "netstat", "-n", "-t", "-u"])
        if code != 0 or not out.strip():
            code, out, _ = self._run_adb(["shell", "ss", "-ntu"])

        connections = []
        if code == 0:
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and ("tcp" in parts[0].lower() or "udp" in parts[0].lower() or parts[0].lower() in ("tcp6", "udp6")):
                    proto = parts[0]
                    local_addr = parts[3] if len(parts) > 3 else "Unknown"
                    foreign_addr = parts[4] if len(parts) > 4 else "Unknown"
                    state = parts[5] if len(parts) > 5 else "ESTABLISHED"
                    
                    if foreign_addr not in ("0.0.0.0:*", ":::*", "*:*", "0.0.0.0:0"):
                        connections.append({
                            "protocol": proto.upper(),
                            "local_address": local_addr,
                            "remote_address": foreign_addr,
                            "connection_state": state,
                            "captured_at": datetime.datetime.now().isoformat()
                        })
        return connections

    def _dump_service(self, service_name: str, prefix: str) -> Path | None:
        code, out, _ = self._run_adb(["shell", "dumpsys", service_name])
        if code == 0 and out.strip():
            dump_file = self.raw_dir / f"{prefix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            dump_file.write_text(out, encoding="utf-8")
            return dump_file
        return None

    def _try_root_pulls(self) -> None:
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root detected. Skipping private WifiConfigStore.xml & bt_config.conf pulls.")
            return

        targets = [
            ("/data/misc/wifi/WifiConfigStore.xml", "pulled_WifiConfigStore.xml"),
            ("/data/misc/bluedroid/bt_config.conf", "pulled_bt_config.conf")
        ]
        for remote_path, local_name in targets:
            code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_path} /data/local/tmp/temp_conn && chmod 777 /data/local/tmp/temp_conn'"])
            if code == 0:
                dest = self.raw_dir / local_name
                self._run_adb(["pull", "/data/local/tmp/temp_conn", str(dest)])
                self._run_adb(["shell", "rm", "/data/local/tmp/temp_conn"])
                if dest.exists():
                    log.info(f"✅ Pulled root connectivity config: {dest}")

    def _save_records(self, records: list[dict], basename: str) -> None:
        if not records:
            return

        json_path = self.parsed_dir / f"{basename}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)
        log.info(f"💾 Saved JSON: {json_path}")

        csv_path = self.parsed_dir / f"{basename}.csv"
        keys = list(records[0].keys())
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(records)
        log.info(f"💾 Saved CSV:  {csv_path}")

        db_path = self.parsed_dir / f"{basename}.db"
        if db_path.exists(): db_path.unlink()
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        cols_sql = ", ".join([f'"{k}" TEXT' for k in keys])
        cur.execute(f"CREATE TABLE IF NOT EXISTS {basename} ({cols_sql})")
        
        placeholders = ", ".join(["?" for _ in keys])
        for r in records:
            cur.execute(f"INSERT INTO {basename} VALUES ({placeholders})", [str(r.get(k, "")) for k in keys])
        conn.commit()
        conn.close()
        log.info(f"💾 Saved SQL:  {db_path}")

def main():
    parser = argparse.ArgumentParser(description="Android Device Connectivity & Network History Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-CONNECTIVITY", help="Output directory for connectivity artifacts")
    args = parser.parse_args()

    extractor = ConnectivityExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
