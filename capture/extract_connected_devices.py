#!/usr/bin/env python3
"""
Android Forensic Framework – Connected Devices & Hardware Peripherals Module
Extracts historical and currently connected physical/wireless peripherals:
  • USB Devices (`dumpsys usb`): Connected PCs, OTG flash drives, USB audio, and charging accessories.
  • Bluetooth Peripherals (`dumpsys bluetooth_manager`): Paired & connected headphones, smart watches, car stereos (`MAC`, `Name`).
  • Wi-Fi Direct & Hotspot Clients (`dumpsys wifip2p`, `dumpsys tethering`): P2P connected phones and tethered laptops.
  • Companion Wearables & Cast TVs (`dumpsys companiondevice`, `dumpsys media_router`): Synced smartwatches and screen cast destinations.

Exports to SQLite (`connected_devices_registry.db`), CSV, JSON, and raw diagnostic dumps.

Usage:
  python capture/extract_connected_devices.py --output evidence/CASE-CONNECTED-DEVICES
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
log = logging.getLogger("ConnectedDevicesExtractor")

class ConnectedDevicesExtractor:
    def __init__(self, output_dir: Path, adb_path: Path = None, serial: str | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir = self.output_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.parsed_dir = self.output_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)
        self.adb_path = adb_path or self._find_adb()
        self.serial = serial

    def _find_adb(self) -> Path:
        local_adb = project_root / "capture" / "components" / "adb-tools" / "windows" / "platform-tools" / "adb.exe"
        if local_adb.exists():
            return local_adb
        return Path("adb")

    def _run_adb(self, args: list[str]) -> tuple[int, str, str]:
        cmd = [str(self.adb_path), *( ["-s", self.serial] if self.serial else [] ), *args]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return 1, "", str(e)

    def extract_all(self) -> dict:
        """Runs full acquisition of connected peripherals across USB, Bluetooth, P2P, and Companion services."""
        log.info("═" * 60)
        log.info(" 🔌 STARTING CONNECTED DEVICES & PERIPHERALS EXTRACTION")
        log.info("═" * 60)

        devices_list = []

        # 1. USB Connected Accessories & PC Connection (`dumpsys usb`)
        log.info("🔍 Method 1: Scanning USB accessories, OTG drives & Host connections (`dumpsys usb`)...")
        usb_devs = self._extract_usb()
        if usb_devs:
            log.info(f"✅ Extracted {len(usb_devs)} USB device profiles/connections!")
            devices_list.extend(usb_devs)

        # 2. Bluetooth Paired & Connected Peripherals (`dumpsys bluetooth_manager`)
        log.info("🔍 Method 2: Harvesting paired & active Bluetooth devices (`dumpsys bluetooth_manager`)...")
        bt_devs = self._extract_bluetooth()
        if bt_devs:
            log.info(f"✅ Extracted {len(bt_devs)} Bluetooth paired/connected devices (`MAC`, `Name`)!")
            devices_list.extend(bt_devs)

        # 3. Wi-Fi Direct (P2P) & Hotspot Connected Clients (`dumpsys wifip2p`, `dumpsys tethering`)
        log.info("🔍 Method 3: Checking Wi-Fi P2P peers and Hotspot/Tethering clients...")
        p2p_devs = self._extract_p2p_and_tethering()
        if p2p_devs:
            log.info(f"✅ Extracted {len(p2p_devs)} P2P / Hotspot connected clients!")
            devices_list.extend(p2p_devs)

        # 4. Companion Wearables & Media Cast Devices (`dumpsys companiondevice`, `dumpsys media_router`)
        log.info("🔍 Method 4: Scanning companion wearables (Galaxy Watch) and Media Cast TVs...")
        comp_devs = self._extract_companion_and_cast()
        if comp_devs:
            log.info(f"✅ Extracted {len(comp_devs)} companion/cast devices!")
            devices_list.extend(comp_devs)

        # Save all records
        devices_list.sort(key=lambda x: x.get("device_type", ""), reverse=False)
        if devices_list:
            self._save_records(devices_list, "connected_devices_registry")

        log.info("═" * 60)
        log.info(" 📊 CONNECTED DEVICES EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Total Connected / Paired Devices: {len(devices_list)}")
        for dtype in ("USB", "Bluetooth", "Wi-Fi P2P / Hotspot", "Companion Wearable / Cast"):
            cnt = sum(1 for d in devices_list if d.get("device_type") == dtype)
            log.info(f"   └─ {dtype:<25}: {cnt}")
        log.info(f"  Output Directory: {self.output_dir.resolve()}")
        log.info("═" * 60)

        return {"devices": devices_list}

    def _extract_usb(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "usb"])
        if code != 0 or not out.strip():
            return []

        dump_file = self.raw_dir / "dumpsys_usb.txt"
        dump_file.write_text(out, encoding="utf-8")

        usb_devs = []
        # Parse current functions / connected host state
        if "Current Functions:" in out or "Connected:" in out:
            conn_match = re.search(r'mConnected:\s*([a-zA-Z0-9]+)', out)
            func_match = re.search(r'Current Functions:\s*([a-zA-Z0-9_,]+)', out)
            is_conn = conn_match.group(1).lower() == "true" if conn_match else ("Connected: true" in out)
            func = func_match.group(1) if func_match else "mtp/adb"

            usb_devs.append({
                "device_type": "USB",
                "device_name": f"USB Cable / Host Connection ({func.upper()})",
                "hardware_identifier": "USB Port",
                "connection_status": "Active / Connected" if is_conn else "Disconnected",
                "last_seen_or_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": f"Functions: {func} | Host connected state: {is_conn}"
            })

        # Parse attached USB devices (DeviceFilter / UsbDevice)
        dev_blocks = re.findall(r'UsbDevice[\[\{]([^\]\}]+)[\]\}]', out)
        for b in dev_blocks:
            name_match = re.search(r'mProductName=([^,]+)', b)
            mfg_match = re.search(r'mManufacturerName=([^,]+)', b)
            serial_match = re.search(r'mSerialNumber=([^,]+)', b)
            id_match = re.search(r'mDeviceId=([^,]+)', b)

            name = name_match.group(1) if name_match and name_match.group(1) != "null" else "USB Accessory"
            mfg = mfg_match.group(1) if mfg_match and mfg_match.group(1) != "null" else "Unknown Manufacturer"
            serial = serial_match.group(1) if serial_match and serial_match.group(1) != "null" else "N/A"

            usb_devs.append({
                "device_type": "USB",
                "device_name": f"{mfg} {name}".strip(),
                "hardware_identifier": f"Serial: {serial} (ID: {id_match.group(1) if id_match else 'N/A'})",
                "connection_status": "Connected Peripheral",
                "last_seen_or_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": b[:150]
            })

        return usb_devs

    def _extract_bluetooth(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "bluetooth_manager"])
        if code != 0 or not out.strip():
            return []

        dump_file = self.raw_dir / "dumpsys_bluetooth_manager.txt"
        dump_file.write_text(out, encoding="utf-8")

        bt_devs = []
        # Parse Bonded devices / active profiles
        # Pattern: 00:11:22:33:44:55 [Galaxy Buds2 Pro] or address: 00:11:22:33:44:55 name: Galaxy Watch
        lines = out.splitlines()
        for line in lines:
            line_str = line.strip()
            mac_match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line_str)
            if mac_match and ("name:" in line_str.lower() or "[" in line_str or "bonded" in line_str.lower() or "connected" in line_str.lower()):
                mac = mac_match.group(1).upper()
                name = "Unknown Bluetooth Device"
                name_match = re.search(r'name:\s*([^,\]\s]+(?:\s+[^,\]\s]+)*)', line_str, re.IGNORECASE)
                if not name_match:
                    name_match = re.search(r'\[([^\]]+)\]', line_str)
                if name_match and not re.match(r'^[0-9a-fA-F:]+$', name_match.group(1)):
                    name = name_match.group(1)

                status = "Paired / Bonded"
                if "connected" in line_str.lower() and "disconnected" not in line_str.lower():
                    status = "Active Connected"

                bt_devs.append({
                    "device_type": "Bluetooth",
                    "device_name": name,
                    "hardware_identifier": mac,
                    "connection_status": status,
                    "last_seen_or_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "details": line_str[:150]
                })

        # Dedup MACs
        seen = set()
        deduped = []
        for d in bt_devs:
            mac = d["hardware_identifier"]
            if mac not in seen and mac != "00:00:00:00:00:00":
                seen.add(mac)
                deduped.append(d)
        return deduped

    def _extract_p2p_and_tethering(self) -> list[dict]:
        p2p_list = []
        # Wi-Fi P2P
        code, out, _ = self._run_adb(["shell", "dumpsys", "wifip2p"])
        if code == 0 and out.strip():
            dump_file = self.raw_dir / "dumpsys_wifip2p.txt"
            dump_file.write_text(out, encoding="utf-8")
            for line in out.splitlines():
                if "deviceAddress=" in line or "deviceName=" in line:
                    mac_match = re.search(r'deviceAddress:\s*([0-9a-fA-F:]+)', line)
                    name_match = re.search(r'deviceName:\s*"?([^"\s,]+)' , line)
                    if mac_match:
                        p2p_list.append({
                            "device_type": "Wi-Fi P2P / Hotspot",
                            "device_name": name_match.group(1) if name_match else "P2P Peer",
                            "hardware_identifier": mac_match.group(1).upper(),
                            "connection_status": "Wi-Fi Direct Peer",
                            "last_seen_or_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "details": line.strip()[:150]
                        })

        # Tethering / Hotspot Clients via ARP
        code, out, _ = self._run_adb(["shell", "ip", "neigh", "show"])
        if code == 0 and out.strip():
            for line in out.splitlines():
                if "wlan1" in line or "swlan" in line or "ap0" in line or "tether" in line:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        p2p_list.append({
                            "device_type": "Wi-Fi P2P / Hotspot",
                            "device_name": f"Hotspot Client ({parts[0]})",
                            "hardware_identifier": parts[4].upper() if ":" in parts[4] else parts[0],
                            "connection_status": "Connected Hotspot Client",
                            "last_seen_or_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "details": line.strip()
                        })
        return p2p_list

    def _extract_companion_and_cast(self) -> list[dict]:
        comp_list = []
        # Companion devices (Wearables like Galaxy Watch)
        code, out, _ = self._run_adb(["shell", "dumpsys", "companiondevice"])
        if code == 0 and out.strip() and "No companion" not in out:
            dump_file = self.raw_dir / "dumpsys_companiondevice.txt"
            dump_file.write_text(out, encoding="utf-8")
            blocks = re.findall(r'Association[\[\{]([^\]\}]+)[\]\}]', out)
            for b in blocks:
                mac_match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', b)
                pkg_match = re.search(r'package=([a-zA-Z0-9_\.]+)', b)
                comp_list.append({
                    "device_type": "Companion Wearable / Cast",
                    "device_name": f"Companion Wearable ({pkg_match.group(1) if pkg_match else 'Synced Device'})",
                    "hardware_identifier": mac_match.group(1).upper() if mac_match else "Companion Association",
                    "connection_status": "Synced Companion Wearable",
                    "last_seen_or_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "details": b[:150]
                })

        # Media Router / Screen Cast destination TVs
        code, out, _ = self._run_adb(["shell", "dumpsys", "media_router"])
        if code == 0 and out.strip():
            dump_file = self.raw_dir / "dumpsys_media_router.txt"
            dump_file.write_text(out, encoding="utf-8")
            for line in out.splitlines():
                if "Route[" in line or "mName=" in line:
                    name_match = re.search(r'mName=([^,]+)', line)
                    if name_match and name_match.group(1) not in ("Phone", "Speaker", "Default"):
                        comp_list.append({
                            "device_type": "Companion Wearable / Cast",
                            "device_name": name_match.group(1).strip(),
                            "hardware_identifier": "Media Cast Destination",
                            "connection_status": "Cast Route / Smart TV",
                            "last_seen_or_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "details": line.strip()[:150]
                        })
        return comp_list

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
    parser = argparse.ArgumentParser(description="Android Connected Devices & Hardware Peripherals Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-CONNECTED-DEVICES", help="Output directory for connected devices artifacts")
    args = parser.parse_args()

    extractor = ConnectedDevicesExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
