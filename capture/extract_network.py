#!/usr/bin/env python3
"""
Android Forensic Framework – Network Diagnostics & Forensic Dump Module
Extracts comprehensive network state:
  • Network Interfaces (`ip addr`, `ifconfig`): IPv4, IPv6, and Hardware MAC Addresses (`wlan0`, `rmnet`, `p2p0`).
  • Active Network Connections (`netstat / ss`, `/proc/net/tcp`): Live TCP/UDP sockets, foreign IPs, and ports.
  • ARP Table & Neighbors (`ip neigh`, `arp`): Local IP-to-MAC address mapping of nearby routers/devices.
  • Routing Tables & Gateways (`ip route`, `dumpsys connectivity`): Default gateways, DNS resolvers, and VPNs.
  • Network Statistics (`dumpsys netstats`): Historical network usage per application.

Usage:
  python capture/extract_network.py --output evidence/CASE-NETWORK
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
log = logging.getLogger("NetworkExtractor")

class NetworkExtractor:
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
        """Runs full network diagnostics and extraction."""
        log.info("═" * 60)
        log.info(" 🌐 STARTING ANDROID NETWORK FORENSIC EXTRACTION")
        log.info("═" * 60)

        results = {
            "interfaces": [],
            "sockets": [],
            "arp_neighbors": [],
            "routes": [],
            "raw_dumps": []
        }

        # 1. Network Interfaces (IP & MAC Addresses)
        log.info("🔍 Method 1: Extracting Network Interfaces, IPv4/IPv6 & MAC Addresses (`ip addr show`)...")
        ifaces = self._extract_interfaces()
        if ifaces:
            log.info(f"✅ Extracted {len(ifaces)} network interface profiles (`wlan0`, `rmnet`, etc.)!")
            results["interfaces"] = ifaces
            self._save_records(ifaces, "network_interfaces")

        # 2. Active Sockets & Connections
        log.info("🔍 Method 2: Capturing live TCP/UDP socket connections & foreign IPs (`netstat / ss`)...")
        sockets = self._extract_sockets()
        if sockets:
            log.info(f"✅ Captured {len(sockets)} active network socket connections!")
            results["sockets"] = sockets
            self._save_records(sockets, "network_sockets")

        # 3. ARP Table & Network Neighbors
        log.info("🔍 Method 3: Dumping ARP neighbor table (`ip neigh show`)...")
        arp = self._extract_arp()
        if arp:
            log.info(f"✅ Extracted {len(arp)} local ARP neighbor mappings (MAC <-> IP)!")
            results["arp_neighbors"] = arp
            self._save_records(arp, "arp_neighbors")

        # 4. Routing Tables & Gateways
        log.info("🔍 Method 4: Dumping routing tables and default gateways (`ip route show`)...")
        routes = self._extract_routes()
        if routes:
            log.info(f"✅ Extracted {len(routes)} network route rules!")
            results["routes"] = routes
            self._save_records(routes, "network_routes")

        # 5. Diagnostic Service Dumps (`dumpsys connectivity`, `dumpsys netstats`)
        log.info("🔍 Method 5: Saving comprehensive diagnostic service dumps (`dumpsys connectivity / netstats`)...")
        dumps = self._dump_services()
        results["raw_dumps"] = dumps

        log.info("═" * 60)
        log.info(" 📊 NETWORK EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Network Interfaces: {len(results['interfaces'])}")
        log.info(f"  Active Sockets:     {len(results['sockets'])}")
        log.info(f"  ARP Neighbors:      {len(results['arp_neighbors'])}")
        log.info(f"  Routing Rules:      {len(results['routes'])}")
        log.info(f"  Diagnostic Dumps:   {len(results['raw_dumps'])} files saved")
        log.info(f"  Output Directory:   {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _extract_interfaces(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "ip", "addr", "show"])
        if code != 0 or not out.strip():
            code, out, _ = self._run_adb(["shell", "ifconfig"])
        if code != 0 or not out.strip():
            return []

        raw_file = self.raw_dir / "ip_addr_show.txt"
        raw_file.write_text(out, encoding="utf-8")

        ifaces = []
        # Parse blocks starting with index like: 1: lo: <LOOPBACK... or wlan0: ...
        blocks = re.split(r'\n(?=\d+:|\w+:)', out)
        for b in blocks:
            b_str = b.strip()
            if not b_str: continue

            name = "Unknown"
            name_match = re.search(r'^(?:\d+:\s*)?([a-zA-Z0-9_-]+):', b_str)
            if name_match: name = name_match.group(1)

            mac = "00:00:00:00:00:00"
            mac_match = re.search(r'link/[a-zA-Z]+\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', b_str)
            if not mac_match:
                mac_match = re.search(r'HWaddr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', b_str)
            if mac_match: mac = mac_match.group(1).upper()

            ipv4 = ""
            ipv4_matches = re.findall(r'inet\s+([0-9\.]+/?\d*)', b_str)
            if ipv4_matches: ipv4 = ", ".join(ipv4_matches)

            ipv6 = ""
            ipv6_matches = re.findall(r'inet6\s+([0-9a-fA-F:]+/?\d*)', b_str)
            if ipv6_matches: ipv6 = ", ".join(ipv6_matches)

            state = "UNKNOWN"
            if "state UP" in b_str or "UP," in b_str: state = "UP"
            elif "state DOWN" in b_str: state = "DOWN"

            if name != "Unknown":
                ifaces.append({
                    "interface_name": name,
                    "mac_address": mac,
                    "ipv4_addresses": ipv4,
                    "ipv6_addresses": ipv6,
                    "state": state,
                    "raw_details": b_str[:150].replace("\n", " ")
                })
        return ifaces

    def _extract_sockets(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "netstat", "-n", "-t", "-u", "-p"])
        if code != 0 or not out.strip() or "Permission" in out:
            code, out, _ = self._run_adb(["shell", "netstat", "-ntu"])
        if code != 0 or not out.strip():
            code, out, _ = self._run_adb(["shell", "ss", "-ntu"])

        raw_file = self.raw_dir / "netstat_sockets.txt"
        raw_file.write_text(out, encoding="utf-8")

        sockets = []
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and ("tcp" in parts[0].lower() or "udp" in parts[0].lower() or parts[0].lower() in ("tcp6", "udp6")):
                proto = parts[0].upper()
                local_addr = parts[3] if len(parts) > 3 else "Unknown"
                foreign_addr = parts[4] if len(parts) > 4 else "Unknown"
                state = parts[5] if len(parts) > 5 and not parts[5].startswith("-") and not parts[5].startswith("/") else "ESTABLISHED"
                pid_info = parts[-1] if len(parts) > 6 and ("/" in parts[-1] or parts[-1].isdigit()) else "N/A"

                if foreign_addr not in ("0.0.0.0:*", ":::*", "*:*", "0.0.0.0:0"):
                    sockets.append({
                        "protocol": proto,
                        "local_address": local_addr,
                        "foreign_address": foreign_addr,
                        "state": state,
                        "process_info": pid_info,
                        "captured_at": datetime.datetime.now().isoformat()
                    })
        return sockets

    def _extract_arp(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "ip", "neigh", "show"])
        if code != 0 or not out.strip():
            code, out, _ = self._run_adb(["shell", "arp", "-a"])

        raw_file = self.raw_dir / "arp_neighbors.txt"
        raw_file.write_text(out, encoding="utf-8")

        arp_list = []
        # Pattern ip neigh: 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        for line in out.splitlines():
            line_str = line.strip()
            if not line_str: continue

            ip_match = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', line_str)
            mac_match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line_str)
            dev_match = re.search(r'dev\s+([a-zA-Z0-9_-]+)', line_str)
            state_match = line_str.split()[-1] if line_str.split() else "UNKNOWN"

            if ip_match and mac_match:
                arp_list.append({
                    "ip_address": ip_match.group(1),
                    "mac_address": mac_match.group(1).upper(),
                    "interface": dev_match.group(1) if dev_match else "wlan0",
                    "reachability_state": state_match,
                    "raw_line": line_str
                })
        return arp_list

    def _extract_routes(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "ip", "route", "show"])
        if code != 0 or not out.strip():
            return []

        raw_file = self.raw_dir / "ip_route.txt"
        raw_file.write_text(out, encoding="utf-8")

        routes = []
        for line in out.splitlines():
            line_str = line.strip()
            if not line_str: continue

            destination = line_str.split()[0]
            via_match = re.search(r'via\s+([0-9\.]+)', line_str)
            dev_match = re.search(r'dev\s+([a-zA-Z0-9_-]+)', line_str)

            routes.append({
                "destination": destination,
                "gateway_via": via_match.group(1) if via_match else "Direct/Local",
                "interface": dev_match.group(1) if dev_match else "Unknown",
                "raw_route": line_str
            })
        return routes

    def _dump_services(self) -> list[str]:
        saved_dumps = []
        services = [
            ("connectivity", "dumpsys_connectivity.txt"),
            ("netstats", "dumpsys_netstats.txt"),
            ("wifi", "dumpsys_wifi.txt")
        ]
        for svc, fname in services:
            code, out, _ = self._run_adb(["shell", "dumpsys", svc])
            if code == 0 and out.strip():
                dest = self.raw_dir / fname
                dest.write_text(out, encoding="utf-8")
                saved_dumps.append(str(dest))
                log.info(f"💾 Saved Diagnostic Dump: {dest}")
        return saved_dumps

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
    parser = argparse.ArgumentParser(description="Android Network Diagnostics & Forensic Dump Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-NETWORK", help="Output directory for network forensic artifacts")
    args = parser.parse_args()

    extractor = NetworkExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
