#!/usr/bin/env python3
"""
Android Forensic Framework – System & Device Events Acquisition Module
Extracts chronological device events and system diagnostics:
  • UsageStats (`dumpsys usagestats`): Screen Unlock (`KEYGUARD_HIDDEN`), Screen Lock (`KEYGUARD_SHOWN`), App Foreground/Background transitions.
  • Battery & Power Events (`dumpsys batterystats`, `dumpsys power`): USB/Charger plug & unplug history, sleep/wake cycles.
  • System Events Buffer (`logcat -b events -d`): Process starts, crashes, and notification events.
  • Boot & Reboot History (`dumpsys bootstat`): Historical system reboots and shutdown reasons.

Exports to SQLite (`device_events_timeline.db`), CSV, JSON, and raw diagnostic text dumps.

Usage:
  python capture/extract_device_events.py --output evidence/CASE-EVENTS
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
log = logging.getLogger("EventsExtractor")

class EventsExtractor:
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
        """Runs full acquisition across system device events and diagnostics."""
        log.info("═" * 60)
        log.info(" ⚙️ STARTING SYSTEM & DEVICE EVENTS FORENSIC EXTRACTION")
        log.info("═" * 60)

        timeline_events = []
        app_usage_summary = []
        power_boot_events = []

        # 1. UsageStats & Screen Lock/Unlock Timeline (`dumpsys usagestats`)
        log.info("🔍 Method 1: Extracting UsageStats, Screen Unlock (`KEYGUARD`) & App Activity timeline...")
        usage_pts, usage_summary, usage_raw = self._extract_usagestats()
        if usage_pts:
            log.info(f"✅ Extracted {len(usage_pts)} chronological device & app activity events!")
            timeline_events.extend(usage_pts)
        if usage_summary:
            app_usage_summary = usage_summary

        # 2. Logcat System Events Buffer (`logcat -b events -d`)
        log.info("🔍 Method 2: Dumping system binary event buffer (`logcat -b events -d`)...")
        log_pts, log_raw = self._extract_logcat_events()
        if log_pts:
            log.info(f"✅ Extracted {len(log_pts)} system kernel/process events from log buffer!")
            timeline_events.extend(log_pts)

        # 3. Boot & Reboot Reasons (`dumpsys bootstat`)
        log.info("🔍 Method 3: Extracting historical boot & reboot reasons (`dumpsys bootstat`)...")
        boot_pts, boot_raw = self._extract_bootstat()
        if boot_pts:
            log.info(f"✅ Extracted {len(boot_pts)} boot/reboot history events!")
            power_boot_events.extend(boot_pts)
            timeline_events.extend(boot_pts)

        # 4. Power & Battery Status (`dumpsys power`, `dumpsys batterystats`)
        log.info("🔍 Method 4: Saving diagnostic Power & Battery state (`dumpsys power / batterystats`)...")
        self._dump_services(["power", "batterystats", "alarm"])

        # Sort all timeline events chronologically
        timeline_events.sort(key=lambda x: x.get("timestamp_sec", 0), reverse=True)

        if timeline_events:
            self._save_records(timeline_events, "device_events_timeline")
        if app_usage_summary:
            self._save_records(app_usage_summary, "app_usage_history")
        if power_boot_events:
            self._save_records(power_boot_events, "power_reboot_history")

        log.info("═" * 60)
        log.info(" 📊 DEVICE EVENTS EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Chronological Timeline Events: {len(timeline_events)}")
        log.info(f"  App Usage Summary Profiles:    {len(app_usage_summary)}")
        log.info(f"  Boot & Reboot Records:         {len(power_boot_events)}")
        log.info(f"  Output Directory:              {self.output_dir.resolve()}")
        log.info("═" * 60)

        return {"timeline_events": timeline_events, "app_usage_summary": app_usage_summary}

    def _extract_usagestats(self) -> tuple[list[dict], list[dict], Path | None]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "usagestats"])
        if code != 0 or not out.strip():
            return [], [], None

        dump_file = self.raw_dir / f"dumpsys_usagestats_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        dump_file.write_text(out, encoding="utf-8")

        events = []
        app_summary = []
        lines = out.splitlines()

        # Parse Event lines inside usagestats: time="2026-07-21 13:45:12" type=MOVE_TO_FOREGROUND package=com.whatsapp ...
        # Or raw lines: 2026-07-21 13:45:12 MOVE_TO_FOREGROUND com.whatsapp
        for line in lines:
            line_str = line.strip()
            # Look for timestamps and event types
            if any(evt in line_str for evt in ("MOVE_TO_FOREGROUND", "MOVE_TO_BACKGROUND", "KEYGUARD_SHOWN", "KEYGUARD_HIDDEN", "USER_INTERACTION", "DEVICE_SHUTDOWN", "SCREEN_INTERACTIVE", "SCREEN_NON_INTERACTIVE")):
                ts_match = re.search(r'([0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2})', line_str)
                if not ts_match:
                    ts_match = re.search(r'time="([^"]+)"', line_str)
                
                dt_str = ts_match.group(1) if ts_match else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ts_sec = int(datetime.datetime.now().timestamp())
                try:
                    dt = datetime.datetime.strptime(dt_str[:19], "%Y-%m-%d %H:%M:%S")
                    ts_sec = int(dt.timestamp())
                except Exception:
                    pass

                evt_type = "UNKNOWN_EVENT"
                for et in ("KEYGUARD_HIDDEN", "KEYGUARD_SHOWN", "MOVE_TO_FOREGROUND", "MOVE_TO_BACKGROUND", "DEVICE_SHUTDOWN", "SCREEN_INTERACTIVE", "SCREEN_NON_INTERACTIVE", "USER_INTERACTION"):
                    if et in line_str:
                        evt_type = et
                        break

                label_map = {
                    "KEYGUARD_HIDDEN": "🔓 Screen Unlocked by User",
                    "KEYGUARD_SHOWN": "🔒 Screen Locked / Keyguard Shown",
                    "MOVE_TO_FOREGROUND": "🟢 App Launched / Opened in Foreground",
                    "MOVE_TO_BACKGROUND": "🔴 App Minimized / Closed to Background",
                    "DEVICE_SHUTDOWN": "⚠️ Device Shutdown Event",
                    "SCREEN_INTERACTIVE": "💡 Screen Turned ON",
                    "SCREEN_NON_INTERACTIVE": "💤 Screen Turned OFF",
                    "USER_INTERACTION": "👆 User Interaction Detected"
                }

                pkg = "System/Device"
                pkg_match = re.search(r'(?:package=|package:\s*)([a-zA-Z0-9_\.]+)', line_str)
                if not pkg_match and "MOVE_TO_" in evt_type:
                    parts = line_str.split()
                    for p in parts:
                        if "." in p and not p.startswith("1") and not p.startswith("2") and "type=" not in p:
                            pkg = p
                            break
                elif pkg_match:
                    pkg = pkg_match.group(1)

                events.append({
                    "event_time": dt_str,
                    "timestamp_sec": ts_sec,
                    "event_type": evt_type,
                    "event_label": label_map.get(evt_type, evt_type),
                    "package_or_target": pkg,
                    "source": "UsageStats (`dumpsys usagestats`)",
                    "raw_context": line_str[:150]
                })

            # Parse aggregate app usage blocks: package=com.whatsapp totalTime="1h 20m" lastTime="2026-07-21..."
            if "totalTime=" in line_str and "lastTime=" in line_str:
                pkg_match = re.search(r'package=([a-zA-Z0-9_\.]+)', line_str)
                time_match = re.search(r'totalTime="([^"]+)"', line_str)
                last_match = re.search(r'lastTime="([^"]+)"', line_str)
                if pkg_match:
                    app_summary.append({
                        "package_name": pkg_match.group(1),
                        "total_foreground_time": time_match.group(1) if time_match else "0s",
                        "last_time_used": last_match.group(1) if last_match else "N/A",
                        "source": "UsageStats Aggregate"
                    })

        return events, app_summary, dump_file

    def _extract_logcat_events(self) -> tuple[list[dict], Path | None]:
        code, out, _ = self._run_adb(["shell", "logcat", "-b", "events", "-d", "-v", "threadtime"])
        if code != 0 or not out.strip():
            return [], None

        dump_file = self.raw_dir / f"logcat_events_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        dump_file.write_text(out, encoding="utf-8")

        events = []
        for line in out.splitlines():
            line_str = line.strip()
            # Pattern: 07-21 13:45:12.123 1000 1200 I am_proc_start: [0,12345,10188,com.whatsapp,activity,...]
            parts = line_str.split()
            if len(parts) >= 6 and (parts[0].startswith("0") or parts[0].startswith("1")):
                date_str = f"{datetime.datetime.now().year}-{parts[0]} {parts[1].split('.')[0]}"
                ts_sec = int(datetime.datetime.now().timestamp())
                try:
                    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                    ts_sec = int(dt.timestamp())
                except Exception:
                    pass

                tag_info = " ".join(parts[4:6])
                details = " ".join(parts[6:]) if len(parts) > 6 else ""

                if any(k in tag_info for k in ("am_proc_start", "screen_toggled", "am_crash", "am_anr", "battery_level", "boot_progress")):
                    events.append({
                        "event_time": date_str,
                        "timestamp_sec": ts_sec,
                        "event_type": tag_info.strip(":"),
                        "event_label": f"System Event ({tag_info.strip(':')})",
                        "package_or_target": details[:80],
                        "source": "Kernel/System Log Buffer (`logcat -b events`)",
                        "raw_context": line_str[:150]
                    })
        return events, dump_file

    def _extract_bootstat(self) -> tuple[list[dict], Path | None]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "bootstat"])
        if code != 0 or not out.strip():
            return [], None

        dump_file = self.raw_dir / "dumpsys_bootstat.txt"
        dump_file.write_text(out, encoding="utf-8")

        events = []
        for line in out.splitlines():
            line_str = line.strip()
            # Pattern: 1: reboot,userrequested 173... or similar
            if "reboot," in line_str or "shutdown," in line_str or "kernel_panic" in line_str or "power_button" in line_str:
                events.append({
                    "event_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "timestamp_sec": int(datetime.datetime.now().timestamp()),
                    "event_type": "BOOT_OR_REBOOT_EVENT",
                    "event_label": "🔄 System Boot / Reboot Record",
                    "package_or_target": line_str,
                    "source": "BootStat (`dumpsys bootstat`)",
                    "raw_context": line_str
                })
        return events, dump_file

    def _dump_services(self, services: list[str]) -> None:
        for svc in services:
            code, out, _ = self._run_adb(["shell", "dumpsys", svc])
            if code == 0 and out.strip():
                dest = self.raw_dir / f"dumpsys_{svc}.txt"
                dest.write_text(out, encoding="utf-8")
                log.info(f"💾 Saved Diagnostic Dump: {dest}")

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
    parser = argparse.ArgumentParser(description="Android System & Device Events Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-EVENTS", help="Output directory for system events artifacts")
    args = parser.parse_args()

    extractor = EventsExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
