#!/usr/bin/env python3
"""
Android Forensic Framework – Device Notifications Acquisition Module
Extracts active notifications and historical notification archive (`dumpsys notification --noredact`,
`NotificationRecord` entries, and `/data/system/notification_log.db` when rooted) into standardized
SQLite, CSV, and JSON formats.

Usage:
  python capture/extract_notifications.py --output evidence/CASE-NOTIFICATIONS
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
log = logging.getLogger("NotificationsExtractor")

class NotificationsExtractor:
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
        """Runs full notifications acquisition across active state and history archive."""
        log.info("═" * 60)
        log.info(" 🔔 STARTING ANDROID NOTIFICATIONS EXTRACTION")
        log.info("═" * 60)

        # Verify device connection
        code, out, _ = self._run_adb(["devices"])
        if code != 0 or "device\n" not in out and "device\r\n" not in out:
            log.error("❌ No authorized ADB device connected! Please check your USB cable and unlock the phone screen.")
            return {"notifications": [], "raw_dump": None}

        results = {
            "notifications": [],
            "raw_dump": None,
            "root_db_file": None,
        }

        # 1. Dump Dumpsys Notification (--noredact)
        log.info("🔍 Method 1: Extracting unredacted notification service dump (`dumpsys notification --noredact`)...")
        notif_list, raw_file = self._extract_dumpsys_notifications()
        if raw_file:
            results["raw_dump"] = str(raw_file)

        if notif_list:
            log.info(f"✅ Successfully extracted {len(notif_list)} active & archived notifications!")
            results["notifications"] = notif_list
            self._save_records(notif_list, "device_notifications")
        else:
            log.info("ℹ️ No active/archived notifications found or notification log is currently empty.")

        # 2. Check Root (`su`) for /data/system/notification_log.db
        log.info("🔍 Method 2: Checking for Root Access (`su`) to pull historical notification_log.db...")
        root_db = self._try_root_pull()
        if root_db:
            results["root_db_file"] = str(root_db)

        log.info("═" * 60)
        log.info(" 📊 NOTIFICATIONS EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Notifications Acquired: {len(results['notifications'])}")
        log.info(f"  Raw Dumpsys Saved:      {'Yes' if results['raw_dump'] else 'No'}")
        log.info(f"  Root DB Pulled:         {'Yes' if results['root_db_file'] else 'No'}")
        log.info(f"  Output Directory:       {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _extract_dumpsys_notifications(self) -> tuple[list[dict], Path | None]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "notification", "--noredact"])
        if code != 0 or not out.strip():
            code, out, _ = self._run_adb(["shell", "dumpsys", "notification"])
        if code != 0 or not out.strip():
            return [], None

        dump_file = self.raw_dir / f"dumpsys_notification_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        dump_file.write_text(out, encoding="utf-8")
        log.info(f"💾 Saved raw Dumpsys Notification: {dump_file}")

        notifications = []
        # Parse NotificationRecord blocks
        # Example: NotificationRecord(0x0: pkg=com.whatsapp user=UserHandle{0} id=1 tag=null key=0|com.whatsapp|1|null|10188):
        #   tickerText=... title=Papa text=Hello where are you postTime=173...
        lines = out.splitlines()
        current_notif = None

        for line in lines:
            line_str = line.strip()
            # Check if start of a NotificationRecord or archive entry
            if "NotificationRecord(" in line_str or "key=" in line_str and "pkg=" in line_str:
                if current_notif and current_notif.get("package"):
                    notifications.append(current_notif)
                
                current_notif = {
                    "package": "Unknown",
                    "title": "",
                    "text": "",
                    "post_time": 0,
                    "datetime_local": "N/A",
                    "status": "Active/Archived",
                    "raw_key": line_str[:150]
                }
                
                pkg_match = re.search(r'pkg=([a-zA-Z0-9_\.]+)', line_str)
                if pkg_match:
                    current_notif["package"] = pkg_match.group(1)

            if current_notif:
                # Extract title / text / ticker
                if "android.title=" in line_str or "title=" in line_str:
                    val = re.sub(r'.*(?:android\.title|title)=("?[^",\n\r]+"?).*', r'\1', line_str)
                    if val != line_str:
                        current_notif["title"] = val.strip().strip('"')
                
                if "android.text=" in line_str or "text=" in line_str:
                    val = re.sub(r'.*(?:android\.text|text)=("?[^",\n\r]+"?).*', r'\1', line_str)
                    if val != line_str:
                        current_notif["text"] = val.strip().strip('"')

                if "postTime=" in line_str or "when=" in line_str:
                    ts_match = re.search(r'(?:postTime|when)=([0-9]{10,13})', line_str)
                    if ts_match:
                        ts = ts_match.group(1)
                        current_notif["post_time"] = int(ts)
                        ts_sec = int(ts) / 1000.0 if len(ts) > 11 else int(ts)
                        try:
                            dt = datetime.datetime.fromtimestamp(ts_sec)
                            current_notif["datetime_local"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass

        if current_notif and current_notif.get("package"):
            notifications.append(current_notif)

        # Dedup based on package + title + text + post_time
        seen = set()
        deduped = []
        for n in notifications:
            key = (n["package"], n["title"], n["text"], n["post_time"])
            if key not in seen and (n["title"] or n["text"] or n["package"] != "Unknown"):
                seen.add(key)
                deduped.append(n)

        deduped.sort(key=lambda x: x.get("post_time", 0), reverse=True)
        return deduped, dump_file

    def _try_root_pull(self) -> Path | None:
        """Checks if device is rooted (`su`) and copies /data/system/notification_log.db."""
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root detected. Skipping private /data/system/notification_log.db pull.")
            return None

        paths = [
            "/data/system/notification_log.db",
            "/data/system/users/0/notification_log.db"
        ]
        for remote_db in paths:
            code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_db} /data/local/tmp/temp_notif.db && chmod 777 /data/local/tmp/temp_notif.db'"])
            if code == 0:
                local_dest = self.raw_dir / "pulled_notification_log.db"
                self._run_adb(["pull", "/data/local/tmp/temp_notif.db", str(local_dest)])
                self._run_adb(["shell", "rm", "/data/local/tmp/temp_notif.db"])
                if local_dest.exists():
                    log.info(f"✅ Pulled root historical notification log: {local_dest}")
                    return local_dest
        return None

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
    parser = argparse.ArgumentParser(description="Android Device Notifications Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-NOTIFICATIONS", help="Output directory for notifications artifacts")
    args = parser.parse_args()

    extractor = NotificationsExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
