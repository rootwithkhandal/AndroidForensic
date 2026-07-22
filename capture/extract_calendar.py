#!/usr/bin/env python3
"""
Android Forensic Framework – Device Calendar & Events Acquisition Module
Extracts Android calendar accounts (`content://com.android.calendar/calendars`), scheduled events
(`content://com.android.calendar/events`), and root `calendar.db` into SQLite, CSV, JSON, and iCalendar (.ics).

Usage:
  python capture/extract_calendar.py --output evidence/CASE-CALENDAR
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
log = logging.getLogger("CalendarExtractor")

class CalendarExtractor:
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
        """Runs full acquisition across device calendars and scheduled events."""
        log.info("═" * 60)
        log.info(" 📅 STARTING ANDROID CALENDAR & EVENTS EXTRACTION")
        log.info("═" * 60)

        results = {
            "calendars": [],
            "events": [],
            "root_db_file": None,
        }

        # 1. Query Calendars list
        log.info("🔍 Method 1: Querying Android Calendars Provider (`content://com.android.calendar/calendars`)...")
        calendars = self._query_calendars()
        if calendars:
            log.info(f"✅ Extracted {len(calendars)} calendar profiles/accounts!")
            results["calendars"] = calendars
            self._save_records(calendars, "device_calendars")
        else:
            log.warning("⚠️ Calendars query denied or returned 0 items (Requires READ_CALENDAR permission or root).")

        # Build calendar map for event resolution
        cal_map = {c["_id"]: c.get("calendar_displayName") or c.get("account_name", "Unknown") for c in calendars}

        # 2. Query Events list
        log.info("🔍 Method 2: Querying Android Calendar Events (`content://com.android.calendar/events`)...")
        events = self._query_events(cal_map)
        if events:
            log.info(f"✅ Extracted {len(events)} scheduled calendar events!")
            results["events"] = events
            self._save_records(events, "calendar_events")
            self._save_ics(events, "calendar_events.ics")
        else:
            log.warning("⚠️ Events query denied or returned 0 scheduled items.")

        # 3. Check Root (`su`) for /data/data/com.android.providers.calendar/databases/calendar.db
        log.info("🔍 Method 3: Checking for Root Access (`su`) to pull private calendar.db...")
        root_db = self._try_root_pull()
        if root_db:
            results["root_db_file"] = str(root_db)

        log.info("═" * 60)
        log.info(" 📊 CALENDAR EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Calendar Accounts: {len(results['calendars'])}")
        log.info(f"  Scheduled Events:  {len(results['events'])}")
        log.info(f"  Root DB Pulled:    {'Yes' if results['root_db_file'] else 'No'}")
        log.info(f"  Output Directory:  {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _query_calendars(self) -> list[dict]:
        uri = "content://com.android.calendar/calendars"
        code, out, err = self._run_adb(["shell", "content", "query", "--uri", uri])
        if code != 0 or "Permission Denial" in out or "Permission Denial" in err:
            return []

        records = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("Row:"):
                continue
            
            row_content = re.sub(r"^Row:\s*\d+\s*", "", line)
            pairs = re.findall(r"([a-zA-Z0-9__]+)=([^,]*)(?:,|$)", row_content)
            record = {}
            for k, v in pairs:
                record[k.strip()] = v.strip()

            clean_rec = {
                "_id": record.get("_id", ""),
                "calendar_displayName": record.get("calendar_displayName", "") or "Default Calendar",
                "account_name": record.get("account_name", "") or "Local/Unknown",
                "account_type": record.get("account_type", ""),
                "ownerAccount": record.get("ownerAccount", ""),
                "visible": 1 if record.get("visible") == "1" else 0,
            }
            records.append(clean_rec)
        return records

    def _query_events(self, cal_map: dict[str, str]) -> list[dict]:
        uri = "content://com.android.calendar/events"
        code, out, err = self._run_adb(["shell", "content", "query", "--uri", uri])
        if code != 0 or "Permission Denial" in out or "Permission Denial" in err:
            return []

        records = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("Row:"):
                continue
            
            row_content = re.sub(r"^Row:\s*\d+\s*", "", line)
            pairs = re.findall(r"([a-zA-Z0-9__]+)=([^,]*)(?:,|$)", row_content)
            record = {}
            for k, v in pairs:
                record[k.strip()] = v.strip()

            cal_id = record.get("calendar_id", "")
            cal_name = cal_map.get(cal_id, f"Calendar ID {cal_id}")

            # Parse start and end timestamps
            def parse_ts(val: str) -> tuple[int, str]:
                if val and val.isdigit():
                    ts = int(val)
                    ts_sec = ts / 1000.0 if len(val) > 11 else ts
                    try:
                        dt = datetime.datetime.fromtimestamp(ts_sec)
                        return ts, dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                return 0, "N/A"

            start_ts, start_dt = parse_ts(record.get("dtstart", ""))
            end_ts, end_dt = parse_ts(record.get("dtend", ""))

            clean_evt = {
                "event_id": record.get("_id", ""),
                "calendar_id": cal_id,
                "calendar_name": cal_name,
                "title": record.get("title", "") or "Untitled Event",
                "description": record.get("description", ""),
                "location": record.get("eventLocation", ""),
                "organizer": record.get("organizer", ""),
                "start_time_local": start_dt,
                "end_time_local": end_dt,
                "all_day": 1 if record.get("allDay") == "1" else 0,
                "start_ts_raw": start_ts,
            }
            records.append(clean_evt)

        records.sort(key=lambda x: x["start_ts_raw"], reverse=True)
        return records

    def _try_root_pull(self) -> Path | None:
        """Checks if device is rooted (`su`) and copies private calendar.db."""
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root detected. Skipping private /data/data/ calendar.db pull.")
            return None

        remote_db = "/data/data/com.android.providers.calendar/databases/calendar.db"
        code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_db} /data/local/tmp/temp_cal.db && chmod 777 /data/local/tmp/temp_cal.db'"])
        if code == 0:
            local_dest = self.raw_dir / "pulled_calendar.db"
            self._run_adb(["pull", "/data/local/tmp/temp_cal.db", str(local_dest)])
            self._run_adb(["shell", "rm", "/data/local/tmp/temp_cal.db"])
            if local_dest.exists():
                log.info(f"✅ Pulled root calendar database: {local_dest}")
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

    def _save_ics(self, events: list[dict], filename: str) -> None:
        if not events:
            return
        ics_path = self.parsed_dir / filename
        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//AndroidForensic//CalendarExtractor//EN"
        ]
        for e in events:
            lines.append("BEGIN:VEVENT")
            lines.append(f"SUMMARY:{e.get('title', 'Untitled Event')}")
            if e.get("description"):
                lines.append(f"DESCRIPTION:{e['description']}")
            if e.get("location"):
                lines.append(f"LOCATION:{e['location']}")
            if e.get("organizer"):
                lines.append(f"ORGANIZER;CN={e['organizer']}:MAILTO:{e['organizer']}")
            
            # Format start/end for iCalendar (YYYYMMDDTHHMMSSZ or raw)
            dt_s = re.sub(r'[- :]', '', str(e.get("start_time_local", "")))
            dt_e = re.sub(r'[- :]', '', str(e.get("end_time_local", "")))
            if len(dt_s) >= 14: lines.append(f"DTSTART:{dt_s}")
            if len(dt_e) >= 14: lines.append(f"DTEND:{dt_e}")
            
            lines.append("END:VEVENT")
        lines.append("END:VCALENDAR")
        with open(ics_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log.info(f"💾 Saved iCalendar export: {ics_path}")

def main():
    parser = argparse.ArgumentParser(description="Android Device Calendar & Events Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-CALENDAR", help="Output directory for calendar artifacts")
    args = parser.parse_args()

    extractor = CalendarExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
