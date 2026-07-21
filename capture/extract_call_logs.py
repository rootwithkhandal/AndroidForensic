#!/usr/bin/env python3
"""
Android Forensic Framework – Call Logs Acquisition Module
Extracts cellular call logs (`content://call_log/calls`, `dumpsys telecom`, `contacts2.db`)
and VoIP call records (WhatsApp `call_log` entries) into standardized CSV, JSON, and SQLite formats.

Usage:
  python capture/extract_call_logs.py --output evidence/CASE-20260721-CALLLOGS
"""

import argparse
import csv
import datetime
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    import adbutils
except ImportError:
    adbutils = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)-8s │ %(message)s")
log = logging.getLogger("CallLogExtractor")

class CallLogExtractor:
    def __init__(self, output_dir: Path, adb_path: Path = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir = self.output_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.parsed_dir = self.output_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)
        self.adb_path = adb_path or self._find_adb()

    def _find_adb(self) -> Path:
        """Find local adb binary or system adb."""
        local_adb = project_root / "capture" / "components" / "adb-tools" / "windows" / "platform-tools" / "adb.exe"
        if local_adb.exists():
            return local_adb
        return Path("adb")

    def _run_adb(self, args: list[str]) -> tuple[int, str, str]:
        """Execute adb shell command."""
        cmd = [str(self.adb_path)] + args
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return 1, "", str(e)

    def extract_all(self) -> dict:
        """Attempts all possible call log extraction channels."""
        log.info("═" * 60)
        log.info(" 📞 STARTING ANDROID CALL LOG EXTRACTION")
        log.info("═" * 60)

        results = {
            "content_query_calls": [],
            "dumpsys_telecom_file": None,
            "root_db_file": None,
            "voip_whatsapp_calls": [],
        }

        # 1. Try Content Provider Query (content://call_log/calls)
        log.info("🔍 Method 1: Querying Android Content Provider (content://call_log/calls)...")
        calls = self._query_content_provider()
        if calls:
            log.info(f"✅ Successfully extracted {len(calls)} cellular call records via Content Provider!")
            results["content_query_calls"] = calls
            self._save_records(calls, "cellular_call_logs")
        else:
            log.warning("⚠️ Content Provider query denied or returned 0 records (Requires READ_CALL_LOG permission or root).")

        # 2. Try Dumpsys Telecom / Call Log diagnostic dump
        log.info("🔍 Method 2: Extracting Dumpsys Telecom diagnostic history...")
        telecom_file = self._dump_telecom()
        if telecom_file:
            results["dumpsys_telecom_file"] = str(telecom_file)

        # 3. Try Root Database Pull (contacts2.db / calllog.db)
        log.info("🔍 Method 3: Checking for Root Access (`su`) to pull private calllog.db...")
        root_db = self._try_root_pull()
        if root_db:
            results["root_db_file"] = str(root_db)

        # 4. Aggregate WhatsApp Companion VoIP Call Logs if available
        log.info("🔍 Method 4: Scanning existing WhatsApp Companion dumps for VoIP Call Logs (`call_log`)...")
        voip_calls = self._extract_whatsapp_voip_calls()
        if voip_calls:
            log.info(f"✅ Extracted {len(voip_calls)} WhatsApp VoIP Call records!")
            results["voip_whatsapp_calls"] = voip_calls
            self._save_records(voip_calls, "whatsapp_voip_calls")

        log.info("═" * 60)
        log.info(" 📊 CALL LOG EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Cellular Calls Acquired: {len(results['content_query_calls'])}")
        log.info(f"  WhatsApp VoIP Calls:     {len(results['voip_whatsapp_calls'])}")
        log.info(f"  Output Directory:        {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _query_content_provider(self) -> list[dict]:
        """Queries content://call_log/calls over ADB shell."""
        # Query projection of standard fields
        uri = "content://call_log/calls"
        code, out, err = self._run_adb(["shell", "content", "query", "--uri", uri])
        if code != 0 or "Permission Denial" in out or "Permission Denial" in err:
            return []

        # Parse content query lines: Row: 0 _id=1, number=+91..., date=173..., duration=45, type=1, name=Papa
        records = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("Row:"):
                continue
            
            # Remove "Row: X " prefix
            row_content = re.sub(r"^Row:\s*\d+\s*", "", line)
            
            # Split key=val pairs
            # Since vals might contain commas or spaces, we use regex parsing
            pairs = re.findall(r"([a-zA-Z0-9__]+)=([^,]*)(?:,|$)", row_content)
            record = {}
            for k, v in pairs:
                k = k.strip()
                v = v.strip()
                record[k] = v

            # Standardize call type
            call_type_map = {
                "1": "Incoming",
                "2": "Outgoing",
                "3": "Missed",
                "4": "Voicemail",
                "5": "Rejected",
                "6": "Blocked",
                "7": "Answered Externally",
            }
            raw_type = record.get("type", "")
            record["type_label"] = call_type_map.get(raw_type, f"Unknown ({raw_type})")

            # Standardize timestamp
            raw_date = record.get("date", "")
            if raw_date.isdigit():
                ts_sec = int(raw_date) / 1000.0 if len(raw_date) > 11 else int(raw_date)
                dt = datetime.datetime.fromtimestamp(ts_sec)
                record["datetime_local"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                record["datetime_local"] = "N/A"

            records.append(record)

        return records

    def _dump_telecom(self) -> Path | None:
        """Runs dumpsys telecom and saves diagnostic output."""
        code, out, _ = self._run_adb(["shell", "dumpsys", "telecom"])
        if code == 0 and out.strip():
            dump_file = self.raw_dir / f"dumpsys_telecom_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            dump_file.write_text(out, encoding="utf-8")
            log.info(f"💾 Saved Dumpsys Telecom diagnostics to: {dump_file}")
            return dump_file
        return None

    def _try_root_pull(self) -> Path | None:
        """Checks if device is rooted (`su`) and copies contacts2.db / calllog.db."""
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root shell detected. Skipping direct /data/data/ database pull.")
            return None

        # Pull via temporary accessible storage
        db_paths = [
            "/data/data/com.android.providers.contacts/databases/calllog.db",
            "/data/data/com.android.providers.contacts/databases/contacts2.db",
        ]
        for remote_db in db_paths:
            code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_db} /data/local/tmp/temp_calllog.db && chmod 777 /data/local/tmp/temp_calllog.db'"])
            if code == 0:
                local_db = self.raw_dir / "pulled_calllog.db"
                self._run_adb(["pull", "/data/local/tmp/temp_calllog.db", str(local_db)])
                self._run_adb(["shell", "rm", "/data/local/tmp/temp_calllog.db"])
                if local_db.exists():
                    log.info(f"✅ Pulled root call log database: {local_db}")
                    return local_db
        return None

    def _extract_whatsapp_voip_calls(self) -> list[dict]:
        """Scans evidence directories for whatsapp_companion JSON dumps and extracts call_log items."""
        voip_records = []
        evidence_dir = project_root / "evidence"
        if not evidence_dir.exists():
            return []

        # Find all raw JSON files
        json_files = list(evidence_dir.glob("**/whatsapp_companion_raw_*.json"))
        for jf in json_files:
            try:
                with open(jf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for m in data.get("message", []):
                    if not isinstance(m, dict): continue
                    if m.get("type") in ("call_log", "call"):
                        ts = m.get("t", 0)
                        dt = datetime.datetime.fromtimestamp(int(ts)) if isinstance(ts, (int, float)) else "N/A"
                        from_jid = m.get("from", "")
                        to_val = m.get("to", "")
                        to_jid = to_val.get("_serialized", str(to_val)) if isinstance(to_val, dict) else str(to_val)
                        
                        voip_records.append({
                            "id": str(m.get("id", "")),
                            "timestamp": int(ts) if isinstance(ts, (int, float)) else 0,
                            "datetime_local": dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(dt, datetime.datetime) else "N/A",
                            "from_jid": str(from_jid),
                            "to_jid": str(to_jid),
                            "call_outcome": str(m.get("callOutcome", "")),
                            "call_duration_seconds": m.get("callDuration", 0),
                            "is_video_call": 1 if m.get("isVideoCall") else 0,
                            "source_file": jf.name,
                        })
            except Exception as e:
                log.warning(f"Error reading {jf}: {e}")

        voip_records.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return voip_records

    def _save_records(self, records: list[dict], basename: str) -> None:
        if not records:
            return

        # Save JSON
        json_path = self.parsed_dir / f"{basename}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)
        log.info(f"💾 Saved JSON: {json_path}")

        # Save CSV
        csv_path = self.parsed_dir / f"{basename}.csv"
        keys = list(records[0].keys())
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(records)
        log.info(f"💾 Saved CSV:  {csv_path}")

        # Save SQLite
        db_path = self.parsed_dir / f"{basename}.db"
        if db_path.exists(): db_path.unlink()
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # Create table dynamically based on keys
        cols_sql = ", ".join([f'"{k}" TEXT' for k in keys])
        cur.execute(f"CREATE TABLE IF NOT EXISTS {basename} ({cols_sql})")
        
        placeholders = ", ".join(["?" for _ in keys])
        for r in records:
            cur.execute(f"INSERT INTO {basename} VALUES ({placeholders})", [str(r.get(k, "")) for k in keys])
        conn.commit()
        conn.close()
        log.info(f"💾 Saved SQL:  {db_path}")

def main():
    parser = argparse.ArgumentParser(description="Android Call Logs Forensic Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-CALLLOGS", help="Output directory for acquired call records")
    args = parser.parse_args()

    extractor = CallLogExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
