#!/usr/bin/env python3
"""
Android Forensic Framework – Unified Messages & IM Acquisition Module
Extracts cellular SMS/MMS messages (`content://sms`) and aggregates Instant Messaging (IM)
databases across WhatsApp, Telegram, Signal, Gmail, and ProtonMail.

Usage:
  python capture/extract_messages.py --output evidence/CASE-MESSAGES
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
log = logging.getLogger("MessagesExtractor")

class MessagesExtractor:
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

    def extract_all(self, run_whatsapp_companion: bool = False) -> dict:
        """Attempts extraction across all SMS and IM channels."""
        log.info("═" * 60)
        log.info(" 💬 STARTING UNIFIED MESSAGES & IM ACQUISITION")
        log.info("═" * 60)

        results = {
            "sms_messages": [],
            "whatsapp_db": None,
            "telegram_data": [],
            "signal_data": [],
            "email_data": [],
        }

        # 1. Cellular SMS Messages (content://sms)
        log.info("🔍 Method 1: Querying Android SMS Content Provider (`content://sms`)...")
        sms_list = self._query_sms()
        if sms_list:
            log.info(f"✅ Successfully extracted {len(sms_list)} cellular SMS text messages!")
            results["sms_messages"] = sms_list
            self._save_records(sms_list, "cellular_sms_messages")
        else:
            log.warning("⚠️ SMS Content Provider query denied or returned 0 records (Requires READ_SMS permission or root).")

        # 2. WhatsApp Acquisition Check
        log.info("🔍 Method 2: Inspecting WhatsApp (`com.whatsapp`) databases & companion dumps...")
        wa_db = self._check_whatsapp(run_companion=run_whatsapp_companion)
        if wa_db:
            results["whatsapp_db"] = str(wa_db)

        # 3. Telegram Acquisition
        log.info("🔍 Method 3: Extracting Telegram (`org.telegram.messenger`) data...")
        tg_res = self._extract_im_app(
            package="org.telegram.messenger",
            name="Telegram",
            private_dbs=["cache4.db", "userconfing.xml"],
            accessible_paths=["/sdcard/Android/data/org.telegram.messenger", "/sdcard/Telegram"]
        )
        results["telegram_data"] = tg_res

        # 4. Signal Acquisition
        log.info("🔍 Method 4: Extracting Signal (`org.thoughtcrime.securesms`) data...")
        sig_res = self._extract_im_app(
            package="org.thoughtcrime.securesms",
            name="Signal",
            private_dbs=["signal.db"],
            accessible_paths=["/sdcard/Android/media/org.thoughtcrime.securesms", "/sdcard/Signal"]
        )
        results["signal_data"] = sig_res

        # 5. Email Clients (Gmail & ProtonMail)
        log.info("🔍 Method 5: Extracting Email client databases & accessible attachments...")
        gmail_res = self._extract_im_app(
            package="com.google.android.gm",
            name="Gmail",
            private_dbs=["mailstore.db"],
            accessible_paths=["/sdcard/Android/data/com.google.android.gm"]
        )
        proton_res = self._extract_im_app(
            package="ch.protonmail.android",
            name="ProtonMail",
            private_dbs=["protonmail.db"],
            accessible_paths=["/sdcard/Android/data/ch.protonmail.android"]
        )
        results["email_data"] = gmail_res + proton_res

        # Summary Log
        log.info("═" * 60)
        log.info(" 📊 UNIFIED MESSAGES EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Cellular SMS Acquired: {len(results['sms_messages'])}")
        log.info(f"  WhatsApp Status:       {'✅ Found DB/Viewer' if results['whatsapp_db'] else 'ℹ️ Run --whatsapp-companion for web sync'}")
        log.info(f"  Telegram Files:        {len(results['telegram_data'])} items extracted")
        log.info(f"  Signal Files:          {len(results['signal_data'])} items extracted")
        log.info(f"  Email Client Items:    {len(results['email_data'])} items extracted")
        log.info(f"  Output Directory:      {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _query_sms(self) -> list[dict]:
        """Queries content://sms over ADB shell."""
        uri = "content://sms"
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

            # Map type: 1 = Inbox, 2 = Sent, 3 = Draft, 4 = Outbox, 5 = Failed, 6 = Queued
            sms_type_map = {
                "1": "Inbox (Received)",
                "2": "Sent",
                "3": "Draft",
                "4": "Outbox",
                "5": "Failed",
                "6": "Queued",
            }
            raw_type = record.get("type", "")
            record["type_label"] = sms_type_map.get(raw_type, f"Other ({raw_type})")

            # Timestamp format
            raw_date = record.get("date", "")
            if raw_date.isdigit():
                ts_sec = int(raw_date) / 1000.0 if len(raw_date) > 11 else int(raw_date)
                dt = datetime.datetime.fromtimestamp(ts_sec)
                record["datetime_local"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                record["datetime_local"] = "N/A"

            records.append(record)

        records.sort(key=lambda x: x.get("date", ""), reverse=True)
        return records

    def _check_whatsapp(self, run_companion: bool) -> Path | None:
        """Checks for existing WhatsApp msgstore.db or invokes Companion sync if requested."""
        # Check existing evidence
        evidence_dir = project_root / "evidence"
        if evidence_dir.exists():
            existing_dbs = list(evidence_dir.glob("**/whatsapp_companion/msgstore.db"))
            if existing_dbs:
                latest_db = max(existing_dbs, key=os.path.getmtime)
                log.info(f"  -> Found existing WhatsApp SQLite database: {latest_db}")
                return latest_db

        if run_companion:
            log.info("  -> Launching live WhatsApp Companion sync...")
            try:
                try:
                    from capture.components.whatsapp_companion import WhatsAppCompanionExtractor
                except ImportError:
                    from components.whatsapp_companion import WhatsAppCompanionExtractor
                ext = WhatsAppCompanionExtractor(output_dir=self.parsed_dir / "whatsapp")
                return ext.run()
            except Exception as e:
                log.error(f"WhatsApp Companion extraction error: {e}")

        # Check su root pull for msgstore.db
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code == 0 and "uid=0(root)" in out:
            remote_db = "/data/data/com.whatsapp/databases/msgstore.db"
            local_db = self.parsed_dir / "whatsapp_root_msgstore.db"
            code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_db} /data/local/tmp/wa.db && chmod 777 /data/local/tmp/wa.db'"])
            if code == 0:
                self._run_adb(["pull", "/data/local/tmp/wa.db", str(local_db)])
                self._run_adb(["shell", "rm", "/data/local/tmp/wa.db"])
                if local_db.exists():
                    log.info(f"  -> Pulled root WhatsApp database: {local_db}")
                    return local_db
        return None

    def _extract_im_app(self, package: str, name: str, private_dbs: list[str], accessible_paths: list[str]) -> list[str]:
        """Attempts logical pull of IM application storage."""
        extracted = []
        app_out = self.raw_dir / name.lower()
        app_out.mkdir(parents=True, exist_ok=True)

        # 1. Try su root pull of private DBs
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        is_root = (code == 0 and "uid=0(root)" in out)
        if is_root:
            for db_name in private_dbs:
                remote_db = f"/data/data/{package}/databases/{db_name}"
                remote_files = f"/data/data/{package}/files/{db_name}"
                for rpath in [remote_db, remote_files]:
                    code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {rpath} /data/local/tmp/temp_db && chmod 777 /data/local/tmp/temp_db'"])
                    if code == 0:
                        local_target = app_out / db_name
                        self._run_adb(["pull", "/data/local/tmp/temp_db", str(local_target)])
                        self._run_adb(["shell", "rm", "/data/local/tmp/temp_db"])
                        if local_target.exists():
                            log.info(f"  -> Pulled root {name} database: {local_target}")
                            extracted.append(str(local_target))

        # 2. Pull accessible storage paths
        for path in accessible_paths:
            code, out, _ = self._run_adb(["shell", f"ls -d {path} 2>/dev/null"])
            if code == 0 and path in out:
                local_dest = app_out / Path(path).name
                log.info(f"  -> Pulling accessible {name} directory: {path} ...")
                self._run_adb(["pull", path, str(local_dest)])
                if local_dest.exists():
                    extracted.append(str(local_dest))

        if not extracted and not is_root:
            log.info(f"  -> {name}: Private databases protected by OS (non-rooted). Accessible media not found or empty.")

        return extracted

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
    parser = argparse.ArgumentParser(description="Android Unified Messages & IM Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-MESSAGES", help="Output directory for extracted messages")
    parser.add_argument("--whatsapp-companion", action="store_true", help="Launch live WhatsApp Companion web sync if no database exists")
    args = parser.parse_args()

    extractor = MessagesExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all(run_whatsapp_companion=args.whatsapp_companion)

if __name__ == "__main__":
    main()
