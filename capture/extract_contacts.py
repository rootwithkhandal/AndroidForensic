#!/usr/bin/env python3
"""
Android Forensic Framework – Phone & IM Contacts Acquisition Module
Extracts Android device address book contacts (`content://com.android.contacts/data/phones`, `contacts2.db`)
and aggregates WhatsApp/IM contact profiles into standardized SQLite, CSV, JSON, and vCard (.vcf) formats.

Usage:
  python capture/extract_contacts.py --output evidence/CASE-CONTACTS
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
log = logging.getLogger("ContactsExtractor")

class ContactsExtractor:
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
        """Extracts contacts across phone address book and instant messaging databases."""
        log.info("═" * 60)
        log.info(" 📇 STARTING ANDROID & IM CONTACTS EXTRACTION")
        log.info("═" * 60)

        results = {
            "phone_contacts": [],
            "whatsapp_contacts": [],
            "root_db_file": None,
        }

        # 1. Query Phone Address Book via Content Provider
        log.info("🔍 Method 1: Querying Android Contacts Provider (`content://com.android.contacts/data/phones`)...")
        phone_contacts = self._query_phone_contacts()
        if phone_contacts:
            log.info(f"✅ Successfully extracted {len(phone_contacts)} Android device contact records!")
            results["phone_contacts"] = phone_contacts
            self._save_records(phone_contacts, "phone_contacts")
            self._save_vcard(phone_contacts, "phone_contacts.vcf")
        else:
            log.warning("⚠️ Contacts Provider query denied or returned 0 records (Requires READ_CONTACTS permission or root).")

        # 2. Check root pull for contacts2.db
        log.info("🔍 Method 2: Checking for Root Access (`su`) to pull private contacts2.db...")
        root_db = self._try_root_pull()
        if root_db:
            results["root_db_file"] = str(root_db)

        # 3. Extract WhatsApp Companion Contacts
        log.info("🔍 Method 3: Scanning existing WhatsApp dumps for contact profiles...")
        wa_contacts = self._extract_whatsapp_contacts()
        if wa_contacts:
            log.info(f"✅ Extracted {len(wa_contacts)} WhatsApp contact profiles & display names!")
            results["whatsapp_contacts"] = wa_contacts
            self._save_records(wa_contacts, "whatsapp_contacts")

        log.info("═" * 60)
        log.info(" 📊 CONTACTS EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Phone Address Book Contacts: {len(results['phone_contacts'])}")
        log.info(f"  WhatsApp Contact Profiles:   {len(results['whatsapp_contacts'])}")
        log.info(f"  Output Directory:            {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _query_phone_contacts(self) -> list[dict]:
        """Queries com.android.contacts/data/phones via ADB shell."""
        uri = "content://com.android.contacts/data/phones"
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

            phone_type_map = {
                "1": "Home",
                "2": "Mobile",
                "3": "Work",
                "4": "Work Fax",
                "5": "Home Fax",
                "6": "Pager",
                "7": "Other",
                "12": "Main",
            }
            raw_type = record.get("data2", "")
            record["phone_type_label"] = phone_type_map.get(raw_type, f"Custom ({raw_type})")

            # Standardize clean keys
            clean_record = {
                "contact_id": record.get("contact_id", ""),
                "display_name": record.get("display_name", "") or "Unknown",
                "phone_number": record.get("data1", ""),
                "phone_type": record["phone_type_label"],
                "starred": 1 if record.get("starred") == "1" else 0,
                "times_contacted": int(record.get("times_contacted", 0)) if record.get("times_contacted", "").isdigit() else 0,
            }
            records.append(clean_record)

        records.sort(key=lambda x: x["display_name"].lower())
        return records

    def _try_root_pull(self) -> Path | None:
        """Checks if device is rooted (`su`) and copies contacts2.db."""
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root shell detected. Skipping direct /data/data/ contacts2.db pull.")
            return None

        remote_db = "/data/data/com.android.providers.contacts/databases/contacts2.db"
        code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_db} /data/local/tmp/temp_contacts2.db && chmod 777 /data/local/tmp/temp_contacts2.db'"])
        if code == 0:
            local_db = self.raw_dir / "pulled_contacts2.db"
            self._run_adb(["pull", "/data/local/tmp/temp_contacts2.db", str(local_db)])
            self._run_adb(["shell", "rm", "/data/local/tmp/temp_contacts2.db"])
            if local_db.exists():
                log.info(f"✅ Pulled root contacts database: {local_db}")
                return local_db
        return None

    def _extract_whatsapp_contacts(self) -> list[dict]:
        """Scans evidence directories for whatsapp_companion JSON dumps and extracts contacts."""
        wa_contacts = []
        evidence_dir = project_root / "evidence"
        if not evidence_dir.exists():
            return []

        json_files = list(evidence_dir.glob("**/whatsapp_companion_raw_*.json"))
        for jf in json_files:
            try:
                with open(jf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for c in data.get("contact", []):
                    if not isinstance(c, dict):
                        continue
                    jid = c.get("id") or c.get("_id")
                    if isinstance(jid, dict):
                        jid = jid.get("_serialized") or str(jid)
                    if not jid:
                        continue
                    
                    jid_str = str(jid)
                    name = (
                        c.get("name")
                        or c.get("shortName")
                        or c.get("pushname")
                        or c.get("verifiedName")
                        or c.get("displayNameLID")
                    )
                    pn = c.get("phoneNumber", "")
                    if isinstance(pn, dict): pn = str(pn)

                    if name or pn or "@lid" in jid_str:
                        wa_contacts.append({
                            "jid": jid_str,
                            "name": str(name or ""),
                            "phone_number": str(pn or jid_str.split("@")[0]),
                            "pushname": str(c.get("pushname", "")),
                            "short_name": str(c.get("shortName", "")),
                            "is_address_book_contact": 1 if c.get("isAddressBookContact") else 0,
                            "source_file": jf.name,
                        })
            except Exception as e:
                log.warning(f"Error reading {jf}: {e}")

        # Remove duplicates based on jid
        seen = set()
        deduped = []
        for c in wa_contacts:
            if c["jid"] not in seen:
                seen.add(c["jid"])
                deduped.append(c)

        deduped.sort(key=lambda x: (x.get("name") or x.get("phone_number")).lower())
        return deduped

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

    def _save_vcard(self, records: list[dict], filename: str) -> None:
        if not records:
            return
        vcf_path = self.parsed_dir / filename
        lines = []
        for r in records:
            lines.append("BEGIN:VCARD")
            lines.append("VERSION:3.0")
            lines.append(f"FN:{r.get('display_name', 'Unknown')}")
            lines.append(f"TEL;TYPE={r.get('phone_type', 'CELL')}:{r.get('phone_number', '')}")
            lines.append("END:VCARD")
        with open(vcf_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log.info(f"💾 Saved vCard: {vcf_path}")

def main():
    parser = argparse.ArgumentParser(description="Android Phone & IM Contacts Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-CONTACTS", help="Output directory for extracted contacts")
    args = parser.parse_args()

    extractor = ContactsExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
