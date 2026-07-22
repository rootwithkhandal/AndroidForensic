#!/usr/bin/env python3
"""
Android Forensic Framework – Web & System Cookies Acquisition Module
Extracts and parses HTTP cookies across all installed web browsers and system WebViews:
  • Google Chrome (`app_chrome/Default/Cookies`)
  • Samsung Internet (`app_sbrowser/Default/Cookies`)
  • Mozilla Firefox (`cookies.sqlite` / `moz_cookies`)
  • Microsoft Edge, Brave, Opera (`app_chrome/Default/Cookies`)
  • System & App WebViews (`app_webview/Default/Cookies`)

Scans acquired evidence for `Cookies` SQLite databases, checks `dumpsys webviewupdate`,
and attempts root pull (`su`) of private cookie stores. Exports to SQLite, CSV, JSON,
and standard Netscape HTTP Cookie File format (`cookies_netscape.txt`).

Usage:
  python capture/extract_cookies.py --output evidence/CASE-COOKIES
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
log = logging.getLogger("CookiesExtractor")

class CookiesExtractor:
    BROWSERS = {
        "Google Chrome": {
            "package": "com.android.chrome",
            "paths": ["/data/data/com.android.chrome/app_chrome/Default/Cookies", "/data/data/com.android.chrome/app_chrome/Default/Network/Cookies"]
        },
        "Samsung Internet": {
            "package": "com.sec.android.app.sbrowser",
            "paths": ["/data/data/com.sec.android.app.sbrowser/app_sbrowser/Default/Cookies", "/data/data/com.sec.android.app.sbrowser/databases/Cookies.db"]
        },
        "Mozilla Firefox": {
            "package": "org.mozilla.firefox",
            "paths": ["/data/data/org.mozilla.firefox/files/mozilla/*.default/cookies.sqlite"]
        },
        "Microsoft Edge": {
            "package": "com.microsoft.emmx",
            "paths": ["/data/data/com.microsoft.emmx/app_chrome/Default/Cookies", "/data/data/com.microsoft.emmx/app_chrome/Default/Network/Cookies"]
        },
        "Brave Browser": {
            "package": "com.brave.browser",
            "paths": ["/data/data/com.brave.browser/app_chrome/Default/Cookies", "/data/data/com.brave.browser/app_chrome/Default/Network/Cookies"]
        },
        "Opera": {
            "package": "com.opera.browser",
            "paths": ["/data/data/com.opera.browser/app_opera/Cookies"]
        }
    }

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
        """Runs full acquisition across browser cookies and system WebViews."""
        log.info("═" * 60)
        log.info(" 🍪 STARTING BROWSER & SYSTEM COOKIES FORENSIC EXTRACTION")
        log.info("═" * 60)

        results = {
            "browser_cookies": [],
            "webview_cookies": [],
            "raw_dumps": []
        }

        # 1. System WebView & Browser Diagnostics (`dumpsys webviewupdate`)
        log.info("🔍 Method 1: Checking System WebView packages & configuration (`dumpsys webviewupdate`)...")
        self._dump_webview_info()

        # 2. Check for Acquired/Synced Cookies SQLite Databases inside evidence folder (`Cookies`, `cookies.sqlite`)
        log.info("🔍 Method 2: Scanning evidence repository for acquired Cookies SQLite databases...")
        synced_cookies = self._extract_synced_cookies()
        if synced_cookies:
            log.info(f"✅ Extracted {len(synced_cookies)} cookie records from acquired evidence databases!")
            for c in synced_cookies:
                if "webview" in c.get("source", "").lower() or "webview" in c.get("browser", "").lower():
                    results["webview_cookies"].append(c)
                else:
                    results["browser_cookies"].append(c)

        # 3. Check Root (`su`) for direct /data/data/<browser>/.../Cookies and app_webview/Default/Cookies pulls
        log.info("🔍 Method 3: Checking for Root Access (`su`) to pull private browser & WebView Cookies SQLite files...")
        root_cookies = self._try_root_pulls()
        if root_cookies:
            log.info(f"✅ Pulled {len(root_cookies)} cookie records via root access!")
            for c in root_cookies:
                if "webview" in c.get("source", "").lower() or "webview" in c.get("browser", "").lower():
                    results["webview_cookies"].append(c)
                else:
                    results["browser_cookies"].append(c)

        # Dedup and sort
        def dedup_sort(lst):
            seen = set()
            out = []
            for c in lst:
                key = (c.get("domain"), c.get("name"), c.get("path"))
                if key not in seen and c.get("domain"):
                    seen.add(key)
                    out.append(c)
            out.sort(key=lambda x: x.get("domain", "").lower())
            return out

        results["browser_cookies"] = dedup_sort(results["browser_cookies"])
        results["webview_cookies"] = dedup_sort(results["webview_cookies"])
        all_cookies = results["browser_cookies"] + results["webview_cookies"]

        if all_cookies:
            self._save_records(results["browser_cookies"], "browser_cookies")
            self._save_records(results["webview_cookies"], "webview_system_cookies")
            self._save_netscape_format(all_cookies, "cookies_netscape.txt")
        else:
            log.info("ℹ️ No unencrypted Cookies SQLite files found right now (Requires root pull or synced database drop).")

        log.info("═" * 60)
        log.info(" 📊 COOKIES EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Browser Cookies:        {len(results['browser_cookies'])}")
        log.info(f"  System WebView Cookies: {len(results['webview_cookies'])}")
        log.info(f"  Total Unique Cookies:   {len(all_cookies)}")
        log.info(f"  Netscape Format Export: {self.parsed_dir / 'cookies_netscape.txt'}")
        log.info("═" * 60)

        return results

    def _dump_webview_info(self) -> None:
        code, out, _ = self._run_adb(["shell", "dumpsys", "webviewupdate"])
        if code == 0 and out.strip():
            dump_file = self.raw_dir / "dumpsys_webviewupdate.txt"
            dump_file.write_text(out, encoding="utf-8")
            log.info(f"💾 Saved WebView Diagnostic Dump: {dump_file}")

    def _extract_synced_cookies(self) -> list[dict]:
        records = []
        evidence_dir = project_root / "evidence"
        if not evidence_dir.exists():
            return []

        # Find Cookies or cookies.sqlite files
        db_files = list(evidence_dir.glob("**/Cookies*")) + list(evidence_dir.glob("**/cookies.sqlite*"))
        for db_file in db_files:
            if db_file.name.endswith("-journal") or db_file.name.endswith("-wal") or db_file.name.endswith("-shm"):
                continue
            try:
                conn = sqlite3.connect(db_file)
                cur = conn.cursor()
                # Check Chrome / Chromium cookies table: SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly FROM cookies
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='cookies' OR name='moz_cookies')")
                row_tbl = cur.fetchone()
                if row_tbl:
                    tbl_name = row_tbl[0]
                    if tbl_name == "cookies":
                        cur.execute("SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly FROM cookies")
                        for row in cur.fetchall():
                            host, cname, cval, cpath, expires, secure, httponly = row[0], row[1], row[2], row[3], row[4], row[5], row[6]
                            # Convert Chrome timestamp
                            dt_str = "Session / N/A"
                            if expires and isinstance(expires, int) and expires > 0:
                                try:
                                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=expires)
                                    dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    pass
                            records.append({
                                "browser": "Google Chrome / Chromium Store",
                                "domain": str(host),
                                "name": str(cname),
                                "value": str(cval) if cval else "[Encrypted/Blob]",
                                "path": str(cpath or "/"),
                                "expires_utc": str(expires),
                                "expires_datetime": dt_str,
                                "is_secure": 1 if secure else 0,
                                "is_httponly": 1 if httponly else 0,
                                "source": f"Acquired SQLite DB ({db_file.name})"
                            })
                    elif tbl_name == "moz_cookies":
                        cur.execute("SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies")
                        for row in cur.fetchall():
                            host, cname, cval, cpath, expires, secure, httponly = row[0], row[1], row[2], row[3], row[4], row[5], row[6]
                            dt_str = "Session / N/A"
                            if expires and isinstance(expires, int) and expires > 0:
                                try:
                                    dt = datetime.datetime.fromtimestamp(expires)
                                    dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    pass
                            records.append({
                                "browser": "Mozilla Firefox (`moz_cookies`)",
                                "domain": str(host),
                                "name": str(cname),
                                "value": str(cval),
                                "path": str(cpath or "/"),
                                "expires_utc": str(expires),
                                "expires_datetime": dt_str,
                                "is_secure": 1 if secure else 0,
                                "is_httponly": 1 if httponly else 0,
                                "source": f"Acquired SQLite DB ({db_file.name})"
                            })
                conn.close()
            except Exception:
                pass
        return records

    def _try_root_pulls(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root detected. Skipping private /data/data/.../Cookies pulls.")
            return []

        records = []
        for name, info in self.BROWSERS.items():
            for remote_path in info["paths"]:
                if "*" in remote_path: continue
                local_name = f"pulled_{info['package']}_Cookies.db"
                code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_path} /data/local/tmp/temp_cook.db && chmod 777 /data/local/tmp/temp_cook.db'"])
                if code == 0:
                    dest = self.raw_dir / local_name
                    self._run_adb(["pull", "/data/local/tmp/temp_cook.db", str(dest)])
                    self._run_adb(["shell", "rm", "/data/local/tmp/temp_cook.db"])
                    if dest.exists():
                        log.info(f"✅ Pulled root Cookies DB for {name}: {dest}")
                        try:
                            conn = sqlite3.connect(dest)
                            cur = conn.cursor()
                            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'")
                            if cur.fetchone():
                                cur.execute("SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly FROM cookies")
                                for row in cur.fetchall():
                                    records.append({
                                        "browser": name,
                                        "domain": str(row[0]),
                                        "name": str(row[1]),
                                        "value": str(row[2]) if row[2] else "[Encrypted]",
                                        "path": str(row[3] or "/"),
                                        "expires_utc": str(row[4]),
                                        "expires_datetime": "Pulled Cookie",
                                        "is_secure": 1 if row[5] else 0,
                                        "is_httponly": 1 if row[6] else 0,
                                        "source": f"Root Pulled DB ({remote_path})"
                                    })
                            conn.close()
                        except Exception as e:
                            log.warning(f"Error parsing root pulled DB {dest}: {e}")
        return records

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

    def _save_netscape_format(self, cookies: list[dict], filename: str) -> None:
        if not cookies:
            return
        path = self.parsed_dir / filename
        lines = [
            "# Netscape HTTP Cookie File",
            "# Generated by Android Forensic Framework (CookiesExtractor)",
            "# format: domain  flag  path  secure  expiration  name  value"
        ]
        for c in cookies:
            domain = c.get("domain", "")
            flag = "TRUE" if domain.startswith(".") else "FALSE"
            cpath = c.get("path", "/")
            secure = "TRUE" if c.get("is_secure") else "FALSE"
            expiration = str(c.get("expires_utc", "0"))
            name = c.get("name", "")
            value = c.get("value", "")
            if domain and name:
                lines.append(f"{domain}\t{flag}\t{cpath}\t{secure}\t{expiration}\t{name}\t{value}")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log.info(f"💾 Saved Netscape Format HTTP Cookie File: {path}")

def main():
    parser = argparse.ArgumentParser(description="Android Web & System Cookies Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-COOKIES", help="Output directory for extracted cookies")
    args = parser.parse_args()

    extractor = CookiesExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
