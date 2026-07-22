#!/usr/bin/env python3
"""
Android Forensic Framework – Multi-Browser Search History & URL Acquisition Module
Extracts search queries, visited URLs, and bookmarks across all Android web browsers:
  • Google Chrome (`com.android.chrome`)
  • Samsung Internet (`com.sec.android.app.sbrowser`)
  • Mozilla Firefox (`org.mozilla.firefox`)
  • Microsoft Edge (`com.microsoft.emmx`)
  • Brave Browser (`com.brave.browser`)
  • Opera (`com.opera.browser`)

Queries Content Providers, checks `dumpsys activity recents` for active URLs, checks root
private `History` / `places.sqlite` databases, and parses synced browser dump imports.

Usage:
  python capture/extract_browser_history.py --output evidence/CASE-BROWSERS
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
log = logging.getLogger("BrowserExtractor")

class BrowserExtractor:
    BROWSERS = {
        "Google Chrome": {
            "package": "com.android.chrome",
            "db_paths": ["/data/data/com.android.chrome/app_chrome/Default/History", "/data/data/com.android.chrome/app_chrome/Default/Bookmarks"],
            "uris": ["content://com.android.chrome.browser/bookmarks", "content://com.android.chrome.browser/history"]
        },
        "Samsung Internet": {
            "package": "com.sec.android.app.sbrowser",
            "db_paths": ["/data/data/com.sec.android.app.sbrowser/databases/SBrowser.db", "/data/data/com.sec.android.app.sbrowser/databases/history.db"],
            "uris": ["content://com.sec.android.app.sbrowser.browser/bookmarks", "content://com.sec.android.app.sbrowser.browser/history"]
        },
        "Mozilla Firefox": {
            "package": "org.mozilla.firefox",
            "db_paths": ["/data/data/org.mozilla.firefox/files/mozilla/*.default/places.sqlite", "/data/data/org.mozilla.firefox/databases/browser.db"],
            "uris": ["content://org.mozilla.firefox.db/bookmarks", "content://org.mozilla.firefox.db/history"]
        },
        "Microsoft Edge": {
            "package": "com.microsoft.emmx",
            "db_paths": ["/data/data/com.microsoft.emmx/app_chrome/Default/History"],
            "uris": ["content://com.microsoft.emmx.browser/bookmarks"]
        },
        "Brave Browser": {
            "package": "com.brave.browser",
            "db_paths": ["/data/data/com.brave.browser/app_chrome/Default/History"],
            "uris": ["content://com.brave.browser/bookmarks"]
        },
        "Opera": {
            "package": "com.opera.browser",
            "db_paths": ["/data/data/com.opera.browser/app_opera/History"],
            "uris": ["content://com.opera.browser/bookmarks"]
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
        """Runs full browser search history and URL extraction across all installed browsers."""
        log.info("═" * 60)
        log.info(" 🌐 STARTING MULTI-BROWSER SEARCH HISTORY & URL EXTRACTION")
        log.info("═" * 60)

        results = {
            "browser_history": [],
            "search_queries": [],
            "bookmarks": [],
            "raw_dumps": []
        }

        # 1. Query Browser Content Providers (bookmarks & history URIs)
        log.info("🔍 Method 1: Querying Browser Content Providers across Chrome, Samsung, Firefox, Edge...")
        cp_records = self._query_content_providers()
        if cp_records:
            log.info(f"✅ Extracted {len(cp_records)} browser history & bookmark records via Content Providers!")
            results["browser_history"].extend(cp_records)

        # 2. Check Dumpsys Activity Recents & Top Tasks for active browser URLs
        log.info("🔍 Method 2: Scanning active memory & recent tasks (`dumpsys activity recents`) for open browser URLs...")
        recents_records = self._extract_recents_urls()
        if recents_records:
            log.info(f"✅ Extracted {len(recents_records)} recently opened browser URLs from system recents!")
            results["browser_history"].extend(recents_records)

        # 3. Check for Synced History Imports inside evidence folder (`History`, `BrowserHistory.json`, `places.sqlite`)
        log.info("🔍 Method 3: Scanning evidence repository for acquired/synced browser database exports...")
        synced_records = self._extract_synced_databases()
        if synced_records:
            log.info(f"✅ Extracted {len(synced_records)} historical search queries & URLs from acquired browser databases!")
            results["browser_history"].extend(synced_records)

        # 4. Check Root (`su`) for direct /data/data/<browser>/.../History pulls
        log.info("🔍 Method 4: Checking for Root Access (`su`) to pull private browser SQLite History databases...")
        root_records = self._try_root_pulls()
        if root_records:
            results["browser_history"].extend(root_records)

        # Categorize search queries vs standard URLs
        for r in results["browser_history"]:
            url = r.get("url", "")
            title = r.get("title", "")
            # Detect search engines (google.com/search?q=..., bing.com/search?q=..., duckduckgo.com/?q=...)
            search_match = re.search(r'(?:google\.|bing\.|yahoo\.|duckduckgo\.|yandex\.|baidu\.).*[\?&](?:q|query|p)=([^&]+)', url, re.IGNORECASE)
            if search_match:
                query = re.sub(r'\+', ' ', search_match.group(1))
                try:
                    from urllib.parse import unquote
                    query = unquote(query)
                except Exception:
                    pass
                results["search_queries"].append({
                    "browser": r.get("browser", "Unknown"),
                    "search_query": query,
                    "search_engine": url.split("/")[2] if "//" in url else "Search Engine",
                    "url": url,
                    "title": title,
                    "visit_time": r.get("visit_time", "N/A"),
                    "source": r.get("source", "Browser History")
                })

        # Sort and save
        results["browser_history"].sort(key=lambda x: x.get("visit_time", ""), reverse=True)
        results["search_queries"].sort(key=lambda x: x.get("visit_time", ""), reverse=True)

        if results["browser_history"]:
            self._save_records(results["browser_history"], "browser_visited_urls")
        if results["search_queries"]:
            self._save_records(results["search_queries"], "browser_search_queries")

        log.info("═" * 60)
        log.info(" 📊 MULTI-BROWSER EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Total Visited URLs / Records: {len(results['browser_history'])}")
        log.info(f"  Extracted Search Queries:     {len(results['search_queries'])}")
        log.info(f"  Output Directory:             {self.output_dir.resolve()}")
        log.info("═" * 60)

        return results

    def _query_content_providers(self) -> list[dict]:
        records = []
        for name, info in self.BROWSERS.items():
            for uri in info["uris"]:
                code, out, err = self._run_adb(["shell", "content", "query", "--uri", uri])
                if code != 0 or "Permission Denial" in out or "Permission Denial" in err:
                    continue
                
                for line in out.splitlines():
                    line_str = line.strip()
                    if not line_str.startswith("Row:"): continue
                    row_content = re.sub(r"^Row:\s*\d+\s*", "", line_str)
                    pairs = re.findall(r"([a-zA-Z0-9__]+)=([^,]*)(?:,|$)", row_content)
                    rec = dict(pairs)

                    url = rec.get("url", "")
                    title = rec.get("title", "") or rec.get("bookmark", "") or url
                    if url:
                        records.append({
                            "browser": name,
                            "url": url,
                            "title": title,
                            "visit_count": rec.get("visits", "1"),
                            "visit_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "source": f"Content Provider ({uri})"
                        })
        return records

    def _extract_recents_urls(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "activity", "recents"])
        if code != 0 or not out.strip():
            return []

        dump_file = self.raw_dir / f"dumpsys_activity_recents_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        dump_file.write_text(out, encoding="utf-8")

        records = []
        lines = out.splitlines()
        for line in lines:
            line_str = line.strip()
            # Look for HTTP/HTTPS URLs associated with browser task packages inside recents
            if ("http://" in line_str or "https://" in line_str) and any(b["package"] in line_str or "browser" in line_str.lower() for b in self.BROWSERS.values()):
                url_match = re.search(r'(https?://[^\s,\)\]"]+)', line_str)
                if url_match:
                    url = url_match.group(1)
                    browser_name = "Android Browser / Webview"
                    for name, info in self.BROWSERS.items():
                        if info["package"] in line_str:
                            browser_name = name
                            break

                    records.append({
                        "browser": browser_name,
                        "url": url,
                        "title": "Recent Task / Open Tab",
                        "visit_count": "Active Tab",
                        "visit_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "System Activity Recents (`dumpsys activity recents`)"
                    })

        # Dedup by URL
        seen = set()
        deduped = []
        for r in records:
            if r["url"] not in seen:
                seen.add(r["url"])
                deduped.append(r)
        return deduped

    def _extract_synced_databases(self) -> list[dict]:
        records = []
        evidence_dir = project_root / "evidence"
        if not evidence_dir.exists():
            return []

        # Find any History SQLite or BrowserHistory JSON
        db_files = list(evidence_dir.glob("**/History*")) + list(evidence_dir.glob("**/places.sqlite*")) + list(evidence_dir.glob("**/SBrowser.db*"))
        for db_file in db_files:
            if db_file.suffix == ".json" or db_file.name.endswith(".json"):
                try:
                    with open(db_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    items = data if isinstance(data, list) else data.get("Browser History", []) or data.get("history", [])
                    for item in items:
                        if isinstance(item, dict) and item.get("url"):
                            records.append({
                                "browser": item.get("browser", "Google Chrome / Synced Dump"),
                                "url": item["url"],
                                "title": item.get("title", "") or item["url"],
                                "visit_count": str(item.get("visit_count", 1)),
                                "visit_time": str(item.get("time_usec", item.get("visit_time", "Synced History"))),
                                "source": f"Synced Database Import ({db_file.name})"
                            })
                except Exception:
                    pass
            else:
                # Attempt SQLite read
                try:
                    conn = sqlite3.connect(db_file)
                    cur = conn.cursor()
                    # Check for Chrome urls table: SELECT url, title, visit_count, last_visit_time FROM urls
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
                    if cur.fetchone():
                        cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
                        for row in cur.fetchall():
                            url, title, count, last_time = row[0], row[1], row[2], row[3]
                            # Convert Chrome timestamp (microseconds since Jan 1 1601)
                            dt_str = "Historical Visit"
                            if last_time and isinstance(last_time, int) and last_time > 0:
                                try:
                                    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_time)
                                    dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    pass
                            records.append({
                                "browser": "Google Chrome (SQLite `urls`)",
                                "url": str(url),
                                "title": str(title or url),
                                "visit_count": str(count or 1),
                                "visit_time": dt_str,
                                "source": f"Acquired SQLite DB ({db_file.name})"
                            })
                    conn.close()
                except Exception:
                    pass
        return records

    def _try_root_pulls(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root detected. Skipping private /data/data/<browser>/.../History pulls.")
            return []

        records = []
        for name, info in self.BROWSERS.items():
            for remote_path in info["db_paths"]:
                if "*" in remote_path: continue
                local_name = f"pulled_{info['package']}_History.db"
                code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_path} /data/local/tmp/temp_brows.db && chmod 777 /data/local/tmp/temp_brows.db'"])
                if code == 0:
                    dest = self.raw_dir / local_name
                    self._run_adb(["pull", "/data/local/tmp/temp_brows.db", str(dest)])
                    self._run_adb(["shell", "rm", "/data/local/tmp/temp_brows.db"])
                    if dest.exists():
                        log.info(f"✅ Pulled root browser DB for {name}: {dest}")
                        # Parse SQLite
                        try:
                            conn = sqlite3.connect(dest)
                            cur = conn.cursor()
                            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
                            if cur.fetchone():
                                cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
                                for row in cur.fetchall():
                                    records.append({
                                        "browser": name,
                                        "url": str(row[0]),
                                        "title": str(row[1] or row[0]),
                                        "visit_count": str(row[2] or 1),
                                        "visit_time": str(row[3]),
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

def main():
    parser = argparse.ArgumentParser(description="Android Multi-Browser Search History & URL Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-BROWSERS", help="Output directory for browser artifacts")
    args = parser.parse_args()

    extractor = BrowserExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
