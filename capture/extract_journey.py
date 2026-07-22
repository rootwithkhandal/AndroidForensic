#!/usr/bin/env python3
"""
Android Forensic Framework – Geolocation & Journey Acquisition Module (Advanced Taxonomy)
Extracts and categorizes locations into professional forensic taxonomy:
  • Visited (Places, Synced Device, Wireless Network)
  • Point of Interest (Mentioned, Searched Places, Shared, Significant Location, User Specified)
  • Media (EXIF Geotagged Media, Media Probably Captured)
  • Other (Cell Tower, Harvested Cell Tower, Harvested WIFI, External)

Queries `dumpsys location`, `dumpsys wifi`, `dumpsys telephony.registry`, EXIF photos,
geocoded call logs/calendars, and checks root/cloud location history caches (`location.db`, `gmm_storage.db`).

Usage:
  python capture/extract_journey.py --output evidence/CASE-JOURNEY
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

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)-8s │ %(message)s")
log = logging.getLogger("JourneyExtractor")

class JourneyExtractor:
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
        """Aggregates location items into Visited, Point of Interest, Media, and Other taxonomy."""
        log.info("═" * 60)
        log.info(" 🗺️ STARTING ADVANCED GEOLOCATION & JOURNEY HARVEST")
        log.info("═" * 60)

        taxonomy = {
            "Visited": {
                "Places": [],
                "Synced Device": [],
                "Wireless Network": []
            },
            "Point of Interest": {
                "Mentioned": [],
                "Searched Places": [],
                "Shared": [],
                "Significant Location": [],
                "Unknown": [],
                "User Specified": []
            },
            "Media": {
                "Media": [],
                "Media Probably Captured": []
            },
            "Other": {
                "Cell Tower": [],
                "External": [],
                "Harvested Cell Tower": [],
                "Harvested WIFI": []
            }
        }

        all_points = []

        # 1. System Location & Fused Provider (Significant / Last Known / Visited Places)
        log.info("🔍 Method 1: Harvesting System GPS, Fused Provider & Geofences (`dumpsys location`)...")
        dumpsys_pts = self._extract_dumpsys_location()
        for p in dumpsys_pts:
            if "geofence" in p.get("details", "").lower() or "significant" in p.get("details", "").lower():
                taxonomy["Point of Interest"]["Significant Location"].append(p)
            elif p.get("source", "").startswith("System Location"):
                taxonomy["Visited"]["Places"].append(p)
            else:
                taxonomy["Visited"]["Places"].append(p)
            all_points.append(p)

        # 2. Wi-Fi Scan & Harvested WIFI (`dumpsys wifi` / scan results)
        log.info("🔍 Method 2: Harvesting surrounding Wi-Fi networks & BSSID scans (`dumpsys wifi`)...")
        wifi_pts = self._extract_harvested_wifi()
        for p in wifi_pts:
            if p.get("is_connected"):
                taxonomy["Visited"]["Wireless Network"].append(p)
            else:
                taxonomy["Other"]["Harvested WIFI"].append(p)
            all_points.append(p)

        # 3. Cellular Tower & Handover (`dumpsys telephony.registry` / cell info)
        log.info("🔍 Method 3: Harvesting Cellular Tower IDs & Handover status...")
        cell_pts = self._extract_cell_towers()
        for p in cell_pts:
            if p.get("is_registered"):
                taxonomy["Other"]["Cell Tower"].append(p)
            else:
                taxonomy["Other"]["Harvested Cell Tower"].append(p)
            all_points.append(p)

        # 4. EXIF Geotagged Media (`/sdcard/DCIM`, evidence images)
        log.info("🔍 Method 4: Harvesting EXIF Geotagged Media across evidence repository...")
        media_pts = self._extract_exif_gps()
        for p in media_pts:
            if p.get("accuracy") == "Exact EXIF":
                taxonomy["Media"]["Media"].append(p)
            else:
                taxonomy["Media"]["Media Probably Captured"].append(p)
            all_points.append(p)

        # 5. Points of Interest (User Specified Calendar, Shared WhatsApp locations, Searched)
        log.info("🔍 Method 5: Harvesting Points of Interest (Calendar events, Shared IM locations)...")
        poi_pts = self._extract_poi_locations()
        for p in poi_pts:
            sub = p.get("subcategory", "User Specified")
            if sub in taxonomy["Point of Interest"]:
                taxonomy["Point of Interest"][sub].append(p)
            else:
                taxonomy["Point of Interest"]["User Specified"].append(p)
            all_points.append(p)

        # 6. Check Root (`su`) / Google Location History (`location.db`, `gmm_storage.db`)
        log.info("🔍 Method 6: Checking Root (`su`) for Google Play Services location cache databases...")
        self._try_root_pulls()

        # Sort all points chronologically
        all_points.sort(key=lambda x: x.get("timestamp_sec", 0), reverse=True)

        if all_points:
            self._save_records(all_points, "journey_all_locations")
            self._save_taxonomy_json(taxonomy, "journey_taxonomy_tree.json")
            self._save_kml(all_points, "journey_locations.kml")
            self._generate_html_map(all_points, taxonomy, "journey_map.html")
        else:
            log.info("ℹ️ No numerical GPS coordinates found across accessible logs right now.")

        # Print clean tree structure
        log.info("═" * 60)
        log.info(" 📊 FORENSIC LOCATION TAXONOMY TREE SUMMARY")
        log.info("═" * 60)
        for cat, subcats in taxonomy.items():
            total_cat = sum(len(lst) for lst in subcats.values())
            log.info(f" 📂 {cat} ({total_cat})")
            for sub_name, lst in subcats.items():
                log.info(f"    └─ {sub_name} ({len(lst)})")
        log.info("═" * 60)
        log.info(f"  Interactive Map Output: {self.parsed_dir / 'journey_map.html'}")
        log.info("═" * 60)

        return {"taxonomy": taxonomy, "all_points": all_points}

    def _extract_dumpsys_location(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "location", "--noredact"])
        if code != 0 or not out.strip():
            code, out, _ = self._run_adb(["shell", "dumpsys", "location"])
        if code != 0 or not out.strip():
            return []

        dump_file = self.raw_dir / f"dumpsys_location_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        dump_file.write_text(out, encoding="utf-8")

        pts = []
        for line in out.splitlines():
            line_str = line.strip()
            loc_match = re.search(r'Location\[([a-zA-Z0-9_]+)\s+([+-]?[0-9]+\.[0-9]+),\s*([+-]?[0-9]+\.[0-9]+)', line_str)
            if loc_match:
                provider = loc_match.group(1)
                lat = float(loc_match.group(2))
                lon = float(loc_match.group(3))
                if lat == 0.0 and lon == 0.0: continue

                accuracy = "N/A"
                acc_match = re.search(r'hAcc=([0-9\.]+)', line_str)
                if acc_match: accuracy = f"{acc_match.group(1)}m"

                dt_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ts_sec = int(datetime.datetime.now().timestamp())
                at_match = re.search(r'at=([0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2})', line_str)
                if at_match:
                    dt_str = at_match.group(1).replace("T", " ")
                    try:
                        dt = datetime.datetime.strptime(dt_str[:19], "%Y-%m-%d %H:%M:%S")
                        ts_sec = int(dt.timestamp())
                    except Exception:
                        pass

                pts.append({
                    "category": "Visited",
                    "subcategory": "Places",
                    "latitude": lat,
                    "longitude": lon,
                    "altitude": 0.0,
                    "source": f"System Location ({provider})",
                    "accuracy": accuracy,
                    "label": f"Visited / Last Known ({provider})",
                    "timestamp_sec": ts_sec,
                    "datetime_local": dt_str,
                    "details": line_str[:120]
                })
        return pts

    def _extract_harvested_wifi(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "wifi"])
        if code != 0 or not out.strip():
            return []

        pts = []
        # Parse BSSID and SSID entries accompanied by scan results or last connected info
        lines = out.splitlines()
        for line in lines:
            line_str = line.strip()
            if "BSSID:" in line_str and "SSID:" in line_str:
                bssid_match = re.search(r'BSSID:\s*([0-9a-fA-F:]+)', line_str)
                ssid_match = re.search(r'SSID:\s*"?([^"\n]+)"?', line_str)
                if bssid_match:
                    bssid = bssid_match.group(1)
                    ssid = ssid_match.group(1) if ssid_match else "Unknown_SSID"
                    is_conn = "CONNECTED" in line_str.upper() or "CURRENT" in line_str.upper()
                    
                    pts.append({
                        "category": "Visited" if is_conn else "Other",
                        "subcategory": "Wireless Network" if is_conn else "Harvested WIFI",
                        "latitude": 0.0,
                        "longitude": 0.0,
                        "altitude": 0.0,
                        "source": f"Wi-Fi Scan ({ssid})",
                        "accuracy": "BSSID Identifier",
                        "label": f"WIFI: {ssid} ({bssid})",
                        "timestamp_sec": int(datetime.datetime.now().timestamp()),
                        "datetime_local": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "details": line_str[:120],
                        "is_connected": is_conn
                    })
        return pts

    def _extract_cell_towers(self) -> list[dict]:
        code, out, _ = self._run_adb(["shell", "dumpsys", "telephony.registry"])
        if code != 0 or not out.strip():
            return []

        pts = []
        # Parse CellIdentity entries: CellIdentityLte:{ mCi=... mMcc=... mMnc=... mLac=... }
        for line in out.splitlines():
            line_str = line.strip()
            if "CellIdentity" in line_str or "mCi=" in line_str or "mTac=" in line_str:
                ci_match = re.search(r'mCi=([0-9]+)', line_str)
                tac_match = re.search(r'mTac=([0-9]+)', line_str)
                mcc_match = re.search(r'mMcc=([0-9]+)', line_str)
                mnc_match = re.search(r'mMnc=([0-9]+)', line_str)
                
                if ci_match and ci_match.group(1) != "2147483647":
                    ci = ci_match.group(1)
                    tac = tac_match.group(1) if tac_match else "N/A"
                    mcc = mcc_match.group(1) if mcc_match else "N/A"
                    mnc = mnc_match.group(1) if mnc_match else "N/A"
                    is_reg = "registered=true" in line_str.lower()

                    pts.append({
                        "category": "Other",
                        "subcategory": "Cell Tower" if is_reg else "Harvested Cell Tower",
                        "latitude": 0.0,
                        "longitude": 0.0,
                        "altitude": 0.0,
                        "source": f"Cell Tower (MCC:{mcc} MNC:{mnc} TAC:{tac} CI:{ci})",
                        "accuracy": "Cell ID",
                        "label": f"Tower CI {ci} (TAC {tac})",
                        "timestamp_sec": int(datetime.datetime.now().timestamp()),
                        "datetime_local": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "details": line_str[:120],
                        "is_registered": is_reg
                    })
        return pts

    def _extract_exif_gps(self) -> list[dict]:
        if not HAS_PIL:
            return []

        pts = []
        evidence_dir = project_root / "evidence"
        if not evidence_dir.exists():
            return []

        img_files = list(evidence_dir.glob("**/*.jpg")) + list(evidence_dir.glob("**/*.jpeg"))
        for img_path in img_files:
            try:
                with Image.open(img_path) as img:
                    exif = img._getexif()
                    if not exif: continue
                    
                    gps_info = {}
                    for tag, val in exif.items():
                        decoded = TAGS.get(tag, tag)
                        if decoded == "GPSInfo":
                            for t in val:
                                sub_decoded = GPSTAGS.get(t, t)
                                gps_info[sub_decoded] = val[t]
                    
                    if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
                        def convert_to_degrees(value):
                            d0 = value[0][0] / value[0][1]
                            d1 = value[1][0] / value[1][1]
                            d2 = value[2][0] / value[2][1]
                            return d0 + (d1 / 60.0) + (d2 / 3600.0)

                        lat = convert_to_degrees(gps_info["GPSLatitude"])
                        if gps_info.get("GPSLatitudeRef", "N") != "N": lat = -lat

                        lon = convert_to_degrees(gps_info["GPSLongitude"])
                        if gps_info.get("GPSLongitudeRef", "E") != "E": lon = -lon

                        dt_str = "N/A"
                        ts_sec = int(img_path.stat().st_mtime)
                        if "DateTimeOriginal" in exif:
                            raw_dt = exif["DateTimeOriginal"]
                            try:
                                dt = datetime.datetime.strptime(raw_dt, "%Y:%m:%d %H:%M:%S")
                                dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                                ts_sec = int(dt.timestamp())
                            except Exception:
                                dt_str = str(raw_dt)

                        pts.append({
                            "category": "Media",
                            "subcategory": "Media",
                            "latitude": round(lat, 6),
                            "longitude": round(lon, 6),
                            "altitude": 0.0,
                            "source": "EXIF Geotagged Photo",
                            "accuracy": "Exact EXIF",
                            "label": img_path.name,
                            "timestamp_sec": ts_sec,
                            "datetime_local": dt_str,
                            "details": f"File: {img_path.relative_to(project_root)}"
                        })
            except Exception:
                pass
        return pts

    def _extract_poi_locations(self) -> list[dict]:
        pts = []
        evidence_dir = project_root / "evidence"
        if not evidence_dir.exists():
            return []

        # Calendar Events (User Specified)
        cal_files = list(evidence_dir.glob("**/calendar_events.json"))
        for cf in cal_files:
            try:
                with open(cf, "r", encoding="utf-8") as f:
                    evts = json.load(f)
                for e in evts:
                    loc = e.get("location", "")
                    coord_match = re.search(r'([+-]?[0-9]{1,2}\.[0-9]{3,8}),\s*([+-]?[0-9]{1,3}\.[0-9]{3,8})', loc)
                    if coord_match:
                        pts.append({
                            "category": "Point of Interest",
                            "subcategory": "User Specified",
                            "latitude": float(coord_match.group(1)),
                            "longitude": float(coord_match.group(2)),
                            "altitude": 0.0,
                            "source": "Calendar Event Location",
                            "accuracy": "User Specified",
                            "label": e.get("title", "Event"),
                            "timestamp_sec": e.get("start_ts_raw", 0),
                            "datetime_local": e.get("start_time_local", "N/A"),
                            "details": f"Location string: {loc}"
                        })
            except Exception:
                pass

        # WhatsApp Companion Shared Locations (Shared / Mentioned)
        wa_files = list(evidence_dir.glob("**/whatsapp_companion_raw_*.json"))
        for wf in wa_files:
            try:
                with open(wf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for msg in data.get("messages", []):
                    if isinstance(msg, dict) and msg.get("location"):
                        loc_obj = msg["location"]
                        pts.append({
                            "category": "Point of Interest",
                            "subcategory": "Shared",
                            "latitude": float(loc_obj.get("latitude", 0.0)),
                            "longitude": float(loc_obj.get("longitude", 0.0)),
                            "altitude": 0.0,
                            "source": "WhatsApp Shared Location",
                            "accuracy": "Shared Pin",
                            "label": loc_obj.get("name") or loc_obj.get("address") or "WhatsApp Location Pin",
                            "timestamp_sec": int(msg.get("timestamp", 0)),
                            "datetime_local": datetime.datetime.fromtimestamp(int(msg.get("timestamp", 0))).strftime("%Y-%m-%d %H:%M:%S") if msg.get("timestamp") else "N/A",
                            "details": f"From JID: {msg.get('from', 'Unknown')}"
                        })
            except Exception:
                pass

        return pts

    def _try_root_pulls(self) -> None:
        code, out, _ = self._run_adb(["shell", "su", "-c", "'id'"])
        if code != 0 or "uid=0(root)" not in out:
            log.info("  -> No su root detected. Skipping private Google Play Services location cache pulls.")
            return

        targets = [
            ("/data/data/com.google.android.gms/databases/location.db", "pulled_gms_location.db"),
            ("/data/data/com.google.android.apps.maps/databases/gmm_storage.db", "pulled_maps_storage.db")
        ]
        for remote_path, local_name in targets:
            code, _, _ = self._run_adb(["shell", "su", "-c", f"'cp {remote_path} /data/local/tmp/temp_loc && chmod 777 /data/local/tmp/temp_loc'"])
            if code == 0:
                dest = self.raw_dir / local_name
                self._run_adb(["pull", "/data/local/tmp/temp_loc", str(dest)])
                self._run_adb(["shell", "rm", "/data/local/tmp/temp_loc"])
                if dest.exists():
                    log.info(f"✅ Pulled root location database: {dest}")

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

    def _save_taxonomy_json(self, taxonomy: dict, filename: str) -> None:
        path = self.parsed_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(taxonomy, f, indent=2, ensure_ascii=False)
        log.info(f"💾 Saved Taxonomy Tree JSON: {path}")

    def _save_kml(self, points: list[dict], filename: str) -> None:
        valid_pts = [p for p in points if p.get("latitude", 0.0) != 0.0 or p.get("longitude", 0.0) != 0.0]
        if not valid_pts:
            return
        kml_path = self.parsed_dir / filename
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2">',
            '<Document>',
            '  <name>Android Forensic Journey & Taxonomy Map</name>',
            '  <description>Categorized locations across Visited, POI, Media, and Harvested taxonomy</description>'
        ]
        for p in valid_pts:
            lines.extend([
                '  <Placemark>',
                f'    <name>{p.get("label", "Point")} [{p.get("subcategory")}]</name>',
                f'    <description><![CDATA[Category: {p.get("category")} -> {p.get("subcategory")}<br>Source: {p.get("source")}<br>Time: {p.get("datetime_local")}<br>Details: {p.get("details")}]]></description>',
                '    <Point>',
                f'      <coordinates>{p.get("longitude")},{p.get("latitude")},{p.get("altitude", 0)}</coordinates>',
                '    </Point>',
                '  </Placemark>'
            ])
        lines.extend(['</Document>', '</kml>'])
        with open(kml_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log.info(f"💾 Saved KML map file: {kml_path}")

    def _generate_html_map(self, points: list[dict], taxonomy: dict, filename: str) -> None:
        html_path = self.parsed_dir / filename
        pts_json = json.dumps([p for p in points if p.get("latitude", 0.0) != 0.0 or p.get("longitude", 0.0) != 0.0])
        tax_json = json.dumps(taxonomy)
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Android Forensic Location Taxonomy & Journey Map</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body {{ margin: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; height: 100vh; background: #1a1d24; color: #fff; }}
        #sidebar {{ width: 420px; background: #222630; border-right: 1px solid #333947; display: flex; flex-direction: column; overflow-y: auto; }}
        #header {{ padding: 20px; background: #1c2029; border-bottom: 1px solid #333947; }}
        #header h2 {{ margin: 0; font-size: 18px; color: #61afef; }}
        #header p {{ margin: 5px 0 0; font-size: 12px; color: #abb2bf; }}
        #taxonomy-tree {{ padding: 15px; background: #181b22; border-bottom: 1px solid #333947; font-size: 13px; }}
        .cat-group {{ margin-bottom: 8px; font-weight: bold; color: #e5c07b; }}
        .subcat-item {{ margin-left: 16px; font-weight: normal; color: #abb2bf; padding: 2px 0; }}
        #list {{ flex: 1; overflow-y: auto; padding: 10px; }}
        .item {{ padding: 12px; background: #282c37; margin-bottom: 10px; border-radius: 6px; cursor: pointer; border-left: 4px solid #98c379; transition: all 0.2s; }}
        .item:hover {{ background: #323846; transform: translateX(3px); }}
        .item-title {{ font-weight: bold; font-size: 14px; color: #e5c07b; }}
        .item-time {{ font-size: 11px; color: #abb2bf; margin-top: 4px; }}
        .item-source {{ font-size: 11px; color: #61afef; margin-top: 4px; }}
        #map {{ flex: 1; height: 100%; }}
    </style>
</head>
<body>
    <div id="sidebar">
        <div id="header">
            <h2>🗺️ Location Taxonomy Tree</h2>
            <p>Total Harvested Items: {len(points)}</p>
        </div>
        <div id="taxonomy-tree"></div>
        <div id="list"></div>
    </div>
    <div id="map"></div>
    <script>
        const taxonomy = {tax_json};
        const points = {pts_json};
        const treeEl = document.getElementById('taxonomy-tree');

        for (const [cat, subcats] of Object.entries(taxonomy)) {{
            let catTotal = 0;
            for (const lst of Object.values(subcats)) catTotal += lst.length;
            
            const div = document.createElement('div');
            div.className = 'cat-group';
            div.innerHTML = `📂 ${{cat}} (${{catTotal}})`;
            treeEl.appendChild(div);

            for (const [subName, lst] of Object.entries(subcats)) {{
                if (lst.length > 0 || true) {{
                    const subDiv = document.createElement('div');
                    subDiv.className = 'subcat-item';
                    subDiv.innerHTML = `└─ ${{subName}} (${{lst.length}})`;
                    treeEl.appendChild(subDiv);
                }}
            }}
        }}

        const defaultLat = points.length > 0 ? points[0].latitude : 28.6139;
        const defaultLon = points.length > 0 ? points[0].longitude : 77.2090;
        const map = L.map('map').setView([defaultLat, defaultLon], 13);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '© OpenStreetMap contributors | Android Forensic Framework'
        }}).addTo(map);

        const listEl = document.getElementById('list');
        points.forEach((p, idx) => {{
            const marker = L.marker([p.latitude, p.longitude]).addTo(map)
                .bindPopup(`<b>${{p.label}}</b><br>Category: ${{p.category}} -> ${{p.subcategory}}<br>Source: ${{p.source}}<br>Time: ${{p.datetime_local}}<br><small>${{p.details}}</small>`);

            const div = document.createElement('div');
            div.className = 'item';
            div.innerHTML = `<div class="item-title">${{p.label}} [${{p.subcategory}}]</div>
                             <div class="item-time">🕒 ${{p.datetime_local}}</div>
                             <div class="item-source">📍 ${{p.source}} (${{p.latitude}}, ${{p.longitude}})</div>`;
            div.onclick = () => {{
                map.setView([p.latitude, p.longitude], 16);
                marker.openPopup();
            }};
            listEl.appendChild(div);
        }});

        if (points.length > 1) {{
            const latlngs = points.map(p => [p.latitude, p.longitude]);
            L.polyline(latlngs, {{color: '#e06c75', weight: 3, dashArray: '5, 10'}}).addTo(map);
            map.fitBounds(L.polyline(latlngs).getBounds(), {{padding: [50, 50]}});
        }}
    </script>
</body>
</html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        log.info(f"💾 Saved Interactive Taxonomy & Journey Map HTML: {html_path}")

def main():
    parser = argparse.ArgumentParser(description="Android Geolocation & Journey Acquisition Tool")
    parser.add_argument("--output", "-o", default="evidence/CASE-JOURNEY", help="Output directory for journey map & artifacts")
    args = parser.parse_args()

    extractor = JourneyExtractor(output_dir=Path(args.output).resolve())
    extractor.extract_all()

if __name__ == "__main__":
    main()
