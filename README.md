<p align="center">
  <h1 align="center">🔍 Android Forensic Framework</h1>
  <p align="center">
    Open-source Android forensic toolkit for logical, filesystem, and physical acquisitions.
    <br />
    Extract artifacts · Recover deleted records · Generate court-ready reports
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.12+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12+" />
    <img src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge" alt="License" />
    <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-6c8dfa?style=for-the-badge" alt="Platform" />
    <img src="https://img.shields.io/badge/status-Phase%201%20Prototype-fb923c?style=for-the-badge" alt="Status" />
  </p>
</p>

---

## 📋 Overview

Android Forensic Framework is a Python-based toolkit designed for mobile forensic investigators. It automates the process of acquiring evidence from Android devices via ADB, computing cryptographic integrity hashes, parsing forensic artifacts, and generating structured reports suitable for legal proceedings.

### Key Capabilities

| Capability | Description |
|---|---|
| 📱 **Device Detection & Profiling** | Auto-detect connected devices via ADB; extract model, OS version, IMEI, security patches, encryption status |
| 📞 **Call Logs Acquisition** | Query `content://call_log/calls` & `dumpsys calllog` into SQLite, CSV, JSON (`--call-logs`) |
| 💬 **Messages & Instant Messaging** | Extract SMS (`content://sms`) and parse WhatsApp/Telegram/Signal/Mail caches (`--messages`) |
| 👥 **Contacts & Address Books** | Extract system contacts (`content://com.android.contacts`) and WhatsApp JSON profiles (`--contacts`) |
| 📶 **Network Connectivity & Interfaces** | Dump Wi-Fi (`dumpsys wifi`), Bluetooth, live sockets (`netstat/ss`), ARP neighbors, and routes (`--connectivity`, `--network`) |
| 🔔 **Notification History** | Capture live & historical system notification queue (`dumpsys notification --noredact`) (`--notifications`) |
| 📅 **Calendars & Events Export** | Query `content://com.android.calendar/` into SQLite, CSV, JSON, and standard iCalendar (`.ics`) (`--calendar`) |
| 🗺️ **Geolocation & Journey Maps** | Harvest GPS (`dumpsys location`), EXIF photo coordinates, and build interactive Leaflet Maps (`.html`) & Google Earth (`.kml`) (`--journey`) |
| 🌐 **Multi-Browser Search & History** | Extract search queries and visited URLs across Chrome, Samsung Internet, Firefox, Edge, Brave, and Opera (`--browser-history`) |
| 🍪 **Web & System Cookies** | Extract HTTP cookies across all browsers and system WebViews into SQLite and Netscape format (`--cookies`) |
| ⚙️ **System & Device Events** | Capture chronological Screen Lock/Unlock (`KEYGUARD`), app transitions (`dumpsys usagestats`), Boot history (`bootstat`), and kernel logs (`--device-events`) |
| 🔌 **Connected Peripherals** | Catalog USB accessories (`dumpsys usb`), Bluetooth gear, P2P peers, and companion wearables (`--connected-devices`) |
| 🔒 **Cryptographic Integrity** | SHA-256 + MD5 dual-hashing for every acquired file with verifiable chain-of-custody manifests |
| 📄 **Court-Ready Reporting** | Generate dark-themed HTML and machine-readable JSON forensic case summaries |

---

## 🏗️ Architecture

```
                       +----------------------+
                       |     Android Device   |
                       +----------+-----------+
                                  |
          +-----------------------+----------------------+
          |                                              |
       ADB Protocol                              Root / Recovery
          |                                              |
          +-----------------------+----------------------+
                                  |
                     Acquisition Engine
                                  |
        +-------------------------+-------------------------+
        |                         |                         |
    Logical                 Filesystem               Physical
   Acquisition              Acquisition              Acquisition
        |                         |                         |
        +-------------------------+-------------------------+
                                  |
                          Evidence Repository
                                  |
                     Integrity Verification Engine
                                  |
                          Artifact Parsing Engine
                                  |
                      Correlation & Timeline Engine
                                  |
             +--------------------+------------------+
             |                                       |
      Report Generator                       Desktop UI
```

> See [`capture/docs/architecture.md`](capture/docs/architecture.md) for the full architecture document with all modules and components.

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **ADB** (Android Debug Bridge) — either:
  - In your system `PATH`, or
  - Placed in `capture/components/adb-tools/<platform>/`
- **Android device** with USB debugging enabled

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/android-forensics.git
cd android-forensics

# Install with mise (recommended)
mise install
mise run install

# Or install manually
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### Run Unified Acquisition via Prototype

```bash
# List connected devices
python capture/prototype.py --list

# Run FULL logical forensic suite across ALL modules
python capture/prototype.py --call-logs --messages --contacts --connectivity --notifications --calendar --journey --network --browser-history --cookies --device-events --connected-devices --skip-media --skip-apk

# Target individual artifact modules directly
python capture/extract_journey.py --output evidence/CASE-JOURNEY
python capture/extract_browser_history.py --output evidence/CASE-BROWSERS
python capture/extract_cookies.py --output evidence/CASE-COOKIES
python capture/extract_network.py --output evidence/CASE-NETWORK
python capture/extract_device_events.py --output evidence/CASE-EVENTS
python capture/extract_connected_devices.py --output evidence/CASE-CONNECTED-DEVICES

# Preview what would be acquired without pulling files
python capture/prototype.py --dry-run
```

---

## 📂 Project Structure

```
android-forensics/
├── capture/
│   ├── prototype.py                 # Core acquisition controller & CLI runner
│   ├── extract_call_logs.py         # Call history extractor
│   ├── extract_messages.py          # SMS & Instant Messaging extractor
│   ├── extract_contacts.py          # Contacts & Address book extractor
│   ├── extract_connectivity.py      # Wi-Fi, Bluetooth & basic connectivity
│   ├── extract_notifications.py     # System notifications queue extractor
│   ├── extract_calendar.py          # Calendar events & .ics exporter
│   ├── extract_journey.py           # Geolocation taxonomy & Leaflet/KML map generator
│   ├── extract_network.py           # Network diagnostics (IPs, MACs, sockets, ARP, routing)
│   ├── extract_browser_history.py   # Multi-browser search queries & visited URLs
│   ├── extract_cookies.py           # Multi-browser & system WebView HTTP cookies
│   ├── extract_device_events.py     # Screen unlock, app transitions, boot & power events
│   ├── extract_connected_devices.py # USB, Bluetooth gear, P2P hotspot & wearables catalog
│   ├── components/
│   │   ├── whatsapp_companion.py    # WhatsApp Web sync & profile parser
│   │   └── adb-tools/               # Bundled ADB platform tools
│   └── docs/
│       └── architecture.md          # Full technical architecture specification
├── analysis/                        # Analysis & correlation modules
├── evidence/                        # Acquired evidence repository (git-ignored)
├── mise.toml                        # Dev environment config
├── requirements.txt                 # Production dependencies
├── .gitignore
└── README.md
```

---

## 📊 Evidence Output

Each acquisition produces a structured, chain-of-custody verified evidence folder:

```
evidence/CASE-YYYYMMDD-HHMMSS/
├── acquisition_metadata.json        # Full case and cryptographic summary
├── raw/                             # Raw system dumps (`dumpsys`, `content query`, text output)
├── parsed/
│   ├── call_logs/                   # SQLite (.db), CSV, JSON
│   ├── messages/                    # SMS & IM databases
│   ├── contacts/                    # System & WhatsApp contacts
│   ├── connectivity/                # Wi-Fi / Bluetooth status
│   ├── notifications/               # Notification queue logs
│   ├── calendar/                    # SQLite, CSV, JSON, and calendar_export.ics
│   ├── journey/                     # SQLite, CSV, JSON, journey_map.html, journey_locations.kml
│   ├── network/                     # network_interfaces.db, network_sockets.db, arp_neighbors.db
│   ├── browsers/                    # browser_visited_urls.db, browser_search_queries.db
│   ├── cookies/                     # browser_cookies.db, webview_system_cookies.db, cookies_netscape.txt
│   ├── events/                      # device_events_timeline.db, app_usage_history.db, power_reboot_history.db
│   └── connected_devices/           # connected_devices_registry.db, CSV, JSON
├── hashes/
│   ├── hash_manifest.json           # SHA-256 + MD5 per file
│   └── hash_manifest.csv            # Spreadsheet-friendly format
└── reports/
    ├── forensic_report.html         # Visual HTML report
    └── forensic_report.json         # Machine-readable report
```

Every single file is hashed with **SHA-256** and **MD5** upon extraction.

---

## 🛠️ Development

### Dev Tasks (via mise)

```bash
mise run install      # Install production dependencies
mise run dev          # Install dev dependencies
mise run test         # Run tests with pytest
mise run lint         # Lint with ruff
mise run format       # Format with ruff
mise run clean        # Remove build artifacts and caches
mise run build        # Build standalone executable
mise run hash-verify  # Verify evidence integrity
```

---

## 🗺️ Roadmap

### Phase 1 — Foundation & Core Forensics ✅ *(Completed)*
- [x] Device detection & ADB connection
- [x] Device information & package enumeration
- [x] Logical media & APK acquisition
- [x] SHA-256 / MD5 integrity hashing & HTML/JSON reporting
- [x] Call Logs (`content://call_log/calls`) acquisition
- [x] SMS & Instant Messaging (`content://sms` & WhatsApp/Telegram hooks)
- [x] Contacts (`content://com.android.contacts` & WhatsApp profiles)
- [x] Connectivity & Network diagnostics (Wi-Fi, Bluetooth, sockets, ARP, routing)
- [x] Notification History & system queue extraction
- [x] Calendar Events (`content://com.android.calendar/` & `.ics` export)

### Phase 2 — Advanced Geolocation & Web Forensics ✅ *(Completed)*
- [x] Geolocation taxonomy extraction (`Visited`, `POI`, `Media`, `Other`)
- [x] Interactive Leaflet HTML Map (`journey_map.html`) & Google Earth (`.kml`) export
- [x] Multi-Browser Search Queries & Visited URLs (Chrome, Samsung Internet, Firefox, Edge, Brave, Opera)
- [x] Multi-Browser & System WebView HTTP Cookies (`cookies_netscape.txt`)
- [x] Chronological System & Device Events (Screen Lock/Unlock, App transitions, Bootstat history)
- [x] Connected Devices & Peripherals catalog (USB accessories, Bluetooth gear, P2P/Hotspot clients, Wearables)

### Phase 3 — Filesystem & Physical Recovery *(In Progress)*
- [ ] Root-enabled full filesystem acquisition (`/data/data/` direct pulls)
- [ ] Low-level SQLite WAL / Rollback journal / Freelist deleted record recovery
- [ ] Physical acquisition (EDL / Fastboot RAW image dumps)
- [ ] Cross-artifact AI correlation & desktop UI (PySide6)

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively for authorized forensic examinations** conducted by qualified investigators with proper legal authority (warrant, consent, or other lawful basis).

**Do not use this tool to access devices without authorization.** Unauthorized access to electronic devices may violate federal and state laws including but not limited to the Computer Fraud and Abuse Act (CFAA), GDPR, and equivalent legislation in your jurisdiction.

The developers assume no liability for misuse of this software.

---

## 📄 License

This project is open-source. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for forensic investigators who need reliable, transparent, and verifiable evidence acquisition.</sub>
</p>
