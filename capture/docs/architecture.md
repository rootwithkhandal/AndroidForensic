# Android Forensic Tool Architecture

> **Project Goal**
>
> Build an open-source Android forensic framework capable of performing logical, filesystem, and (where supported) physical acquisitions, extracting forensic artifacts, recovering deleted SQLite records, generating timelines, and producing court-ready forensic reports.

---

# High-Level Architecture

```text
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
        +--------------------------------------------------+
        |                Recovery Engine                    |
        |  SQLite • WAL • Journal • Freelist • Cache        |
        +--------------------------------------------------+
                                  |
                      Correlation & Timeline Engine
                                  |
                    Search / Index / Analytics Engine
                                  |
             +--------------------+------------------+
             |                                       |
      Report Generator                       Desktop UI
             |                                       |
      HTML / PDF / JSON                     Investigator
```

---

# Overall Project Structure

```text
android-forensics/

├── collector/
├── acquisition/
├── parser/
├── recovery/
├── timeline/
├── analyzer/
├── reports/
├── ui/
├── database/
├── plugins/
├── core/
├── utils/
├── docs/
└── tests/
```

---

# Layered Architecture

```text
Presentation Layer

Desktop GUI
CLI
REST API


Business Layer

Acquisition
Parsing
Recovery
Analysis
Timeline
Reporting


Data Layer

Evidence
SQLite
Media
Metadata
Logs
Cache


Device Layer

ADB
Fastboot
Root
Recovery
```

---

# Module Breakdown

---

## 1. Device Connection Layer

Responsible for communicating with Android devices.

Supports

- adb
- fastboot
- recovery shell
- root shell

### Responsibilities

Detect devices

```text
adb devices
```

Collect properties

```text
getprop
dumpsys
settings
service list
pm
cmd
```

Retrieve

- Build information
- Android version
- Security patch
- Model
- Manufacturer
- IMEI
- Serial
- Bootloader state

---

## 2. Acquisition Engine

### Logical Acquisition

Uses standard ADB.

Collects

- APKs
- SD card
- Downloads
- Media
- Public documents

---

### Filesystem Acquisition

Root required.

Collects

```text
/data/
  |-system/
  |-vendor/
  |-product/
  |-storage/
  |-sdcard/
```

Includes

- databases
- shared preferences
- caches
- logs
- application files

---

### Physical Acquisition

Future module.

Supports

- EDL
- Fastboot
- Recovery
- Vendor exploit
- Raw partition dumps

---

# 3. Evidence Repository

Stores every acquired artifact.

Structure

```text
Evidence/

Device001/

raw/

parsed/

logs/

hashes/

reports/
```

Every file contains

- SHA256
- MD5
- acquisition timestamp
- acquisition source
- path

---

# 4. Integrity Engine

Calculates

- MD5
- SHA1
- SHA256

Supports

```text
File Verification

Evidence Validation

Hash Comparison

Chain of Custody
```

---

# 5. Artifact Parsing Engine

The most important component.

Every application has its own parser.

```text
parser/

browser/

whatsapp/

telegram/

signal/

sms/

contacts/

calllog/

media/

location/

accounts/

notifications/
```

Every parser outputs

```json
{
  "artifact": "...",
  "timestamp": "...",
  "source": "...",
  "deleted": false
}
```

---

# 6. SQLite Recovery Engine

Recovers deleted records.

Input

```text
database.db

database.db-wal

database.db-shm

journal

rollback journal
```

Recovers

- deleted rows
- freelist pages
- WAL records
- orphan pages
- partial records

Modules

```text
sqlite_parser.py

wal_parser.py

journal_parser.py

freelist_parser.py
```

---

# 7. Application Artifact Parsers

Each application gets its own parser.

Example

```text
apps/

Chrome

Firefox

Edge

WhatsApp

Signal

Telegram

Discord

Facebook

Instagram

Snapchat

Google Maps

YouTube

Gmail

Drive

Photos
```

Each parser extracts

- messages
- media
- accounts
- cache
- searches
- timestamps

---

# 8. Device Information Parser

Collects

```text
getprop

settings

dumpsys

packages.xml

accounts

users
```

Produces

- Device profile
- Installed apps
- Hardware
- Build
- Security patch

---

# 9. Browser Parser

Supported browsers

- Chrome
- Firefox
- Edge
- Brave
- Samsung Internet
- Opera
- DuckDuckGo

Artifacts

- History
- Cookies
- Bookmarks
- Downloads
- Sessions
- Favicons
- Searches

---

# 10. Communication Parser

Supports

SMS

MMS

Call logs

WhatsApp

Telegram

Signal

Messenger

Discord

Extracts

- Messages
- Attachments
- Calls
- Groups
- Contacts

---

# 11. Location Engine

Collects

GPS

WiFi

Bluetooth

Cell Towers

Google Maps

Location History

Geofences

Outputs

- Places
- Timeline
- Routes

---

# 12. Media Engine

Extracts

Images

Videos

Audio

Documents

Downloads

Reads

EXIF

GPS

Camera metadata

Thumbnails

Hidden files

---

# 13. Notification Parser

Extracts

Notification history

Messaging previews

OTP

Dismissed notifications

Foreground applications

---

# 14. Accounts Parser

Parses

Google

Samsung

Microsoft

Facebook

Telegram

Signal

Application accounts

---

# 15. Network Parser

Collects

WiFi

Bluetooth

VPN

DNS

DHCP

Known Networks

Hotspots

Cell Towers

---

# 16. Timeline Engine

Receives artifacts from every parser.

Normalizes timestamps.

Produces

```text
08:12 Device Boot

08:14 WiFi Connected

08:15 Chrome Search

08:18 WhatsApp Message

08:20 Camera Photo

08:24 GPS Update

08:31 Telegram Call

08:40 Browser Download
```

Supports

- filtering
- search
- export

---

# 17. Correlation Engine

Links artifacts together.

Example

```text
Photo

↓

EXIF GPS

↓

Nearby WiFi

↓

Cell Tower

↓

Google Timeline

↓

WhatsApp Image

↓

Contact
```

Produces relationship graphs.

---

# 18. Search Engine

Indexes

- Messages
- Contacts
- URLs
- Email
- GPS
- Package names
- Phone numbers
- IMEI
- File names

Supports

- Full-text search
- Regex
- Fuzzy search

---

# 19. Report Generator

Generates

HTML

PDF

JSON

CSV

Excel

Includes

- hashes
- evidence info
- screenshots
- timeline
- deleted artifacts
- recovered files

---

# 20. Plugin System

Every parser is a plugin.

```text
plugins/

whatsapp.py

telegram.py

chrome.py

firefox.py

instagram.py
```

Interface

```python
class ArtifactPlugin:

    name = "Chrome"

    def detect(self):
        pass

    def parse(self):
        pass

    def recover(self):
        pass

    def report(self):
        pass
```

---

# Internal Data Flow

```text
ADB

↓

Collector

↓

Filesystem

↓

Evidence Repository

↓

Hash Verification

↓

Artifact Parser

↓

SQLite Recovery

↓

Correlation

↓

Timeline

↓

Search Index

↓

Report Generator

↓

GUI
```

---

# Suggested Technology Stack

| Layer | Technology |
|---------|------------|
| Language | Python 3.12+ |
| GUI | PySide6 (Qt) |
| Database | SQLite (project), PostgreSQL (optional) |
| ORM | SQLAlchemy |
| ADB Interface | adbutils or subprocess |
| Hashing | hashlib |
| SQLite Parsing | sqlite3, APSW, custom page parser |
| Reporting | Jinja2 + ReportLab / WeasyPrint |
| Search | SQLite FTS5 or Whoosh |
| Logging | loguru |
| Packaging | PyInstaller |

---

# Roadmap

## Phase 1

- Device detection
- ADB connection
- Device info
- Installed apps
- Media extraction
- APK extraction

---

## Phase 2

- Filesystem acquisition
- SQLite parser
- Browser artifacts
- SMS
- Contacts
- Call logs

---

## Phase 3

- WhatsApp
- Telegram
- Signal
- Notifications
- Accounts
- Location
- Timeline

---

## Phase 4

- Deleted SQLite recovery
- WAL parser
- Journal parser
- Freelist parser
- Correlation engine

---

## Phase 5

- Physical acquisition support
- EDL integration
- Fastboot imaging
- Plugin marketplace
- AI-assisted artifact classification
- Multi-device case management
