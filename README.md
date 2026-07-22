# Android Forensic Framework

> Phase 1 prototype for authorized Android logical acquisition over ADB.

Android Forensic Framework collects selected, accessible Android artifacts,
stores them in a case folder, and records hashes and metadata alongside the
output. It is a prototype: use it only on devices you are authorized to
examine, validate results independently, and do not represent its output as
court-ready without a validated forensic workflow.

## What the MVP supports

- ADB device discovery and explicit device selection
- Device profile and installed-package collection
- Logical acquisition of accessible media and APKs
- Optional extraction modules for call logs, messages, contacts,
  connectivity, notifications, calendar, journey, network, browser history,
  cookies, device events, and connected devices
- SHA-256 and MD5 hashes, acquisition metadata, a basic timeline, and HTML/
  JSON reports

Availability depends on the device, Android version, permissions, OEM
implementation, and whether root access is authorized and available. A module
reporting no records is not proof that the artifact never existed.

## Requirements

- Python 3.12+
- Android Debug Bridge (ADB) on `PATH`, or the bundled tools under
  `capture/components/adb-tools/<platform>/`
- A device with USB debugging enabled and authorized for this workstation

## Install

```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

With mise:

```bash
mise install
mise run install
```

## Run the prototype

The preferred entry point is the package command. The legacy script command
continues to work.

```bash
# Check the CLI without needing a device
python -m capture --help

# List authorized / unauthorized connected devices
python -m capture --list

# Target exactly one device
python -m capture --serial DEVICE_SERIAL --case-id CASE-001 --examiner "Examiner"

# Preview default acquisition paths without pulling data
python -m capture --serial DEVICE_SERIAL --dry-run

# Run selected optional artifact modules
python -m capture --serial DEVICE_SERIAL --case-id CASE-001 --skip-media --skip-apk \
  --call-logs --messages --contacts --connectivity --notifications --calendar \
  --journey --network --browser-history --cookies --device-events --connected-devices

# Legacy equivalent
python capture/prototype.py --list
```

When `--serial` is selected, optional extractors receive that same serial and
ADB binary. This prevents them from silently using another connected device.

## Outputs

Each run creates `evidence/<case-id>/` (or the directory given by `--output`)
with a structure similar to:

```text
CASE-001/
  raw/                 # ADB dumps and pulled logical files
  parsed/              # Module-specific SQLite, CSV, JSON, HTML, KML, or ICS files
  hashes/              # hash_manifest.json and hash_manifest.csv
  reports/             # forensic_report.html and forensic_report.json
  acquisition_metadata.json
```

The project hashes registered files using SHA-256 and MD5. Preserve the entire
case folder, record the command used, and independently verify manifests
before relying on the results.

## Project layout

```text
capture/
  __main__.py                 # python -m capture entry point
  prototype.py                # MVP orchestration, evidence, timeline, reports
  extract_*.py                # Optional artifact extractors
  components/                 # WhatsApp companion and bundled ADB tools
  docs/architecture.md        # MVP architecture and boundaries
docs/                         # Static documentation portal and MVP guide
tests/                        # CLI smoke tests
main.py                       # Build-tool entry point
```

## Development

```bash
mise run dev       # install development dependencies
mise run test      # pytest tests/
mise run lint      # ruff check .
mise run format    # ruff format .
mise run build     # PyInstaller build using main.py
```

## Limitations and responsible use

- This is not a physical-imaging or deleted-record recovery tool.
- Root-only paths may be inaccessible, and the tool must not bypass device
  security controls.
- Content-provider results and diagnostic output vary by Android release and
  vendor; review the raw output and extraction errors.
- Hashing improves traceability but does not by itself establish legal chain
  of custody or certify forensic validity.

Use only with documented consent, a warrant, or another valid legal basis.

## Documentation

- [MVP architecture](capture/docs/architecture.md)
- [Documentation portal](docs/index.html)
- [CLI help](docs/help.html)
- [FAQ and operating guidance](docs/faq.html)
