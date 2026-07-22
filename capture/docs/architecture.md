# Android Forensic Framework MVP Architecture

## Scope

The current implementation is a Python/ADB logical-acquisition prototype. It
does not implement physical imaging, EDL/Fastboot acquisition, deleted SQLite
record recovery, a REST API, or a desktop UI. Those ideas are future work, not
current capabilities.

```text
Android device
      |
      v
ADB wrapper (selected serial)
      |
      +--> DeviceCollector --------> device profile and packages
      |
      +--> LogicalAcquisition -----> raw files and application paths
      |
      +--> Optional extractors ----> parsed module artifacts
      |
      v
EvidenceRepository --> hashes / metadata --> timeline --> HTML and JSON reports
```

## Runtime entry points

- `python -m capture`: preferred command-line entry point.
- `python capture/prototype.py`: retained for existing users.
- `main.py`: minimal wrapper used by the PyInstaller build task.

`prototype.py` selects the ADB binary and device serial. When an optional
extractor is enabled, the controller passes both values to it. This keeps all
ADB requests in an acquisition on the intended device.

## Components

| Component | Current responsibility |
|---|---|
| `ADB` | Finds ADB, lists devices, executes shell and pull commands. |
| `DeviceCollector` | Collects device properties and installed packages. |
| `LogicalAcquisition` | Pulls configured accessible media, APK, and application targets. |
| `EvidenceRepository` | Creates case folders and stores metadata and hash manifests. |
| `IntegrityEngine` | Calculates SHA-256 and MD5 for registered evidence files. |
| `TimelineGenerator` | Produces a basic timeline from the acquisition summary. |
| `ReportGenerator` | Creates HTML and JSON reports. |
| `extract_*.py` | Optional, focused artifact acquisition and parsing modules. |

## Evidence model

The prototype writes one case directory per acquisition:

```text
evidence/CASE-YYYYMMDD-HHMMSS/
  raw/
  parsed/
  hashes/hash_manifest.json
  hashes/hash_manifest.csv
  reports/forensic_report.html
  reports/forensic_report.json
  acquisition_metadata.json
```

`FileEvidence` captures the original path, local path, source, category, file
size, acquisition timestamp, SHA-256, and MD5. Errors from individual modules
are retained in the final acquisition summary rather than terminating the
entire run.

## Supported acquisition boundary

The prototype uses standard ADB commands and may use `su` only when it is
already available on the device. It must not attempt to bypass authentication,
encryption, or other device protections. Output completeness depends on the
device, permissions, Android version, and OEM behavior.

The hash manifests support traceability, but they do not replace validated
forensic procedures, documentation of handling, independent verification, or
legal chain-of-custody requirements.

## Future work

Potential future areas include root-authorized filesystem acquisition, SQLite
WAL/journal/freelist recovery, physical acquisition where lawfully supported,
cross-artifact correlation, and a UI. They should be implemented as separate,
tested modules rather than assumed from the MVP.
