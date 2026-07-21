#!/usr/bin/env python3
"""
Android Forensic Framework – Phase 1 Prototype
================================================

Capabilities (Phase 1 Roadmap):
  • Device detection & ADB connection
  • Device information extraction
  • Installed application enumeration
  • Logical acquisition (media, APKs, downloads)
  • App database extraction (WhatsApp, Signal, Telegram, Email)
  • Evidence integrity hashing (SHA-256 / MD5)
  • Evidence repository with chain-of-custody metadata
  • Basic timeline generation
  • HTML + JSON report generation

Usage:
  python prototype.py                     # auto-detect device, full acquisition
  python prototype.py --list              # list connected devices
  python prototype.py --serial <SERIAL>   # target specific device
  python prototype.py --output ./evidence # set evidence output directory
  python prototype.py --skip-media        # skip large media pulls
  python prototype.py --skip-apk         # skip APK extraction
  python prototype.py --dry-run           # show what would be acquired

Zero external dependencies – stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────
#  Constants
# ──────────────────────────────────────────────

VERSION = "0.1.0-prototype"
TOOL_NAME = "AndroidForensic"

# ADB pull targets for logical acquisition
MEDIA_PATHS = [
    "/sdcard/DCIM",
    "/sdcard/Pictures",
    "/sdcard/Movies",
    "/sdcard/Music",
    "/sdcard/Download",
    "/sdcard/Documents",
    "/sdcard/Recordings",
    "/sdcard/Screenshots",
]

# Application database paths for extraction
# Each entry: (app_name, package_name, root_paths, non_root_paths)
APP_TARGETS = [
    {
        "name": "WhatsApp",
        "package": "com.whatsapp",
        "root_paths": [
            "/data/data/com.whatsapp/databases",
            "/data/data/com.whatsapp/shared_prefs",
        ],
        "accessible_paths": [
            "/sdcard/Android/media/com.whatsapp",
            "/sdcard/WhatsApp",
        ],
    },
    {
        "name": "WhatsApp Business",
        "package": "com.whatsapp.w4b",
        "root_paths": [
            "/data/data/com.whatsapp.w4b/databases",
            "/data/data/com.whatsapp.w4b/shared_prefs",
        ],
        "accessible_paths": [
            "/sdcard/Android/media/com.whatsapp.w4b",
            "/sdcard/WhatsApp Business",
        ],
    },
    {
        "name": "Signal",
        "package": "org.thoughtcrime.securesms",
        "root_paths": [
            "/data/data/org.thoughtcrime.securesms/databases",
            "/data/data/org.thoughtcrime.securesms/shared_prefs",
        ],
        "accessible_paths": [
            "/sdcard/Android/media/org.thoughtcrime.securesms",
        ],
    },
    {
        "name": "Telegram",
        "package": "org.telegram.messenger",
        "root_paths": [
            "/data/data/org.telegram.messenger/databases",
            "/data/data/org.telegram.messenger/shared_prefs",
            "/data/data/org.telegram.messenger/files",
        ],
        "accessible_paths": [
            "/sdcard/Android/data/org.telegram.messenger",
            "/sdcard/Telegram",
        ],
    },
    {
        "name": "Telegram X",
        "package": "org.thunderdog.chalern",
        "root_paths": [
            "/data/data/org.thunderdog.chalern/databases",
            "/data/data/org.thunderdog.chalern/shared_prefs",
        ],
        "accessible_paths": [],
    },
    {
        "name": "Gmail",
        "package": "com.google.android.gm",
        "root_paths": [
            "/data/data/com.google.android.gm/databases",
            "/data/data/com.google.android.gm/shared_prefs",
            "/data/data/com.google.android.gm/cache",
        ],
        "accessible_paths": [],
    },
    {
        "name": "Samsung Email",
        "package": "com.samsung.android.email.provider",
        "root_paths": [
            "/data/data/com.samsung.android.email.provider/databases",
            "/data/data/com.samsung.android.email.provider/shared_prefs",
        ],
        "accessible_paths": [],
    },
    {
        "name": "AOSP Email",
        "package": "com.android.email",
        "root_paths": [
            "/data/data/com.android.email/databases",
            "/data/data/com.android.email/shared_prefs",
        ],
        "accessible_paths": [],
    },
    {
        "name": "Outlook",
        "package": "com.microsoft.office.outlook",
        "root_paths": [
            "/data/data/com.microsoft.office.outlook/databases",
            "/data/data/com.microsoft.office.outlook/shared_prefs",
        ],
        "accessible_paths": [],
    },
    {
        "name": "ProtonMail",
        "package": "ch.protonmail.android",
        "root_paths": [
            "/data/data/ch.protonmail.android/databases",
            "/data/data/ch.protonmail.android/shared_prefs",
        ],
        "accessible_paths": [],
    },
]

# Device properties to collect
DEVICE_PROPS = [
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.name",
    "ro.product.device",
    "ro.build.display.id",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.type",
    "ro.build.fingerprint",
    "ro.serialno",
    "ro.hardware",
    "ro.board.platform",
    "ro.bootloader",
    "persist.sys.timezone",
    "gsm.operator.alpha",
    "gsm.sim.operator.alpha",
    "ro.crypto.state",
    "ro.boot.verifiedbootstate",
]

# ──────────────────────────────────────────────
#  Logging Setup
# ──────────────────────────────────────────────

LOG_FORMAT = "%(asctime)s │ %(levelname)-8s │ %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(log_dir: Path, level: str = "DEBUG") -> logging.Logger:
    """Configure console + file logging."""
    logger = logging.getLogger(TOOL_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.DEBUG))

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(console)

    # File handler
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"forensic_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(file_handler)

    return logger


log = logging.getLogger(TOOL_NAME)

# ──────────────────────────────────────────────
#  Data Structures
# ──────────────────────────────────────────────


@dataclass
class DeviceInfo:
    """Parsed device information."""

    serial: str = ""
    model: str = ""
    manufacturer: str = ""
    brand: str = ""
    android_version: str = ""
    sdk_version: str = ""
    security_patch: str = ""
    build_fingerprint: str = ""
    build_type: str = ""
    hardware: str = ""
    board_platform: str = ""
    bootloader: str = ""
    boot_verified_state: str = ""
    crypto_state: str = ""
    timezone: str = ""
    carrier: str = ""
    sim_operator: str = ""
    imei: str = ""
    all_properties: dict = field(default_factory=dict)
    installed_packages: list = field(default_factory=list)
    collection_timestamp: str = ""


@dataclass
class FileEvidence:
    """Metadata for a single acquired file."""

    original_path: str
    local_path: str
    sha256: str
    md5: str
    size_bytes: int
    acquired_at: str
    source: str  # e.g. "logical_acquisition"
    category: str  # e.g. "media", "apk", "document"


@dataclass
class AcquisitionSummary:
    """Summary of an acquisition session."""

    case_id: str
    examiner: str
    device: DeviceInfo
    started_at: str
    completed_at: str = ""
    total_files: int = 0
    total_bytes: int = 0
    evidence_files: list[FileEvidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    acquisition_types: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────
#  ADB Interface
# ──────────────────────────────────────────────


class ADB:
    """Wrapper around the ADB command-line tool."""

    def __init__(self, adb_path: Optional[str] = None, serial: Optional[str] = None):
        self.adb_path = adb_path or self._find_adb()
        self.serial = serial
        log.debug(f"ADB binary: {self.adb_path}")

    @staticmethod
    def _find_adb() -> str:
        """Locate ADB binary – check bundled tools first, then PATH."""
        project_root = Path(__file__).resolve().parent

        # Check bundled platform tools
        system = platform.system().lower()
        platform_map = {"windows": "windows", "linux": "linux", "darwin": "mac"}
        platform_dir = platform_map.get(system, system)

        bundled = project_root / "components" / "adb-tools" / platform_dir
        adb_name = "adb.exe" if system == "windows" else "adb"

        # Check multiple candidate locations within bundled dir
        candidates = [
            bundled / adb_name,                        # direct
            bundled / "platform-tools" / adb_name,     # standard SDK layout
        ]
        # Also search recursively as a fallback
        for candidate in candidates:
            if candidate.is_file():
                log.debug(f"Using bundled ADB: {candidate}")
                return str(candidate)

        # Try glob as last resort for bundled
        for match in bundled.rglob(adb_name):
            if match.is_file():
                log.debug(f"Using bundled ADB (discovered): {match}")
                return str(match)

        # Fall back to PATH
        adb_name = "adb.exe" if system == "windows" else "adb"
        path_adb = shutil.which(adb_name)
        if path_adb:
            log.debug(f"Using system ADB: {path_adb}")
            return path_adb

        # Check ANDROID_HOME / ANDROID_SDK_ROOT
        for env_var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
            sdk_path = os.environ.get(env_var)
            if sdk_path:
                candidate = Path(sdk_path) / "platform-tools" / adb_name
                if candidate.is_file():
                    log.debug(f"Using ADB from {env_var}: {candidate}")
                    return str(candidate)

        raise FileNotFoundError(
            "ADB not found. Install Android platform-tools or place them in "
            "capture/components/adb-tools/<platform>/"
        )

    def _build_cmd(self, *args: str) -> list[str]:
        """Build ADB command with optional serial targeting."""
        cmd = [self.adb_path]
        if self.serial:
            cmd.extend(["-s", self.serial])
        cmd.extend(args)
        return cmd

    def run(
        self,
        *args: str,
        timeout: int = 30,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Execute an ADB command and return the result."""
        cmd = self._build_cmd(*args)
        log.debug(f"ADB exec: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check,
                encoding="utf-8",
                errors="replace",
            )
            return result
        except subprocess.TimeoutExpired:
            log.error(f"ADB command timed out after {timeout}s: {' '.join(cmd)}")
            raise
        except subprocess.CalledProcessError as e:
            log.error(f"ADB command failed: {e.stderr.strip()}")
            raise

    def devices(self) -> list[dict[str, str]]:
        """List connected devices with their state."""
        result = self.run("devices", "-l")
        devices = []
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                info = {"serial": parts[0], "state": parts[1]}
                # Parse additional key:value pairs
                for part in parts[2:]:
                    if ":" in part:
                        key, value = part.split(":", 1)
                        info[key] = value
                devices.append(info)
        return devices

    def shell(self, command: str, timeout: int = 30) -> str:
        """Execute a shell command on the device."""
        result = self.run("shell", command, timeout=timeout, check=False)
        return result.stdout.strip()

    def getprop(self, prop: Optional[str] = None) -> str:
        """Get device property or all properties."""
        if prop:
            return self.shell(f"getprop {prop}")
        return self.shell("getprop")

    def pull(self, remote: str, local: str, timeout: int = 300) -> bool:
        """Pull a file or directory from the device."""
        try:
            self.run("pull", "-a", remote, local, timeout=timeout, check=True)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.warning(f"Failed to pull {remote}: {e}")
            return False

    def get_state(self) -> str:
        """Get device connection state."""
        try:
            result = self.run("get-state", timeout=5)
            return result.stdout.strip()
        except Exception:
            return "offline"


# ──────────────────────────────────────────────
#  Integrity Engine
# ──────────────────────────────────────────────


class IntegrityEngine:
    """Compute and verify cryptographic hashes for forensic integrity."""

    BUFFER_SIZE = 65536  # 64 KB

    @staticmethod
    def hash_file(filepath: Path) -> tuple[str, str]:
        """Compute SHA-256 and MD5 for a file. Returns (sha256, md5)."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()

        with open(filepath, "rb") as f:
            while chunk := f.read(IntegrityEngine.BUFFER_SIZE):
                sha256.update(chunk)
                md5.update(chunk)

        return sha256.hexdigest(), md5.hexdigest()

    @staticmethod
    def hash_string(data: str) -> str:
        """SHA-256 hash of a string (for metadata integrity)."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_file(filepath: Path, expected_sha256: str) -> bool:
        """Verify a file against an expected SHA-256 hash."""
        actual_sha256, _ = IntegrityEngine.hash_file(filepath)
        return actual_sha256 == expected_sha256


# ──────────────────────────────────────────────
#  Evidence Repository
# ──────────────────────────────────────────────


class EvidenceRepository:
    """Manages the evidence directory structure and metadata."""

    def __init__(self, base_dir: Path, case_id: str):
        self.case_id = case_id
        self.root = base_dir / case_id
        self.raw_dir = self.root / "raw"
        self.parsed_dir = self.root / "parsed"
        self.logs_dir = self.root / "logs"
        self.hashes_dir = self.root / "hashes"
        self.reports_dir = self.root / "reports"
        self._hash_log: list[dict] = []

    def initialize(self) -> None:
        """Create the evidence directory structure."""
        for directory in [
            self.raw_dir,
            self.parsed_dir,
            self.logs_dir,
            self.hashes_dir,
            self.reports_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)
        log.info(f"Evidence repository initialized: {self.root}")

    def get_raw_path(self, category: str) -> Path:
        """Get the raw evidence path for a category (media, apk, etc.)."""
        path = self.raw_dir / category
        path.mkdir(parents=True, exist_ok=True)
        return path

    def register_file(self, evidence: FileEvidence) -> None:
        """Register an acquired file with its hash in the hash log."""
        self._hash_log.append(asdict(evidence))

    def save_hash_log(self) -> Path:
        """Persist the hash log to disk."""
        hash_file = self.hashes_dir / "hash_manifest.json"
        with open(hash_file, "w", encoding="utf-8") as f:
            json.dump(self._hash_log, f, indent=2, ensure_ascii=False)

        # Also write a CSV version for quick reference
        csv_file = self.hashes_dir / "hash_manifest.csv"
        if self._hash_log:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self._hash_log[0].keys())
                writer.writeheader()
                writer.writerows(self._hash_log)

        log.info(f"Hash manifest saved: {hash_file}")
        return hash_file

    def save_metadata(self, summary: AcquisitionSummary) -> Path:
        """Save acquisition metadata as JSON."""
        meta_file = self.root / "acquisition_metadata.json"
        data = asdict(summary)
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        log.info(f"Acquisition metadata saved: {meta_file}")
        return meta_file


# ──────────────────────────────────────────────
#  Device Information Collector
# ──────────────────────────────────────────────


class DeviceCollector:
    """Collects comprehensive device information via ADB."""

    def __init__(self, adb: ADB):
        self.adb = adb

    def collect(self) -> DeviceInfo:
        """Gather all device information."""
        log.info("Collecting device information...")
        info = DeviceInfo()
        info.collection_timestamp = datetime.datetime.now().isoformat()

        # Collect targeted properties
        props = {}
        for prop in DEVICE_PROPS:
            value = self.adb.getprop(prop)
            if value:
                props[prop] = value

        # Map to structured fields
        info.serial = props.get("ro.serialno", self.adb.serial or "unknown")
        info.model = props.get("ro.product.model", "unknown")
        info.manufacturer = props.get("ro.product.manufacturer", "unknown")
        info.brand = props.get("ro.product.brand", "unknown")
        info.android_version = props.get("ro.build.version.release", "unknown")
        info.sdk_version = props.get("ro.build.version.sdk", "unknown")
        info.security_patch = props.get(
            "ro.build.version.security_patch", "unknown"
        )
        info.build_fingerprint = props.get("ro.build.fingerprint", "unknown")
        info.build_type = props.get("ro.build.type", "unknown")
        info.hardware = props.get("ro.hardware", "unknown")
        info.board_platform = props.get("ro.board.platform", "unknown")
        info.bootloader = props.get("ro.bootloader", "unknown")
        info.boot_verified_state = props.get(
            "ro.boot.verifiedbootstate", "unknown"
        )
        info.crypto_state = props.get("ro.crypto.state", "unknown")
        info.timezone = props.get("persist.sys.timezone", "unknown")
        info.carrier = props.get("gsm.operator.alpha", "unknown")
        info.sim_operator = props.get("gsm.sim.operator.alpha", "unknown")

        # IMEI (requires permissions, may fail)
        imei = self.adb.shell("service call iphonesubinfo 1 2>/dev/null")
        if imei and "error" not in imei.lower():
            # Parse the service call output to extract IMEI digits
            digits = "".join(c for c in imei if c.isdigit())
            if len(digits) >= 15:
                info.imei = digits[:15]

        # Collect all properties for the raw dump
        all_props_raw = self.adb.getprop()
        for line in all_props_raw.splitlines():
            line = line.strip()
            if line.startswith("[") and "]: [" in line:
                key = line.split("]: [")[0].lstrip("[")
                value = line.split("]: [")[1].rstrip("]")
                info.all_properties[key] = value

        # Installed packages
        info.installed_packages = self._list_packages()

        log.info(
            f"Device: {info.manufacturer} {info.model} "
            f"(Android {info.android_version}, API {info.sdk_version})"
        )
        return info

    def _list_packages(self) -> list[dict]:
        """List all installed packages with version info."""
        log.info("Enumerating installed packages...")
        packages = []

        # List all packages (system + third-party)
        output = self.adb.shell("pm list packages -f", timeout=60)
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            # Format: package:<path>=<package_name>
            rest = line[len("package:"):]
            if "=" in rest:
                apk_path, pkg_name = rest.rsplit("=", 1)
            else:
                apk_path = ""
                pkg_name = rest

            packages.append({
                "package": pkg_name,
                "apk_path": apk_path,
            })

        # Identify third-party packages
        third_party_output = self.adb.shell("pm list packages -3", timeout=60)
        third_party = set()
        for line in third_party_output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                third_party.add(line[len("package:"):])

        for pkg in packages:
            pkg["is_system"] = pkg["package"] not in third_party

        log.info(
            f"Found {len(packages)} packages "
            f"({len(third_party)} third-party)"
        )
        return packages


# ──────────────────────────────────────────────
#  Acquisition Engine (Logical)
# ──────────────────────────────────────────────


class LogicalAcquisition:
    """Performs logical acquisition via ADB pull."""

    def __init__(self, adb: ADB, repo: EvidenceRepository):
        self.adb = adb
        self.repo = repo
        self.integrity = IntegrityEngine()
        self._acquired: list[FileEvidence] = []
        self._errors: list[str] = []

    @property
    def acquired(self) -> list[FileEvidence]:
        return self._acquired

    @property
    def errors(self) -> list[str]:
        return self._errors

    def acquire_media(self) -> None:
        """Pull media directories from the device."""
        log.info("=" * 50)
        log.info("Starting media acquisition...")
        log.info("=" * 50)

        for remote_path in MEDIA_PATHS:
            # Check if the path exists on device
            check = self.adb.shell(f'[ -d "{remote_path}" ] && echo EXISTS')
            if "EXISTS" not in check:
                log.debug(f"Skipping {remote_path} (not found on device)")
                continue

            # Determine category from path
            category = remote_path.rstrip("/").split("/")[-1].lower()
            local_dir = self.repo.get_raw_path(f"media/{category}")

            log.info(f"Pulling: {remote_path} → {local_dir}")
            success = self.adb.pull(remote_path, str(local_dir), timeout=600)

            if success:
                self._register_pulled_files(local_dir, remote_path, "media")
            else:
                err = f"Failed to pull {remote_path}"
                self._errors.append(err)
                log.warning(err)

    def acquire_apks(self) -> None:
        """Extract APK files for third-party applications."""
        log.info("=" * 50)
        log.info("Starting APK extraction...")
        log.info("=" * 50)

        apk_dir = self.repo.get_raw_path("apk")

        # Get third-party package paths
        output = self.adb.shell("pm list packages -3 -f", timeout=60)
        apk_entries = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            rest = line[len("package:"):]
            if "=" in rest:
                apk_path, pkg_name = rest.rsplit("=", 1)
                apk_entries.append((pkg_name, apk_path))

        log.info(f"Found {len(apk_entries)} third-party APKs to extract")

        for pkg_name, remote_apk in apk_entries:
            local_apk = apk_dir / f"{pkg_name}.apk"
            log.info(f"Extracting: {pkg_name}")

            success = self.adb.pull(remote_apk, str(local_apk), timeout=120)
            if success and local_apk.is_file():
                sha256, md5 = self.integrity.hash_file(local_apk)
                evidence = FileEvidence(
                    original_path=remote_apk,
                    local_path=str(local_apk.relative_to(self.repo.root)),
                    sha256=sha256,
                    md5=md5,
                    size_bytes=local_apk.stat().st_size,
                    acquired_at=datetime.datetime.now().isoformat(),
                    source="logical_acquisition",
                    category="apk",
                )
                self._acquired.append(evidence)
                self.repo.register_file(evidence)
            else:
                err = f"Failed to extract APK: {pkg_name}"
                self._errors.append(err)
                log.warning(err)

    def acquire_app_databases(self) -> None:
        """Extract databases and data from messaging and email apps.

        Attempts both root-level paths (/data/data/) and user-accessible
        storage paths (/sdcard/Android/media/). Root paths will fail
        gracefully on non-rooted devices.
        """
        log.info("=" * 50)
        log.info("Starting application database extraction...")
        log.info("=" * 50)

        # Check which target apps are installed
        installed_output = self.adb.shell("pm list packages", timeout=60)
        installed_packages = set()
        for line in installed_output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                installed_packages.add(line[len("package:"):])

        # Check if device is rooted
        root_check = self.adb.shell("su -c 'id' 2>/dev/null || echo NO_ROOT")
        has_root = "uid=0" in root_check
        if has_root:
            log.info("Root access detected – will attempt root-level extraction")
        else:
            log.info("No root access – will extract accessible storage only")

        extracted_count = 0

        for app in APP_TARGETS:
            if app["package"] not in installed_packages:
                log.debug(f"Skipping {app['name']} (not installed)")
                continue

            log.info(f"📲 Extracting {app['name']} ({app['package']})...")
            app_dir = self.repo.get_raw_path(f"apps/{app['name'].lower().replace(' ', '_')}")

            # Try root-level paths (databases, shared_prefs)
            if has_root:
                for remote_path in app["root_paths"]:
                    # Determine subdirectory name from path
                    subdir = remote_path.rstrip("/").split("/")[-1]
                    local_target = app_dir / "root" / subdir
                    local_target.mkdir(parents=True, exist_ok=True)

                    log.info(f"  [root] Pulling: {remote_path}")
                    # Use su to copy to a temp location first, then pull
                    temp_remote = f"/data/local/tmp/_forensic_{subdir}"
                    self.adb.shell(
                        f"su -c 'cp -r {remote_path} {temp_remote}' 2>/dev/null",
                        timeout=120,
                    )
                    # Fix permissions so adb can pull
                    self.adb.shell(
                        f"su -c 'chmod -R 755 {temp_remote}' 2>/dev/null",
                        timeout=30,
                    )
                    success = self.adb.pull(temp_remote, str(local_target), timeout=300)
                    # Cleanup temp
                    self.adb.shell(f"su -c 'rm -rf {temp_remote}' 2>/dev/null")

                    if success:
                        self._register_pulled_files(
                            local_target, remote_path, f"app_{app['name'].lower().replace(' ', '_')}"
                        )
                        extracted_count += 1
                    else:
                        log.debug(f"  [root] Could not pull {remote_path}")

            # Try accessible paths (non-root, /sdcard/Android/media/ etc.)
            for remote_path in app["accessible_paths"]:
                check = self.adb.shell(f'[ -d "{remote_path}" ] && echo EXISTS')
                if "EXISTS" not in check:
                    log.debug(f"  [accessible] Not found: {remote_path}")
                    continue

                subdir = remote_path.rstrip("/").split("/")[-1]
                local_target = app_dir / "accessible" / subdir
                local_target.mkdir(parents=True, exist_ok=True)

                log.info(f"  [accessible] Pulling: {remote_path}")
                success = self.adb.pull(remote_path, str(local_target), timeout=600)

                if success:
                    self._register_pulled_files(
                        local_target, remote_path, f"app_{app['name'].lower().replace(' ', '_')}"
                    )
                    extracted_count += 1
                else:
                    err = f"Failed to pull {remote_path}"
                    self._errors.append(err)
                    log.warning(f"  {err}")

        log.info(f"App database extraction complete: {extracted_count} paths extracted")

    def acquire_device_dumps(self, device_info: DeviceInfo) -> None:
        """Save device information dumps."""
        log.info("Saving device information dumps...")
        dump_dir = self.repo.get_raw_path("device_info")

        # Save all properties
        all_props = self.adb.getprop()
        self._save_dump(dump_dir / "getprop.txt", all_props)

        # Save dumpsys outputs (selected services)
        dumpsys_services = [
            "battery",
            "wifi",
            "connectivity",
            "account",
            "notification",
            "usagestats",
            "diskstats",
        ]
        for service in dumpsys_services:
            output = self.adb.shell(f"dumpsys {service}", timeout=30)
            if output and "error" not in output.lower()[:50]:
                self._save_dump(dump_dir / f"dumpsys_{service}.txt", output)

        # Save device info as structured JSON
        info_json = json.dumps(asdict(device_info), indent=2, ensure_ascii=False)
        self._save_dump(dump_dir / "device_info.json", info_json)

        # Save installed packages list
        pkg_json = json.dumps(
            device_info.installed_packages, indent=2, ensure_ascii=False
        )
        self._save_dump(dump_dir / "installed_packages.json", pkg_json)

        log.info(f"Device dumps saved to {dump_dir}")

    def _save_dump(self, filepath: Path, content: str) -> None:
        """Save a text dump and register its hash."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        sha256, md5 = self.integrity.hash_file(filepath)
        evidence = FileEvidence(
            original_path="device_dump",
            local_path=str(filepath.relative_to(self.repo.root)),
            sha256=sha256,
            md5=md5,
            size_bytes=filepath.stat().st_size,
            acquired_at=datetime.datetime.now().isoformat(),
            source="device_dump",
            category="device_info",
        )
        self._acquired.append(evidence)
        self.repo.register_file(evidence)

    def _register_pulled_files(
        self, local_dir: Path, remote_base: str, category: str
    ) -> None:
        """Hash and register all files pulled into a directory."""
        for filepath in local_dir.rglob("*"):
            if not filepath.is_file():
                continue
            try:
                sha256, md5 = self.integrity.hash_file(filepath)
                # Reconstruct approximate original path
                relative = filepath.relative_to(local_dir)
                original = f"{remote_base}/{relative}".replace("\\", "/")

                evidence = FileEvidence(
                    original_path=original,
                    local_path=str(filepath.relative_to(self.repo.root)),
                    sha256=sha256,
                    md5=md5,
                    size_bytes=filepath.stat().st_size,
                    acquired_at=datetime.datetime.now().isoformat(),
                    source="logical_acquisition",
                    category=category,
                )
                self._acquired.append(evidence)
                self.repo.register_file(evidence)
            except Exception as e:
                err = f"Error hashing {filepath}: {e}"
                self._errors.append(err)
                log.warning(err)


# ──────────────────────────────────────────────
#  Timeline Generator
# ──────────────────────────────────────────────


class TimelineGenerator:
    """Generates a basic forensic timeline from acquired evidence."""

    def __init__(self, summary: AcquisitionSummary):
        self.summary = summary

    def generate(self) -> list[dict]:
        """Build a chronological timeline of events."""
        events = []

        # Acquisition start
        events.append({
            "timestamp": self.summary.started_at,
            "event": "Acquisition Started",
            "source": "framework",
            "details": f"Case {self.summary.case_id}",
        })

        # Device info collection
        if self.summary.device.collection_timestamp:
            events.append({
                "timestamp": self.summary.device.collection_timestamp,
                "event": "Device Info Collected",
                "source": "device_collector",
                "details": (
                    f"{self.summary.device.manufacturer} "
                    f"{self.summary.device.model}"
                ),
            })

        # File acquisitions (group by category)
        categories: dict[str, list] = {}
        for ef in self.summary.evidence_files:
            categories.setdefault(ef.category, []).append(ef)

        for category, files in sorted(categories.items()):
            # Use earliest timestamp in category
            timestamps = [f.acquired_at for f in files if f.acquired_at]
            earliest = min(timestamps) if timestamps else self.summary.started_at
            total_size = sum(f.size_bytes for f in files)
            events.append({
                "timestamp": earliest,
                "event": f"{category.title()} Acquisition",
                "source": "logical_acquisition",
                "details": (
                    f"{len(files)} files, "
                    f"{total_size / (1024 * 1024):.2f} MB"
                ),
            })

        # Acquisition end
        if self.summary.completed_at:
            events.append({
                "timestamp": self.summary.completed_at,
                "event": "Acquisition Completed",
                "source": "framework",
                "details": (
                    f"{self.summary.total_files} files, "
                    f"{self.summary.total_bytes / (1024 * 1024):.2f} MB total"
                ),
            })

        # Sort chronologically
        events.sort(key=lambda e: e["timestamp"])
        return events


# ──────────────────────────────────────────────
#  Report Generator
# ──────────────────────────────────────────────


class ReportGenerator:
    """Generates forensic reports in HTML and JSON formats."""

    def __init__(self, repo: EvidenceRepository):
        self.repo = repo

    def generate_json_report(
        self, summary: AcquisitionSummary, timeline: list[dict]
    ) -> Path:
        """Generate a JSON report."""
        report = {
            "report_metadata": {
                "tool": TOOL_NAME,
                "version": VERSION,
                "generated_at": datetime.datetime.now().isoformat(),
                "report_hash": "",  # filled below
            },
            "case": {
                "case_id": summary.case_id,
                "examiner": summary.examiner,
                "started_at": summary.started_at,
                "completed_at": summary.completed_at,
            },
            "device": asdict(summary.device),
            "acquisition": {
                "types": summary.acquisition_types,
                "total_files": summary.total_files,
                "total_bytes": summary.total_bytes,
                "errors": summary.errors,
            },
            "timeline": timeline,
            "evidence_files": [asdict(f) for f in summary.evidence_files],
        }

        # Compute report integrity hash (excluding the hash field itself)
        report_str = json.dumps(report, sort_keys=True, default=str)
        report["report_metadata"]["report_hash"] = IntegrityEngine.hash_string(
            report_str
        )

        report_file = self.repo.reports_dir / "forensic_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        log.info(f"JSON report generated: {report_file}")
        return report_file

    def generate_html_report(
        self, summary: AcquisitionSummary, timeline: list[dict]
    ) -> Path:
        """Generate an HTML forensic report."""
        device = summary.device

        # Build evidence table rows
        evidence_rows = ""
        for i, ef in enumerate(summary.evidence_files, 1):
            size_display = self._format_size(ef.size_bytes)
            evidence_rows += textwrap.dedent(f"""\
                <tr>
                    <td>{i}</td>
                    <td class="path" title="{ef.original_path}">{self._truncate(ef.original_path, 55)}</td>
                    <td>{ef.category}</td>
                    <td>{size_display}</td>
                    <td class="hash" title="{ef.sha256}">{ef.sha256[:16]}…</td>
                    <td class="hash" title="{ef.md5}">{ef.md5[:12]}…</td>
                </tr>
            """)

        # Build timeline rows
        timeline_rows = ""
        for event in timeline:
            timeline_rows += textwrap.dedent(f"""\
                <tr>
                    <td>{event['timestamp']}</td>
                    <td><strong>{event['event']}</strong></td>
                    <td>{event['source']}</td>
                    <td>{event['details']}</td>
                </tr>
            """)

        # Build package rows (first 50 third-party)
        third_party_pkgs = [
            p for p in device.installed_packages if not p.get("is_system", True)
        ]
        pkg_rows = ""
        for pkg in third_party_pkgs[:50]:
            pkg_rows += f"<tr><td>{pkg['package']}</td><td>{pkg.get('apk_path', '')}</td></tr>\n"

        # Error rows
        error_section = ""
        if summary.errors:
            error_items = "".join(f"<li>{e}</li>" for e in summary.errors)
            error_section = f"""
            <div class="section">
                <h2>⚠️ Errors & Warnings</h2>
                <ul class="errors">{error_items}</ul>
            </div>
            """

        total_size = self._format_size(summary.total_bytes)
        system_count = len(device.installed_packages) - len(third_party_pkgs)

        html = textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Forensic Report – {summary.case_id}</title>
            <style>
                :root {{
                    --bg: #0f1117;
                    --surface: #1a1d27;
                    --surface2: #232734;
                    --border: #2d3348;
                    --text: #e4e6f0;
                    --text-dim: #8b8fa3;
                    --accent: #6c8dfa;
                    --accent2: #a78bfa;
                    --green: #4ade80;
                    --red: #f87171;
                    --orange: #fb923c;
                }}
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                    background: var(--bg);
                    color: var(--text);
                    line-height: 1.6;
                    padding: 2rem;
                }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{
                    background: linear-gradient(135deg, #1e2235 0%, #2a1f3d 100%);
                    border: 1px solid var(--border);
                    border-radius: 12px;
                    padding: 2rem;
                    margin-bottom: 1.5rem;
                }}
                .header h1 {{
                    font-size: 1.75rem;
                    background: linear-gradient(135deg, var(--accent), var(--accent2));
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    margin-bottom: 0.5rem;
                }}
                .header .meta {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                    gap: 0.75rem;
                    margin-top: 1rem;
                }}
                .header .meta span {{
                    font-size: 0.85rem;
                    color: var(--text-dim);
                }}
                .header .meta strong {{ color: var(--text); }}
                .section {{
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: 12px;
                    padding: 1.5rem;
                    margin-bottom: 1.5rem;
                }}
                .section h2 {{
                    font-size: 1.15rem;
                    color: var(--accent);
                    margin-bottom: 1rem;
                    padding-bottom: 0.5rem;
                    border-bottom: 1px solid var(--border);
                }}
                .grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 0.5rem;
                }}
                .grid .item {{
                    display: flex;
                    justify-content: space-between;
                    padding: 0.4rem 0;
                    border-bottom: 1px solid var(--border);
                    font-size: 0.9rem;
                }}
                .grid .item .label {{ color: var(--text-dim); }}
                .grid .item .value {{ font-weight: 600; text-align: right; }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                    gap: 1rem;
                    margin-bottom: 1rem;
                }}
                .stat-card {{
                    background: var(--surface2);
                    border-radius: 8px;
                    padding: 1rem;
                    text-align: center;
                }}
                .stat-card .number {{
                    font-size: 1.75rem;
                    font-weight: 700;
                    color: var(--accent);
                }}
                .stat-card .label {{
                    font-size: 0.8rem;
                    color: var(--text-dim);
                    margin-top: 0.25rem;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 0.85rem;
                }}
                th {{
                    background: var(--surface2);
                    color: var(--accent);
                    text-align: left;
                    padding: 0.6rem 0.75rem;
                    font-weight: 600;
                    position: sticky;
                    top: 0;
                }}
                td {{
                    padding: 0.5rem 0.75rem;
                    border-bottom: 1px solid var(--border);
                    color: var(--text);
                }}
                tr:hover td {{ background: var(--surface2); }}
                .hash {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.8rem; color: var(--text-dim); }}
                .path {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.8rem; }}
                .table-wrap {{ max-height: 500px; overflow-y: auto; border-radius: 8px; }}
                .errors {{ list-style: none; }}
                .errors li {{
                    padding: 0.4rem 0.75rem;
                    margin-bottom: 0.25rem;
                    background: rgba(248, 113, 113, 0.1);
                    border-left: 3px solid var(--red);
                    border-radius: 4px;
                    font-size: 0.85rem;
                }}
                .footer {{
                    text-align: center;
                    font-size: 0.8rem;
                    color: var(--text-dim);
                    margin-top: 2rem;
                    padding-top: 1rem;
                    border-top: 1px solid var(--border);
                }}
            </style>
        </head>
        <body>
        <div class="container">

            <div class="header">
                <h1>🔍 Android Forensic Report</h1>
                <p style="color: var(--text-dim); font-size: 0.9rem;">
                    Generated by {TOOL_NAME} v{VERSION}
                </p>
                <div class="meta">
                    <span>Case ID: <strong>{summary.case_id}</strong></span>
                    <span>Examiner: <strong>{summary.examiner}</strong></span>
                    <span>Started: <strong>{summary.started_at}</strong></span>
                    <span>Completed: <strong>{summary.completed_at}</strong></span>
                </div>
            </div>

            <div class="stats">
                <div class="stat-card">
                    <div class="number">{summary.total_files}</div>
                    <div class="label">Files Acquired</div>
                </div>
                <div class="stat-card">
                    <div class="number">{total_size}</div>
                    <div class="label">Total Size</div>
                </div>
                <div class="stat-card">
                    <div class="number">{len(device.installed_packages)}</div>
                    <div class="label">Installed Apps</div>
                </div>
                <div class="stat-card">
                    <div class="number">{len(summary.errors)}</div>
                    <div class="label">Errors</div>
                </div>
            </div>

            <div class="section">
                <h2>📱 Device Information</h2>
                <div class="grid">
                    <div class="item"><span class="label">Manufacturer</span><span class="value">{device.manufacturer}</span></div>
                    <div class="item"><span class="label">Model</span><span class="value">{device.model}</span></div>
                    <div class="item"><span class="label">Brand</span><span class="value">{device.brand}</span></div>
                    <div class="item"><span class="label">Serial</span><span class="value">{device.serial}</span></div>
                    <div class="item"><span class="label">Android Version</span><span class="value">{device.android_version}</span></div>
                    <div class="item"><span class="label">SDK / API Level</span><span class="value">{device.sdk_version}</span></div>
                    <div class="item"><span class="label">Security Patch</span><span class="value">{device.security_patch}</span></div>
                    <div class="item"><span class="label">Build Fingerprint</span><span class="value" style="font-size:0.75rem">{device.build_fingerprint}</span></div>
                    <div class="item"><span class="label">Hardware</span><span class="value">{device.hardware}</span></div>
                    <div class="item"><span class="label">Bootloader</span><span class="value">{device.bootloader}</span></div>
                    <div class="item"><span class="label">Verified Boot</span><span class="value">{device.boot_verified_state}</span></div>
                    <div class="item"><span class="label">Encryption</span><span class="value">{device.crypto_state}</span></div>
                    <div class="item"><span class="label">Timezone</span><span class="value">{device.timezone}</span></div>
                    <div class="item"><span class="label">Carrier</span><span class="value">{device.carrier}</span></div>
                    <div class="item"><span class="label">IMEI</span><span class="value">{device.imei or 'N/A'}</span></div>
                </div>
            </div>

            <div class="section">
                <h2>📦 Installed Applications ({len(third_party_pkgs)} third-party / {system_count} system)</h2>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Package Name</th><th>APK Path</th></tr></thead>
                        <tbody>{pkg_rows}</tbody>
                    </table>
                </div>
                {"<p style='color:var(--text-dim);margin-top:0.5rem;font-size:0.85rem'>Showing first 50 of " + str(len(third_party_pkgs)) + " third-party packages. See full list in installed_packages.json.</p>" if len(third_party_pkgs) > 50 else ""}
            </div>

            <div class="section">
                <h2>⏱️ Timeline</h2>
                <table>
                    <thead><tr><th>Timestamp</th><th>Event</th><th>Source</th><th>Details</th></tr></thead>
                    <tbody>{timeline_rows}</tbody>
                </table>
            </div>

            <div class="section">
                <h2>📂 Evidence Files ({summary.total_files})</h2>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr><th>#</th><th>Original Path</th><th>Category</th><th>Size</th><th>SHA-256</th><th>MD5</th></tr>
                        </thead>
                        <tbody>{evidence_rows}</tbody>
                    </table>
                </div>
            </div>

            {error_section}

            <div class="footer">
                <p>{TOOL_NAME} v{VERSION} &mdash; Report generated {datetime.datetime.now():%Y-%m-%d %H:%M:%S}</p>
                <p>This report is intended for authorized forensic examination purposes only.</p>
            </div>

        </div>
        </body>
        </html>
        """)

        report_file = self.repo.reports_dir / "forensic_report.html"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(html)

        log.info(f"HTML report generated: {report_file}")
        return report_file

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format byte count to human-readable string."""
        for unit in ("B", "KB", "MB", "GB"):
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max_len - 1] + "…"


# ──────────────────────────────────────────────
#  Main Orchestrator
# ──────────────────────────────────────────────


def print_banner() -> None:
    """Print the tool banner."""
    banner = f"""
╔══════════════════════════════════════════════════════╗
║                                                      ║
║   🔍  Android Forensic Framework                     ║
║       Phase 1 Prototype – v{VERSION:<22s}  ║
║                                                      ║
║   Logical Acquisition · Device Info · Integrity      ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
"""
    print(banner)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Android Forensic Framework – Phase 1 Prototype",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--list", action="store_true", help="List connected devices and exit"
    )
    parser.add_argument(
        "--serial", "-s", help="Target a specific device by serial number"
    )
    parser.add_argument(
        "--output",
        "-o",
        default=os.environ.get("FORENSIC_EVIDENCE_DIR", "./evidence"),
        help="Evidence output directory (default: ./evidence)",
    )
    parser.add_argument(
        "--case-id", help="Case identifier (auto-generated if not provided)"
    )
    parser.add_argument(
        "--examiner", default=os.environ.get("USER", "examiner"), help="Examiner name"
    )
    parser.add_argument(
        "--skip-media", action="store_true", help="Skip media acquisition"
    )
    parser.add_argument(
        "--skip-apk", action="store_true", help="Skip APK extraction"
    )
    parser.add_argument(
        "--skip-apps", action="store_true", help="Skip app database extraction (WhatsApp, Signal, Telegram, Email)"
    )
    parser.add_argument(
        "--whatsapp-companion", action="store_true", help="Launch WhatsApp Companion / Web Sync window for live historical chat extraction"
    )
    parser.add_argument(
        "--call-logs", action="store_true", help="Extract cellular call logs (content provider, telecom dump) and WhatsApp VoIP call records"
    )
    parser.add_argument(
        "--messages", action="store_true", help="Extract cellular SMS text messages and aggregate IM databases (WhatsApp, Telegram, Signal, Mails)"
    )
    parser.add_argument(
        "--contacts", action="store_true", help="Extract device address book contacts and IM/WhatsApp contact profiles into SQL/vCard"
    )
    parser.add_argument(
        "--connectivity", action="store_true", help="Extract device connectivity history (Wi-Fi networks, Bluetooth paired devices, USB history, active sockets)"
    )
    parser.add_argument(
        "--notifications", action="store_true", help="Extract active notifications and notification archive history (--noredact)"
    )
    parser.add_argument(
        "--calendar", action="store_true", help="Extract calendar accounts, scheduled events, and generate iCalendar (.ics) / SQLite exports"
    )
    parser.add_argument(
        "--journey", action="store_true", help="Extract device geolocation & journey history into interactive HTML Map (.html) and KML (.kml)"
    )
    parser.add_argument(
        "--network", action="store_true", help="Extract network diagnostics & forensics (IPs, MAC addresses, interfaces, ARP neighbors, live sockets, routing)"
    )
    parser.add_argument(
        "--browser-history", action="store_true", help="Extract search queries, visited URLs, and bookmarks across all browsers (Chrome, Samsung Internet, Firefox, Edge, Brave, Opera)"
    )
    parser.add_argument(
        "--cookies", action="store_true", help="Extract and parse HTTP cookies across all browsers and system WebViews (`app_webview`) into SQLite/Netscape format"
    )
    parser.add_argument(
        "--device-events", action="store_true", help="Extract chronological device events timeline (Screen Lock/Unlock, App activity, Boot history, Power state)"
    )
    parser.add_argument(
        "--connected-devices", action="store_true", help="Extract connected devices and hardware peripherals (USB accessories, Bluetooth gear, P2P hotspot peers, Companion wearables/cast TVs)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be acquired without pulling files",
    )
    parser.add_argument(
        "--adb-path", help="Explicit path to ADB binary"
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    print_banner()
    args = parse_args()

    # ── Initialize ADB ──
    try:
        adb = ADB(adb_path=args.adb_path, serial=args.serial)
    except FileNotFoundError as e:
        print(f"\n❌ {e}")
        return 1

    # ── List devices ──
    devices = adb.devices()
    if args.list:
        print(f"\n{'Serial':<25} {'State':<12} {'Model':<20} {'Transport'}")
        print("─" * 70)
        for d in devices:
            print(
                f"{d['serial']:<25} {d['state']:<12} "
                f"{d.get('model', 'N/A'):<20} {d.get('transport_id', 'N/A')}"
            )
        print(f"\n{len(devices)} device(s) found.")
        return 0

    # ── Validate device connection ──
    authorized = [d for d in devices if d["state"] == "device"]
    if not authorized:
        if devices:
            print("\n❌ Device(s) found but not authorized:\n")
            for d in devices:
                print(f"   📱 {d['serial']}  →  {d['state']}")
            print("\n   To fix this:")
            print("   1. Unlock the phone screen")
            print("   2. Look for the 'Allow USB debugging?' popup and tap Allow")
            print("   3. If no popup appears:")
            print(f"      → Run: {adb.adb_path} kill-server")
            print(f"      → Run: {adb.adb_path} start-server")
            print("      → Or go to Settings → Developer Options → Revoke USB debugging authorizations")
            print("      → Unplug and replug the USB cable")
        else:
            print("\n❌ No devices connected.")
            print("   Connect a device with USB debugging enabled.")
        return 1

    # Select target device
    if not args.serial:
        target = authorized[0]
        adb.serial = target["serial"]
        print(f"\n📱 Auto-selected device: {target['serial']}")
    else:
        matching = [d for d in authorized if d["serial"] == args.serial]
        if not matching:
            print(f"\n❌ Device {args.serial} not found or not authorized.")
            return 1
        target = matching[0]

    # ── Generate case ID ──
    case_id = args.case_id or f"CASE-{datetime.datetime.now():%Y%m%d-%H%M%S}"
    started_at = datetime.datetime.now().isoformat()

    print(f"📁 Case ID:    {case_id}")
    print(f"👤 Examiner:   {args.examiner}")
    print(f"📂 Output:     {args.output}")
    print()

    # ── Setup evidence repository ──
    output_dir = Path(args.output).resolve()
    repo = EvidenceRepository(output_dir, case_id)
    repo.initialize()

    # ── Setup logging (to evidence dir) ──
    logger = setup_logging(repo.logs_dir)

    log.info(f"Case {case_id} started by {args.examiner}")
    log.info(f"Target device: {adb.serial}")

    # ── Dry run mode ──
    if args.dry_run:
        print("\n🔎 DRY RUN – showing acquisition plan:\n")
        print("  ✓ Device information (getprop, dumpsys, packages)")
        if not args.skip_media:
            for path in MEDIA_PATHS:
                check = adb.shell(f'[ -d "{path}" ] && echo EXISTS')
                status = "✓" if "EXISTS" in check else "✗"
                print(f"  {status} Media: {path}")
        else:
            print("  ✗ Media (skipped)")
        if not args.skip_apk:
            output = adb.shell("pm list packages -3", timeout=60)
            count = sum(1 for l in output.splitlines() if l.startswith("package:"))
            print(f"  ✓ APKs: {count} third-party packages")
        else:
            print("  ✗ APKs (skipped)")
        if not args.skip_apps:
            installed_output = adb.shell("pm list packages", timeout=60)
            installed = set(
                l.strip()[len("package:"):]
                for l in installed_output.splitlines()
                if l.strip().startswith("package:")
            )
            found_apps = [a for a in APP_TARGETS if a["package"] in installed]
            for a in found_apps:
                print(f"  ✓ App DB: {a['name']} ({a['package']})")
            if not found_apps:
                print("  ✗ App DBs: no target apps installed")
        else:
            print("  ✗ App DBs (skipped)")
        print("\nRe-run without --dry-run to execute.")
        return 0

    # ── Phase 1: Device Info ──
    collector = DeviceCollector(adb)
    device_info = collector.collect()

    # ── Phase 1: Logical Acquisition ──
    acquisition = LogicalAcquisition(adb, repo)

    # Always dump device info
    acquisition.acquire_device_dumps(device_info)

    if not args.skip_media:
        acquisition.acquire_media()

    if not args.skip_apk:
        acquisition.acquire_apks()

    if not args.skip_apps:
        acquisition.acquire_app_databases()

    if args.whatsapp_companion:
        try:
            # Ensure project root & capture dir are in sys.path
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.components.whatsapp_companion import WhatsAppCompanionExtractor
            except ImportError:
                from components.whatsapp_companion import WhatsAppCompanionExtractor

            companion_output = repo.root / "parsed" / "whatsapp_companion"
            companion_extractor = WhatsAppCompanionExtractor(output_dir=companion_output)
            sqlite_db = companion_extractor.run()
            if sqlite_db and sqlite_db.exists():
                sha256, md5 = IntegrityEngine.hash_file(sqlite_db)
                ev = FileEvidence(
                    original_path="whatsapp_web_companion/msgstore.db",
                    local_path=str(sqlite_db.relative_to(repo.root)),
                    sha256=sha256,
                    md5=md5,
                    size_bytes=sqlite_db.stat().st_size,
                    acquired_at=datetime.datetime.now().isoformat(),
                    source="whatsapp_companion_sync",
                    category="app_whatsapp",
                )
                acquisition.acquired.append(ev)
                repo.register_file(ev)
        except Exception as e:
            log.error(f"WhatsApp Companion acquisition failed: {e}")
            acquisition.errors.append(f"WhatsApp Companion error: {e}")

    # ── Call Logs Acquisition ──
    if args.call_logs:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Android Call Logs & VoIP Records Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_call_logs import CallLogExtractor
            except ImportError:
                from extract_call_logs import CallLogExtractor

            call_logs_output = repo.root / "parsed" / "call_logs"
            extractor = CallLogExtractor(output_dir=call_logs_output)
            res = extractor.extract_all()
            for db_file in call_logs_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"call_logs/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="call_logs_extractor",
                        category="system_calllog",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Call Logs acquisition failed: {e}")
            acquisition.errors.append(f"Call Logs error: {e}")

    # ── Unified Messages & IM Acquisition ──
    if args.messages:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Unified Cellular SMS & Instant Messages Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_messages import MessagesExtractor
            except ImportError:
                from extract_messages import MessagesExtractor

            messages_output = repo.root / "parsed" / "messages"
            extractor = MessagesExtractor(output_dir=messages_output)
            res = extractor.extract_all(run_whatsapp_companion=args.whatsapp_companion)
            for db_file in messages_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"messages/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="messages_extractor",
                        category="system_sms",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Unified Messages acquisition failed: {e}")
            acquisition.errors.append(f"Messages error: {e}")

    # ── Contacts Acquisition ──
    if args.contacts:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Phone Address Book & IM Contacts Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_contacts import ContactsExtractor
            except ImportError:
                from extract_contacts import ContactsExtractor

            contacts_output = repo.root / "parsed" / "contacts"
            extractor = ContactsExtractor(output_dir=contacts_output)
            res = extractor.extract_all()
            for db_file in contacts_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"contacts/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="contacts_extractor",
                        category="system_contacts",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Contacts acquisition failed: {e}")
            acquisition.errors.append(f"Contacts error: {e}")

    # ── Device Connectivity & Network History Acquisition ──
    if args.connectivity:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Device Connectivity & Network History Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_connectivity import ConnectivityExtractor
            except ImportError:
                from extract_connectivity import ConnectivityExtractor

            conn_output = repo.root / "parsed" / "connectivity"
            extractor = ConnectivityExtractor(output_dir=conn_output)
            res = extractor.extract_all()
            for db_file in conn_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"connectivity/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="connectivity_extractor",
                        category="system_network",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Connectivity acquisition failed: {e}")
            acquisition.errors.append(f"Connectivity error: {e}")

    # ── Device Notifications Acquisition ──
    if args.notifications:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Device Notifications & Archive Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_notifications import NotificationsExtractor
            except ImportError:
                from extract_notifications import NotificationsExtractor

            notif_output = repo.root / "parsed" / "notifications"
            extractor = NotificationsExtractor(output_dir=notif_output)
            res = extractor.extract_all()
            for db_file in notif_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"notifications/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="notifications_extractor",
                        category="system_notification",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Notifications acquisition failed: {e}")
            acquisition.errors.append(f"Notifications error: {e}")

    # ── Device Calendar & Events Acquisition ──
    if args.calendar:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Device Calendar & Events Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_calendar import CalendarExtractor
            except ImportError:
                from extract_calendar import CalendarExtractor

            cal_output = repo.root / "parsed" / "calendar"
            extractor = CalendarExtractor(output_dir=cal_output)
            res = extractor.extract_all()
            for db_file in cal_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"calendar/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="calendar_extractor",
                        category="system_calendar",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Calendar acquisition failed: {e}")
            acquisition.errors.append(f"Calendar error: {e}")

    # ── Geolocation & Journey Acquisition ──
    if args.journey:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Geolocation & Journey Map Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_journey import JourneyExtractor
            except ImportError:
                from extract_journey import JourneyExtractor

            journey_output = repo.root / "parsed" / "journey"
            extractor = JourneyExtractor(output_dir=journey_output)
            res = extractor.extract_all()
            for ext_file in list(journey_output.glob("*.db")) + list(journey_output.glob("*.html")) + list(journey_output.glob("*.kml")):
                if ext_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(ext_file)
                    ev = FileEvidence(
                        original_path=f"journey/{ext_file.name}",
                        local_path=str(ext_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=ext_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="journey_extractor",
                        category="system_geolocation",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Journey acquisition failed: {e}")
            acquisition.errors.append(f"Journey error: {e}")

    # ── Network Diagnostics & Forensics Acquisition ──
    if args.network:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Network Diagnostics & Forensics Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_network import NetworkExtractor
            except ImportError:
                from extract_network import NetworkExtractor

            net_output = repo.root / "parsed" / "network"
            extractor = NetworkExtractor(output_dir=net_output)
            res = extractor.extract_all()
            for db_file in net_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"network/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="network_extractor",
                        category="system_network_diagnostics",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Network acquisition failed: {e}")
            acquisition.errors.append(f"Network error: {e}")

    # ── Multi-Browser Search History & URL Acquisition ──
    if args.browser_history:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Multi-Browser Search History & URL Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_browser_history import BrowserExtractor
            except ImportError:
                from extract_browser_history import BrowserExtractor

            browser_output = repo.root / "parsed" / "browsers"
            extractor = BrowserExtractor(output_dir=browser_output)
            res = extractor.extract_all()
            for db_file in browser_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"browsers/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="browser_extractor",
                        category="user_browser_history",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Browser history acquisition failed: {e}")
            acquisition.errors.append(f"Browser history error: {e}")

    # ── Web & System Cookies Acquisition ──
    if args.cookies:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Web & System Cookies Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_cookies import CookiesExtractor
            except ImportError:
                from extract_cookies import CookiesExtractor

            cookies_output = repo.root / "parsed" / "cookies"
            extractor = CookiesExtractor(output_dir=cookies_output)
            res = extractor.extract_all()
            for db_file in list(cookies_output.glob("*.db")) + list(cookies_output.glob("*.txt")):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"cookies/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="cookies_extractor",
                        category="user_browser_cookies",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Cookies acquisition failed: {e}")
            acquisition.errors.append(f"Cookies error: {e}")

    # ── System & Device Events Acquisition ──
    if args.device_events:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting System & Device Events Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_device_events import EventsExtractor
            except ImportError:
                from extract_device_events import EventsExtractor

            events_output = repo.root / "parsed" / "events"
            extractor = EventsExtractor(output_dir=events_output)
            res = extractor.extract_all()
            for db_file in events_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"events/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="events_extractor",
                        category="system_device_events",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Device events acquisition failed: {e}")
            acquisition.errors.append(f"Device events error: {e}")

    # ── Connected Devices & Peripherals Acquisition ──
    if args.connected_devices:
        log.info("════════════════════════════════════════════════════════════")
        log.info(" 🟢 Starting Connected Devices & Peripherals Acquisition")
        log.info("════════════════════════════════════════════════════════════")
        try:
            project_root = Path(__file__).resolve().parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
            try:
                from capture.extract_connected_devices import ConnectedDevicesExtractor
            except ImportError:
                from extract_connected_devices import ConnectedDevicesExtractor

            conn_output = repo.root / "parsed" / "connected_devices"
            extractor = ConnectedDevicesExtractor(output_dir=conn_output)
            res = extractor.extract_all()
            for db_file in conn_output.glob("*.db"):
                if db_file.exists():
                    sha256, md5 = IntegrityEngine.hash_file(db_file)
                    ev = FileEvidence(
                        original_path=f"connected_devices/{db_file.name}",
                        local_path=str(db_file.relative_to(repo.root)),
                        sha256=sha256,
                        md5=md5,
                        size_bytes=db_file.stat().st_size,
                        acquired_at=datetime.datetime.now().isoformat(),
                        source="connected_devices_extractor",
                        category="system_connected_peripherals",
                    )
                    acquisition.acquired.append(ev)
                    repo.register_file(ev)
        except Exception as e:
            log.error(f"Connected devices acquisition failed: {e}")
            acquisition.errors.append(f"Connected devices error: {e}")

    # ── Build Summary ──
    completed_at = datetime.datetime.now().isoformat()
    summary = AcquisitionSummary(
        case_id=case_id,
        examiner=args.examiner,
        device=device_info,
        started_at=started_at,
        completed_at=completed_at,
        total_files=len(acquisition.acquired),
        total_bytes=sum(e.size_bytes for e in acquisition.acquired),
        evidence_files=acquisition.acquired,
        errors=acquisition.errors,
        acquisition_types=["logical"],
    )

    # ── Save Evidence Metadata ──
    repo.save_hash_log()
    repo.save_metadata(summary)

    # ── Generate Timeline ──
    timeline_gen = TimelineGenerator(summary)
    timeline = timeline_gen.generate()

    # Save timeline as JSON
    timeline_file = repo.parsed_dir / "timeline.json"
    with open(timeline_file, "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2, ensure_ascii=False)

    # ── Generate Reports ──
    reporter = ReportGenerator(repo)
    reporter.generate_json_report(summary, timeline)
    html_report = reporter.generate_html_report(summary, timeline)

    # ── Final Summary ──
    print()
    print("═" * 55)
    print("  ACQUISITION COMPLETE")
    print("═" * 55)
    print(f"  Case:       {case_id}")
    print(f"  Device:     {device_info.manufacturer} {device_info.model}")
    print(f"  Android:    {device_info.android_version}")
    print(f"  Files:      {summary.total_files}")
    print(f"  Size:       {ReportGenerator._format_size(summary.total_bytes)}")
    print(f"  Errors:     {len(summary.errors)}")
    print(f"  Evidence:   {repo.root}")
    print(f"  Report:     {html_report}")
    print("═" * 55)

    if summary.errors:
        print(f"\n⚠️  {len(summary.errors)} error(s) occurred during acquisition.")
        for err in summary.errors[:5]:
            print(f"   • {err}")
        if len(summary.errors) > 5:
            print(f"   ... and {len(summary.errors) - 5} more (see log)")

    log.info("Acquisition completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
