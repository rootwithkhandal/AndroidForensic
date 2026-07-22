"""Smoke tests for the public MVP command-line entry points."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from capture.extract_call_logs import CallLogExtractor


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ | {"PYTHONUTF8": "1"}
    return subprocess.run(
        [sys.executable, *args],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_module_help_is_available_without_adb() -> None:
    result = run_cli("-m", "capture", "--help")

    assert result.returncode == 0, result.stderr
    assert "Android Forensic Framework" in result.stdout
    assert "--call-logs" in result.stdout


def test_build_entry_point_exposes_the_same_cli() -> None:
    result = run_cli("main.py", "--help")

    assert result.returncode == 0, result.stderr
    assert "--browser-history" in result.stdout


def test_optional_extractor_uses_the_selected_adb_serial(tmp_path: Path) -> None:
    extractor = CallLogExtractor(
        output_dir=tmp_path,
        adb_path=Path("adb"),
        serial="device-123",
    )

    with patch("capture.extract_call_logs.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "ok", "")
        extractor._run_adb(["shell", "getprop"])

    assert run.call_args.args[0] == ["adb", "-s", "device-123", "shell", "getprop"]
