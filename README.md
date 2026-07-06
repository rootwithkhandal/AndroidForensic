# AndroidForensic Everywhere
=====

![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Interfaces](https://img.shields.io/badge/interfaces-CLI%20%7C%20TUI%20%7C%20Web-00f2fe)](README.md)

**AndroidForensic Everywhere** (formerly Andriller CE) is a modernized, multi-interface software utility and collection of forensic tools for Android smartphones. It performs read-only, forensically sound, non-destructive data acquisition from Android devices and offline archives.

Featuring a completely redesigned architecture decoupled from Tkinter, **AndroidForensic Everywhere** provides three seamless interfaces to match your investigative workflow:
1. **Responsive Web GUI (Flask + Vanilla CSS/JS)**: Stunning rich dark-mode aesthetics, real-time Server-Sent Events (SSE) execution log streaming, and responsive grid layouts.
2. **Modern Terminal User Interface (Textual)**: A keyboard-driven, reactive terminal dashboard with sidebar navigation and live monitoring.
3. **Command-Line Interface (Click + Rich)**: Scriptable, automated commands with beautiful rich-formatted terminal outputs.

---

## 🔥 Key Features
- **Multi-Interface Suite**: Run as a standalone Web server, interactive Textual terminal app, or scripted CLI tool.
- **Automated Data Acquisition & Decoding**: Acquire forensically sound data via USB/ADB or parse offline folders and tarballs.
- **Android Backup (.ab) Support**: Convert and extract non-rooted device backups.
- **30+ Specialized Decoders**: Automated parsing and decoding of Android app databases (WhatsApp, Facebook, Skype, Viber, Chrome, Call logs, SMS, Calendar, Google Photos, etc.) into HTML and Excel reports.
- **WhatsApp Offline Decryption**: Decrypt encrypted WhatsApp databases (`.crypt7`, `.crypt8`, `.crypt12`) using extracted key files.
- **Lockscreen Cracking**: High-speed cracking for gesture patterns (hex hash or `gesture.key`) and numeric PINs/passwords (with Samsung PBKDF/SHA1 algorithm support).
- **Device Screen Capture**: Capture live device display screens directly to PNG reports.

---

## 💻 System & Python Requirements
- **Python**: 3.10, 3.11, or 3.12 (64-bit recommended)
- **ADB**: Android Debug Bridge (`adb`) must be installed and accessible in system PATH.

### Installing ADB:
- **Ubuntu/Debian**: `sudo apt-get install android-tools-adb`
- **macOS (Homebrew)**: `brew install android-platform-tools`
- **Windows**: Included in toolkit bin/ directory or install via Android SDK.

---

## 🚀 Installation & Setup
Create and activate a Python virtual environment:
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install the package in editable/development mode:
```bash
pip install -e .
```

---

## 🎯 Quick Start Guide

### 1️⃣ Launch Web GUI (Flask)
Launch the responsive web interface with real-time SSE streaming:
```bash
androidforensic gui --port 5000
# OR via launcher script
python androidforensic-gui.py
```
Open your browser at `http://127.0.0.1:5000/`.

### 2️⃣ Launch Terminal User Interface (Textual TUI)
Launch the interactive terminal dashboard:
```bash
androidforensic tui
# OR via launcher script
python androidforensic-tui.py
```

### 3️⃣ Use Command-Line Interface (CLI)
Run automated commands directly from terminal:
```bash
# Check connected device status
androidforensic device status

# Start USB extraction to ~/Desktop
androidforensic extract usb --output ~/Desktop --shared

# Parse an existing Android Backup (.ab) file
androidforensic extract ab /path/to/backup.ab --output ~/Desktop

# Crack a gesture pattern hash
androidforensic crack pattern c8c0b24a15dc8bbf11516e87a20c3ec78e4f1659

# Decrypt WhatsApp database
androidforensic tools wa-decrypt msgstore.db.crypt12 key
```

---

## 📁 Architecture & Package Structure
```
androidforensic/
├── __init__.py       # Package entry point & unified launcher
├── __main__.py       # CLI dispatch
├── cli/              # Click + Rich command-line interface
├── tui/              # Textual terminal user interface
├── web/              # Flask web server, REST APIs & SSE streaming
│   ├── static/       # Responsive CSS & client-side JavaScript
│   └── templates/    # Modern HTML templates
├── decoders.py       # 30+ forensic artifact decoders & Registry
├── driller.py        # Core extraction orchestration & ChainExecution
├── cracking.py       # Pattern and PIN lockscreen cracking algorithms
├── decrypts.py       # WhatsApp crypt7/8/12 offline decryption
├── screencap.py      # ADB screen capture & reporting
├── adb_conn.py       # ADB device connection manager
├── engines.py        # Jinja2 and XlsxWriter reporting engines
└── config.py         # Global configuration manager
```

---

## 📄 License
This project is licensed under the **MIT License**.
