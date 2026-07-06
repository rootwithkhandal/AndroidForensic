# AndroidForensic - Working & Architecture Documentation (Prototype)

## Overview

AndroidForensic is a forensic toolkit for Android devices that performs read-only, forensically sound, non-destructive data acquisition and analysis. It extracts, decodes, and generates reports from Android device data.

**Version**: 3.6.3
**License**: MIT
**Python Requirements**: 3.6-3.10 (64-bit recommended)

---

## Project Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        GUI Layer                            │
│          (andriller/gui/windows.py - MainWindow)            │
│  User interaction, menu building, workflow coordination     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────┐
│                   Execution Layer                           │
│            (andriller/driller.py)                           │
│   ChainExecution - orchestrates extraction workflow         │
└──────────────────────┬──────────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
┌─────────▼───────┐ ┌──▼───────┐ ┌─▼─────────────────┐
│ ADB Connection  │ │ Decoding │ │ Cryptographic     │
│  (adb_conn.py)  │ │ Engine   │ │ Operations        │
│ Device comms    │ │(decoders)│ │ (decrypts.py)     │
└─────────────────┘ └──────────┘ └───────────────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
┌─────────▼───────┐ ┌──▼───────┐ ┌─▼─────────────────┐
│  Report Gen     │ │ Lockscreen│ │ Utilities         │
│  HTML/XLSX      │ │ Cracking  │ │ (utils.py)        │
│  (engines.py)   │ │(cracking) │ │                   │
└─────────────────┘ └───────────┘ └───────────────────┘
```

---

## Core Components

### 1. GUI Layer (`andriller/gui/`)

**Purpose**: Provides the graphical user interface for user interaction

**Key Files**:
- `windows.py` - Main application window (MainWindow class)
- `lockscreens.py` - Lockscreen cracking UI
- `wa_crypt.py` - WhatsApp decryption UI
- `preferences.py` - User preferences/settings
- `screen_cap.py` - Device screen capture UI

**MainWindow Class** (`windows.py`):
- Entry point for GUI execution
- Builds menu system (File, Decoders, Tools, ADB, Help)
- Handles extraction workflows (USB, AB, TAR, DIR modes)
- Integrates logging display
- Manages threading for long-running operations

---

### 2. Execution & Orchestration Layer (`driller.py`)

**ChainExecution Class**:
Central orchestrator that coordinates the entire forensic workflow.

**Key Methods**:
- `InitialAdbRead()` - Reads device information via ADB
- `CreateWorkDir()` - Creates timestamped work directory for output
- `DataAcquisition()` - Extracts data from device (via ADB backup or root)
- `DataExtraction()` - Unpacks extracted archives (TAR/AB files)
- `DataDecoding()` - Runs appropriate decoders on extracted databases
- `DecodeShared()` - Processes shared storage/filesystem
- `GenerateHtmlReport()` - Creates HTML forensic report
- `GenerateXlsxReport()` - Creates Excel forensic report

**Workflow Chain**:
```
Device Connection → Data Acquisition → Data Extraction →
Data Decoding → Report Generation
```

---

### 3. ADB Communication Layer (`adb_conn.py`)

**ADBConn Class**:
Handles all Android Debug Bridge communications with connected devices.

**Key Capabilities**:
- Cross-platform ADB binary management (Windows/Linux/macOS)
- Device detection and connection management
- File operations: pull, push, cat, ls, stat
- Shell command execution (with optional superuser)
- Reboot control (recovery, bootloader modes)
- Binary data transfer with proper encoding handling

**Platform-Specific Behavior**:
- Windows: Uses bundled `adb.exe` from `andriller/bin/`
- Unix/Mac: Uses system-installed `adb` (via brew/apt)

**Key Methods**:
- `adb(cmd)` - Execute ADB command
- `adb_out(cmd)` - Execute command on device and retrieve output
- `get_file(path)` - Download file content as bytes
- `pull_file(src, dst)` - Pull file from device
- `exists(path)` - Check if remote file exists
- `get_size(path)` - Get remote file size

---

### 4. Decoder Registry (`decoders.py`)

**Purpose**: Database parsers for various Android applications

**Decoder Architecture**:
All decoders inherit from `AndroidDecoder` base class (in `classes.py`)

**Base Decoder Pattern**:
```python
class SomeDecoder(AndroidDecoder):
    def main(self):
        # Parse SQLite database
        # Extract relevant data
        # Format for reporting
        # Call report_html() and report_xlsx()
```

**Available Decoders** (30+ decoders):

**System Decoders**:
- `SettingsDecoder` - System settings
- `LocksettingsDecoder` - Lock screen settings
- `AccountsDecoder` - User accounts
- `WifiPasswordsDecoder` - WiFi credentials
- `GenericCallsDecoder` - Call logs
- `SMSMMSDecoder` - Text messages
- `AndroidCalendarDecoder` - Calendar events
- `DownloadsDecoder` - Download history

**Browser Decoders**:
- `WebViewDecoder` - Android WebView data
- `BrowserHistoryDecoder` - Browser history
- `ChromeHistoryDecoder` - Chrome browser history
- `ChromePasswordsDecoder` - Saved passwords
- `ChromeArchivedHistoryDecoder` - Archived history

**Messaging App Decoders**:
- `WhatsAppContactsDecoder` - WhatsApp contacts
- `WhatsAppMessagesDecoder` - WhatsApp messages
- `WhatsAppCallsDecoder` - WhatsApp calls
- `FacebookMessagesDecoder` - Facebook Messenger
- `FacebookMessagesLiteDecoder` - FB Messenger Lite
- `SkypeMessagesDecoder` - Skype messages
- `SkypeCallsDecoder` - Skype calls
- `ViberMessagesDecoder` - Viber messages
- `ViberContactsDecoder` - Viber contacts
- `KikMessagesDecoder` - Kik messages

**Other Decoders**:
- `SamsungSnippetsDecoder` - Samsung-specific data
- `GooglePhotosDecoder` - Google Photos metadata
- `SharedFilesystemDecoder` - Shared storage files

**Registry Class**:
- Manages decoder registration
- Maps target files to appropriate decoders
- Provides decoder discovery for different extraction modes (root/AB/posix)

---

### 5. Base Decoder Class (`classes.py`)

**AndroidDecoder Class**:
Abstract base class for all decoders.

**Key Features**:
- SQLite database connection management
- Read-only database access (forensic integrity)
- SQL query helpers with WHERE clause support
- Time conversion utilities (Unix, WebKit, milliseconds)
- HTML and XLSX report generation
- Configuration management
- Error handling with retry logic

**Report Generation Flow**:
```python
def main(self):
    cursor = self.get_cursor()
    data = self.sql_table_as_dict('messages')
    self.report_html()  # Generate HTML report
    self.report_xlsx()  # Generate Excel report
```

**Utility Methods**:
- `unix_to_time()` - Convert Unix timestamp to readable format
- `webkit_to_time()` - Convert WebKit timestamp
- `decode_safe()` - Safe UTF-8 decoding
- `xml_root()` - Parse XML files
- `get_artifact()` - Find target database files

---

### 6. Cryptographic Operations (`decrypts.py`)

**Purpose**: Decrypt encrypted application databases

**WhatsAppCrypt Classes**:
Decrypt WhatsApp encrypted databases from crypt7 to crypt12 formats.

**Encryption Versions Supported**:
- `WhatsAppCrypt7` - AES CBC mode
- `WhatsAppCrypt8` - AES CBC + GZIP compression
- `WhatsAppCrypt9` - AES GCM mode + GZIP
- `WhatsAppCrypt10` - Same as crypt9
- `WhatsAppCrypt11` - Same as crypt9
- `WhatsAppCrypt12` - AES GCM + ZLIB compression

**Decryption Process**:
1. Read encrypted database file (.crypt*)
2. Extract encryption key from key file (158 bytes)
3. Extract IV (Initialization Vector) from file header or key
4. Decrypt using AES (mode depends on version)
5. Decompress (GZIP or ZLIB)
6. Verify SQLite magic bytes
7. Save decrypted .db file

**Key File Requirements**:
- Key file size: 158 bytes
- Key location: bytes [126:158]
- IV location: varies by version (from file or key)

---

### 7. Lockscreen Cracking (`cracking.py`)

**Purpose**: Crack Android lockscreen patterns, PINs, and passwords

**Pattern Cracking** (`crack_pattern()`):
- Brute-force gesture patterns (4-9 points)
- Compares SHA1 hash of permutations
- Tests all combinations of pattern gestures

**Password Cracking** (`PasswordCrack` class):

**Attack Methods**:
1. **Numeric PIN**: Sequential generation (0000-9999+)
2. **Alphanumeric**: Custom character range combinations
3. **Dictionary**: Word list based attacks

**Algorithms**:
- **Generic Android**: `SHA1(password + salt)`
- **Samsung**: `SHA1(0 + password + salt)` iterated 1024 times

**Key Features**:
- Configurable min/max password length
- Custom character ranges
- Dictionary file support
- Progress tracking and rate estimation
- Tkinter GUI integration for live updates

**Performance**:
- Update rate: configurable (default 50,000 attempts)
- Real-time statistics: attempts, rate, progress percentage
- Time remaining estimation

---

### 8. Report Generation (`engines.py`, `classes.py`)

**HTML Reports** (Jinja2 Templates):

**Template Location**: `andriller/templates/`

**Key Templates**:
- `REPORT.html` - Master report template
- `base.html` - Base template with styles
- `style.html` - CSS styling
- App-specific templates (e.g., `whatsapp_messages.html`)

**Report Components**:
- Device information header
- Custom header/footer (configurable)
- Extraction metadata
- Decoded data tables
- Media attachments (if present)
- Timestamps in configured timezone

**Excel Reports** (xlsxwriter):

**Workbook Class**:
- Creates .xlsx files with multiple sheets
- One sheet per decoder/artifact
- Formatted headers (bold, colored background)
- Disabled formula/URL conversion (forensic safety)

**Report Features**:
- Tab-separated data sheets
- Consistent formatting
- All timestamps in user-configured timezone
- Searchable and filterable data

---

### 9. Configuration Management (`config.py`)

**Config Class**:
Manages user preferences and application settings.

**Configuration File**: `~/.config/andriller/config.ini` (Linux/Mac) or `%APPDATA%/andriller/config.ini` (Windows)

**Configurable Settings**:
- `default_path` - Default working directory
- `time_zone` - Timezone for timestamp conversion (UTC, GMT, etc.)
- `date_format` - Date/time display format
- `update_rate` - Cracking update rate
- `theme` - GUI theme
- `custom_header/footer` - Report branding
- `offline_mode` - Disable version checking
- `save_log` - Auto-save logs

**Time Handling**:
- Supports timezones from UTC-12 to UTC+14
- Configurable date format (Y-m-d H:M:S Z)
- Converts all timestamps consistently across reports

**Version Management**:
- Auto-checks PyPI for updates
- Migrates config on version upgrades
- Preserves user settings across updates

---

## Data Extraction Workflows

### Workflow 1: USB Extraction (Rooted Device)

**Requirements**: Rooted device with ADB debugging enabled

**Process**:
1. Connect device via USB
2. ADB detects device and reads system info
3. Creates timestamped work directory
4. Enumerates target databases
5. Pulls files using `adb pull` or `adb shell cat`
6. Runs decoders on extracted databases
7. Generates reports

**Advantages**:
- Direct file access
- Faster extraction
- Access to protected data
- No backup limitations

### Workflow 2: Android Backup (Non-Rooted)

**Requirements**: Android 4.x-7.x with backup enabled

**Process**:
1. Create Android backup: `adb backup -f backup.ab`
2. Convert backup to TAR: unpack `.ab` file
3. Extract TAR contents to directory structure
4. Run decoders on extracted databases
5. Generate reports

**Limitations**:
- Limited to apps allowing backup
- Some system data inaccessible
- Backup must be unlocked on device

### Workflow 3: TAR File Analysis

**Purpose**: Analyze nanddroid/CWM backups

**Process**:
1. Select TAR file (from recovery backup)
2. Extract target databases from archive
3. Run decoders
4. Generate reports

### Workflow 4: Directory Analysis

**Purpose**: Analyze pre-extracted file structure

**Process**:
1. Select directory containing data/ structure
2. Enumerate databases in directory tree
3. Run decoders
4. Generate reports

**Use Case**: Analyzing previously extracted data or manual extractions

---

## Utility Components

### Screen Capture (`screencap.py`)
- Captures device screen via ADB
- Creates HTML report with screenshots
- Useful for documenting device state

### Messages (`messages.py`)
- Standard message definitions
- Error messages
- User notifications

### Statics (`statics.py`)
- Static data and constants
- Default HTML header/footer templates
- Application metadata

### Utils (`utils.py`)
- Helper functions
- Threading decorators
- Time formatting
- Data validation
- Cross-platform compatibility helpers

---

## Security & Forensic Considerations

### Forensic Soundness

**Read-Only Operations**:
- SQLite databases opened in read-only mode
- No modifications to source data
- Timestamps preserved
- Original file hashes maintained

**Integrity**:
```python
def sqlite_readonly(self):
    return f'file:{self.input_file}?mode=ro'
```

**Non-Destructive**:
- All operations create copies
- Source devices/files remain unchanged
- Extraction to separate work directory

### Evidence Preservation

**Timestamped Work Directories**:
```
output/
  ├── 2026-07-03_153045_DEVICENAME/
  │   ├── extracted_data/
  │   ├── reports/
  │   └── logs/
```

**Audit Trail**:
- Comprehensive logging
- Extraction metadata
- Tool version information
- Timestamp records

**Report Chain of Custody**:
- Device information
- Extraction date/time
- Examiner information (via custom header)
- Tool version

---

## Technology Stack

### Core Dependencies

**Python Libraries**:
- `sqlite3` - Database parsing
- `jinja2` - HTML template rendering
- `xlsxwriter` - Excel report generation
- `pycryptodome` - Cryptographic operations (AES, SHA1)
- `tkinter` - GUI framework
- `appdirs` - Cross-platform config directory handling
- `requests` - Update checking
- `wrapt-timeout-decorator` - Command timeouts (Unix)

**System Dependencies**:
- `adb` (Android Debug Bridge) - Device communication
- `python3-tk` - Tkinter GUI support (Linux)

**Bundled Resources** (`andriller/bin/`):
- Windows: ADB binaries included
- Unix/Mac: Uses system-installed ADB

---

## Entry Points

### GUI Mode (Default)
```bash
python -m andriller
# or
python andriller-gui.py
```

**Flow**: `__main__.py` → `run()` → `gui.windows.MainWindow()`

### CLI Mode (with options)
```bash
# Debug mode
python -m andriller --debug

# Save log to file
python -m andriller --debug --file andriller.log

# Check version
python -m andriller --version

# Disable threading
python -m andriller --nothread
```

---

## Decoder Registration System

**Registry Pattern** (`decoders.py`):

```python
@dataclass
class Registry:
    """Manages decoder registration and lookup"""

    def populate(self):
        # Auto-discovers all AndroidDecoder subclasses
        for decoder in AndroidDecoder.get_subclasses():
            # Register decoder with target files

    def has_target(self, target_file):
        # Check if decoder exists for file

    def decoders_target(self, target_file):
        # Return appropriate decoders for target
```

**Auto-Discovery**:
- Uses reflection to find all decoder subclasses
- Maps decoders to target database paths
- Supports multiple decoders per file
- Platform-aware path handling (root/AB/posix)

---

## Error Handling

**Custom Exceptions**:
- `ADBConnError` - ADB communication failures
- `DecoderError` - Database decoding failures
- `WhatsAppCryptError` - Decryption failures
- `PasswordCrackError` - Invalid crack parameters

**Retry Logic**:
```python
@sqlite_error_retry
def get_cursor(self):
    # Retries SQLite operations on lock/busy errors
```

**Graceful Degradation**:
- Failed decoders don't stop workflow
- Partial results still reported
- Detailed error logging

---

## Testing Structure

**Test Directory**: `tests/`

**Test Data**: `tests/data/`
- Sample databases
- Mock device structures
- Test encryption keys

**Test Coverage**:
- Decoder functionality
- ADB operations
- Encryption/decryption
- Report generation

---

## Build & Distribution

**Setup Configuration** (`setup.py`):
- Package name: `andriller`
- Entry script: `andriller-gui.py`
- Includes templates and resources
- Python package discovery

**PyInstaller Spec** (`pyinst.spec`):
- Creates standalone executables
- Bundles dependencies
- Platform-specific builds

**GitHub Actions** (`.github/workflows/`):
- `python-package-test.yml` - Automated testing
- `python-package-upload.yml` - PyPI publishing

---

## Development Workflow

### Adding a New Decoder

1. Create decoder class inheriting from `AndroidDecoder`
2. Define `target_path_ab`, `target_path_root`, `target_path_posix`
3. Implement `main()` method with parsing logic
4. Create HTML template in `andriller/templates/`
5. Call `self.report_html()` and `self.report_xlsx()`
6. Registry auto-discovers new decoder

**Example**:
```python
class NewAppDecoder(AndroidDecoder):
    target_path_ab = 'apps/com.example.app/db/messages.db'
    target_path_root = '/data/data/com.example.app/databases/messages.db'

    def main(self):
        cursor = self.get_cursor()
        messages = self.sql_table_as_dict('messages')
        self.report_html()
        self.report_xlsx()
```

---

## Summary

Andriller CE is a modular, extensible forensic toolkit with a clean separation of concerns:

1. **GUI Layer** - User interaction
2. **Execution Layer** - Workflow orchestration
3. **Communication Layer** - Device interaction (ADB)
4. **Decoding Layer** - Data parsing (30+ decoders)
5. **Cryptography Layer** - Decryption (WhatsApp, etc.)
6. **Analysis Layer** - Lockscreen cracking
7. **Reporting Layer** - HTML/Excel output
8. **Configuration Layer** - User preferences

The architecture follows a plugin-style pattern for decoders, making it easy to extend with new app support while maintaining forensic integrity through read-only operations and comprehensive logging.
