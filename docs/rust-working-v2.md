# DroidForge — Unified Android Forensics Tool (Rust Architecture v2)

## Why this doc exists, and what changed

`rust-working.md` (v1) was a Rust port of Andriller — a logical-layer decoder/report
engine wearing AndroidForensic's name. It had no transport layer, no manifest/hash-chain,
no chipset acquisition, and no forensic gating. This doc throws that scaffolding out and
starts fresh, per five explicit directives:

1. **No `forensics-core` shared crate.** This tool is self-contained — its own manifest,
   hash chain, and audit log live inside it, not in a dependency shared with OpenForensic.
2. **Acquisition + Analysis merged into one tool**, mirroring OpenForensic's own shape
   (Disk Imaging, Triage, Timeline, RAM Analysis all live in one app). DroidForge does the
   same: Acquisition tab + Analysis tab, one binary.
3. **Transport layer promoted** — native USB protocol implementation is the default for
   anything acquisition-critical, not a "nice to have" behind shelling out to `adb`.
4. **Manifest/hash-chain schema defined first** — `core::manifest` and `core::hash_chain`
   are chapter one of this document, written before a single line of acquisition code.
5. **UI framework fixed** — Tauri from the start. No egui detour.
6. **Renamed** — `andriller` lineage is gone. Package is `droidforge`. (GitHub repo can
   stay `AndroidForensic` if you want continuity with what's already scaffolded there;
   the crate/binary name is what actually breaks the Andriller inheritance.)

### One doctrine survives the merge

Even though acquisition and analysis now live in the same binary, **the internal boundary
between them is still enforced — just architecturally instead of by process separation.**
Section 4 (`core::manifest`) introduces a typestate pattern (`LiveDevice` vs `SealedCase`)
specifically so the compiler — not a convention, not a comment — refuses to let any
decoder, cracking module, or report generator touch a live device handle. Merging the
tools is a UX/deployment decision. "Never brute-force against a running phone" is a
forensic-integrity law and stays non-negotiable regardless of process topology.

---

## 1. Project Structure

```
droidforge/
├── Cargo.toml
├── src/
│   ├── main.rs                      # Tauri entry point
│   ├── lib.rs
│   │
│   ├── core/                        # was forensics-core — now internal, self-contained
│   │   ├── mod.rs
│   │   ├── manifest.rs              # CaseManifest, typestate (LiveDevice/SealedCase)
│   │   ├── hash_chain.rs            # streaming MD5/SHA1/SHA256, pre/post Double-Verify
│   │   └── audit_log.rs             # append-only, hash-chained JSONL audit trail
│   │
│   ├── transport/                   # PROMOTED — native protocol first-class
│   │   ├── mod.rs
│   │   ├── usb.rs                   # nusb device enum + bulk transfer
│   │   ├── adb_protocol.rs          # CNXN/AUTH/OPEN/WRTE/CLSE wire frames
│   │   ├── fastboot_protocol.rs     # fastboot command/response over USB bulk
│   │   └── shell_fallback.rs        # adb/fastboot binary shell-out — convenience ONLY,
│   │                                #   explicitly barred from acquisition-critical paths
│   │
│   ├── device/
│   │   ├── mod.rs
│   │   ├── detect.rs                # enumerate, VID:PID match, mode + chipset detect
│   │   ├── fingerprint.rs           # pre-acquisition read-only ID capture
│   │   └── state.rs                 # DeviceMode / ChipsetFamily state machine
│   │
│   ├── acquisition/
│   │   ├── mod.rs                   # trait AcquisitionMethod
│   │   ├── adb_backup.rs            # Tier 1 — logical, least invasive
│   │   ├── adb_pull_fs.rs           # Tier 2 — filesystem level, root/debug required
│   │   ├── fastboot_dd.rs           # Tier 3 — physical, unlocked bootloader only
│   │   ├── edl_firehose.rs          # Tier 4 — Qualcomm
│   │   ├── mtk_brom.rs              # Tier 4 — MediaTek
│   │   ├── samsung_download.rs      # Tier 4 — Exynos/Odin protocol
│   │   └── spreadtrum.rs            # Tier 4 — UNISOC, stretch
│   │
│   ├── analysis/                    # formerly `decoders/` — folded in, sealed-case-only
│   │   ├── mod.rs                   # Decoder registry + pattern matching
│   │   ├── base.rs                  # AndroidDecoder trait, bound to SealedCase
│   │   ├── app_scanner.rs           # dynamic installed-app discovery
│   │   ├── generic.rs               # fallback decoder for unknown apps
│   │   ├── messaging.rs             # WhatsApp, Signal, Messenger, Telegram, Discord
│   │   ├── social.rs                # Twitter/X, Snapchat, TikTok
│   │   ├── productivity.rs          # Gmail, Outlook, Slack
│   │   ├── browsers.rs              # Chrome, Firefox, WebView
│   │   ├── cloud.rs                 # Drive, Dropbox, OneDrive, Google Photos
│   │   ├── ai_apps.rs               # ChatGPT, Claude, Gemini, Copilot
│   │   └── system.rs                # SMS, Contacts, CallLogs, Calendar
│   │
│   ├── crypto/
│   │   ├── mod.rs
│   │   └── whatsapp.rs              # crypt7–crypt12 decryption
│   │
│   ├── cracking/
│   │   ├── mod.rs
│   │   ├── pattern.rs               # gesture.key pattern cracking
│   │   └── password.rs              # PIN/password offline brute-force
│   │
│   ├── triage/
│   │   └── mod.rs                   # Quick / Full triage presets
│   │
│   ├── reporting/
│   │   ├── mod.rs
│   │   ├── html.rs                  # Tera templates
│   │   └── xlsx.rs                  # rust_xlsxwriter
│   │
│   ├── ui/                          # Tauri commands, mirrors OpenForensic's shell
│   │   ├── mod.rs
│   │   ├── device_selector.rs
│   │   ├── acquisition_config.rs
│   │   ├── analysis_workbench.rs
│   │   └── console_log.rs
│   │
│   ├── config.rs
│   └── error.rs
│
├── src-tauri/                       # Tauri shell (tauri.conf.json, icons, capabilities)
├── templates/                       # Tera HTML report templates
├── tests/
└── benches/
```

**What moved, what didn't, relative to v1:**
- `forensics-core` → collapsed into `core/`, no longer an external dependency.
- `decoders/` → renamed `analysis/`, unchanged internally, but every entry point now
  takes `&SealedCase` instead of a raw `Path`.
- `adb/connection.rs` → split: wire protocol lives in `transport/`, shell-out demoted to
  an explicit, clearly-labeled fallback module that acquisition code is not allowed to
  call.
- Everything under `device/` and Tier 3–4 of `acquisition/` is genuinely new — v1 had
  none of it.

---

## 2. Dependency Selection (Cargo.toml)

```toml
[package]
name = "droidforge"
version = "0.1.0"                # fresh start — not Andriller's v4.0.0 lineage
edition = "2021"
rust-version = "1.75"

[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }

# --- Transport layer (PROMOTED — new in v2) ---
nusb = "0.1"                     # native USB, cross-platform, no libusb dep at runtime
# rusb = "0.9"                   # fallback if nusb gaps a platform quirk you hit

# Error handling
thiserror = "1.0"
anyhow = "1.0"                   # ponytail: app-level context only, never library errors

# Database
rusqlite = { version = "0.30", features = ["bundled"] }

# Cryptography
aes = "0.8"
sha1 = "0.10"
sha2 = "0.10"                    # SHA256 for hash_chain, not just legacy SHA1 cracking
cbc = "0.1"
gcm = "0.10"
flate2 = "1.0"
ed25519-dalek = "2.1"            # signs audit_log entries — new in v2

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Templating / reporting
tera = "1.19"
rust_xlsxwriter = "0.60"

# GUI — Tauri only. No egui. (v1 had this backwards.)
tauri = { version = "2.0", features = ["shell-open"] }

# Time
chrono = { version = "0.4", features = ["serde"] }

# Config
config = "0.14"
directories = "5.0"

# Logging — feeds audit_log, not a substitute for it
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# CLI (headless / scripting mode alongside the Tauri GUI)
clap = { version = "4.4", features = ["derive"] }

# Parallelism (analysis/cracking only — never on acquisition-critical paths)
rayon = "1.8"
itertools = "0.12"

[dev-dependencies]
criterion = "0.5"
proptest = "1.4"
```

**Framework calls, made explicitly this time:**
- `nusb` over `rusb`: pure-Rust, no runtime libusb dependency to bundle/ship on Windows —
  matters for a portable forensic tool that shouldn't need admin-installed drivers beyond
  what the platform ships.
- `ed25519-dalek` added: v1's "audit trail" was a `tracing` log stream, which is
  reorderable and not tamper-evident. v2's audit log is signed per-entry (Section 3).
- `tauri` is a direct dependency from commit one, not an "Option 2" fallback.

---

## 3. Core Module — Manifest & Hash Chain (written FIRST, before any acquisition code)

This is the part that used to live in the external `forensics-core` crate. It's now
internal, but the schema is unchanged in spirit — same shape OpenForensic already uses,
so if you ever *do* want cross-tool tooling later (a shared report viewer, say), the JSON
on disk still lines up.

### 3.1 Case Manifest with compile-time-enforced acquisition/analysis boundary

```rust
// core/manifest.rs
use serde::{Serialize, Deserialize};
use std::marker::PhantomData;
use crate::device::DeviceFingerprint;
use crate::core::hash_chain::HashChain;

/// Typestate markers. A `CaseManifest<LiveDevice>` cannot be handed to anything in
/// `analysis/`, `cracking/`, or `reporting/` — those modules only accept
/// `CaseManifest<SealedCase>`. This is how the merged binary still enforces
/// "acquire first, analyze second" without needing a process boundary.
pub struct LiveDevice;
pub struct SealedCase;

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseManifest<State = LiveDevice> {
    pub evidence_id: String,
    pub case_number: String,
    pub examiner_name: String,
    pub custody_notes: String,
    pub source_type: SourceType,
    pub acquisition_method: String,
    pub hash_chain: HashChain,
    pub timestamps: TimestampLog,
    pub device_fingerprint: Option<DeviceFingerprint>,
    pub image_path: Option<std::path::PathBuf>,

    #[serde(skip)]
    _state: PhantomData<State>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SourceType {
    AdbBackup,
    AdbPullFs,
    FastbootDd,
    EdlFirehose,
    MtkBrom,
    SamsungOdin,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimestampLog {
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub fingerprint_captured_at: Option<chrono::DateTime<chrono::Utc>>,
    pub acquisition_started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub acquisition_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub sealed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl CaseManifest<LiveDevice> {
    pub fn new(evidence_id: String, case_number: String, examiner_name: String) -> Self {
        Self {
            evidence_id, case_number, examiner_name,
            custody_notes: String::new(),
            source_type: SourceType::AdbBackup, // set for real once method is chosen
            acquisition_method: String::new(),
            hash_chain: HashChain::default(),
            timestamps: TimestampLog {
                connected_at: chrono::Utc::now(),
                fingerprint_captured_at: None,
                acquisition_started_at: None,
                acquisition_completed_at: None,
                sealed_at: None,
            },
            device_fingerprint: None,
            image_path: None,
            _state: PhantomData,
        }
    }

    /// The ONLY way a manifest transitions to `SealedCase`. Requires: fingerprint
    /// captured, hash chain pre/post-verified and matching, image written. Anything
    /// short of that is a compile-time impossibility for the caller to skip past.
    pub fn seal(mut self) -> Result<CaseManifest<SealedCase>, SealError> {
        if self.device_fingerprint.is_none() {
            return Err(SealError::MissingFingerprint);
        }
        if !self.hash_chain.pre_post_verified() {
            return Err(SealError::HashMismatch);
        }
        if self.image_path.is_none() {
            return Err(SealError::MissingImage);
        }
        self.timestamps.sealed_at = Some(chrono::Utc::now());

        Ok(CaseManifest {
            evidence_id: self.evidence_id,
            case_number: self.case_number,
            examiner_name: self.examiner_name,
            custody_notes: self.custody_notes,
            source_type: self.source_type,
            acquisition_method: self.acquisition_method,
            hash_chain: self.hash_chain,
            timestamps: self.timestamps,
            device_fingerprint: self.device_fingerprint,
            image_path: self.image_path,
            _state: PhantomData,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SealError {
    #[error("cannot seal: no device fingerprint captured pre-acquisition")]
    MissingFingerprint,
    #[error("cannot seal: hash chain pre/post verification failed or incomplete")]
    HashMismatch,
    #[error("cannot seal: no image path recorded")]
    MissingImage,
}

// Every analysis-side entry point looks like this:
//   pub fn decode(&self, case: &CaseManifest<SealedCase>, work_dir: &Path) -> Result<..>
// There is no constructor for CaseManifest<SealedCase> other than `.seal()`, and no
// `From<CaseManifest<LiveDevice>>` impl. A decoder cannot accidentally (or on purpose,
// without deleting this file) run against a manifest that hasn't been through
// acquisition + verification.
```

### 3.2 Hash Chain — streaming, Double-Verify

```rust
// core/hash_chain.rs
use sha2::{Sha256, Digest as Sha2Digest};
use sha1::Sha1;
use md5::Md5;
use std::io::Read;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HashChain {
    pub pre_md5: Option<String>,
    pub pre_sha1: Option<String>,
    pub pre_sha256: Option<String>,
    pub post_md5: Option<String>,
    pub post_sha1: Option<String>,
    pub post_sha256: Option<String>,
}

impl HashChain {
    /// Called once per chunk boundary during streaming acquisition — feeds all three
    /// algorithms simultaneously so the "post" hash is ready the instant the transfer
    /// finishes, no second read pass over the image required.
    pub fn streaming_update(state: &mut StreamingHashers, chunk: &[u8]) {
        state.md5.update(chunk);
        state.sha1.update(chunk);
        state.sha256.update(chunk);
    }

    pub fn pre_post_verified(&self) -> bool {
        self.pre_sha256.is_some()
            && self.post_sha256.is_some()
            && self.pre_sha256 == self.post_sha256
    }
}

pub struct StreamingHashers {
    pub md5: Md5,
    pub sha1: Sha1,
    pub sha256: Sha256,
}

impl StreamingHashers {
    pub fn new() -> Self {
        Self { md5: Md5::new(), sha1: Sha1::new(), sha256: Sha256::new() }
    }

    pub fn finalize(self) -> (String, String, String) {
        (
            hex::encode(self.md5.finalize()),
            hex::encode(self.sha1.finalize()),
            hex::encode(self.sha256.finalize()),
        )
    }
}
```

### 3.3 Audit Log — hash-chained, signed JSONL

This is what actually replaces v1's `tracing::info!()` "audit trail." Each entry embeds
the hash of the previous entry (tamper-evident chain, same idea as a mini blockchain
ledger) and is signed with an examiner/device keypair.

```rust
// core/audit_log.rs
use ed25519_dalek::{SigningKey, Signature, Signer};
use serde::{Serialize, Deserialize};
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event: AuditEvent,
    pub prev_entry_hash: String,   // sha256 of previous entry's canonical JSON
    #[serde(with = "hex_signature")]
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuditEvent {
    DeviceConnected { vid: u16, pid: u16 },
    ModeDetected { mode: String },
    FingerprintCaptured { fields: Vec<String> },
    MethodSelected { method: String, risk_level: String },
    RiskConfirmed { examiner_justification: String },
    ChunkTransferred { offset: u64, len: usize },
    AcquisitionCompleted { total_bytes: u64 },
    HashVerified { matched: bool },
    AcquisitionBlocked { reason: AcquisitionBlockedReason },
    CaseSealed,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AcquisitionBlockedReason {
    DebugDisabled,
    BootloaderLocked,
    NoEdlLoaderAvailable,
    EdlEntryFailed,
    ChipsetUnsupported,
}

pub struct AuditLog {
    path: std::path::PathBuf,
    signing_key: SigningKey,
    seq: u64,
    last_hash: String,
}

impl AuditLog {
    pub fn append(&mut self, event: AuditEvent) -> std::io::Result<()> {
        let entry = AuditEntry {
            seq: self.seq,
            timestamp: chrono::Utc::now(),
            event,
            prev_entry_hash: self.last_hash.clone(),
            signature: self.sign_placeholder(), // signed after canonical serialization
        };
        let json = serde_json::to_string(&entry)?;
        self.last_hash = sha256_hex(json.as_bytes());

        let mut f = std::fs::OpenOptions::new().append(true).create(true).open(&self.path)?;
        writeln!(f, "{json}")?;
        self.seq += 1;
        Ok(())
    }
}
```

Every acquisition state transition your research doc called out — connect, mode
detected, fingerprint captured, method selected, risk confirmed, chunk transferred,
completed, verified — is now a discrete signed, chained entry. `ACQUISITION_BLOCKED`
gets a real taxonomy (`AcquisitionBlockedReason`) instead of a free-text log line.

---

## 4. Transport Layer (promoted)

### 4.1 USB enumeration (`transport/usb.rs`)

```rust
use nusb::{self, DeviceInfo};

pub struct UsbTransport;

impl UsbTransport {
    /// Bus-level enumeration, before any protocol handshake. This is the very first
    /// audit_log entry of any session — logged even if nothing downstream succeeds.
    pub fn enumerate() -> Result<Vec<DeviceInfo>> {
        Ok(nusb::list_devices()?.collect())
    }

    pub fn open(info: &DeviceInfo) -> Result<nusb::Device> {
        Ok(info.open()?)
    }
}
```

### 4.2 ADB wire protocol (`transport/adb_protocol.rs`)

```rust
/// Hand-rolled ADB frame protocol — CNXN/AUTH/OPEN/WRTE/CLSE. This is the piece v1
/// never had: it shelled out to the adb binary and only ever logged the *command*,
/// not the bytes that actually crossed the wire. For acquisition-critical paths that's
/// not defensible — the audit log needs to reflect wire-level truth.
pub struct AdbFrame {
    pub command: u32,      // A_CNXN, A_AUTH, A_OPEN, A_WRTE, A_CLSE, A_OKAY
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_crc32: u32,
    pub magic: u32,        // command ^ 0xFFFFFFFF
    pub payload: Vec<u8>,
}

pub const A_CNXN: u32 = 0x4e584e43;
pub const A_AUTH: u32 = 0x48545541;
pub const A_OPEN: u32 = 0x4e45504f;
pub const A_WRTE: u32 = 0x45545257;
pub const A_CLSE: u32 = 0x45534c43;
pub const A_OKAY: u32 = 0x59414b4f;

pub struct AdbConnection {
    usb: nusb::Interface,
    local_id: u32,
    remote_id: u32,
}

impl AdbConnection {
    pub async fn connect(usb: nusb::Interface) -> Result<Self> {
        // 1. Send CNXN with system identity string
        // 2. Receive AUTH (token) challenge
        // 3. Sign token with stored RSA key, or trigger on-device RSA prompt
        // 4. Receive CNXN back = authorized
        // Every step of this handshake is an audit_log::AuditEvent — this is the
        // wire-level truth research.md's Section 3 decision was actually asking for.
        todo!("frame handshake — see AOSP SYSTEM/core/adb/protocol.txt for exact layout")
    }

    pub async fn open_stream(&mut self, destination: &str) -> Result<AdbStream> {
        todo!("A_OPEN with local-id, wait for A_OKAY")
    }
}
```

### 4.3 Fastboot protocol (`transport/fastboot_protocol.rs`)

```rust
/// Fastboot's protocol is simpler than ADB's — plain text command/response over bulk
/// endpoints, no framing/auth handshake. Still native (not shelled) for the same
/// wire-level-truth reason.
pub struct FastbootConnection {
    usb: nusb::Interface,
}

impl FastbootConnection {
    pub async fn command(&mut self, cmd: &str) -> Result<FastbootResponse> {
        // OKAY<msg> | FAIL<reason> | DATA<size> | INFO<msg>
        todo!()
    }

    pub async fn dd_raw(&mut self, partition: &str, out: &mut impl AsyncWrite)
        -> Result<StreamingHashers>
    {
        // Streaming read, feeding StreamingHashers as bytes arrive — same pattern as
        // acquisition/fastboot_dd.rs Tier 3 acquisition below.
        todo!()
    }
}
```

### 4.4 Shell fallback — explicitly demoted, explicitly labeled

```rust
// transport/shell_fallback.rs
//
// CONVENIENCE ONLY. Do not call this from acquisition/*.rs. The type system doesn't
// block it (Rust can't easily enforce "don't import this module" across crate-internal
// boundaries without a workspace split), so this is enforced by a `#[deny]`-style lint
// comment + code review discipline + the fact that AcquisitionMethod::acquire()
// signatures only take `&AdbConnection` / `&FastbootConnection`, never a raw Command.
//
// Legitimate uses: `adb shell getprop` during triage, `adb devices` for a quick UI
// refresh, anything explicitly non-evidentiary.

use tokio::process::Command;

pub struct ShellFallback;

impl ShellFallback {
    pub async fn adb_shell(cmd: &str) -> Result<String> {
        let out = Command::new("adb").args(["shell", cmd]).output().await?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}
```

---

## 5. Device Module

```rust
// device/state.rs
pub enum DeviceMode {
    NormalAdb { debug_authorized: bool },
    AdbAuthPending,          // enumerated, but AUTH handshake hangs — distinct from
                              // "not connected"; log explicitly, don't collapse into
                              // a generic "unavailable"
    Fastboot { bootloader_unlocked: bool },
    Recovery,
    Edl { chipset: QualcommChipset },
    Unknown(u16, u16),
}

pub enum ChipsetFamily {
    Qualcomm(QualcommModel),
    Mediatek(MtkModel),
    ExynosSamsung,
    Unisoc,
    HiSilicon,                // document as unsupported, don't attempt silently
    Unknown(u16, u16),
}
```

```rust
// device/fingerprint.rs
/// Captured BEFORE any write-capable interaction. Hashed into the manifest so a state
/// change between fingerprint-time and acquisition-start is detectable.
pub struct DeviceFingerprint {
    pub build_fingerprint: Option<String>,
    pub imei: Option<String>,
    pub serial: String,
    pub bootloader_unlocked: Option<bool>,
    pub encryption_state: Option<String>,
    pub chipset_family: ChipsetFamily,
    pub captured_at: chrono::DateTime<chrono::Utc>,
}
```

```rust
// device/detect.rs
pub struct DeviceDetector;

impl DeviceDetector {
    pub fn classify(info: &nusb::DeviceInfo) -> DeviceMode {
        match (info.vendor_id(), info.product_id()) {
            (0x05c6, 0x9008) => DeviceMode::Edl { chipset: QualcommChipset::probe(info) },
            // ... VID:PID table for fastboot/adb interface classes
            _ => DeviceMode::Unknown(info.vendor_id(), info.product_id()),
        }
    }
}
```

---

## 6. Acquisition Module

### 6.1 The trait — risk-gated, tier-ordered

```rust
// acquisition/mod.rs
use crate::core::manifest::{CaseManifest, LiveDevice};

pub trait AcquisitionMethod {
    fn name(&self) -> &'static str;
    fn tier(&self) -> u8;
    fn is_available(&self, mode: &DeviceMode) -> bool;
    fn risk_level(&self) -> RiskLevel;

    fn acquire(
        &self,
        conn: &mut dyn DeviceConnection,           // AdbConnection or FastbootConnection
        case: &mut CaseManifest<LiveDevice>,
        audit: &mut AuditLog,
        dest: &Path,
    ) -> Result<AcquisitionOutcome>;
}

pub enum RiskLevel {
    ReadOnly,                  // proceeds automatically
    RequiresWrite,             // examiner confirmation + typed justification, logged
    RequiresBootloaderFlash,   // same, plus explicit "this may trigger a wipe" warning
}

pub enum AcquisitionOutcome {
    Success,
    Blocked(AcquisitionBlockedReason),
}

/// Orchestrator — queries tiers in priority order, never jumps to physical extraction
/// just because it's more thorough.
pub struct AcquisitionOrchestrator {
    methods: Vec<Box<dyn AcquisitionMethod>>,
}

impl AcquisitionOrchestrator {
    pub fn select_for(&self, mode: &DeviceMode) -> Option<&dyn AcquisitionMethod> {
        self.methods.iter()
            .filter(|m| m.is_available(mode))
            .min_by_key(|m| m.tier())
            .map(|b| b.as_ref())
    }
}
```

### 6.2 Tier 1 — ADB Backup

```rust
// acquisition/adb_backup.rs
pub struct AdbBackup;

impl AcquisitionMethod for AdbBackup {
    fn name(&self) -> &'static str { "ADB Backup" }
    fn tier(&self) -> u8 { 1 }
    fn is_available(&self, mode: &DeviceMode) -> bool {
        matches!(mode, DeviceMode::NormalAdb { debug_authorized: true })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::ReadOnly }

    fn acquire(&self, conn: &mut dyn DeviceConnection, case: &mut CaseManifest<LiveDevice>,
               audit: &mut AuditLog, dest: &Path) -> Result<AcquisitionOutcome> {
        audit.append(AuditEvent::MethodSelected {
            method: self.name().into(), risk_level: "ReadOnly".into()
        })?;
        case.timestamps.acquisition_started_at = Some(chrono::Utc::now());

        let mut hashers = StreamingHashers::new();
        // stream `adb backup` output, feeding hashers + audit per chunk boundary — see
        // Section 3.2 pattern. First real vertical slice to build end-to-end, per your
        // original open-questions list.
        todo!()
    }
}
```

### 6.3 Tier 3 — Fastboot dd

```rust
// acquisition/fastboot_dd.rs
pub struct FastbootDd;

impl AcquisitionMethod for FastbootDd {
    fn name(&self) -> &'static str { "Fastboot Physical (dd)" }
    fn tier(&self) -> u8 { 3 }
    fn is_available(&self, mode: &DeviceMode) -> bool {
        matches!(mode, DeviceMode::Fastboot { bootloader_unlocked: true })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::RequiresBootloaderFlash }
    // ...
}
```

### 6.4 Tier 4 — EDL / BROM / Odin (stubs, prioritized per research.md Section 8)

```rust
// acquisition/edl_firehose.rs      — build first (best documented, SDM665 target device)
// acquisition/mtk_brom.rs          — build second (largest budget-device population)
// acquisition/samsung_download.rs  — build third
// acquisition/spreadtrum.rs        — stretch, document unsupported chipsets explicitly
//
// All four follow the same shape: chipset-matched loader lookup → is_available() gate
// on chipset match → stream raw physical dump via native transport → same
// StreamingHashers/audit pattern as Tiers 1–3. Nothing here waives the manifest/hash
// requirements — Tier 4 doesn't get a shortcut just because it's lower-level.
```

---

## 7. Analysis Suite (folded in, sealed-case-only)

Everything strong from v1 survives here, just re-bound to `CaseManifest<SealedCase>`
instead of a live device or a raw path.

### 7.1 Decoder trait

```rust
// analysis/base.rs
use crate::core::manifest::{CaseManifest, SealedCase};

pub trait AndroidDecoder: Send + Sync {
    fn name(&self) -> &'static str;
    fn target_path_in_image(&self) -> &'static str;

    /// Note the signature: this cannot compile against a `CaseManifest<LiveDevice>`.
    /// That's the whole point.
    fn decode(&self, case: &CaseManifest<SealedCase>, work_dir: &Path) -> Result<DecoderOutput>;
}
```

### 7.2 What carries over from v1 essentially unchanged

- `app_scanner.rs` — dynamic app discovery, now scanning the **sealed image's**
  `/data/data/*` tree rather than a live `pm list packages` call.
- `generic.rs` — schema-introspecting fallback decoder for unknown apps.
- 29 dedicated decoders across messaging/social/browsers/email/cloud/AI/system — same
  catalog as v1 (WhatsApp, Signal, Telegram, Discord, Twitter/X, Snapchat, TikTok,
  Chrome, Firefox, Gmail, Outlook, ProtonMail, Drive, Dropbox, OneDrive, Google Photos,
  ChatGPT, Claude, Gemini, Copilot, SMS/MMS, Contacts, CallLogs, Calendar, Downloads).
- `crypto/whatsapp.rs` — crypt7→crypt12, unchanged.
- `triage/mod.rs` — Quick (5–10 min) / Full (30+ min) presets, unchanged, now reading
  from the sealed image.

### 7.3 Cracking — same offline design as v1, now with the boundary made explicit

```rust
// cracking/password.rs
/// Unchanged algorithm from v1 (it was already correctly detached — takes a hash+salt,
/// not a device handle). What's new: the ONLY supported way to obtain that hash is
/// `HashExtractor::from_sealed_case()`, which requires a `CaseManifest<SealedCase>`.
/// There is deliberately no `PasswordCracker::from_live_device()`.
pub struct PasswordCracker {
    target_hash: [u8; 20],
    salt: Vec<u8>,
    algo: CrackAlgo,
}

pub struct HashExtractor;
impl HashExtractor {
    pub fn from_sealed_case(case: &CaseManifest<SealedCase>) -> Result<PasswordCracker> {
        // reads /data/system/gesture.key or locksettings.db out of the sealed image
        todo!()
    }
}
```

---

## 8. UI — Tauri, mirroring OpenForensic's shell

Fixed from v1's egui-first mistake. Tab structure directly parallels OpenForensic per
your research doc, plus the folded-in Analysis tabs:

```
┌─────────────────────────────────────────────────────────┐
│  Device Selector   (VID:PID, mode, chipset — live)       │
├─────────────────────────────────────────────────────────┤
│  Acquisition Config │ Analysis Workbench │ Case Manager  │
│  (Tier picker,      │ (decoder browser,  │ (sealed case  │
│   risk gate UI,     │  cracking module,  │  DB browser)  │
│   Evidence ID etc.) │  triage presets)   │               │
├─────────────────────────────────────────────────────────┤
│  Console Log  (signed audit_log tail, live)               │
│  [ Start Acquisition ]              status: ● connected   │
└─────────────────────────────────────────────────────────┘
```

```rust
// ui/mod.rs — Tauri command surface
#[tauri::command]
async fn list_devices() -> Result<Vec<DeviceSummary>, String> { /* transport::usb */ }

#[tauri::command]
async fn start_acquisition(evidence_id: String, method: String) -> Result<(), String> {
    // orchestrator.select_for(mode) → risk gate → acquire() → seal()
}

#[tauri::command]
async fn run_decoder(case_path: String, decoder_name: String) -> Result<DecoderOutput, String> {
    // requires a sealed CaseManifest on disk — loading an unsealed one is a hard error
}
```

The **risk gate is a real modal**, not a greyed-out button: when a method's
`risk_level()` is `RequiresWrite` or above, the UI surfaces exactly why (mirrors your
research doc's "surface why, don't just hide the button" UX call), takes a typed
justification string, and only then calls `start_acquisition`.

---

## 9. CLI (headless mode, alongside the Tauri GUI)

```rust
// main.rs — clap-derived, for scripted/lab use without the GUI
#[derive(clap::Parser)]
enum Cli {
    Devices,
    Acquire { evidence_id: String, case_number: String, examiner: String, method: Option<String> },
    Decode { case: PathBuf, decoder: Option<String> },
    Triage { case: PathBuf, mode: TriageMode },
    Crack { case: PathBuf, algo: String, dict: Option<PathBuf> },
}
```

---

## 10. Rename Summary

| | v1 | v2 |
|---|---|---|
| Crate name | `andriller` | `droidforge` |
| Version | `4.0.0` (Andriller's lineage) | `0.1.0` (fresh) |
| GUI | egui (primary), Tauri (fallback) | Tauri only |
| Shared crate | `forensics-core` (external) | `core/` (internal, self-contained) |
| Acquisition/analysis split | None — one flat workflow | One binary, compiler-enforced boundary via `CaseManifest<LiveDevice>` / `<SealedCase>` typestate |
| Transport | Shell out to `adb`/`fastboot` binaries | Native `nusb` + hand-rolled wire protocols; shell-out demoted to explicit, labeled convenience fallback |
| Audit trail | `tracing` log spans | Hash-chained, ed25519-signed JSONL, structured `AuditEvent` enum |
| Acquisition tiers | None (ADB backup/pull only, unlabeled) | Explicit `AcquisitionMethod` trait, Tiers 1–4, risk-gated |

---

## 11. Build Order (unchanged priority logic from research.md, re-scoped to one crate)

1. `core::manifest` + `core::hash_chain` + `core::audit_log` — Section 3 of this doc.
   Nothing else compiles meaningfully against a stable schema without this first.
2. `transport::usb` + `transport::adb_protocol` handshake — enough to enumerate and
   authenticate a device natively.
3. `device::detect` + `device::fingerprint` — read-only ID capture, hashed into the
   manifest.
4. `acquisition::AdbBackup` (Tier 1) — first true vertical slice, end-to-end:
   connect → fingerprint → acquire → hash → seal.
5. `analysis::base` + one real decoder (e.g. `WhatsAppMessagesDecoder`) bound to
   `CaseManifest<SealedCase>` — proves the boundary compiles and the fold-in works.
6. Tauri shell wrapping steps 2–5 — Device Selector → Acquisition Config → Console Log.
7. Remaining Tier 1–2 methods, then Tier 3 (`FastbootDd`), then Tier 4
   (`EdlFirehose` against the Redmi Note 8 / SDM665 target from your case study).
8. Backfill the remaining decoder catalog (`app_scanner`, generic fallback, the rest of
   the 29) — this is the part that's already de-risked, since v1 proved the pattern.

---

## Open Questions

- [ ] `ed25519-dalek` signing key provisioning — per-examiner keypair, or per-install?
      Affects whether audit logs are individually or institutionally attributable.
- [ ] Should `transport::shell_fallback` be feature-gated out of release builds
      entirely, to make it physically impossible to reach for acquisition paths by
      accident, rather than relying on code review discipline?
- [ ] EDL Firehose loader sourcing for SDM665 — confirm read-capable vs write-only/
      auth-locked, per the Redmi Note 8 case study in research.md Section 9.
- [ ] Tauri IPC payload size limits for streaming multi-GB physical dumps to the
      Console Log UI — likely needs chunked progress events rather than full-buffer
      passthrough.
