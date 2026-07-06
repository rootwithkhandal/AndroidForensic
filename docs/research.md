# AndroidForensic — Research & Architecture Notes

> Living research doc for the AndroidForensic acquisition tool (part of the OpenForensic /
> AndroidForensic / Analysis Suite tri-tool ecosystem). Captures architecture decisions,
> chipset research, and forensic-integrity doctrine as they're worked out.

---

## 1. Tool Ecosystem Context

Three separate tools, deliberately not merged:

| Tool | Domain | Language | Status |
|---|---|---|---|
| **OpenForensic** | Windows disk/system/RAM acquisition (block devices, VSS, live triage) | Rust | Being rebuilt |
| **AndroidForensic** | Android-only acquisition (ADB/fastboot/EDL/chipset-specific) | Rust | New build |
| **Analysis Suite** | Ingests outputs from both acquisition tools, does parsing/timeline/artifact/cracking work | Go or Rust (leaning Rust for shared crate reuse) | Not started |

**Why not merge into one tool:** OpenForensic's architecture is fundamentally block-device
shaped (PhysicalDrive handles, VSS snapshots, NTFS/MFT parsing). Android acquisition is
transport-shaped (USB protocol frames — ADB/fastboot/EDL), not block-device shaped. Forcing
Android into OpenForensic's paradigm creates architectural debt. Separate tools, shared core
crate.

**Why not merge acquisition + analysis:** Chain-of-custody discipline — acquisition tools
touch live/original evidence and must stay minimal, auditable, and write-averse. Analysis
(including password cracking) should only ever operate against a sealed, hash-verified
**copy**, never the original device. Keeping them as separate tools enforces this boundary
architecturally, not just procedurally.

### Shared `forensics-core` crate (used by all three tools)
- `case_manifest.rs` — Evidence ID, Case #, Examiner, source type, hash chain
- `hash_chain.rs` — streaming MD5/SHA1/SHA256, pre/post verify (mirrors OpenForensic's
  "Double-Verify" pattern)
- `audit_log.rs` — append-only, signed JSONL audit trail (mirrors OpenForensic's "Forensic
  Console Log")

Scaffold this crate **before** writing acquisition logic in either OpenForensic's rebuild or
AndroidForensic — everything downstream depends on a stable manifest/hash-chain schema so the
future Analysis Suite has one ingestion contract instead of two bespoke ones.

---

## 2. OpenForensic UI Reference (from screenshots, v2.0.2)

Existing tab structure worth mirroring in AndroidForensic for UX consistency:

- **Disk Imaging** — Source Selector (Physical Drive / Logical Folder) → Acquisition
  Configuration (Evidence ID, Case Number, Examiner Name, Custody Notes, Output Format,
  Destination Path, Verification Hashing [Pre & Post-Acquisition Double-Verify], Block Size,
  On-the-fly Hashing Algorithms [MD5/SHA-1/SHA-256/SHA-512], Compression, Image Splitting,
  Read Verification, Keyword Pre-Scanning, YARA Rules folder, Sparse Imaging, Digital Signing)
- **System Triage** — Rapid Forensic Triage & RAM Capture (volatile state, registry hives,
  browser metadata, OS event logs) + Triage Analysis Workbench (query triage.db)
- **Live Acquisition** — VSS-based live system acquisition (VSS snapshot, locked file copy,
  physical RAM capture, consistency validation)
- **Timeline** — MFT/$LogFile/Ext4 journal parsing → chronological master timeline
  (CSV/JSON output)
- **Case Management** — case DB browser
- **RAM Analysis** — Volatility 3 integration + threat intel enrichment (AbuseIPDB,
  VirusTotal)

Bottom bar: **Forensic Console Log** (timestamped system log, Export/Clear) + status +
Start Acquisition button. This layout skeleton (Source/Device Selector → Acquisition
Config → Start → Console Log) should be reused in AndroidForensic's UI for consistency and
schema compatibility.

### Theme reference (from Cellebrite marketing site — NOT their product UI)
Cellebrite's *website* uses a soft enterprise-trust palette (near-white blue gradient
background `#E8F2FC`→`#D4E8F7`, navy `#1B2951`, accent blue `#4A90D9`, pill-tab category
switcher, card grid with tag+heading+description+"Find out more"). This is the opposite of
Forgelens/OpenForensic's hacker cyan-on-navy identity — intentionally not copied for the
app itself. Only the **structural pattern** (pill-tab switcher, card rhythm, info density) is
worth borrowing, e.g. for a docs/marketing page, not the palette.

---

## 3. Rust ADB/Fastboot Support

Rust supports both. Two implementation approaches:

1. **Shell out to platform-tools** (`adb`, `fastboot` binaries via `std::process::Command` /
   `tokio::process`) — fast to ship, battle-tested, but audit log only captures the command
   issued, not wire-level truth. Fine for convenience/triage features.
2. **Native protocol implementation** (via `rusb`/`nusb` for USB transport, crates like
   `adb_client`/`forensic-adb`, or custom) — full control over exact bytes crossing the wire,
   required for defensible chain-of-custody logging on acquisition-critical paths.

**Decision:** Native protocol implementation for acquisition-critical paths (device detection,
backup pull, fastboot dd). Shelling out acceptable for non-evidentiary convenience calls
(e.g. `adb shell getprop` during triage).

---

## 4. AndroidForensic — Crate/Module Architecture

```
android-forensic/
├── forensics-core/          (shared crate — also used by OpenForensic)
│   ├── case_manifest.rs
│   ├── hash_chain.rs
│   └── audit_log.rs
│
├── transport/
│   ├── usb.rs                 (rusb/nusb — raw USB device enum + bulk transfer)
│   ├── adb_protocol.rs        (ADB wire protocol: CNXN/AUTH/OPEN/WRTE/CLSE frames)
│   └── fastboot_protocol.rs   (fastboot command/response over USB bulk)
│
├── device/
│   ├── detect.rs               (enumerate devices, VID/PID match, mode + chipset detection)
│   ├── fingerprint.rs          (pre-acquisition read-only ID capture: IMEI, serial, build
│                                 fingerprint, bootloader/encryption state — BEFORE any
│                                 write-capable interaction)
│   └── state.rs                (device mode state machine)
│
├── acquisition/
│   ├── mod.rs                  (trait AcquisitionMethod)
│   ├── adb_backup.rs            (Tier 1 — logical, least invasive)
│   ├── adb_pull_fs.rs           (Tier 2 — file-system level, needs root/debug)
│   ├── fastboot_dd.rs           (Tier 3 — physical, unlocked bootloader only)
│   ├── edl_firehose.rs          (Tier 4 — Qualcomm, gated behind escalation flag)
│   ├── mtk_brom.rs              (Tier 4 — MediaTek, planned)
│   ├── samsung_download_mode.rs (Tier 4 — Exynos/Odin protocol, planned)
│   └── spreadtrum.rs            (Tier 4 — UNISOC, stretch goal)
│
├── ui/                          (Tauri, mirrors OpenForensic's shell)
│   ├── acquisition_config.rs
│   ├── device_selector.rs
│   └── console_log.rs
│
└── main.rs
```

### Core trait
```rust
pub trait AcquisitionMethod {
    fn name(&self) -> &'static str;
    fn is_available(&self, device: &DeviceState) -> bool;
    fn risk_level(&self) -> RiskLevel;   // ReadOnly | RequiresWrite | RequiresBootloaderFlash
    fn acquire(&self, device: &DeviceHandle, case: &CaseManifest, dest: &Path)
        -> Result<AcquisitionResult>;
}
```
Orchestrator queries `is_available()` across methods in priority order (least invasive
first). Methods with `RequiresWrite`+ risk force explicit UI confirmation, logged with
examiner's explicit confirmation + timestamp before executing.

### Device mode / chipset classification
```rust
pub enum DeviceMode {
    NormalAdb { debug_authorized: bool },
    Fastboot { bootloader_unlocked: bool },
    Recovery,
    Edl { chipset: QualcommChipset },   // VID:PID 05c6:9008
    Unknown(u16, u16),
}

pub enum ChipsetFamily {
    Qualcomm(QualcommModel),   // → edl_firehose.rs
    Mediatek(MtkModel),        // → mtk_brom.rs
    ExynosSamsung,             // → samsung_download_mode.rs
    Unisoc,                    // → spreadtrum.rs
    HiSilicon,                 // → likely unsupported, log + escalate
    Unknown(u16, u16),         // → log raw VID:PID, no automated path
}
```
Chipset ID must happen **before** mode/method selection — EDL-style approaches are
chipset-family-specific, not a universal Android mechanism.

### Case manifest (shared schema across all three tools)
```rust
pub struct CaseManifest {
    pub evidence_id: String,
    pub case_number: String,
    pub examiner_name: String,
    pub custody_notes: String,
    pub source_type: SourceType,        // Disk | Ram | Android
    pub acquisition_method: String,
    pub hash_chain: HashChain,          // pre + post, Double-Verify pattern
    pub timestamps: TimestampLog,
    pub device_fingerprint: Option<DeviceFingerprint>,
}
```

---

## 5. Full Acquisition Flow (Working)

1. **USB enumeration** — VID:PID read at bus level, before any protocol handshake. Logged
   immediately (mirrors OpenForensic's `[SYSTEM] Discovered N device(s)` pattern).
2. **Mode detection** — classify into NormalAdb / Fastboot / Recovery / Edl based on VID:PID
   + lightweight handshake. Determines the entire menu of what's possible next.
3. **Pre-acquisition fingerprint** — capture whatever read-only ID is available in current
   mode (build fingerprint, IMEI, bootloader/unlock state, chip family) and hash it into the
   manifest **before** any state-altering method runs. Enables detecting inconsistency if
   device state changes between fingerprint and acquisition start.
4. **Method selection** — orchestrator iterates tiers, picks least invasive available method.
   Never jumps to physical extraction just because it's more thorough.
5. **Risk gate** — `ReadOnly` methods proceed automatically; `RequiresWrite`/
   `RequiresBootloaderFlash` force explicit examiner confirmation with typed justification,
   logged with timestamp. This is the literal mechanism behind "abort on ambiguity," not just
   a principle.
6. **Acquisition execution** — streaming USB bulk transfer, simultaneously: write to disk +
   feed hash chain (MD5+SHA256) + append audit log entry per chunk boundary.
7. **Post-acquisition verification** — re-hash output, compare against streaming hash.
   Mismatch → manifest marked `FAILED`, not silently accepted.
8. **Case manifest sealed** — written alongside extracted image/backup, consumed identically
   by the future Analysis Suite regardless of which acquisition tool produced it.

**Core principle:** every state transition (connect → mode detected → fingerprint captured →
method selected → risk confirmed → transfer streamed → hash verified) is a discrete,
timestamped, audit-logged event before the next step is allowed to proceed. Chain-of-custody
defensibility comes from nothing happening silently or out of order — not from the
acquisition method itself.

---

## 6. USB Debugging Requirement — By Method

| Method | USB Debugging Required? | Why |
|---|---|---|
| ADB Backup / ADB Pull FS (Tier 1–2) | **Yes, mandatory** | ADB protocol cannot establish a session without on-device RSA-key authorization over USB debugging. No software workaround exists — it's Android's own security model. |
| Fastboot dd (Tier 3) | **No** | Separate bootloader-mode protocol, independent of OS/debugging setting. Requires bootloader already unlocked though. |
| EDL/Firehose (Tier 4) | **No** | Pre-OS, chip-level download mode. Debugging is irrelevant since Android hasn't booted. |

If debugging is off, `NormalAdb` mode still gets *detected* (device enumerates) but the ADB
handshake hangs at the AUTH step. This is a distinct state from "not connected" — log it
explicitly as `ADB_AUTH_PENDING`, not just "unavailable."

UI should surface **why** a method is greyed out (e.g. "USB Debugging not authorized —
enable in Developer Options and accept RSA prompt") rather than just hiding the button —
both better UX and better forensic transparency (examiner needs to know a method was
unavailable and why, not just that it wasn't attempted).

---

## 7. Cloning Without ADB — Tier Breakdown

| Tier | Method | Debugging needed? | Bootloader unlock needed? | Notes |
|---|---|---|---|---|
| 1–2 | ADB backup/pull | Yes | No | Dead end if debugging off |
| 3 | Fastboot dd | No | **Yes** | Unlocking usually wipes data if not already unlocked — dead end on a locked-OEM-unlock evidence device |
| 4 | EDL/Firehose (Qualcomm) | No | No | Chip-level, pre-OS. Requires chipset-matched Firehose loader (OEM-signed or vulnerability-class) |
| 4 | MTK BROM (MediaTek) | No | No (more viable when unlocked, but BROM itself is often exploitable even locked) | Own protocol, own research needed |
| 4 | Samsung Download Mode (Odin protocol) | No | No | Exynos-specific, chip/firmware-version specific |
| 4 | LG LAF | No | No | Proprietary, works across LG's chipset choices |
| 4 | Spreadtrum download mode | No | No | UNISOC, budget devices, less documented |
| 5 | JTAG / Chip-off / ISP | No | No | Hardware-level, no software cooperation from device needed. Destructive-adjacent (desoldering). Not something AndroidForensic-the-software does standalone. |

**Reality check on EDL/Firehose specifically:** not a universal skeleton key. Requires either
a leaked/signed OEM loader for that exact chipset, or an actual unpatched boot-ROM auth
vulnerability. Continuously shifting target as OEMs patch loader signing — this is why
commercial vendors (Cellebrite/Oxygen/Magnet) maintain dedicated vulnerability research teams
rather than shipping one static algorithm.

---

## 8. Chipset Vendor Map (Non-Qualcomm Devices)

| Chipset | Low-level mode | Notes |
|---|---|---|
| **Qualcomm** | EDL (Emergency Download Mode) / Firehose | Best community documentation, build first |
| **MediaTek (MTK)** | BROM / Preloader mode | Huge market share in budget devices (very relevant given likely Indian device population — lots of Xiaomi/Realme/Redmi MTK variants). Famous in flashing-tool community (SP Flash Tool) for being exploitable even on some locked devices. Build second. |
| **Samsung Exynos** | Download Mode (Odin protocol) | Proprietary, key-combo entry (Vol Up+Down+Power or Bixby+Vol Down+Power depending on model). Chip/firmware-version specific. Build third — Samsung's market share justifies it despite difficulty. |
| **UNISOC (Spreadtrum)** | Spreadtrum download mode | Ultra-budget devices, has its own research community, less commercially documented. Stretch goal. |
| **HiSilicon Kirin (Huawei)** | Vendor-specific, poorly documented | Huawei's post-2019 lockdown makes this one of the hardest. Commercial vendors explicitly flag limited support. Document as unsupported rather than attempting silently. |
| **Google Tensor** | Custom secure boot, Qualcomm-adjacent | Not standard EDL-exploitable; Google's own protections layered on top. |
| **LG proprietary (older devices)** | LAF (LG Advanced Flashing) | Works across LG's chipset choices since it's LG's own protocol layered on top of whatever SoC. |

**Prioritization for AndroidForensic roadmap:**
1. Qualcomm (EDL) — most devices, best documentation
2. MediaTek (BROM) — huge budget-device market share
3. Samsung (Download Mode) — market share justifies difficulty
4. UNISOC / HiSilicon — stretch goals, document as unsupported explicitly rather than
   silently failing

---

## 9. Case Study: Redmi Note 8, OEM Unlock Disabled

- Chipset: **Snapdragon 665 (SDM665)** — Qualcomm, so EDL path applies.
- OEM unlock disabled → `fastboot flashing unlock` refused → **Tier 3 (fastboot dd) fully
  closed**, regardless of anything else attempted.
- Xiaomi also requires Mi Unlock account binding + waiting period for legitimate unlock even
  when the toggle IS on — moot here since it's off entirely.
- **EDL is the viable path.** SDM665 is common/well-deployed, meaning Firehose loader
  research is comparatively well-documented vs. newer flagship SoCs. Xiaomi's own "Mi Flash"
  tool ships an authenticated programmer for this chip family for legitimate factory
  reflashing — open question whether it's repurposable for **read** (vs. write-only/
  auth-locked), which determines whether the "legitimate" loader works or a vulnerability-
  class loader is needed instead.
- EDL entry: device/region-variant-dependent key combo, or `adb reboot edl` (moot, debugging
  off), or deep-flash-cable/test-point short if the key combo is disabled in that firmware
  build.

**Sequence:**
```
1. detect.rs → NormalAdb{debug_authorized:false}, locked, OEM unlock off
2. Attempt EDL entry (device-specific key combo)
3. If reached → identify chipset (SDM665)
4. Check loader availability for SDM665
5a. Read-capable loader exists → stream raw physical dump via Firehose, hash while streaming
5b. Only write-capable/auth-locked loader → EDL blocked too, log ACQUISITION_BLOCKED
6. If EDL entry itself fails → fallback to chip-off/ISP or "document and escalate"
```

**Assessment:** Redmi Note 8 is actually a *favorable* first real-device target for
validating the EDL module, not a worst case — SDM665's ubiquity means better community
loader documentation than newer/rarer chipsets.

---

## 10. Locked Device, Debugging Off — Full Decision Tree

Order a working examiner would triage:

1. **Confirm device mode via `detect.rs`** — don't assume.
2. **EDL/Firehose (or chipset-equivalent)** — the actual answer for locked + debugging-off +
   no bootloader-unlock scenarios. Works because it operates below the OS, before
   debug-authorization checks ever load.
3. **OEM service mode** (LG LAF / MTK BROM) — check device make/chipset before assuming
   Qualcomm-only.
4. **Legal/procedural options** (not a technical bypass, but real):
   - Compelled unlock — jurisdiction-dependent; biometric unlock often compellable via
     warrant, passcode often not (varies by country's legal protections)
   - Passcode from another source — subpoenaed from manufacturer/cloud backup, informant,
     prior record
   - Specialist lab escalation — Cellebrite/Grayshift/Oxygen "advanced unlocking services"
     for chipsets/cases your own tooling doesn't cover yet
5. **Document and stop** — if none of the above apply, this is the forensically correct
   outcome, not a failure. Log `ACQUISITION_BLOCKED` with specific reason
   (`debug_disabled`, `bootloader_locked`, `no_edl_loader_available`), device fingerprint
   already captured, timestamp. A documented inability to access is defensible; a silent
   failure or fudged partial result is the actual integrity violation.

**UI implication:** when Tier 1/2 report `is_available() == false`, surface exactly which
condition failed and route the examiner toward Tier 4 or the "document and escalate" path,
rather than a greyed-out button with no explanation.

---

## 11. Password Cracking (hashcat-class tools) — Scope & Limitations

### What hashcat actually cracks
Not a live-device interaction — cracks a **hash already extracted from device storage**
(requires prior physical/EDL/chip-off access to obtain the hash file offline).

Relevant legacy files:
- `/data/system/gesture.key` — SHA1 hash of pattern (pre-Android ~4.4)
- `/data/system/password.key` — hash of PIN/password (older Android)
- `/data/system/locksettings.db` + Gatekeeper — modern Android's actual scheme

### Critical limitation
The ability to crack the lockscreen credential via extracted hash **stopped being generally
viable around Android 6**, due to hardware-backed Gatekeeper/Keymaster (TEE/StrongBox) —
credential is tied to hardware-bound keys with enforced retry-throttling/cooldown baked into
secure hardware itself, not just software. On Android 6+ (essentially all currently relevant
devices), you cannot pull the hash and brute-force it offline like a leaked password
database — the hardware rate-limits/wipes regardless of what's asking.

### Where it still applies
- Legacy/low-end Android (pre-6, or budget devices skipping TEE-backed keystore)
- Android `.ab` backup file encryption (PBKDF2-based, genuinely crackable offline if you
  have the backup file — separate from the lockscreen itself)
- Some OEM bootloader/unlock tokens on older devices

### "Cilocks"
Not a recognized/documented legitimate forensic tool — flagged as possibly grey-market or a
name mix-up. Not researched further; revisit if a proper name/source is identified.

---

## 12. Evidence Integrity & Password Cracking — The Rule

**Two distinct scenarios, very different integrity implications:**

### A. Cracking against a LIVE device, before acquisition — VOIDS INTEGRITY
- Automated PIN brute-forcing against a running phone risks triggering the device's own
  defenses: escalating lockout timers, and on many OEMs, **auto-wipe after N failed
  attempts** (commonly 10). Triggering a wipe destroys the evidence outright.
- Every unlock attempt is a write/state-change event on the device (attempt counters,
  Gatekeeper throttling state) — this is you altering evidence before it was preserved.
- **Doctrine: acquire first, analyze second, always.** Make a bit-for-bit forensic copy in a
  read-only/write-blocked manner before attempting anything that could alter device state.

### B. Cracking OFFLINE, against a hash pulled from an already-completed forensic image —
DOES NOT AFFECT INTEGRITY
```
1. AndroidForensic acquires image (hashed, sealed, manifest written)
2. Original device done being touched — chain-of-custody closed for that step
3. Analysis Suite works ONLY against the acquired image copy
4. hashcat runs against a hash extracted from the IMAGE, not the device
5. Original device's evidentiary state never altered by steps 3–4
```
Integrity guarantee is about the **original evidence item**; once the hash-verified copy
exists, computation against that copy (including exhaustive offline cracking) is standard
analysis work, not a violation.

### Architectural constraint to enforce
No cracking/brute-force module should ever be allowed to target a **live connected device**.
Analysis Suite's input contract = "accepts a sealed, hash-verified case image only," never a
live device handle. A cracking module pointed at `/dev/bus/usb/...` directly is a design
flaw — it reintroduces the exact live-device-mutation risk that acquisition/analysis
separation exists to eliminate.

---

## 13. Open Questions / Next Steps

- [ ] Scaffold `forensics-core` crate (Cargo.toml + module skeleton) — blocks everything else
- [ ] Implement `AcquisitionMethod` trait + `AdbBackup` (Tier 1) as first working vertical
      slice end-to-end
- [ ] Validate EDL/Firehose module against Redmi Note 8 (SDM665) as first real-device target
- [ ] Research MTK BROM as second chipset-family module (high value given likely device
      population)
- [ ] Define UI copy/behavior for risk-gate confirmations (RequiresWrite /
      RequiresBootloaderFlash)
- [ ] Confirm Analysis Suite language (Go vs Rust) — leaning Rust for `forensics-core` reuse
- [ ] Design `ACQUISITION_BLOCKED` reason taxonomy for audit log (debug_disabled,
      bootloader_locked, no_edl_loader_available, edl_entry_failed, etc.)
