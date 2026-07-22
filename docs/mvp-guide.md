# MVP Operations Guide

## Before acquisition

1. Confirm authorization and document the case context.
2. Enable USB debugging on the device and accept the workstation key.
3. Run `python -m capture --list` and record the device serial.
4. Use `--serial` for every acquisition when more than one device may be
   connected.

## Recommended commands

```bash
python -m capture --help
python -m capture --list
python -m capture --serial DEVICE_SERIAL --case-id CASE-001 --dry-run
python -m capture --serial DEVICE_SERIAL --case-id CASE-001 --skip-media --skip-apk --call-logs --messages --contacts
```

Optional extractors inherit the serial selected by the controller. Inspect the
final report and acquisition metadata for module failures or unavailable data.

## Validate output

Keep the complete case directory together. Review `hashes/hash_manifest.json`,
`acquisition_metadata.json`, raw source dumps, and extraction errors. Hashes
are an integrity aid, not a substitute for an independently validated
chain-of-custody process.

## MVP boundaries

This release performs logical ADB collection only. It does not provide
physical imaging, security bypasses, or deleted-data recovery. Device access
and record availability vary across Android versions and OEM builds.
