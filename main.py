"""Backward-compatible application entry point used by build tooling."""

from capture.prototype import main


if __name__ == "__main__":
    raise SystemExit(main())
