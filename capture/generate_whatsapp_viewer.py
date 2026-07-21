#!/usr/bin/env python3
"""
Generate interactive HTML WhatsApp Chat Viewer from existing extracted JSON dumps.
Usage:
  python capture/generate_whatsapp_viewer.py --input ./evidence/CASE-.../parsed/whatsapp_companion/raw/whatsapp_companion_raw_*.json
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path when script is executed directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from capture.components.whatsapp_companion import WhatsAppCompanionExtractor
except ImportError:
    from components.whatsapp_companion import WhatsAppCompanionExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)-8s │ %(message)s")
log = logging.getLogger("ViewerGen")

def main():
    parser = argparse.ArgumentParser(description="WhatsApp HTML Chat Viewer Generator")
    parser.add_argument("--input", "-i", required=True, help="Path to whatsapp_companion_raw_*.json dump")
    parser.add_argument("--output", "-o", help="Output path for whatsapp_chat_viewer.html")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        log.error(f"Input file not found: {input_path}")
        return 1

    output_path = Path(args.output).resolve() if args.output else input_path.parent.parent / "whatsapp_chat_viewer.html"

    log.info(f"Loading raw JSON data from: {input_path}")
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    extractor = WhatsAppCompanionExtractor(output_dir=output_path.parent)
    extractor._generate_html_viewer(data, output_path)
    log.info(f"✅ Interactive HTML Chat Viewer generated successfully at:")
    log.info(f"   {output_path}")
    return 0

if __name__ == "__main__":
    main()
