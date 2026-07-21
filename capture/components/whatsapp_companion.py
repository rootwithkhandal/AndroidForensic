#!/usr/bin/env python3
"""
WhatsApp Companion / Web Sync Forensic Extractor
==================================================
Extracts historical WhatsApp chat messages, contacts, and group metadata
by linking as a companion device via WhatsApp Web.

How it works:
  1. Launches a controlled Chromium browser pointing to https://web.whatsapp.com
  2. The investigator scans the QR code using the target unlocked phone
     (WhatsApp -> Linked Devices -> Link a Device).
  3. WhatsApp servers synchronize up to 1-2 years of encrypted historical chats
     over the Signal/Noise protocol directly into the browser's IndexedDB.
  4. This script extracts the entire `model-storage` IndexedDB (chats, messages,
     contacts, and media metadata).
  5. Converts the extracted data into a clean, query-ready SQLite database
     (`msgstore.db`) and raw JSON dumps, fully hashed for chain of custody.

Usage:
  python -m capture.components.whatsapp_companion --output ./evidence/whatsapp_companion
  python capture/components/whatsapp_companion.py --output ./evidence/whatsapp_companion
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("WhatsAppCompanion")


class WhatsAppCompanionExtractor:
    """Automates WhatsApp Web companion linking and IndexedDB extraction."""

    def __init__(self, output_dir: Path, timeout_seconds: int = 300):
        self.output_dir = output_dir
        self.raw_dir = output_dir / "raw"
        self.parsed_dir = output_dir / "parsed"
        self.timeout_seconds = timeout_seconds
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.parsed_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> Path | None:
        """Execute the companion acquisition flow."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            log.error("Playwright is not installed. Please run:")
            log.error("  pip install playwright")
            log.error("  playwright install chromium")
            return None

        log.info("═" * 60)
        log.info(" 🟢 Starting WhatsApp Companion / Web Sync Acquisition")
        log.info("═" * 60)
        log.info("Launching browser window...")

        with sync_playwright() as p:
            # Launch windowed Chromium so the investigator can easily scan the QR code
            browser = p.chromium.launch(
                headless=False,
                args=[
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()

            log.info("Navigating to https://web.whatsapp.com ...")
            page.goto("https://web.whatsapp.com")

            log.info("═" * 60)
            log.info(" 📲 ACTION REQUIRED BY INVESTIGATOR:")
            log.info("  1. Unlock the target Android device.")
            log.info("  2. Open WhatsApp -> Three dots (⋮) -> Linked Devices -> Link a Device.")
            log.info("  3. Scan the QR code shown in the browser window.")
            log.info("═" * 60)

            # Wait for login (chat list side pane or search bar appearing)
            try:
                page.wait_for_selector(
                    "#pane-side, [data-testid='chat-list'], [data-testid='search']",
                    timeout=self.timeout_seconds * 1000,
                )
                log.info("✅ QR Code scanned successfully! Session authenticated.")
            except Exception as e:
                log.error(f"Timed out waiting for QR scan / login ({self.timeout_seconds}s): {e}")
                browser.close()
                return None

            # Wait for historical sync to complete / settle
            log.info("⏳ Waiting for WhatsApp servers to synchronize historical messages...")
            # Monitor if "Syncing older messages" banner is active
            sync_start = time.time()
            while time.time() - sync_start < 60:
                try:
                    sync_text = page.locator("text=/Syncing older messages|Organizing messages/i").count()
                    if sync_text > 0:
                        log.info("   ... historical sync in progress, holding...")
                        time.sleep(5)
                    else:
                        break
                except Exception:
                    break
                time.sleep(2)

            log.info("Allowing 10 additional seconds for IndexedDB transactions to commit...")
            time.sleep(10)

            # Extract IndexedDB model-storage via JavaScript execution inside the browser
            log.info("📦 Extracting IndexedDB ('model-storage') tables...")
            db_data = self._extract_indexeddb(page)

            if not db_data or not db_data.get("chat"):
                log.warning("Extracted database is empty. Attempting fallback extraction...")
                time.sleep(15)
                db_data = self._extract_indexeddb(page)

            log.info("Closing browser session...")
            browser.close()

        if not db_data:
            log.error("Failed to extract data from WhatsApp Web IndexedDB.")
            return None

        # Save raw JSON dumps + compute hashes
        raw_json_path = self.raw_dir / f"whatsapp_companion_raw_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
        with open(raw_json_path, "w", encoding="utf-8") as f:
            json.dump(db_data, f, indent=2, ensure_ascii=False)
        sha256, md5 = self._hash_file(raw_json_path)
        log.info(f"Raw JSON dump saved: {raw_json_path}")
        log.info(f"  SHA-256: {sha256}")
        log.info(f"  MD5:     {md5}")

        # Convert to forensic SQLite msgstore.db
        sqlite_path = self.parsed_dir / "msgstore.db"
        self._convert_to_sqlite(db_data, sqlite_path)
        sqlite_sha, sqlite_md5 = self._hash_file(sqlite_path)
        log.info(f"✅ Clean SQLite database created: {sqlite_path}")
        log.info(f"  SHA-256: {sqlite_sha}")
        log.info(f"  MD5:     {sqlite_md5}")

        # Generate interactive HTML Chat Viewer
        html_viewer_path = self.parsed_dir / "whatsapp_chat_viewer.html"
        self._generate_html_viewer(db_data, html_viewer_path)
        log.info(f"🌐 Interactive HTML Chat Viewer generated: {html_viewer_path}")

        # Summary report
        chat_count = len(db_data.get("chat", []))
        msg_count = len(db_data.get("message", []))
        contact_count = len(db_data.get("contact", []))
        log.info("═" * 60)
        log.info(" 📊 EXTRACTION SUMMARY")
        log.info("═" * 60)
        log.info(f"  Conversations (Chats): {chat_count}")
        log.info(f"  Messages Acquired:     {msg_count}")
        log.info(f"  Contacts & Profiles:   {contact_count}")
        log.info(f"  Output SQLite DB:      {sqlite_path}")
        log.info(f"  Interactive HTML:      {html_viewer_path}")
        log.info("═" * 60)

        return sqlite_path

    def _extract_indexeddb(self, page: Any) -> dict[str, list]:
        """Runs asynchronous JS inside the browser to dump all IndexedDB records."""
        js_code = """
        async () => {
            return new Promise((resolve, reject) => {
                const request = indexedDB.open('model-storage');
                request.onerror = (e) => reject('Failed to open model-storage: ' + e.target.error);
                request.onsuccess = (e) => {
                    const db = e.target.result;
                    const stores = ['chat', 'message', 'contact'];
                    const result = {};
                    let completed = 0;

                    stores.forEach((storeName) => {
                        if (!db.objectStoreNames.contains(storeName)) {
                            result[storeName] = [];
                            completed++;
                            if (completed === stores.length) resolve(result);
                            return;
                        }
                        const tx = db.transaction(storeName, 'readonly');
                        const store = tx.objectStore(storeName);
                        const getAllReq = store.getAll();

                        getAllReq.onsuccess = () => {
                            result[storeName] = getAllReq.result || [];
                            completed++;
                            if (completed === stores.length) resolve(result);
                        };
                        getAllReq.onerror = () => {
                            result[storeName] = [];
                            completed++;
                            if (completed === stores.length) resolve(result);
                        };
                    });
                };
            });
        }
        """
        try:
            return page.evaluate(js_code)
        except Exception as e:
            log.error(f"JavaScript evaluation error while dumping IndexedDB: {e}")
            return {}

    def _convert_to_sqlite(self, data: dict[str, list], db_path: Path) -> None:
        """Converts raw IndexedDB JSON objects into a standardized SQLite database."""
        if db_path.exists():
            db_path.unlink()

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Create contacts table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                jid TEXT PRIMARY KEY,
                name TEXT,
                pushname TEXT,
                verified_name TEXT,
                is_business INTEGER,
                raw_json TEXT
            )
        """)

        # Create chats table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id TEXT PRIMARY KEY,
                name TEXT,
                unread_count INTEGER,
                last_message_time INTEGER,
                is_group INTEGER,
                is_archived INTEGER,
                raw_json TEXT
            )
        """)

        # Create messages table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                chat_id TEXT,
                sender_id TEXT,
                from_me INTEGER,
                timestamp INTEGER,
                message_type TEXT,
                text_content TEXT,
                caption TEXT,
                media_url TEXT,
                media_mimetype TEXT,
                raw_json TEXT
            )
        """)

        # Insert contacts
        for c in data.get("contact", []):
            if not isinstance(c, dict):
                continue
            jid = c.get("id") or c.get("_id")
            if isinstance(jid, dict):
                jid = jid.get("_serialized") or str(jid)
            if not jid:
                continue
            cur.execute(
                "INSERT OR REPLACE INTO contacts VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(jid),
                    c.get("name") or c.get("formattedName", ""),
                    c.get("pushname", ""),
                    c.get("verifiedName", ""),
                    1 if c.get("isBusiness") else 0,
                    json.dumps(c, ensure_ascii=False),
                ),
            )

        # Insert chats
        for ch in data.get("chat", []):
            if not isinstance(ch, dict):
                continue
            cid = ch.get("id") or ch.get("_id")
            if isinstance(cid, dict):
                cid = cid.get("_serialized") or str(cid)
            if not cid:
                continue
            cur.execute(
                "INSERT OR REPLACE INTO chats VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(cid),
                    ch.get("name") or ch.get("formattedTitle", ""),
                    ch.get("unreadCount", 0),
                    ch.get("t", 0),
                    1 if ch.get("isGroup") else 0,
                    1 if ch.get("archive") else 0,
                    json.dumps(ch, ensure_ascii=False),
                ),
            )

        # Insert messages
        for m in data.get("message", []):
            if not isinstance(m, dict):
                continue
            mid_val = m.get("id") or m.get("_id")
            if isinstance(mid_val, dict):
                mid = mid_val.get("_serialized") or mid_val.get("id") or str(mid_val)
            else:
                mid = str(mid_val) if mid_val else ""
            if not mid:
                continue

            id_dict = mid_val if isinstance(mid_val, dict) else {}
            chat_id = m.get("chatId") or id_dict.get("remote")
            if isinstance(chat_id, dict):
                chat_id = chat_id.get("_serialized") or str(chat_id)

            sender_id = m.get("sender") or m.get("author") or chat_id
            if isinstance(sender_id, dict):
                sender_id = sender_id.get("_serialized") or str(sender_id)

            from_me = 1 if (id_dict.get("fromMe") or m.get("fromMe")) else 0
            timestamp = m.get("t", 0)
            msg_type = m.get("type", "chat")
            body = m.get("body") or m.get("text") or ""
            caption = m.get("caption", "")

            media_data = m.get("mediaData")
            media_data_dict = media_data if isinstance(media_data, dict) else {}
            media_url = media_data_dict.get("mediaStage", "") or m.get("directPath", "")
            mimetype = m.get("mimetype", "")

            cur.execute(
                "INSERT OR REPLACE INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(mid),
                    str(chat_id or ""),
                    str(sender_id or ""),
                    from_me,
                    int(timestamp) if isinstance(timestamp, (int, float)) else 0,
                    str(msg_type),
                    str(body),
                    str(caption),
                    str(media_url),
                    str(mimetype),
                    json.dumps(m, ensure_ascii=False),
                ),
            )

        conn.commit()
        conn.close()

    def _generate_html_viewer(self, data: dict[str, list], output_html: Path) -> None:
        """Generates a self-contained, interactive HTML Chat & Evidence Viewer."""
        # Build contact lookup map
        contact_map = {}
        for c in data.get("contact", []):
            if not isinstance(c, dict):
                continue
            jid = c.get("id") or c.get("_id")
            if isinstance(jid, dict):
                jid = jid.get("_serialized") or str(jid)
            if jid:
                jid_str = str(jid)
                name = (
                    c.get("name")
                    or c.get("shortName")
                    or c.get("pushname")
                    or c.get("verifiedName")
                    or c.get("displayNameLID")
                )
                if not name and c.get("phoneNumber"):
                    pn = c.get("phoneNumber")
                    name = pn if isinstance(pn, str) else str(pn)
                if not name:
                    name = jid_str.split("@")[0]

                contact_map[jid_str] = name
                contact_map[jid_str.split("@")[0]] = name

        # Process chats
        chats_clean = []
        for ch in data.get("chat", []):
            if not isinstance(ch, dict):
                continue
            cid = ch.get("id") or ch.get("_id")
            if isinstance(cid, dict):
                cid = cid.get("_serialized") or str(cid)
            if not cid:
                continue
            cid_str = str(cid)
            chat_name = ch.get("name") or ch.get("formattedTitle") or contact_map.get(cid_str) or contact_map.get(cid_str.split("@")[0]) or cid_str
            chats_clean.append({
                "id": cid_str,
                "name": chat_name,
                "unread": ch.get("unreadCount", 0),
                "timestamp": ch.get("t", 0),
                "is_group": 1 if (ch.get("isGroup") or "@g.us" in cid_str) else 0,
            })
        chats_clean.sort(key=lambda x: x["timestamp"], reverse=True)

        # Process messages
        messages_clean = []
        for m in data.get("message", []):
            if not isinstance(m, dict):
                continue
            mid_val = m.get("id") or m.get("_id")
            if isinstance(mid_val, dict):
                mid = mid_val.get("_serialized") or mid_val.get("id") or str(mid_val)
            else:
                mid = str(mid_val) if mid_val else ""
            if not mid:
                continue

            id_dict = mid_val if isinstance(mid_val, dict) else {}
            from_me = 1 if (id_dict.get("fromMe") or m.get("fromMe") or mid.startswith("true_")) else 0

            # Determine chat_id
            chat_id = m.get("chatId")
            if isinstance(chat_id, dict):
                chat_id = chat_id.get("_serialized") or str(chat_id)

            if not chat_id:
                if from_me:
                    to_val = m.get("to")
                    chat_id = to_val.get("_serialized") if isinstance(to_val, dict) else to_val
                else:
                    from_val = m.get("from")
                    chat_id = from_val.get("_serialized") if isinstance(from_val, dict) else from_val

            if not chat_id and "_" in mid:
                parts = mid.split("_")
                if len(parts) >= 2 and ("@g.us" in parts[1] or "@c.us" in parts[1] or "@lid" in parts[1]):
                    chat_id = parts[1]

            # Determine sender_id
            author_val = m.get("author")
            sender_id = author_val.get("_serialized") if isinstance(author_val, dict) else author_val
            if not sender_id:
                from_val = m.get("from")
                sender_id = from_val.get("_serialized") if isinstance(from_val, dict) else from_val
            if not sender_id:
                sender_id = chat_id

            timestamp = m.get("t", 0)
            msg_type = m.get("type", "chat")
            body = m.get("body") or m.get("text") or ""
            caption = m.get("caption", "")

            media_data = m.get("mediaData")
            media_data_dict = media_data if isinstance(media_data, dict) else {}
            media_url = media_data_dict.get("mediaStage", "") or m.get("directPath", "")
            mimetype = m.get("mimetype", "")

            if from_me:
                sender_name = "Me"
            else:
                sender_str = str(sender_id or "")
                sender_name = contact_map.get(sender_str) or contact_map.get(sender_str.split("@")[0]) or sender_str.split("@")[0]

            messages_clean.append({
                "id": str(mid),
                "chat_id": str(chat_id or ""),
                "sender_name": sender_name,
                "from_me": from_me,
                "timestamp": int(timestamp) if isinstance(timestamp, (int, float)) else 0,
                "type": str(msg_type),
                "body": str(body),
                "caption": str(caption),
                "media_url": str(media_url),
                "mimetype": str(mimetype),
            })
        messages_clean.sort(key=lambda x: x["timestamp"])

        embed_payload = json.dumps({
            "chats": chats_clean,
            "messages": messages_clean,
            "contacts": contact_map,
        }, ensure_ascii=False)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WhatsApp Forensic Chat Viewer – Android Forensic Framework</title>
    <style>
        :root {{
            --bg: #111b21;
            --sidebar-bg: #111b21;
            --header-bg: #202c33;
            --chat-bg: #0b141a;
            --bubble-in: #202c33;
            --bubble-out: #005c4b;
            --text: #e9edef;
            --text-dim: #8696a0;
            --accent: #00a884;
            --border: #222d34;
            --hover: #202c33;
            --active: #2a3942;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }}
        header {{ background: var(--header-bg); padding: 0.8rem 1.5rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); z-index: 10; }}
        .header-title {{ display: flex; align-items: center; gap: 0.8rem; font-size: 1.1rem; font-weight: 600; color: var(--accent); }}
        .header-stats {{ font-size: 0.85rem; color: var(--text-dim); display: flex; gap: 1.2rem; align-items: center; }}
        .view-toggle {{ background: var(--active); border: 1px solid var(--border); color: var(--text); padding: 0.4rem 0.8rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem; transition: background 0.2s; }}
        .view-toggle:hover {{ background: var(--accent); color: #fff; }}
        .app-container {{ display: flex; flex: 1; overflow: hidden; }}
        
        /* Sidebar */
        .sidebar {{ width: 360px; background: var(--sidebar-bg); border-right: 1px solid var(--border); display: flex; flex-direction: column; }}
        .search-bar {{ padding: 0.75rem; background: var(--sidebar-bg); border-bottom: 1px solid var(--border); }}
        .search-input {{ width: 100%; background: var(--header-bg); border: 1px solid var(--border); color: var(--text); padding: 0.5rem 0.8rem; border-radius: 8px; font-size: 0.9rem; outline: none; }}
        .search-input:focus {{ border-color: var(--accent); }}
        .chat-list {{ flex: 1; overflow-y: auto; }}
        .chat-item {{ display: flex; align-items: center; gap: 0.8rem; padding: 0.8rem 1rem; border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.15s; }}
        .chat-item:hover {{ background: var(--hover); }}
        .chat-item.active {{ background: var(--active); }}
        .chat-avatar {{ width: 44px; height: 44px; border-radius: 50%; background: var(--header-bg); display: flex; align-items: center; justify-content: center; font-size: 1.3rem; flex-shrink: 0; }}
        .chat-info {{ flex: 1; min-width: 0; }}
        .chat-name {{ font-weight: 600; font-size: 0.95rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .chat-meta {{ font-size: 0.78rem; color: var(--text-dim); display: flex; justify-content: space-between; margin-top: 0.2rem; }}
        .badge {{ background: var(--accent); color: #111; font-size: 0.75rem; font-weight: 700; padding: 0.1rem 0.4rem; border-radius: 10px; }}
        
        /* Main Chat Window */
        .chat-window {{ flex: 1; display: flex; flex-direction: column; background: var(--chat-bg); position: relative; }}
        .chat-header {{ background: var(--header-bg); padding: 0.8rem 1.5rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }}
        .chat-title {{ font-size: 1rem; font-weight: 600; }}
        .chat-subtitle {{ font-size: 0.8rem; color: var(--text-dim); margin-top: 0.1rem; }}
        .messages-area {{ flex: 1; overflow-y: auto; padding: 1.5rem 3rem; display: flex; flex-direction: column; gap: 0.6rem; }}
        
        /* Bubble UI */
        .msg-bubble {{ max-width: 65%; padding: 0.6rem 0.8rem; border-radius: 8px; position: relative; line-height: 1.4; word-wrap: break-word; font-size: 0.93rem; box-shadow: 0 1px 0.5px rgba(0,0,0,0.2); }}
        .msg-in {{ align-self: flex-start; background: var(--bubble-in); border-top-left-radius: 0; }}
        .msg-out {{ align-self: flex-end; background: var(--bubble-out); border-top-right-radius: 0; }}
        .msg-sender {{ font-size: 0.78rem; font-weight: 700; color: #53bdeb; margin-bottom: 0.2rem; }}
        .msg-time {{ font-size: 0.7rem; color: rgba(255,255,255,0.6); text-align: right; margin-top: 0.3rem; margin-left: 1rem; float: right; }}
        .msg-media {{ background: rgba(0,0,0,0.2); padding: 0.4rem 0.6rem; border-radius: 6px; font-size: 0.85rem; color: #ffbc00; margin-bottom: 0.4rem; display: flex; align-items: center; gap: 0.4rem; }}
        
        /* Table UI */
        .table-view {{ width: 100%; border-collapse: collapse; display: none; font-size: 0.85rem; }}
        .table-view th {{ background: var(--header-bg); color: var(--accent); text-align: left; padding: 0.6rem 0.8rem; position: sticky; top: 0; border-bottom: 1px solid var(--border); }}
        .table-view td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--border); }}
        .table-view tr:hover td {{ background: var(--hover); }}
        .dir-in {{ color: #53bdeb; font-weight: 600; }}
        .dir-out {{ color: var(--accent); font-weight: 600; }}
    </style>
</head>
<body>
    <header>
        <div class="header-title">
            <span>🟢 Android Forensic Framework – WhatsApp Companion Viewer</span>
        </div>
        <div class="header-stats">
            <span id="stat-chats">Chats: 0</span>
            <span id="stat-msgs">Messages: 0</span>
            <span id="stat-contacts">Contacts: 0</span>
            <button class="view-toggle" onclick="toggleViewMode()" id="viewModeBtn">📋 Table / Grid View</button>
        </div>
    </header>
    <div class="app-container">
        <div class="sidebar">
            <div class="search-bar">
                <input type="text" class="search-input" id="searchInput" placeholder="🔍 Search chats or messages..." oninput="filterChats()">
            </div>
            <div class="chat-list" id="chatList"></div>
        </div>
        <div class="chat-window">
            <div class="chat-header">
                <div>
                    <div class="chat-title" id="activeChatTitle">Select a conversation</div>
                    <div class="chat-subtitle" id="activeChatMeta">To view historical transcript & evidence</div>
                </div>
            </div>
            <div class="messages-area" id="messagesArea">
                <div style="text-align: center; color: var(--text-dim); margin-top: 4rem;">
                    👈 Select any conversation from the sidebar to inspect messages.
                </div>
            </div>
            <table class="table-view" id="tableView">
                <thead>
                    <tr>
                        <th>Timestamp (Local)</th>
                        <th>Direction</th>
                        <th>Sender</th>
                        <th>Type</th>
                        <th>Content / Caption</th>
                        <th>Media Details</th>
                    </tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>
    </div>

    <script>
        const WA_DATA = {embed_payload};
        let currentChatId = null;
        let isTableView = false;

        function init() {{
            document.getElementById('stat-chats').textContent = `Chats: ${{WA_DATA.chats.length}}`;
            document.getElementById('stat-msgs').textContent = `Messages: ${{WA_DATA.messages.length}}`;
            document.getElementById('stat-contacts').textContent = `Contacts: ${{Object.keys(WA_DATA.contacts).length}}`;
            renderChatList(WA_DATA.chats);
            if (WA_DATA.chats.length > 0) {{
                selectChat(WA_DATA.chats[0].id);
            }}
        }}

        function formatTimestamp(ts) {{
            if (!ts) return 'N/A';
            const date = new Date(ts * 1000);
            return date.toLocaleString();
        }}

        function formatTimeShort(ts) {{
            if (!ts) return '';
            const date = new Date(ts * 1000);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {{hour: '2-digit', minute:'2-digit'}});
        }}

        function renderChatList(chats) {{
            const container = document.getElementById('chatList');
            container.innerHTML = '';
            chats.forEach(ch => {{
                const item = document.createElement('div');
                item.className = `chat-item ${{ch.id === currentChatId ? 'active' : ''}}`;
                item.onclick = () => selectChat(ch.id);
                item.innerHTML = `
                    <div class="chat-avatar">${{ch.is_group ? '👥' : '👤'}}</div>
                    <div class="chat-info">
                        <div class="chat-name">${{ch.name}}</div>
                        <div class="chat-meta">
                            <span>${{formatTimeShort(ch.timestamp)}}</span>
                            ${{ch.unread ? `<span class="badge">${{ch.unread}}</span>` : ''}}
                        </div>
                    </div>
                `;
                container.appendChild(item);
            }});
        }}

        function filterChats() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            if (!query) {{
                renderChatList(WA_DATA.chats);
                return;
            }}
            // Filter chats where name matches OR message body in chat matches
            const matchingChatIds = new Set();
            WA_DATA.chats.forEach(ch => {{
                if (ch.name.toLowerCase().includes(query) || ch.id.toLowerCase().includes(query)) {{
                    matchingChatIds.add(ch.id);
                }}
            }});
            WA_DATA.messages.forEach(m => {{
                if (m.body.toLowerCase().includes(query) || m.caption.toLowerCase().includes(query)) {{
                    matchingChatIds.add(m.chat_id);
                }}
            }});
            const filtered = WA_DATA.chats.filter(ch => matchingChatIds.has(ch.id));
            renderChatList(filtered);
        }}

        function selectChat(chatId) {{
            currentChatId = chatId;
            document.querySelectorAll('.chat-item').forEach(el => el.classList.remove('active'));
            const chat = WA_DATA.chats.find(c => c.id === chatId);
            if (chat) {{
                document.getElementById('activeChatTitle').textContent = chat.name;
                document.getElementById('activeChatMeta').textContent = `ID: ${{chat.id}} | Last active: ${{formatTimestamp(chat.timestamp)}}`;
            }}

            const msgs = WA_DATA.messages.filter(m => m.chat_id === chatId);
            renderMessages(msgs, chat ? chat.is_group : false);
        }}

        function renderMessages(msgs, isGroup) {{
            const bubbleContainer = document.getElementById('messagesArea');
            const tableBody = document.getElementById('tableBody');
            bubbleContainer.innerHTML = '';
            tableBody.innerHTML = '';

            if (msgs.length === 0) {{
                bubbleContainer.innerHTML = `<div style="text-align: center; color: var(--text-dim); margin-top: 3rem;">No messages captured for this conversation.</div>`;
                return;
            }}

            msgs.forEach(m => {{
                // Bubble View
                const bubble = document.createElement('div');
                bubble.className = `msg-bubble ${{m.from_me ? 'msg-out' : 'msg-in'}}`;
                
                let html = '';
                if (!m.from_me && isGroup) {{
                    html += `<div class="msg-sender">${{m.sender_name}}</div>`;
                }}
                if (m.type !== 'chat' && m.type !== '') {{
                    html += `<div class="msg-media">📎 [${{m.type.toUpperCase()}}] ${{m.mimetype || ''}}</div>`;
                }}
                if (m.caption) {{
                    html += `<div style="font-weight:600; margin-bottom:0.2rem;">${{m.caption}}</div>`;
                }}
                html += `<div>${{m.body ? m.body.replace(/\\n/g, '<br>') : ''}}</div>`;
                html += `<div class="msg-time" title="${{formatTimestamp(m.timestamp)}}">${{formatTimeShort(m.timestamp)}}</div>`;
                bubble.innerHTML = html;
                bubbleContainer.appendChild(bubble);

                // Table View
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${{formatTimestamp(m.timestamp)}}</td>
                    <td class="${{m.from_me ? 'dir-out' : 'dir-in'}}">${{m.from_me ? 'Outgoing (Me)' : 'Incoming'}}</td>
                    <td>${{m.sender_name}}</td>
                    <td><span style="background:var(--active);padding:0.2rem 0.5rem;border-radius:4px;">${{m.type}}</span></td>
                    <td>${{m.body || m.caption || '<em>No text</em>'}}</td>
                    <td>${{m.media_url ? `Path/URL: ${{m.media_url}}<br>MIME: ${{m.mimetype}}` : 'N/A'}}</td>
                `;
                tableBody.appendChild(tr);
            }});

            bubbleContainer.scrollTop = bubbleContainer.scrollHeight;
        }}

        function toggleViewMode() {{
            isTableView = !isTableView;
            const bubbleContainer = document.getElementById('messagesArea');
            const tableView = document.getElementById('tableView');
            const btn = document.getElementById('viewModeBtn');
            if (isTableView) {{
                bubbleContainer.style.display = 'none';
                tableView.style.display = 'table';
                btn.textContent = '💬 Bubble UI View';
            }} else {{
                bubbleContainer.style.display = 'flex';
                tableView.style.display = 'none';
                btn.textContent = '📋 Table / Grid View';
            }}
        }}

        window.onload = init;
    </script>
</body>
</html>"""
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html_template)

    @staticmethod
    def _hash_file(filepath: Path) -> tuple[str, str]:
        """Compute SHA-256 and MD5 hashes of a file."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest(), md5.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WhatsApp Companion / Web Sync Forensic Extractor"
    )
    parser.add_argument(
        "--output", "-o",
        default="./evidence/whatsapp_companion",
        help="Output directory for extracted evidence (default: ./evidence/whatsapp_companion)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=300,
        help="Timeout in seconds waiting for QR code scan and sync (default: 300)"
    )
    args = parser.parse_args()

    extractor = WhatsAppCompanionExtractor(
        output_dir=Path(args.output).resolve(),
        timeout_seconds=args.timeout,
    )
    result = extractor.run()
    return 0 if result else 1


if __name__ == "__main__":
    sys.exit(main())
