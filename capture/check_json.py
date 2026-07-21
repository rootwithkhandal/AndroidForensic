import json
from pathlib import Path

raw_path = Path("evidence/CASE-20260721-124005/parsed/whatsapp_companion/raw/whatsapp_companion_raw_20260721_124048.json")
data = json.loads(raw_path.read_text("utf-8"))

print("--- Contacts that have any name/title ---")
named_contacts = []
for c in data.get("contact", []):
    if not isinstance(c, dict): continue
    # Check all possible string fields
    possible_names = [v for k, v in c.items() if isinstance(v, str) and k not in ("id", "userid", "type", "sectionHeader") and not v.endswith("@lid") and not v.endswith("@c.us") and not v.endswith("@g.us")]
    if possible_names:
        named_contacts.append((c, possible_names))

print(f"Total contacts with string properties: {len(named_contacts)}")
for c, names in named_contacts[:10]:
    jid = c.get("id")
    if isinstance(jid, dict): jid = jid.get("_serialized")
    print(f"JID: {jid} | KEYS: {list(c.keys())}")
    print("   -> String values:", {k: c[k] for k in c if isinstance(c[k], str) and c[k] in names})

print("\n--- Checking Chat objects for names ---")
for ch in data.get("chat", [])[:5]:
    cid = ch.get("id")
    if isinstance(cid, dict): cid = cid.get("_serialized")
    print(f"Chat JID: {cid} | Name: {ch.get('name')} | formattedTitle: {ch.get('formattedTitle')} | contactName: {ch.get('contact', {}).get('name') if isinstance(ch.get('contact'), dict) else None}")
