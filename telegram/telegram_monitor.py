#!/usr/bin/env python3
"""Telegram client-mention and potential-exposure monitor.

Scans public channels/groups discovered through Telegram chat search, explicitly
configured channels, and channels/supergroups visible in the account's dialogs.
It does NOT perform global Telegram post search. Findings are heuristic and
must be reviewed by an analyst.
"""

import asyncio
import csv
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from telethon import TelegramClient, functions, types
from telethon.errors import FloodWaitError, RPCError


# ---------------------------------------------------------------------------
# Paths and credentials
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
load_dotenv(PROJECT_DIR / ".env")

API_ID_VALUE = os.getenv("TELEGRAM_API_ID")
API_HASH = os.getenv("TELEGRAM_API_HASH")

if not API_ID_VALUE or not API_HASH:
    raise SystemExit(
        f"Missing TELEGRAM_API_ID or TELEGRAM_API_HASH. Expected in: {PROJECT_DIR / '.env'}"
    )
try:
    API_ID = int(API_ID_VALUE)
except ValueError as exc:
    raise SystemExit("TELEGRAM_API_ID must be an integer.") from exc

CONFIG_FILE = BASE_DIR / "config.json"
SESSION_FILE = BASE_DIR / "telegram_threat_intel"
CLIENT_MENTIONS_CSV = BASE_DIR / "telegram_client_mentions.csv"
EXPOSURE_CSV = BASE_DIR / "telegram_potential_exposures.csv"
JSON_FILE = BASE_DIR / "telegram_findings.json"
CHANNELS_FILE = BASE_DIR / "discovered_channels.json"


# ---------------------------------------------------------------------------
# Default configuration. Edit config.json after the first run.
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "known_channels": [],
    "discovery_keywords": [
        "ransomware", "data breach", "data leak", "initial access broker",
        "stolen credentials", "corporate VPN access", "database leak",
        "malware analysis", "phishing campaign", "corporate data exposure",
        "employee credential leak", "enterprise ransomware",
        "Indian company data breach"
    ],
    "client_watchlist": [
        {
            "name": "Infosys",
            "keywords": [
                "Infosys", "Infosys Limited", "Infosys Ltd",
                "Infosys Technologies", "Infosys BPM", "Infosys Consulting",
                "Infosys McCamish", "Infosys Cobalt", "Infosys Topaz",
                "EdgeVerve Systems", "Finacle", "infosys.com",
                "infosysbpm.com", "edgeverve.com", "finacle.com"
            ]
        }
    ],
    "messages_per_channel": 500,
    "max_discovered_channels_per_keyword": 20,
    "scan_existing_dialogs": True,
    "store_message_text": True,
    "store_source_message_link": True,
    "scan_delay_seconds": 0.5
}

# These are high-signal phrases, not a complete dictionary of breach language.
EXPOSURE_TERMS = [
    "data stolen", "database leaked", "database for sale", "data dump for sale",
    "customer records leaked", "employee records leaked",
    "employee credentials leaked", "credentials for sale", "vpn access for sale",
    "initial access for sale", "corporate access for sale", "source code leaked",
    "internal documents leaked", "confidential documents leaked",
    "exfiltrated company data", "exfiltrated customer data",
    "ransomware attack on", "ransomware victim", "extortion claim against",
    "breach notification for", "unauthorized access to company",
    "unauthorized access to corporate", "stolen customer database",
    "leaked customer database", "leaked employee database", "company data dump",
    "company database dump", "access to the network for sale",
    "company database for sale", "customer database for sale",
    "employee data for sale", "corporate vpn credentials", "network access for sale",
    "leaked source code", "stolen credentials", "compromised credentials",
    "data breach", "security breach", "ransomware group claims"
]

# Redact likely personal/secret values before saving message text.
SENSITIVE_PATTERNS = [
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[REDACTED_EMAIL]"),
    (re.compile(
        r"(?i)\b(password|passwd|pwd|token|api[_-]?key|client[_-]?secret|"
        r"access[_-]?key|secret|authorization)\b(\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ), r"\1\2[REDACTED_SECRET]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)"), "[REDACTED_PHONE]"),
    (re.compile(r"\b[a-fA-F0-9]{64,}\b"), "[REDACTED_LONG_HEX]"),
]
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)


# ---------------------------------------------------------------------------
# Configuration and text helpers
# ---------------------------------------------------------------------------
def load_config():
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        raise SystemExit(
            f"Created {CONFIG_FILE}. Review client_watchlist and known_channels, "
            "then run the script again."
        )

    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    for key, value in DEFAULT_CONFIG.items():
        config.setdefault(key, value)
    return config


def normalize_text(value):
    return re.sub(r"\s+", " ", value or "").strip()


def searchable_text(value):
    # Remove URLs so a company name in a URL alone does not create a match.
    return normalize_text(URL_PATTERN.sub(" ", value or ""))


def redact_sensitive_text(value):
    safe = value or ""
    for pattern, replacement in SENSITIVE_PATTERNS:
        safe = pattern.sub(replacement, safe)
    safe = URL_PATTERN.sub("[URL_REDACTED]", safe)
    return normalize_text(safe)[:1500]


def phrase_matches(text, phrases):
    text = (text or "").casefold()
    matches = []
    for phrase in phrases:
        phrase = normalize_text(str(phrase)).casefold()
        if not phrase:
            continue
        # Avoid matching a phrase as a substring of a larger word.
        pattern = r"(?<!\w)" + re.escape(phrase) + r"(?!\w)"
        if re.search(pattern, text):
            matches.append(phrase)
    return sorted(set(matches))


def get_client_matches(text, watchlist):
    results = []
    for item in watchlist:
        name = item.get("name", "Unnamed Client")
        matches = phrase_matches(text, item.get("keywords", []))
        if matches:
            results.append({"client_name": name, "matched_keywords": matches})
    return results


def get_exposure_matches(text):
    return phrase_matches(text, EXPOSURE_TERMS)


def get_message_text(message):
    return normalize_text(getattr(message, "message", None) or getattr(message, "text", None) or "")


def get_entity_title(entity):
    return (getattr(entity, "title", None) or getattr(entity, "first_name", None)
            or getattr(entity, "username", None) or str(getattr(entity, "id", "unknown")))


def get_entity_username(entity):
    username = getattr(entity, "username", None)
    return f"@{username}" if username else ""


def is_candidate_channel(entity):
    return isinstance(entity, types.Channel)


def make_finding(entity, message, client_matches, exposure_matches, config):
    username = getattr(entity, "username", None)
    message_id = getattr(message, "id", "")
    date_value = getattr(message, "date", None)
    if date_value:
        if date_value.tzinfo is None:
            date_value = date_value.replace(tzinfo=timezone.utc)
        date_value = date_value.astimezone(timezone.utc).isoformat()
    else:
        date_value = ""

    message_link = ""
    if config.get("store_source_message_link", True) and username and message_id:
        message_link = f"https://t.me/{username}/{message_id}"

    original = get_message_text(message)
    return {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "channel_title": get_entity_title(entity),
        "channel_username": get_entity_username(entity),
        "channel_id": str(getattr(entity, "id", "")),
        "message_id": message_id,
        "message_date_utc": date_value,
        "message_link": message_link,
        "client_related": bool(client_matches),
        "matched_clients": client_matches,
        "exposure_indicators": exposure_matches,
        "review_status": "UNVERIFIED - ANALYST REVIEW REQUIRED",
        "message_text_redacted": redact_sensitive_text(original) if config.get("store_message_text", True) else ""
    }


# ---------------------------------------------------------------------------
# Telegram discovery and scan
# ---------------------------------------------------------------------------
async def discover_channels(client, search_terms, max_per_keyword):
    discovered = {}
    for keyword in search_terms:
        print(f"[DISCOVERY] Searching chats for: {keyword}")
        try:
            result = await client(functions.contacts.SearchRequest(q=keyword, limit=100))
            added = 0
            for entity in result.chats:
                if not is_candidate_channel(entity):
                    continue
                username = getattr(entity, "username", None)
                if not username:
                    continue
                entity_id = str(entity.id)
                if entity_id not in discovered:
                    discovered[entity_id] = {
                        "id": entity_id,
                        "title": get_entity_title(entity),
                        "username": username,
                        "discovered_by": [keyword]
                    }
                    added += 1
                elif keyword not in discovered[entity_id]["discovered_by"]:
                    discovered[entity_id]["discovered_by"].append(keyword)
                if added >= max_per_keyword:
                    break
            print(f"[DISCOVERY] {keyword}: {added} new candidate(s)")
        except FloodWaitError as exc:
            print(f"[WAIT] Telegram rate limit: sleeping {exc.seconds} seconds")
            await asyncio.sleep(exc.seconds)
        except RPCError as exc:
            print(f"[WARNING] Chat search failed for '{keyword}': {exc}")
        except Exception as exc:
            print(f"[WARNING] Unexpected discovery error for '{keyword}': {exc}")
    return discovered


async def build_scan_list(client, config, discovery_terms):
    scan_entities = {}
    discovered = await discover_channels(
        client, discovery_terms,
        max(1, int(config.get("max_discovered_channels_per_keyword", 20)))
    )

    for channel in discovered.values():
        try:
            entity = await client.get_entity(channel["username"])
            if is_candidate_channel(entity):
                scan_entities[str(entity.id)] = entity
        except Exception as exc:
            print(f"[WARNING] Cannot resolve @{channel['username']}: {exc}")

    for channel_ref in config.get("known_channels", []):
        try:
            entity = await client.get_entity(channel_ref)
            if is_candidate_channel(entity):
                scan_entities[str(entity.id)] = entity
                print(f"[KNOWN] Added {get_entity_title(entity)}")
            else:
                print(f"[SKIP] Not a channel/supergroup: {channel_ref}")
        except Exception as exc:
            print(f"[WARNING] Cannot open '{channel_ref}': {exc}")

    if config.get("scan_existing_dialogs", True):
        print("[DIALOGS] Checking channels/supergroups visible in your Telegram dialogs...")
        try:
            async for dialog in client.iter_dialogs():
                entity = dialog.entity
                if is_candidate_channel(entity):
                    scan_entities[str(entity.id)] = entity
        except Exception as exc:
            print(f"[WARNING] Could not list dialogs: {exc}")

    CHANNELS_FILE.write_text(json.dumps(list(discovered.values()), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[CHANNELS] Discovered: {len(discovered)} | Queued for scanning: {len(scan_entities)}")
    return list(scan_entities.values())


async def scan_channel(client, entity, config, watchlist, counters):
    title = get_entity_title(entity)
    username = get_entity_username(entity)
    limit = max(1, int(config.get("messages_per_channel", 500)))
    delay = max(0.0, float(config.get("scan_delay_seconds", 0.5)))
    mention_findings = []
    exposure_findings = []
    counters["channels_started"] += 1
    print(f"[SCAN] {title} {username} | last {limit} messages")

    try:
        async for message in client.iter_messages(entity, limit=limit):
            counters["messages_scanned"] += 1
            original_text = get_message_text(message)
            if not original_text:
                continue

            text_for_matching = searchable_text(original_text)
            client_matches = get_client_matches(text_for_matching, watchlist)
            if not client_matches:
                continue

            counters["client_mentions"] += 1
            exposure_matches = get_exposure_matches(text_for_matching)
            finding = make_finding(entity, message, client_matches, exposure_matches, config)
            mention_findings.append(finding)

            if exposure_matches:
                counters["potential_exposures"] += 1
                exposure_findings.append(finding)

            if delay:
                await asyncio.sleep(delay)

    except FloodWaitError as exc:
        print(f"[WAIT] Telegram requested {exc.seconds} seconds while scanning {title}")
        await asyncio.sleep(exc.seconds)
    except RPCError as exc:
        print(f"[WARNING] Telegram error for {title}: {exc}")
    except Exception as exc:
        print(f"[WARNING] Could not scan {title}: {exc}")

    counters["channels_completed"] += 1
    print(f"[SCAN] {title}: {len(mention_findings)} client mention(s), {len(exposure_findings)} potential exposure(s)")
    return mention_findings, exposure_findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
CSV_FIELDS = [
    "collected_at_utc", "channel_title", "channel_username", "channel_id",
    "message_id", "message_date_utc", "message_link", "client_related",
    "matched_clients", "exposure_indicators", "review_status", "message_text_redacted"
]


def deduplicate(findings):
    unique = {}
    for item in findings:
        key = (item.get("channel_id"), str(item.get("message_id")))
        unique[key] = item
    return list(unique.values())


def write_csv(path, findings):
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            row = finding.copy()
            row["matched_clients"] = json.dumps(row.get("matched_clients", []), ensure_ascii=False)
            row["exposure_indicators"] = ", ".join(row.get("exposure_indicators", []))
            writer.writerow(row)


def save_reports(client_mentions, potential_exposures):
    client_mentions = deduplicate(client_mentions)
    potential_exposures = deduplicate(potential_exposures)
    write_csv(CLIENT_MENTIONS_CSV, client_mentions)
    write_csv(EXPOSURE_CSV, potential_exposures)
    JSON_FILE.write_text(
        json.dumps({
            "client_mentions": client_mentions,
            "potential_exposures": potential_exposures
        }, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"[REPORT] Client mentions CSV: {CLIENT_MENTIONS_CSV}")
    print(f"[REPORT] Potential exposures CSV: {EXPOSURE_CSV}")
    print(f"[REPORT] JSON: {JSON_FILE}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    config = load_config()
    watchlist = config.get("client_watchlist", [])
    if not watchlist:
        raise SystemExit("client_watchlist is empty in config.json. Add at least one client.")

    discovery_terms = list(dict.fromkeys(
        list(config.get("discovery_keywords", [])) +
        [keyword for item in watchlist for keyword in item.get("keywords", [])]
    ))

    print("========== TELEGRAM THREAT MONITOR ==========")
    print(f"Clients configured: {len(watchlist)}")
    print(f"Discovery terms: {len(discovery_terms)}")
    print(f"Messages per channel: {config.get('messages_per_channel', 500)}")
    print("Connecting to Telegram...")

    all_mentions = []
    all_exposures = []
    counters = {
        "channels_started": 0,
        "channels_completed": 0,
        "messages_scanned": 0,
        "client_mentions": 0,
        "potential_exposures": 0
    }

    async with TelegramClient(str(SESSION_FILE), API_ID, API_HASH) as client:
        entities = await build_scan_list(client, config, discovery_terms)
        for entity in entities:
            mentions, exposures = await scan_channel(client, entity, config, watchlist, counters)
            all_mentions.extend(mentions)
            all_exposures.extend(exposures)

    all_mentions = deduplicate(all_mentions)
    all_exposures = deduplicate(all_exposures)
    save_reports(all_mentions, all_exposures)

    print("\n========== SUMMARY ==========")
    print(f"Channels queued: {len(entities)}")
    print(f"Channels completed: {counters['channels_completed']}")
    print(f"Messages scanned: {counters['messages_scanned']}")
    print(f"Client mentions: {len(all_mentions)}")
    print(f"Potential exposures: {len(all_exposures)}")
    print("All findings are unverified and require analyst review.")
    print("Message text is redacted before being written to reports.")
    print("Note: discovery is chat/channel discovery, not global Telegram post search.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user.")
