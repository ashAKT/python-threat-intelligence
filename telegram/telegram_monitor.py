
import asyncio
import csv
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from telethon import TelegramClient, functions, types
from telethon.errors import FloodWaitError, RPCError


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

load_dotenv(PROJECT_DIR / ".env")

API_ID = os.getenv("TELEGRAM_API_ID")
API_HASH = os.getenv("TELEGRAM_API_HASH")

if not API_ID or not API_HASH:
    raise SystemExit(
        "Missing TELEGRAM_API_ID or TELEGRAM_API_HASH in project .env"
    )

try:
    API_ID = int(API_ID)
except ValueError:
    raise SystemExit("TELEGRAM_API_ID must be an integer.")

CONFIG_FILE = BASE_DIR / "config.json"
SESSION_FILE = BASE_DIR / "telegram_threat_intel"

CSV_FILE = BASE_DIR / "telegram_findings.csv"
JSON_FILE = BASE_DIR / "telegram_findings.json"
CHANNELS_FILE = BASE_DIR / "discovered_channels.json"


# =========================================================
# DEFAULT CONFIGURATION
# =========================================================

DEFAULT_CONFIG = {
    "known_channels": [],
    "discovery_keywords": [
        "ransomware",
        "data breach",
        "data leak",
        "initial access broker",
        "stolen credentials",
        "corporate VPN access",
        "database leak",
        "malware analysis",
        "phishing campaign",
        "corporate data exposure",
        "employee credential leak",
        "enterprise ransomware",
        "Indian company data breach"
    ],
    "client_watchlist": [
        {
            "name": "Infosys",
            "keywords": [
                "Infosys",
                "Infosys Limited",
                "Infosys Ltd",
                "Infosys Technologies",
                "Infosys BPM",
                "Infosys Consulting",
                "Infosys McCamish",
                "Infosys Cobalt",
                "Infosys Topaz",
                "EdgeVerve Systems",
                "Finacle",
                "infosys.com",
                "infosysbpm.com",
                "edgeverve.com",
                "finacle.com"
            ]
        }
    ],
    "messages_per_channel": 100,
    "max_discovered_channels_per_keyword": 20,
    "scan_existing_dialogs": True,
    "store_message_text": True,
    "store_source_message_link": True
}


# =========================================================
# HIGHER-CONFIDENCE EXPOSURE INDICATORS
#
# These are deliberately specific. Add phrases as needed.
# Detection is heuristic and will not catch every incident.
# =========================================================

EXPOSURE_TERMS = [
    "data stolen",
    "database leaked",
    "database for sale",
    "data dump for sale",
    "customer records leaked",
    "employee records leaked",
    "employee credentials leaked",
    "credentials for sale",
    "vpn access for sale",
    "initial access for sale",
    "corporate access for sale",
    "source code leaked",
    "internal documents leaked",
    "confidential documents leaked",
    "exfiltrated company data",
    "exfiltrated customer data",
    "ransomware attack on",
    "ransomware victim",
    "extortion claim against",
    "breach notification for",
    "unauthorized access to company",
    "unauthorized access to corporate",
    "stolen customer database",
    "leaked customer database",
    "leaked employee database",
    "company data dump",
    "company database dump",
    "access to the network for sale"
]


# =========================================================
# SENSITIVE-DATA REDACTION
#
# Never treat redaction as a guarantee. Avoid storing raw
# message contents or indicators unless specifically needed.
# =========================================================

SENSITIVE_PATTERNS = [
    # Email addresses
    (
        re.compile(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            re.IGNORECASE
        ),
        "[REDACTED_EMAIL]"
    ),

    # Common credential assignments
    (
        re.compile(
            r"""(?i)\b(password|passwd|pwd|token|api[_-]?key|"""
            r"""client[_-]?secret|access[_-]?key|secret|"""
            r"""authorization)\b(\s*[:=]\s*)"""
            r"""(?:"[^"]*"|'[^']*'|[^\s,;]+)"""
        ),
        r"\1\2[REDACTED_SECRET]"
    ),

    # Bearer tokens
    (
        re.compile(
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"
        ),
        "Bearer [REDACTED_TOKEN]"
    ),

    # JWT-like strings
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
        "[REDACTED_TOKEN]"
    ),

    # Indian mobile numbers
    (
        re.compile(
            r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)"
        ),
        "[REDACTED_PHONE]"
    ),

    # Long hexadecimal values that may contain hashes or secrets
    (
        re.compile(r"\b[a-fA-F0-9]{64,}\b"),
        "[REDACTED_LONG_HEX]"
    )
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


# =========================================================
# GENERAL HELPERS
# =========================================================

def load_config():
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(
            json.dumps(DEFAULT_CONFIG, indent=2),
            encoding="utf-8"
        )
        raise SystemExit(
            f"Created {CONFIG_FILE}. Review the client watchlist, "
            "then run the script again."
        )

    with CONFIG_FILE.open("r", encoding="utf-8") as file:
        config = json.load(file)

    config.setdefault("known_channels", [])
    config.setdefault("discovery_keywords", [])
    config.setdefault("client_watchlist", [])
    config.setdefault("messages_per_channel", 100)
    config.setdefault("max_discovered_channels_per_keyword", 20)
    config.setdefault("scan_existing_dialogs", True)
    config.setdefault("store_message_text", True)
    config.setdefault("store_source_message_link", True)

    return config


def normalize_text(value):
    return re.sub(r"\s+", " ", value or "").strip()


def remove_urls(text):
    """Remove URLs before matching so link text does not trigger alerts."""
    return normalize_text(URL_PATTERN.sub(" ", text or ""))


def redact_sensitive_text(text):
    """Redact common sensitive patterns before report storage."""
    safe_text = text or ""

    for pattern, replacement in SENSITIVE_PATTERNS:
        safe_text = pattern.sub(replacement, safe_text)

    # Never place clickable external links in the stored message text.
    safe_text = URL_PATTERN.sub("[URL_REDACTED]", safe_text)

    return normalize_text(safe_text)


def keyword_matches(text, keywords):
    """Case-insensitive phrase matching with word boundaries."""
    text = (text or "").casefold()
    matched = []

    for keyword in keywords:
        keyword = normalize_text(str(keyword)).casefold()

        if not keyword:
            continue

        pattern = r"(?<!\w)" + re.escape(keyword) + r"(?!\w)"

        if re.search(pattern, text):
            matched.append(keyword)

    return sorted(set(matched))


def get_message_text(message):
    return normalize_text(
        getattr(message, "message", None)
        or getattr(message, "text", None)
        or ""
    )


def get_entity_title(entity):
    return (
        getattr(entity, "title", None)
        or getattr(entity, "first_name", None)
        or getattr(entity, "username", None)
        or str(getattr(entity, "id", "unknown"))
    )


def get_entity_username(entity):
    username = getattr(entity, "username", None)
    return f"@{username}" if username else ""


def is_candidate_channel(entity):
    # Telethon Channel includes broadcast channels and supergroups.
    return isinstance(entity, types.Channel)


def detect_exposure_context(text):
    """Return specific exposure phrases found in a message."""
    text = (text or "").casefold()
    matched = []

    for term in EXPOSURE_TERMS:
        pattern = r"(?<!\w)" + re.escape(term.casefold()) + r"(?!\w)"

        if re.search(pattern, text):
            matched.append(term)

    return sorted(set(matched))


def get_client_matches(text, watchlist):
    results = []

    for client_item in watchlist:
        name = client_item.get("name", "Unnamed Client")
        keywords = client_item.get("keywords", [])

        matches = keyword_matches(text, keywords)

        if matches:
            results.append({
                "client_name": name,
                "matched_keywords": matches
            })

    return results


# =========================================================
# TELEGRAM CHANNEL DISCOVERY
# =========================================================

async def discover_channels(client, search_terms, max_per_keyword):
    """
    Discover candidate public channels using Telegram chat search.

    This does not perform global post search and cannot discover
    every public Telegram channel.
    """
    discovered = {}

    for keyword in search_terms:
        print(f"[DISCOVERY] {keyword}")

        try:
            result = await client(
                functions.contacts.SearchRequest(
                    q=keyword,
                    limit=100
                )
            )

            added = 0

            for entity in result.chats:
                if not is_candidate_channel(entity):
                    continue

                username = getattr(entity, "username", None)

                # Focus on publicly addressable channels/groups.
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
            print(
                f"[WAIT] Telegram requested {exc.seconds} seconds "
                "before another request."
            )
            await asyncio.sleep(exc.seconds)

        except RPCError as exc:
            print(f"[WARNING] Search failed for '{keyword}': {exc}")

        except Exception as exc:
            print(f"[WARNING] Unexpected discovery error: {exc}")

    return discovered


async def build_scan_list(client, config, discovery_terms):
    scan_entities = {}

    discovered = await discover_channels(
        client,
        discovery_terms,
        int(config["max_discovered_channels_per_keyword"])
    )

    # Resolve discovered channel usernames.
    for channel in discovered.values():
        try:
            entity = await client.get_entity(channel["username"])
            scan_entities[str(entity.id)] = entity
        except Exception as exc:
            print(
                f"[WARNING] Cannot resolve @{channel['username']}: {exc}"
            )

    # Optional explicitly configured channels.
    for channel_ref in config.get("known_channels", []):
        try:
            entity = await client.get_entity(channel_ref)

            if is_candidate_channel(entity):
                scan_entities[str(entity.id)] = entity
                print(f"[KNOWN] {get_entity_title(entity)}")
            else:
                print(f"[SKIP] Not a channel: {channel_ref}")

        except Exception as exc:
            print(f"[WARNING] Cannot open '{channel_ref}': {exc}")

    # Include channels and supergroups visible in the user's dialogs.
    if config.get("scan_existing_dialogs", True):
        print("[DIALOGS] Checking accessible dialogs...")

        try:
            async for dialog in client.iter_dialogs():
                entity = dialog.entity

                if is_candidate_channel(entity):
                    scan_entities[str(entity.id)] = entity

        except Exception as exc:
            print(f"[WARNING] Could not list dialogs: {exc}")

    # Save channel discovery metadata, not message contents.
    CHANNELS_FILE.write_text(
        json.dumps(
            list(discovered.values()),
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print(f"[CHANNELS] Queued for scanning: {len(scan_entities)}")
    return list(scan_entities.values())


# =========================================================
# MESSAGE SCANNING
# =========================================================

async def scan_channel(client, entity, config, watchlist):
    title = get_entity_title(entity)
    username = get_entity_username(entity)

    print(f"[SCAN] {title} {username}")

    findings = []
    limit = max(1, int(config.get("messages_per_channel", 100)))

    try:
        async for message in client.iter_messages(entity, limit=limit):
            original_text = get_message_text(message)

            if not original_text:
                continue

            # Do not let URLs alone trigger detection.
            searchable_text = remove_urls(original_text)

            client_matches = get_client_matches(
                searchable_text,
                watchlist
            )

            # Ignore ordinary company mentions.
            if not client_matches:
                continue

            exposure_matches = detect_exposure_context(searchable_text)

            # Require both a client identifier and a specific exposure phrase.
            if not exposure_matches:
                continue

            message_date = getattr(message, "date", None)

            if message_date:
                message_date = message_date.astimezone(
                    timezone.utc
                ).isoformat()
            else:
                message_date = ""

            message_id = getattr(message, "id", "")
            message_link = ""

            if (
                config.get("store_source_message_link", True)
                and username
                and message_id
            ):
                message_link = (
                    f"https://t.me/{username.lstrip('@')}/{message_id}"
                )

            safe_message = ""

            if config.get("store_message_text", True):
                safe_message = redact_sensitive_text(original_text)[:1500]

            findings.append({
                "collected_at_utc": datetime.now(
                    timezone.utc
                ).isoformat(),
                "channel_title": title,
                "channel_username": username,
                "channel_id": str(entity.id),
                "message_id": message_id,
                "message_date_utc": message_date,
                "message_link": message_link,
                "client_related": True,
                "matched_clients": client_matches,
                "exposure_indicators": exposure_matches,
                "review_status": "UNVERIFIED - ANALYST REVIEW REQUIRED",
                "message_text_redacted": safe_message
            })

    except FloodWaitError as exc:
        print(
            f"[WAIT] Telegram requested {exc.seconds} seconds "
            f"while scanning {title}."
        )
        await asyncio.sleep(exc.seconds)

    except RPCError as exc:
        print(f"[WARNING] Telegram error for {title}: {exc}")

    except Exception as exc:
        print(f"[WARNING] Could not scan {title}: {exc}")

    print(f"[SCAN] {title}: {len(findings)} potential finding(s)")
    return findings


# =========================================================
# REPORT GENERATION
# =========================================================

def save_reports(findings):
    fieldnames = [
        "collected_at_utc",
        "channel_title",
        "channel_username",
        "channel_id",
        "message_id",
        "message_date_utc",
        "message_link",
        "client_related",
        "matched_clients",
        "exposure_indicators",
        "review_status",
        "message_text_redacted"
    ]

    with CSV_FILE.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            row = finding.copy()
            row["matched_clients"] = json.dumps(
                row["matched_clients"],
                ensure_ascii=False
            )
            row["exposure_indicators"] = ", ".join(
                row["exposure_indicators"]
            )
            writer.writerow(row)

    JSON_FILE.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"[REPORT] CSV:  {CSV_FILE}")
    print(f"[REPORT] JSON: {JSON_FILE}")


# =========================================================
# MAIN
# =========================================================

async def main():
    config = load_config()
    watchlist = config.get("client_watchlist", [])

    # Discover channels using general threat terms AND client keywords.
    discovery_terms = list(dict.fromkeys(
        [
            *config.get("discovery_keywords", []),
            *[
                keyword
                for client_item in watchlist
                for keyword in client_item.get("keywords", [])
            ]
        ]
    ))

    print("========== TELEGRAM THREAT MONITOR ==========")
    print(f"Clients configured: {len(watchlist)}")
    print(f"Discovery terms: {len(discovery_terms)}")
    print("Connecting to Telegram...")

    all_findings = []

    async with TelegramClient(
        str(SESSION_FILE),
        API_ID,
        API_HASH
    ) as client:
        entities = await build_scan_list(
            client,
            config,
            discovery_terms
        )

        for entity in entities:
            findings = await scan_channel(
                client,
                entity,
                config,
                watchlist
            )
            all_findings.extend(findings)

    # Deduplicate by channel ID and message ID.
    unique = {}

    for finding in all_findings:
        key = (
            finding["channel_id"],
            str(finding["message_id"])
        )
        unique[key] = finding

    findings = list(unique.values())
    save_reports(findings)

    print("\n========== SUMMARY ==========")
    print(f"Channels scanned: {len(entities)}")
    print(f"Potential findings: {len(findings)}")
    print("All findings are unverified and require analyst review.")
    print("Sensitive values may not all be detected by the redaction rules.")
    print("Reports contain no extracted IOC lists or unredacted message text.")


if __name__ == "__main__":
    asyncio.run(main())
