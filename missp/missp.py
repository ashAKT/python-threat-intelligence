#!/usr/bin/env python3
"""
SOC threat-feed collector: MISP catalogue + configurable JSON/text/CSV feeds.

Install:
    pip install requests

Default mode (MISP catalogue):
    python collect_threat_feeds_main_updated.py --limit 3

Custom feeds:
    1. Copy threat_feeds_config.example.json to threat_feeds_config.json
    2. Add provider-approved feed URLs and run:
       python collect_threat_feeds_main_updated.py --config threat_feeds_config.json

Other examples:
    python collect_threat_feeds_main_updated.py --config threat_feeds_config.json --name CIRCL
    python collect_threat_feeds_main_updated.py --config threat_feeds_config.json --no-cache
    python collect_threat_feeds_main_updated.py --include-disabled
    python collect_threat_feeds_main_updated.py --refresh-metadata

The collector does not bypass authentication, paywalls, rate limits, or anti-bot challenges.
Use only feed URLs and credentials you are authorized to access.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

METADATA_URL = (
    "https://raw.githubusercontent.com/MISP/MISP/2.5/"
    "app/files/feed-metadata/defaults.json"
)
BASE_DIR = Path(__file__).resolve().parent
METADATA_FILE = BASE_DIR / "misp_feed_metadata.json"
CONFIG_EXAMPLE = BASE_DIR / "threat_feeds_config.example.json"
RAW_DIR = BASE_DIR / "threat_feed_raw"
EVENT_DIR = BASE_DIR / "threat_feed_events"
OUTPUT_CSV = BASE_DIR / "threat_indicators.csv"
OUTPUT_JSON = BASE_DIR / "threat_indicators.json"
OUTPUT_ERRORS = BASE_DIR / "threat_feed_errors.csv"
FEED_CATALOG_CSV = BASE_DIR / "misp_available_feeds.csv"
OVERRIDES_FILE = BASE_DIR / "feed_url_overrides.json"

TIMEOUT = (10, 45)
USER_AGENT = "SOC-ThreatFeed-Collector/2.0"
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_DELAY = 1.0
MAX_RETRIES = 3
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

URL_RE = re.compile(r"""(?i)\bhttps?://[^\s"'<>]+""")
EMAIL_RE = re.compile(r"""(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b""")
HASH_RE = re.compile(r"""(?i)(?<![A-F0-9])(?:[A-F0-9]{32}|[A-F0-9]{40}|[A-F0-9]{64}|[A-F0-9]{128})(?![A-F0-9])""")
DOMAIN_RE = re.compile(
    r"""(?i)(?<![A-Z0-9_.-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![A-Z0-9_.-])"""
)
IP_CANDIDATE_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DEFANG_REPLACEMENTS = [
    (re.compile(r"(?i)\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}"), "."),
    (re.compile(r"(?i)hxxps"), "https"),
    (re.compile(r"(?i)hxxp"), "http"),
    (re.compile(r"(?i)\[\s*:\s*\]"), ":"),
]
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
INDICATOR_KEYS = {
    "indicator", "value", "ioc", "ip", "ip_address", "ipv4", "ipv6",
    "domain", "hostname", "host", "url", "uri", "md5", "sha1", "sha256",
    "sha512", "hash", "email", "email_address", "artifact", "observable",
}
CONTEXT_KEYS = {
    "description", "comment", "notes", "reference", "references", "name",
    "title", "message", "summary", "threat_actor", "campaign", "tag",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_duration(seconds: float) -> str:
    """Format elapsed time/ETA as HH:MM:SS."""
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def safe_filename(name: str, max_len: int = 90) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (cleaned or "feed")[:max_len]


def request_with_retry(
    session: requests.Session, url: str, max_bytes: int,
    retries: int = MAX_RETRIES, headers: dict[str, str] | None = None,
) -> tuple[requests.Response, bytes]:
    """GET with bounded retries and a hard response-size limit."""
    for attempt in range(retries + 1):
        response = None
        try:
            response = session.get(
                url, timeout=TIMEOUT, stream=True, allow_redirects=True,
                headers=headers or {},
            )
            if response.status_code in RETRYABLE_STATUS and attempt < retries:
                retry_after = response.headers.get("Retry-After")
                response.close()
                try:
                    wait = min(60.0, float(retry_after)) if retry_after else 2 ** attempt
                except ValueError:
                    wait = 2 ** attempt
                logging.warning("HTTP %s for %s; retrying in %.1fs",
                                response.status_code, url, wait)
                time.sleep(wait)
                continue
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"Response exceeded {max_bytes // (1024 * 1024)} MB size limit")
                chunks.append(chunk)
            body = b"".join(chunks)
            response.close()
            return response, body
        except requests.RequestException as exc:
            if response is not None:
                response.close()
            if attempt >= retries:
                raise
            wait = min(30, 2 ** attempt)
            logging.warning("Network error for %s: %s; retrying in %ss", url, exc, wait)
            time.sleep(wait)
        finally:
            if response is not None:
                response.close()
    raise RuntimeError("Request retry loop ended unexpectedly")


def load_metadata(session: requests.Session, refresh: bool = False) -> list[dict[str, Any]]:
    if METADATA_FILE.exists() and not refresh:
        data = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
    else:
        _, body = request_with_retry(session, METADATA_URL, DEFAULT_MAX_BYTES)
        if not body:
            raise ValueError("MISP metadata response was empty")
        try:
            data = json.loads(body.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("MISP metadata endpoint did not return valid JSON") from exc
        METADATA_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if isinstance(data, dict):
        data = data.get("feeds", data.get("Feed", []))
    if not isinstance(data, list):
        raise ValueError("Unexpected MISP metadata format; expected a JSON list.")
    return [entry for entry in data if isinstance(entry, dict)]


def get_feed(item: dict[str, Any]) -> dict[str, Any]:
    feed = item.get("Feed", item)
    return feed if isinstance(feed, dict) else {}


def write_feed_catalog(entries: list[dict[str, Any]]) -> int:
    """Save the complete discovered MISP feed catalogue before downloading feeds."""
    columns = [
        "name", "provider", "url", "source_format", "enabled",
        "input_source", "lookup_visible", "caching_enabled", "tags", "metadata_json",
    ]
    count = 0
    with FEED_CATALOG_CSV.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for entry in entries:
            feed = get_feed(entry)
            if not feed:
                continue
            tags = feed.get("Tag") or feed.get("tags") or []
            row = {
                "name": feed.get("name", ""),
                "provider": feed.get("provider", ""),
                "url": feed.get("url", ""),
                "source_format": feed.get("source_format", feed.get("format", "")),
                "enabled": is_enabled(feed),
                "input_source": feed.get("input_source", feed.get("input", "")),
                "lookup_visible": feed.get("lookup_visible", ""),
                "caching_enabled": feed.get("caching_enabled", feed.get("caching", "")),
                "tags": ";".join(str(t.get("name", t)) if isinstance(t, dict) else str(t) for t in tags) if isinstance(tags, list) else str(tags),
                "metadata_json": json.dumps(feed, ensure_ascii=False, sort_keys=True),
            }
            writer.writerow(row)
            count += 1
    logging.info("Saved %d catalogue entries to %s", count, FEED_CATALOG_CSV)
    return count


def is_enabled(feed: dict[str, Any]) -> bool:
    value = feed.get("enabled", False)
    return value is True or str(value).strip().lower() in {"1", "true", "yes"}


def load_overrides() -> dict[str, str]:
    if not OVERRIDES_FILE.exists():
        return {}
    data = json.loads(OVERRIDES_FILE.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{OVERRIDES_FILE.name} must contain a JSON object")
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def is_cloudflare_challenge(body: bytes, content_type: str) -> bool:
    if "html" not in (content_type or "").lower():
        return False
    text = body[:100_000].decode("utf-8", errors="ignore").lower()
    return (
        "just a moment..." in text
        or "/cdn-cgi/challenge-platform/" in text
        or "enable javascript and cookies to continue" in text
    )


def looks_like_html(body: bytes, content_type: str) -> bool:
    if "html" in (content_type or "").lower():
        return True
    sample = body[:500].lstrip().lower()
    return sample.startswith(b"<!doctype html") or sample.startswith(b"<html")


def clean_candidate(value: str) -> str:
    value = value.strip().strip(" \t\r\n\"'`(){}[]<>,;")
    for pattern, replacement in DEFANG_REPLACEMENTS:
        value = pattern.sub(replacement, value)
    return value.rstrip(".,;:!?)\"]}")


def valid_domain(value: str) -> bool:
    value = value.rstrip(".").lower()
    if len(value) > 253 or "." not in value:
        return False
    if value in {"example.com", "example.org", "example.net", "localhost"}:
        return False
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in value.split(".")
    )


def classify(value: str) -> tuple[str, str] | None:
    value = clean_candidate(value)
    if not value:
        return None
    if value.lower().startswith(("http://", "https://")):
        try:
            parsed = urlparse(value)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                host = parsed.hostname.strip("[]").lower()
                try:
                    ipaddress.ip_address(host)
                    return "url", value
                except ValueError:
                    if valid_domain(host):
                        return "url", value
        except ValueError:
            pass
    if EMAIL_RE.fullmatch(value):
        return "email", value.lower()
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_global:
            return ("ip" if ip.version == 4 else "ipv6"), str(ip)
        return None
    except ValueError:
        pass
    if HASH_RE.fullmatch(value):
        return HASH_TYPES[len(value)], value.lower()
    if valid_domain(value):
        return "domain", value.rstrip(".").lower()
    return None


def extract_from_text(text: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    normalized = text
    for pattern, replacement in DEFANG_REPLACEMENTS:
        normalized = pattern.sub(replacement, normalized)
    for pattern in (URL_RE, EMAIL_RE, HASH_RE, IP_CANDIDATE_RE, DOMAIN_RE):
        for match in pattern.findall(normalized):
            item = classify(match)
            if item:
                found.add(item)
    # Handle strings that are themselves a single indicator.
    item = classify(normalized.strip())
    if item:
        found.add(item)
    return found


def iter_json_values(obj: Any, key_path: str = ""):
    """Yield scalar JSON values with their field names and context path."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key).lower()
            path = f"{key_path}.{key_s}" if key_path else key_s
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                yield str(value), key_s, path
            else:
                yield from iter_json_values(value, path)
    elif isinstance(obj, list):
        for value in obj:
            yield from iter_json_values(value, key_path)
    elif isinstance(obj, str):
        yield obj, "", key_path


def extract_json_indicators(parsed: Any, field_map: dict[str, str] | None = None) -> set[tuple[str, str]]:
    """
    Extract from arbitrary JSON. field_map maps provider field names to canonical
    types (e.g. {"ipAddress": "ip", "fileHash": "sha256"}). Generic recursive
    scanning is also used so unknown schemas remain useful.
    """
    found: set[tuple[str, str]] = set()
    field_map = {str(k).lower(): str(v).lower() for k, v in (field_map or {}).items()}
    for value, key, _path in iter_json_values(parsed):
        value = value.strip()
        mapped_type = field_map.get(key)
        if mapped_type:
            cleaned = clean_candidate(value)
            if mapped_type in {"ip", "ipv4", "ipv6"}:
                try:
                    ip = ipaddress.ip_address(cleaned)
                    if ip.is_global:
                        found.add(("ipv6" if ip.version == 6 else "ip", str(ip)))
                except ValueError:
                    found.update(extract_from_text(value))
            elif mapped_type in {"md5", "sha1", "sha256", "sha512"}:
                if re.fullmatch(r"[A-Fa-f0-9]+", cleaned) and len(cleaned) == {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}[mapped_type]:
                    found.add((mapped_type, cleaned.lower()))
            elif mapped_type in {"domain", "hostname"}:
                if valid_domain(cleaned):
                    found.add(("domain", cleaned.lower().rstrip(".")))
            elif mapped_type in {"url", "uri"}:
                item = classify(cleaned)
                if item and item[0] == "url":
                    found.add(item)
            elif mapped_type in {"email", "email_address"}:
                if EMAIL_RE.fullmatch(cleaned):
                    found.add(("email", cleaned.lower()))
            else:
                found.update(extract_from_text(value))
        else:
            # Prefer likely IOC fields, but scan other values for IOCs embedded
            # in descriptions/references too. Preserve no arbitrary scalar as an IOC.
            found.update(extract_from_text(value))
    return found


def extract_indicators(body: bytes, content_type: str, source_format: str,
                       field_map: dict[str, str] | None = None) -> set[tuple[str, str]]:
    text = body.decode("utf-8-sig", errors="replace")
    if "json" in (content_type or "").lower() or "json" in (source_format or "").lower() or text.lstrip().startswith(("{", "[")):
        try:
            return extract_json_indicators(json.loads(text), field_map)
        except (json.JSONDecodeError, RecursionError):
            pass
    return extract_from_text(text)


def load_custom_config(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        if path.name == CONFIG_EXAMPLE.name:
            path.write_text(json.dumps({
                "feeds": [
                    {
                        "name": "CIRCL MISP OSINT",
                        "url": "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
                        "format": "misp_manifest",
                        "enabled": True
                    },
                    {
                        "name": "Example JSON IOC feed",
                        "url": "https://provider.example/threat-feed.json",
                        "format": "json",
                        "enabled": False,
                        "field_map": {"ipAddress": "ip", "fileHash": "sha256"}
                    }
                ]
            }, indent=2), encoding="utf-8")
            raise FileNotFoundError(
                f"Created example config at {path}. Edit it with real, authorized feed URLs, "
                "then rerun with --config {path.name}."
            )
        raise FileNotFoundError(f"Configuration file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("feeds", [])
    if not isinstance(data, list):
        raise ValueError("Custom config must be a JSON list or an object containing a 'feeds' list")
    result = []
    for item in data:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        if item.get("enabled", True) is False:
            continue
        if not str(item["url"]).startswith(("https://", "http://")):
            logging.warning("Skipping feed with non-HTTP URL: %s", item.get("name", "unnamed"))
            continue
        result.append(item)
    return result


def auth_headers(feed: dict[str, Any]) -> dict[str, str]:
    headers = {str(k): str(v) for k, v in (feed.get("headers") or {}).items()}
    # Optional bearer token sourced from an environment variable.
    env_name = feed.get("bearer_token_env")
    if env_name:
        token = os.getenv(str(env_name))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            logging.warning("Environment variable %s is not set for feed %s",
                            env_name, feed.get("name", "unnamed"))
    return headers


def make_row(indicator_type: str, value: str, feed: dict[str, Any],
             url: str, fetched_at: str, context: dict[str, str] | None = None) -> dict[str, str]:
    context = context or {}
    return {
        "indicator_type": indicator_type,
        "indicator": value,
        "feed_name": str(feed.get("name") or "Unnamed feed"),
        "provider": str(feed.get("provider") or ""),
        "feed_url": url,
        "source_format": str(feed.get("format") or feed.get("source_format") or ""),
        "retrieved_at_utc": fetched_at,
        "event_name": context.get("event_name", ""),
        "tags": context.get("tags", ""),
        "confidence": context.get("confidence", ""),
        "context": context.get("context", ""),
    }


def process_regular_feed(session: requests.Session, feed: dict[str, Any],
                         url: str, args: argparse.Namespace,
                         rows: dict[tuple[str, str, str, str], dict[str, str]],
                         errors: list[dict[str, str]]) -> None:
    name = str(feed.get("name") or "Unnamed feed")
    _, body = request_with_retry(
        session, url, max(1, args.max_mb) * 1024 * 1024,
        headers=auth_headers(feed),
    )
    # Retrieve response headers using a second small metadata result is avoided;
    # content sniffing and configured format are sufficient for parsing.
    text = body[:500].lstrip().lower()
    if is_cloudflare_challenge(body, ""):
        raise ValueError("blocked_by_cloudflare: JavaScript challenge page returned")
    if looks_like_html(body, ""):
        raise ValueError("html_response_not_feed: expected raw feed data, received HTML")
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]
    (RAW_DIR / f"{safe_filename(name)}_{digest}.dat").write_bytes(body)
    indicators = extract_indicators(
        body, "application/json" if text.startswith((b"{", b"[")) else "",
        str(feed.get("format") or feed.get("source_format") or ""),
        feed.get("field_map") if isinstance(feed.get("field_map"), dict) else None,
    )
    fetched_at = now_utc()
    for indicator_type, value in indicators:
        row = make_row(indicator_type, value, feed, url, fetched_at)
        key = (indicator_type, value, name, url)
        rows[key] = row
    logging.info("%s: downloaded %d bytes; extracted %d indicators",
                 name, len(body), len(indicators))


def process_vxvault_feed(session: requests.Session, feed: dict[str, Any],
                         url: str, args: argparse.Namespace,
                         rows: dict[tuple[str, str, str, str], dict[str, str]]) -> None:
    """Collect VXVault's URL list, whose endpoint may label the response as HTML."""
    name = str(feed.get("name") or "VXVault URL List")
    _, body = request_with_retry(
        session, url, max(1, args.max_mb) * 1024 * 1024,
        headers=auth_headers(feed),
    )
    if is_cloudflare_challenge(body, ""):
        raise ValueError("blocked_by_cloudflare: JavaScript challenge page returned")

    text = body.decode("utf-8-sig", errors="replace")
    candidates: set[str] = set()
    for line in text.splitlines():
        value = line.strip().strip('"\'')
        # VXVault's list is URL-per-line. Ignore HTML markup, page navigation,
        # and URLs embedded in markup rather than treating the whole page as a feed.
        if not value or value.startswith("#") or "<" in value or ">" in value:
            continue
        if not value.lower().startswith(("http://", "https://")):
            continue
        value = value.rstrip(".,;)")
        item = classify(value)
        if item and item[0] == "url":
            candidates.add(item[1])

    if not candidates:
        if looks_like_html(body, ""):
            raise ValueError("html_response_not_feed: VXVault returned HTML without URL-per-line indicators")
        raise ValueError("no_valid_urls: VXVault response contained no valid URL indicators")

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]
    (RAW_DIR / f"{safe_filename(name)}_{digest}.dat").write_bytes(body)
    fetched_at = now_utc()
    for value in sorted(candidates):
        row = make_row("url", value, feed, url, fetched_at,
                       {"context": "VXVault URL-list entry"})
        rows[("url", value, name, url)] = row
    logging.info("%s: downloaded %d bytes; extracted %d unique URL indicators",
                 name, len(body), len(candidates))


def process_misp_manifest(session: requests.Session, feed: dict[str, Any],
                          manifest_url: str, args: argparse.Namespace,
                          rows: dict[tuple[str, str, str, str], dict[str, str]]) -> None:
    name = str(feed.get("name") or "MISP JSON manifest")
    _, body = request_with_retry(session, manifest_url, min(args.max_mb, 20) * 1024 * 1024,
                                 headers=auth_headers(feed))
    if is_cloudflare_challenge(body, "") or looks_like_html(body, ""):
        raise ValueError("Manifest URL returned HTML/challenge, not JSON")
    manifest = json.loads(body.decode("utf-8-sig"))
    # Standard MISP manifest is commonly an object keyed by event UUID.
    if isinstance(manifest, dict):
        uuids = [str(k) for k in manifest.keys() if re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", str(k)
        )]
        # Some manifests wrap their event list in a named field.
        if not uuids:
            candidate = manifest.get("events") or manifest.get("data") or manifest.get("items")
            if isinstance(candidate, list):
                uuids = [str(x.get("uuid") or x.get("id")) for x in candidate if isinstance(x, dict) and (x.get("uuid") or x.get("id"))]
    elif isinstance(manifest, list):
        uuids = [str(x.get("uuid") or x.get("id")) for x in manifest if isinstance(x, dict) and (x.get("uuid") or x.get("id"))]
    else:
        uuids = []
    if not uuids:
        raise ValueError("No event UUIDs found in MISP manifest JSON")
    if args.limit > 0:
        uuids = uuids[:args.limit]
    EVENT_DIR.mkdir(parents=True, exist_ok=True)
    base_url = manifest_url.rsplit("/", 1)[0] + "/"
    field_map = feed.get("field_map") if isinstance(feed.get("field_map"), dict) else None
    total_indicators = 0
    progress_started = time.monotonic()
    logging.info("%s: %d event(s) queued; starting downloads/parsing", name, len(uuids))
    for i, event_uuid in enumerate(uuids, start=1):
        cache_path = EVENT_DIR / f"{safe_filename(event_uuid)}.json"
        event_started = time.monotonic()
        percent_before = ((i - 1) / len(uuids)) * 100
        elapsed_before = event_started - progress_started
        avg_before = elapsed_before / (i - 1) if i > 1 else 0
        eta_before = avg_before * (len(uuids) - (i - 1)) if i > 1 else 0
        logging.info(
            "%s progress: %d/%d (%.1f%%) | starting event %s | elapsed %s | ETA %s",
            name, i - 1, len(uuids), percent_before, event_uuid,
            format_duration(elapsed_before), format_duration(eta_before) if i > 1 else "calculating",
        )
        try:
            from_cache = cache_path.exists() and not args.no_cache
            if from_cache:
                event_body = cache_path.read_bytes()
            else:
                event_url = base_url + event_uuid + ".json"
                _, event_body = request_with_retry(
                    session, event_url, max(1, args.max_mb) * 1024 * 1024,
                    headers=auth_headers(feed),
                )
                if is_cloudflare_challenge(event_body, "") or looks_like_html(event_body, ""):
                    raise ValueError("event URL returned HTML/challenge, not JSON")
                json.loads(event_body.decode("utf-8-sig"))  # validate before caching
                cache_path.write_bytes(event_body)
            event = json.loads(event_body.decode("utf-8-sig"))
            event_indicator_count = 0
            if isinstance(event, dict) and isinstance(event.get("Event"), dict):
                event = event["Event"]
            if not isinstance(event, dict):
                continue
            event_info = str(event.get("info") or event.get("Info") or "")
            event_tags = event.get("Tag") or event.get("tags") or []
            tags = []
            if isinstance(event_tags, list):
                for tag in event_tags:
                    if isinstance(tag, dict):
                        tags.append(str(tag.get("name") or tag.get("Name") or ""))
                    elif isinstance(tag, str):
                        tags.append(tag)
            attributes = event.get("Attribute") or event.get("attributes") or []
            if isinstance(attributes, list):
                for attr in attributes:
                    if not isinstance(attr, dict):
                        continue
                    to_ids = attr.get("to_ids", attr.get("to-ids", True))
                    if not args.include_non_ids and str(to_ids).strip().lower() not in {"true", "1", "yes"}:
                        continue
                    attr_type = str(attr.get("type") or attr.get("category") or "").lower()
                    value = str(attr.get("value") or "").strip()
                    found = set()
                    if attr_type in {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "ip"}:
                        found.update(extract_from_text(value.split("|", 1)[0]))
                    elif attr_type in {"domain", "hostname", "domain|ip"}:
                        found.update(extract_from_text(value.split("|", 1)[0]))
                    elif attr_type in {"url", "uri"}:
                        found.update(extract_from_text(value))
                    elif attr_type in {"md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha1", "filename|sha256"}:
                        found.update(extract_from_text(value.split("|")[-1]))
                    else:
                        found.update(extract_from_text(value))
                    attr_tags = attr.get("Tag") or attr.get("tags") or []
                    all_tags = list(tags)
                    if isinstance(attr_tags, list):
                        all_tags.extend(str(t.get("name") or t.get("Name") or "") if isinstance(t, dict) else str(t) for t in attr_tags)
                    context = {
                        "event_name": event_info,
                        "tags": ";".join(sorted(set(t for t in all_tags if t))),
                        "context": str(attr.get("comment") or attr.get("Comment") or ""),
                    }
                    for indicator_type, indicator in found:
                        row = make_row(indicator_type, indicator, feed, base_url + event_uuid + ".json", now_utc(), context)
                        key = (indicator_type, indicator, name, context["event_name"])
                        rows[key] = row
                        total_indicators += 1
                        event_indicator_count += 1
            elapsed = time.monotonic() - progress_started
            completed_percent = (i / len(uuids)) * 100
            average = elapsed / i
            eta = average * (len(uuids) - i)
            logging.info(
                "%s progress: %d/%d (%.1f%%) | event %s: %d indicators | %s | event time %s | elapsed %s | ETA %s",
                name, i, len(uuids), completed_percent, event_uuid, event_indicator_count,
                "cache" if from_cache else "downloaded", format_duration(time.monotonic() - event_started),
                format_duration(elapsed), format_duration(eta),
            )
            if args.delay > 0 and i < len(uuids):
                time.sleep(args.delay)
        except (requests.RequestException, OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            logging.warning("%s event %s failed: %s", name, event_uuid, exc)
            # Event failures are added to shared errors in main by separate exception records if needed.
            raise
    logging.info("%s: processed %d event(s); extracted %d indicator records",
                 name, len(uuids), total_indicators)



class _DirectoryLinks(HTMLParser):
    """Collect hrefs from a provider's ordinary HTML directory listing."""
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


def process_rosti_feed(session: requests.Session, feed: dict[str, Any],
                       directory_url: str, args: argparse.Namespace,
                       rows: dict[tuple[str, str, str, str], dict[str, str]]) -> None:
    """Download MISP event JSON files from Rösti's directory index."""
    from urllib.parse import urljoin, urlparse

    name = str(feed.get("name") or "Rösti MISP Feed")
    _, index_body = request_with_retry(
        session, directory_url, max(1, args.max_mb) * 1024 * 1024,
        headers=auth_headers(feed),
    )
    if is_cloudflare_challenge(index_body, ""):
        raise ValueError("blocked_by_cloudflare: Rösti directory returned a challenge")
    if not looks_like_html(index_body, ""):
        raise ValueError("unexpected_response: Rösti root did not return an HTML directory listing")

    parser = _DirectoryLinks()
    parser.feed(index_body.decode("utf-8", errors="replace"))
    event_urls: list[str] = []
    for href in parser.links:
        candidate = urljoin(directory_url.rstrip("/") + "/", href)
        path = urlparse(candidate).path
        if (urlparse(candidate).netloc == urlparse(directory_url).netloc
                and path.lower().endswith(".json")
                and re.fullmatch(r"[0-9a-fA-F-]{36}\.json", path.rsplit("/", 1)[-1])):
            event_urls.append(candidate)
    event_urls = sorted(set(event_urls))
    if not event_urls:
        raise ValueError("no_event_json_files: Rösti directory listing contained no UUID JSON files")
    if args.limit > 0:
        event_urls = event_urls[:args.limit]

    EVENT_DIR.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    total = len(event_urls)
    total_indicators = 0
    logging.info("%s: %d event JSON file(s) queued", name, total)
    for i, event_url in enumerate(event_urls, start=1):
        event_id = urlparse(event_url).path.rsplit("/", 1)[-1].removesuffix(".json")
        cache_path = EVENT_DIR / f"rosti_{safe_filename(event_id)}.json"
        from_cache = cache_path.exists() and not args.no_cache
        try:
            if from_cache:
                event_body = cache_path.read_bytes()
            else:
                _, event_body = request_with_retry(
                    session, event_url, max(1, args.max_mb) * 1024 * 1024,
                    headers=auth_headers(feed),
                )
                if is_cloudflare_challenge(event_body, "") or looks_like_html(event_body, ""):
                    raise ValueError("event URL returned HTML/challenge, not JSON")
                json.loads(event_body.decode("utf-8-sig"))
                cache_path.write_bytes(event_body)
            parsed = json.loads(event_body.decode("utf-8-sig"))
            event = parsed.get("Event", parsed) if isinstance(parsed, dict) else {}
            if not isinstance(event, dict):
                continue
            event_info = str(event.get("info") or event.get("Info") or "")
            event_uuid = str(event.get("uuid") or event_id)
            event_tags = event.get("Tag") or event.get("tags") or []
            tags: list[str] = []
            if isinstance(event_tags, list):
                tags.extend(str(t.get("name") or t.get("Name") or "") if isinstance(t, dict) else str(t)
                            for t in event_tags)

            # MISP stores indicators in both Event.Attribute and Object[].Attribute.
            attributes: list[dict[str, Any]] = []
            direct = event.get("Attribute") or event.get("attributes") or []
            if isinstance(direct, list):
                attributes.extend(a for a in direct if isinstance(a, dict))
            objects = event.get("Object") or event.get("objects") or []
            if isinstance(objects, list):
                for obj in objects:
                    if isinstance(obj, dict):
                        obj_attrs = obj.get("Attribute") or obj.get("attributes") or []
                        if isinstance(obj_attrs, list):
                            attributes.extend(a for a in obj_attrs if isinstance(a, dict))

            count = 0
            for attr in attributes:
                to_ids = attr.get("to_ids", attr.get("to-ids", True))
                if not args.include_non_ids and str(to_ids).strip().lower() not in {"true", "1", "yes"}:
                    continue
                attr_type = str(attr.get("type") or attr.get("category") or "").lower()
                value = str(attr.get("value") or "").strip()
                if not value:
                    continue
                if attr_type in {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "ip"}:
                    found = extract_from_text(value.split("|", 1)[0])
                elif attr_type in {"domain", "hostname", "domain|ip"}:
                    found = extract_from_text(value.split("|", 1)[0])
                elif attr_type in {"md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha1", "filename|sha256"}:
                    found = extract_from_text(value.split("|")[-1])
                else:
                    found = extract_from_text(value)
                attr_tags = attr.get("Tag") or attr.get("tags") or []
                all_tags = list(tags)
                if isinstance(attr_tags, list):
                    all_tags.extend(str(t.get("name") or t.get("Name") or "") if isinstance(t, dict) else str(t)
                                    for t in attr_tags)
                context = {
                    "event_name": event_info or event_uuid,
                    "tags": ";".join(sorted(set(t for t in all_tags if t))),
                    "context": str(attr.get("comment") or attr.get("Comment") or ""),
                }
                for indicator_type, indicator in found:
                    row = make_row(indicator_type, indicator, feed, event_url, now_utc(), context)
                    rows[(indicator_type, indicator, name, event_uuid)] = row
                    count += 1
            total_indicators += count
            elapsed = time.monotonic() - started
            eta = (elapsed / i) * (total - i) if i else 0
            logging.info("%s progress: %d/%d (%.1f%%) | %d indicators | %s | elapsed %s | ETA %s",
                         name, i, total, i * 100 / total, count,
                         "cache" if from_cache else "downloaded",
                         format_duration(elapsed), format_duration(eta))
        except (requests.RequestException, OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            logging.warning("%s event %s failed: %s", name, event_id, exc)
            raise
        if args.delay > 0 and i < total:
            time.sleep(args.delay)
    logging.info("%s: processed %d event(s); extracted %d indicator records", name, total, total_indicators)

def write_outputs(rows: dict[tuple[str, str, str, str], dict[str, str]],
                  errors: list[dict[str, str]]) -> None:
    columns = [
        "indicator_type", "indicator", "feed_name", "provider", "feed_url",
        "source_format", "retrieved_at_utc", "event_name", "tags", "confidence", "context",
    ]
    ordered = sorted(rows.values(), key=lambda r: (
        r["indicator_type"], r["indicator"], r["feed_name"], r["event_name"]
    ))
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(ordered)
    OUTPUT_JSON.write_text(json.dumps(ordered, indent=2, ensure_ascii=False), encoding="utf-8")
    error_columns = ["feed_name", "provider", "feed_url", "status", "error", "timestamp_utc"]
    with OUTPUT_ERRORS.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=error_columns)
        writer.writeheader()
        writer.writerows(errors)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect threat indicators from MISP catalogue and configurable JSON/text/CSV feeds.")
    parser.add_argument("--config", default="", help="custom JSON feed config; if omitted, use MISP catalogue")
    parser.add_argument("--include-disabled", "--all-feeds", dest="include_disabled", action="store_true", help="attempt all catalogue feeds, including entries marked disabled (some may require credentials or be unavailable)")
    parser.add_argument("--include-non-ids", action="store_true", help="for MISP events, include attributes with to_ids=false")
    parser.add_argument("--refresh-metadata", action="store_true", help="download fresh MISP feed metadata")
    parser.add_argument("--limit", type=int, default=0, help="maximum feeds (or MISP events in manifest mode); 0 means all")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="delay between requests in seconds")
    parser.add_argument("--max-mb", type=int, default=50, help="maximum download size per request in MB")
    parser.add_argument("--name", default="", help="process only feeds whose names contain this text")
    parser.add_argument("--no-cache", action="store_true", help="redownload MISP event JSON rather than using cached copies")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, text/csv, */*"})

    try:
        if args.config:
            config_path = Path(args.config)
            if not config_path.is_absolute():
                config_path = BASE_DIR / config_path
            feeds = load_custom_config(config_path)
        else:
            entries = load_metadata(session, refresh=args.refresh_metadata)
            # Always persist the full catalogue first, including disabled entries.
            write_feed_catalog(entries)
            overrides = load_overrides()
            feeds = []
            for entry in entries:
                feed = get_feed(entry)
                name = str(feed.get("name") or "Unnamed feed")
                url = str(feed.get("url") or "").strip()
                if not url.startswith(("http://", "https://")):
                    continue
                if not args.include_disabled and not is_enabled(feed):
                    continue
                if args.name and args.name.casefold() not in name.casefold():
                    continue
                feed = dict(feed)
                feed["name"] = name
                feed["url"] = overrides.get(name, url)
                feed["format"] = feed.get("source_format", "")
                feeds.append(feed)
    except (requests.RequestException, OSError, ValueError, json.JSONDecodeError) as exc:
        logging.error("Could not load feed metadata/config: %s", exc)
        return 1

    if args.name and args.config:
        feeds = [f for f in feeds if args.name.casefold() in str(f.get("name", "")).casefold()]

    # Process the large MISP event collections last, preserving their relative
    # order and the order of all other configured feeds. Sorting happens before
    # execution so smaller feeds are not delayed by multi-thousand-event sources.
    def is_large_misp_feed(feed: dict[str, Any]) -> bool:
        identity = " ".join(
            str(feed.get(k) or "") for k in ("name", "provider", "url", "format")
        ).casefold()
        return any(marker in identity for marker in (
            "misp.rosti.dev", "rosti", "circl",
            "www.circl.lu/doc/misp/feed-osint", "feed-osint/manifest.json",
            "botvrij", "www.botvrij.eu/data/feed-osint",
            "rectifyq", "feeds.rectifyq.com/misp2026",
        ))

    feeds = [feed for _, feed in sorted(
        enumerate(feeds), key=lambda pair: (is_large_misp_feed(pair[1]), pair[0])
    )]

    if args.limit > 0 and not args.config:
        feeds = feeds[:args.limit]
    elif args.limit > 0 and args.config:
        # In custom config, --limit means number of feeds, except MISP manifest where it
        # limits events within that feed.
        feeds = feeds[:args.limit] if not any(str(f.get("format", "")).lower() in {"misp_manifest", "misp-manifest", "misp_manifest_json"} for f in feeds) else feeds

    logging.info("Selected %d feed(s)", len(feeds))
    rows: dict[tuple[str, str, str, str], dict[str, str]] = {}
    errors: list[dict[str, str]] = []
    for index, feed in enumerate(feeds, start=1):
        name = str(feed.get("name") or f"Feed {index}")
        url = str(feed.get("url") or "").strip()
        logging.info("[%d/%d] %s", index, len(feeds), name)
        try:
            feed_format = str(feed.get("format", feed.get("source_format", ""))).lower().replace("-", "_")
            feed_identity = " ".join(str(feed.get(k) or "") for k in ("name", "provider", "url")).casefold()
            if "feeds.rectifyq.com" in feed_identity:
                feed["format"] = "rosti_directory"
                url = str(feed.get("url") or url)
                process_rosti_feed(session, feed, url, args, rows)
            elif "circl.lu/doc/misp/feed-osint" in feed_identity:
                url = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
                process_misp_manifest(session, feed, url, args, rows)
            elif "botvrij.eu/data/feed-osint" in feed_identity:
                url = "https://www.botvrij.eu/data/feed-osint/manifest.json"
                process_misp_manifest(session, feed, url, args, rows)
            elif feed_format in {"misp", "misp_manifest", "misp_manifest_json"}:
                process_misp_manifest(session, feed, url, args, rows)
            elif feed_format in {"vxvault", "vxvault_url_list", "vxvault_urls"} or "vxvault.net/url_list.php" in feed_identity.replace(" ", ""):
                process_vxvault_feed(session, feed, url, args, rows)
            elif feed_format in {"rosti", "rosti_misp", "rosti_directory"} or "misp.rosti.dev" in feed_identity or "rosti" in str(feed.get("provider", "")).casefold():
                process_rosti_feed(session, feed, url, args, rows)
            else:
                process_regular_feed(session, feed, url, args, rows, errors)
        except (requests.RequestException, OSError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            message = str(exc)
            logging.warning("Feed failed: %s", message)
            status = (
                "blocked_by_cloudflare" if "blocked_by_cloudflare" in message or "challenge" in message.lower()
                else "html_response_not_feed" if "html_response_not_feed" in message
                else "http_or_download_error"
            )
            errors.append({
                "feed_name": name,
                "provider": str(feed.get("provider") or ""),
                "feed_url": url,
                "status": status,
                "error": message,
                "timestamp_utc": now_utc(),
            })
        if args.delay > 0 and index < len(feeds):
            time.sleep(args.delay)

    write_outputs(rows, errors)
    logging.info("Finished: %d feed(s), %d indicator records, %d errors", len(feeds), len(rows), len(errors))
    logging.info("Feed catalogue CSV: %s", FEED_CATALOG_CSV if not args.config else "not generated in custom-config mode")
    logging.info("IOC CSV: %s", OUTPUT_CSV)
    logging.info("IOC JSON: %s", OUTPUT_JSON)
    logging.info("Errors CSV: %s", OUTPUT_ERRORS)
    logging.info("Raw feed files: %s", RAW_DIR)
    logging.info("Cached MISP event JSON: %s", EVENT_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
