
#!/usr/bin/env python3
"""
abuse.ch IOC Enrichment Script

Feeds:
    1. ThreatFox
    2. MalwareBazaar
    3. URLhaus

Input:
    indicators.csv, hashes.csv, indicators.txt, or hashes.txt

Output:
    abusech_ioc_results.csv

Environment:
    ABUSECH_API_KEY in .env
"""

import csv
import ipaddress
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")
load_dotenv()

API_KEY = (os.getenv("ABUSECH_API_KEY"))

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"

INPUT_CANDIDATES = [
    "indicators.csv",
    "hashes.csv",
    "indicators.txt",
    "hashes.txt",
]

OUTPUT_FILE = BASE_DIR / "abusech_ioc_results.csv"
TIMEOUT = 30
REQUEST_DELAY = 0.25

FIELDS = [
    "indicator",
    "indicator_type",
    "source",
    "verdict",
    "query_status",
    "threat_type",
    "malware_family",
    "confidence",
    "first_seen",
    "last_seen",
    "file_name",
    "file_type",
    "signature",
    "tags",
    "reference",
    "error",
]

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "abusech-ioc-lookup/4.0"
})


# =========================================================
# INDICATOR DETECTION
# =========================================================

def detect_type(value):
    value = value.strip()

    if re.fullmatch(r"(?i)[a-f0-9]{32}", value):
        return "md5"

    if re.fullmatch(r"(?i)[a-f0-9]{40}", value):
        return "sha1"

    if re.fullmatch(r"(?i)[a-f0-9]{64}", value):
        return "sha256"

    try:
        ipaddress.ip_address(value.strip("[]"))
        return "ip"
    except ValueError:
        pass

    if value.lower().startswith(("http://", "https://")):
        return "url"

    host = value.rstrip(".").lower()

    if "." in host and not any(c.isspace() for c in host):
        return "domain"

    return "unknown"


def is_hash(kind):
    return kind in {"md5", "sha1", "sha256"}


def normalize_host(value):
    value = value.strip()

    if value.lower().startswith(("http://", "https://")):
        return (
            urlparse(value).hostname or ""
        ).lower().rstrip(".")

    # Remove a port from an IPv4 address or hostname.
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            value = host

    return value.strip("[]").lower().rstrip(".")


# =========================================================
# INPUT HANDLING
# =========================================================

def read_indicators():
    input_path = next(
        (
            BASE_DIR / name
            for name in INPUT_CANDIDATES
            if (BASE_DIR / name).is_file()
        ),
        None,
    )

    if input_path is None:
        print(
            "ERROR: No input file found. Create indicators.csv, "
            "hashes.csv, indicators.txt, or hashes.txt beside the script."
        )
        sys.exit(1)

    values = []

    if input_path.suffix.lower() == ".txt":
        values = [
            line.strip()
            for line in input_path.read_text(
                encoding="utf-8-sig"
            ).splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    else:
        with input_path.open(
            "r", encoding="utf-8-sig", newline=""
        ) as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                print("ERROR: Input CSV has no header.")
                sys.exit(1)

            normalized = {
                name.strip().lower(): name
                for name in reader.fieldnames
                if name
            }

            preferred = [
                "indicator",
                "ioc",
                "hash",
                "ip",
                "domain",
                "url",
                "value",
            ]

            column = next(
                (
                    normalized[name]
                    for name in preferred
                    if name in normalized
                ),
                None,
            )

            if column is None:
                column = reader.fieldnames[0]

            for row in reader:
                value = (row.get(column) or "").strip()

                if value and not value.startswith("#"):
                    values.append(value)

    # Remove duplicates while preserving the original order.
    unique_values = []
    seen = set()

    for value in values:
        value = value.strip().lstrip("\ufeff")

        if value and value.lower() not in seen:
            seen.add(value.lower())
            unique_values.append(value)

    print(
        f"Loaded {len(unique_values)} unique indicators "
        f"from {input_path.name}"
    )

    return unique_values


# =========================================================
# COMMON HELPERS
# =========================================================

def base_row(indicator, kind, source):
    row = {field: "" for field in FIELDS}

    row.update({
        "indicator": indicator,
        "indicator_type": kind,
        "source": source,
    })

    return row


def safe_request_json(method, url, **kwargs):
    try:
        response = SESSION.request(
            method,
            url,
            timeout=TIMEOUT,
            **kwargs,
        )

        if response.status_code == 429:
            return (
                None,
                "RATE_LIMITED",
                f"HTTP 429: {response.text[:300]}",
            )

        response.raise_for_status()

        try:
            return response.json(), "", ""
        except ValueError:
            return (
                None,
                "API_ERROR",
                f"Invalid JSON: {response.text[:300]}",
            )

    except requests.Timeout as exc:
        return None, "REQUEST_ERROR", f"Timeout: {exc}"

    except requests.ConnectionError as exc:
        return None, "REQUEST_ERROR", f"Connection error: {exc}"

    except requests.HTTPError as exc:
        response = exc.response
        status = (
            response.status_code
            if response is not None
            else "unknown"
        )
        body = (
            response.text[:300]
            if response is not None
            else ""
        )

        return None, "API_ERROR", f"HTTP {status}: {body}"

    except requests.RequestException as exc:
        return None, "REQUEST_ERROR", str(exc)


def list_data(value):
    return value if isinstance(value, list) else []


def format_tags(value):
    if isinstance(value, list):
        return ", ".join(str(tag) for tag in value)

    return value or ""


def record_matches_indicator(record, indicator, kind):
    """Return (matched, related) for a ThreatFox record."""

    if not isinstance(record, dict):
        return False, False

    target = indicator.strip().lower()
    returned = str(record.get("ioc", "")).strip().lower()

    if returned == target:
        return True, False

    # Match an IP against a ThreatFox IOC stored with a port.
    # Example: input 82.47.101.191, record 82.47.101.191:8848
    if kind == "ip" and returned.count(":") == 1:
        host, port = returned.rsplit(":", 1)

        if port.isdigit():
            try:
                if ipaddress.ip_address(host) == ipaddress.ip_address(target):
                    return True, True
            except ValueError:
                pass

    return False, False


def api_key_error(row):
    row.update(
        verdict="CONFIG_ERROR",
        error=(
            "Missing ABUSECH_API_KEY or "
            "MALWAREBAZAAR_API_KEY in .env"
        ),
    )
    return row


# =========================================================
# THREATFOX
# =========================================================

def threatfox_lookup(indicator, kind):
    row = base_row(indicator, kind, "ThreatFox")

    if not API_KEY:
        return api_key_error(row)

    headers = {
        "Auth-Key": API_KEY,
        "Accept": "application/json",
    }

    target = indicator.strip().lower()

    if kind in {"md5", "sha256"}:
        payloads = [
            {
                "query": "search_hash",
                "hash": target,
            },
            {
                "query": "search_ioc",
                "search_term": target,
                "exact_match": True,
            },
        ]

    elif kind == "ip":
        payloads = [
            {
                "query": "search_ioc",
                "search_term": target,
                "exact_match": True,
            },
            {
                "query": "search_ioc",
                "search_term": target,
                "exact_match": False,
            },
        ]

    else:
        payloads = [
            {
                "query": "search_ioc",
                "search_term": target,
                "exact_match": True,
            },
        ]

    last_status = ""
    last_result = None

    for payload in payloads:
        result, error_status, error = safe_request_json(
            "POST",
            THREATFOX_URL,
            headers=headers,
            json=payload,
        )

        if error_status:
            row.update(
                verdict=error_status,
                error=error,
            )
            return row

        if not isinstance(result, dict):
            row.update(
                verdict="API_ERROR",
                error="Response JSON was not an object",
            )
            return row

        status = str(result.get("query_status", "unknown"))
        last_status = status
        last_result = result

        if status == "ok":
            records = list_data(result.get("data"))

            for record in records:
                matched, related = record_matches_indicator(
                    record, indicator, kind
                )

                if not matched:
                    continue

                row.update(
                    verdict=(
                        "RELATED_FOUND" if related else "FOUND"
                    ),
                    query_status=status,
                    threat_type=(
                        record.get("threat_type_desc")
                        or record.get("threat_type")
                        or ""
                    ),
                    malware_family=(
                        record.get("malware_printable")
                        or record.get("malware")
                        or ""
                    ),
                    confidence=record.get("confidence_level", ""),
                    first_seen=record.get("first_seen", ""),
                    last_seen=record.get("last_seen", ""),
                    file_name=record.get("file_name", ""),
                    file_type=(
                        record.get("ioc_type_desc")
                        or record.get("ioc_type")
                        or ""
                    ),
                    signature=record.get("malware_alias", ""),
                    tags=format_tags(record.get("tags")),
                    reference=(
                        record.get("reference")
                        or record.get("malware_malpedia")
                        or ""
                    ),
                )

                if related:
                    row["error"] = (
                        "ThreatFox IOC includes a port: "
                        + str(record.get("ioc", ""))
                    )

                return row

            row.update(
                verdict="NO_EXACT_MATCH",
                query_status=status,
                error=(
                    f"ThreatFox returned {len(records)} record(s), "
                    "but none matched the submitted IOC"
                ),
            )
            return row

        if status not in {
            "no_result",
            "no_results",
            "hash_not_found",
        }:
            row.update(
                verdict="API_ERROR",
                query_status=status,
                error=str(result.get("data", status))[:500],
            )
            return row

    row.update(
        verdict="NOT_FOUND",
        query_status=last_status,
    )

    if last_result and isinstance(last_result.get("data"), str):
        row["error"] = last_result["data"][:300]

    return row


# =========================================================
# MALWAREBAZAAR
# =========================================================

def malwarebazaar_lookup(indicator, kind):
    row = base_row(indicator, kind, "MalwareBazaar")

    if not is_hash(kind):
        row.update(
            verdict="SKIPPED",
            query_status="unsupported_indicator",
            error="MalwareBazaar lookup requires a file hash",
        )
        return row

    if not API_KEY:
        return api_key_error(row)

    headers = {
        "Auth-Key": API_KEY,
        "Accept": "application/json",
    }

    result, error_status, error = safe_request_json(
        "POST",
        MALWAREBAZAAR_URL,
        headers=headers,
        data={
            "query": "get_info",
            "hash": indicator.strip().lower(),
        },
    )

    if error_status:
        row.update(verdict=error_status, error=error)
        return row

    if not isinstance(result, dict):
        row.update(
            verdict="API_ERROR",
            error="Response JSON was not an object",
        )
        return row

    status = str(result.get("query_status", "unknown"))
    row["query_status"] = status

    if status == "hash_not_found":
        row["verdict"] = "NOT_FOUND"
        return row

    if status != "ok":
        row.update(verdict="API_ERROR", error=status)
        return row

    target = indicator.strip().lower()
    records = list_data(result.get("data"))
    matching_record = None

    for record in records:
        if not isinstance(record, dict):
            continue

        hashes = {
            str(record.get("md5_hash", "")).lower(),
            str(record.get("sha1_hash", "")).lower(),
            str(record.get("sha256_hash", "")).lower(),
        }

        if target in hashes:
            matching_record = record
            break

    if matching_record is None:
        row.update(
            verdict="NO_EXACT_MATCH",
            error=(
                "MalwareBazaar returned ok but no record "
                "matched the submitted hash"
            ),
        )
        return row

    record = matching_record

    row.update(
        verdict="FOUND",
        threat_type=record.get("file_type", ""),
        malware_family=record.get("signature", "") or "",
        first_seen=record.get("first_seen", ""),
        last_seen=record.get("last_seen", ""),
        file_name=record.get("file_name", ""),
        file_type=record.get("file_type", ""),
        signature=record.get("signature", ""),
        tags=format_tags(record.get("tags")),
        reference=record.get("reporter", ""),
    )

    return row


# =========================================================
# URLHAUS
# =========================================================

def urlhaus_lookup(indicator, kind):
    row = base_row(indicator, kind, "URLhaus")

    if kind not in {"url", "domain", "ip"}:
        row.update(
            verdict="SKIPPED",
            query_status="unsupported_indicator",
            error="URLhaus supports URLs, domains, and IP addresses",
        )
        return row

    if not API_KEY:
        return api_key_error(row)

    if kind == "url":
        endpoint = URLHAUS_URL + "url/"
        form_data = {"url": indicator.strip()}
    else:
        endpoint = URLHAUS_URL + "host/"
        form_data = {"host": normalize_host(indicator)}

    headers = {
        "Auth-Key": API_KEY,
        "Accept": "application/json",
    }

    result, error_status, error = safe_request_json(
        "POST",
        endpoint,
        headers=headers,
        data=form_data,
    )

    if error_status:
        row.update(verdict=error_status, error=error)
        return row

    if not isinstance(result, dict):
        row.update(
            verdict="API_ERROR",
            error="Response JSON was not an object",
        )
        return row

    status = str(result.get("query_status", "unknown"))
    row["query_status"] = status

    if status in {"no_results", "no_result", "not_found"}:
        row["verdict"] = "NOT_FOUND"
        return row

    if status != "ok":
        row.update(
            verdict="API_ERROR",
            error=status,
        )
        return row

    target_url = indicator.strip().rstrip("/").lower()
    target_host = normalize_host(indicator)

    found_record = None
    related = False

    if kind == "url":
        returned_url = (
            str(result.get("url", "")).strip().rstrip("/").lower()
        )

        if returned_url == target_url:
            found_record = result

    else:
        returned_host = (
            normalize_host(str(result.get("host", "")))
            if result.get("host")
            else ""
        )

        url_records = (
            result.get("urls")
            if isinstance(result.get("urls"), list)
            else []
        )

        if returned_host == target_host:
            # The API returned the queried host itself.
            found_record = (
                url_records[0]
                if url_records and isinstance(url_records[0], dict)
                else result
            )

        else:
            # Look for a returned URL whose hostname matches the input.
            for record in url_records:
                if not isinstance(record, dict):
                    continue

                record_url = str(record.get("url", ""))

                if normalize_host(record_url) == target_host:
                    found_record = record
                    related = True
                    break

    if not found_record:
        row.update(
            verdict="NO_EXACT_MATCH",
            error=(
                "URLhaus returned query_status=ok but no matching "
                "URL or host was identified"
            ),
        )
        return row

    row.update(
        verdict="RELATED_FOUND" if related else "FOUND",
        threat_type=(
            found_record.get("threat")
            or found_record.get("threat_type")
            or ""
        ),
        malware_family=found_record.get("threat") or "",
        first_seen=(
            found_record.get("date_added")
            or found_record.get("first_seen")
            or ""
        ),
        last_seen=(
            found_record.get("last_online")
            or found_record.get("last_seen")
            or ""
        ),
        file_name=(
            found_record.get("url")
            or found_record.get("host")
            or ""
        ),
        file_type=found_record.get("url_status") or "",
        tags=format_tags(found_record.get("tags")),
        reference=(
            found_record.get("urlhaus_reference")
            or found_record.get("reference")
            or ""
        ),
    )

    return row


# =========================================================
# MAIN
# =========================================================

def main():
    indicators = read_indicators()

    if not indicators:
        print("No indicators found in the input file.")
        return

    total = len(indicators)
    rows = []

    for index, indicator in enumerate(indicators, start=1):
        kind = detect_type(indicator)

        # Query all feeds before printing the final IOC line.
        if kind == "unknown":
            ioc_rows = []

            for source in (
                "ThreatFox",
                "MalwareBazaar",
                "URLhaus",
            ):
                row = base_row(indicator, kind, source)
                row.update(
                    verdict="SKIPPED",
                    error="Unable to determine indicator type",
                )
                ioc_rows.append(row)

        else:
            ioc_rows = [
                threatfox_lookup(indicator, kind),
                malwarebazaar_lookup(indicator, kind),
                urlhaus_lookup(indicator, kind),
            ]

        rows.extend(ioc_rows)

        # Only feeds with a confirmed match are shown.
        matched_feeds = list(dict.fromkeys(
            row["source"]
            for row in ioc_rows
            if str(row.get("verdict", "")).upper()
            in {"FOUND", "RELATED_FOUND"}
        ))

        if matched_feeds:
            print(
                f"[{index}/{total}] {indicator} ({kind}) : "
                f"Match found in [{', '.join(matched_feeds)}]",
                flush=True,
            )
        else:
            # No remarks for unmatched indicators.
            print(
                f"[{index}/{total}] {indicator} ({kind})",
                flush=True,
            )

        time.sleep(REQUEST_DELAY)

    # Export the detailed per-feed results.
    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nCompleted. Wrote {len(rows)} source results to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()
