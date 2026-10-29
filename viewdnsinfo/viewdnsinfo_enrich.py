#!/usr/bin/env python3
"""
ViewDNS IOC Enrichment
----------------------
Enrich IP addresses and domain names using the ViewDNS.info API.

API key environment variable:
    ViewDNSInfo_API_KEY

Input:
  * .txt: one IP/domain/URL per line (blank lines and # comments ignored)
  * .csv: a column named indicator, ioc, domain, ip, url, or value; otherwise
          the first column is used.

Outputs:
  * JSON: complete API responses per indicator/check
  * CSV: one row per indicator/check, with response_json containing the result

Install:
    python -m pip install -r requirements.txt

Examples:
    python viewdns_enrich.py --input iocs.txt
    python viewdns_enrich.py --input iocs.csv --checks dnsrecord,iphistory,whois
    python viewdns_enrich.py --indicator example.com --checks dnsrecord,iphistory,whois
    python viewdns_enrich.py --input iocs.txt --delay 1.0
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

BASE_URL = "https://api.viewdns.info"
API_KEY_ENV = "ViewDNSInfo_API_KEY"
TIMEOUT_SECONDS = 25

# Endpoint names and required query parameter names are based on ViewDNS API docs.
ENDPOINTS = {
    "dnsrecord": ("dnsrecord/", "domain"),
    "iphistory": ("iphistory/", "domain"),
    "iplocation": ("iplocation/", "ip"),
    "reverseip": ("reverseip/", "host"),
    "spamdblookup": ("spamdblookup/", "ip"),
    "abuselookup": ("abuselookup/", "domain"),
    "whois": ("whois/v2", "domain"),
    "reversedns": ("reversedns/", "ip"),
}

DEFAULT_IP_CHECKS = ["iplocation", "spamdblookup", "abuselookup", "reversedns"]
DEFAULT_DOMAIN_CHECKS = [
    "dnsrecord", "iphistory", "whois", "abuselookup", "reverseip"
]


def normalize_indicator(raw: str) -> str:
    """Trim whitespace and extract hostname from a URL."""
    value = raw.strip().strip('"').strip("'")
    if not value or value.startswith("#"):
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or value
    else:
        # Handle domain/path values pasted without a scheme.
        value = value.split("/", 1)[0]
    return value.strip().strip(".").lower()


def indicator_type(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    # Basic hostname validation. This intentionally doesn't treat URLs as a separate API type.
    if len(value) <= 253 and re.fullmatch(
        r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\."
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*",
        value,
    ):
        return "domain"
    return "invalid"


def load_indicators(input_path: Path) -> list[str]:
    suffix = input_path.suffix.lower()
    values: list[str] = []

    if suffix == ".csv":
        with input_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return []
            names = {name.lower().strip(): name for name in reader.fieldnames if name}
            column = next(
                (names[name] for name in ("indicator", "ioc", "domain", "ip", "url", "value")
                 if name in names),
                reader.fieldnames[0],
            )
            for row in reader:
                raw = row.get(column, "")
                if raw:
                    normalized = normalize_indicator(raw)
                    if normalized:
                        values.append(normalized)
    else:
        with input_path.open("r", encoding="utf-8-sig") as handle:
            for line in handle:
                normalized = normalize_indicator(line)
                if normalized:
                    values.append(normalized)

    # Preserve input order while removing duplicates.
    return list(dict.fromkeys(values))


def select_checks(kind: str, requested: list[str] | None) -> list[str]:
    if requested:
        return requested
    return DEFAULT_IP_CHECKS.copy() if kind == "ip" else DEFAULT_DOMAIN_CHECKS.copy()


def request_endpoint(
    session: requests.Session,
    api_key: str,
    check: str,
    indicator: str,
    kind: str,
) -> dict[str, Any]:
    endpoint, parameter = ENDPOINTS[check]
    params = {parameter: indicator, "apikey": api_key, "output": "json"}

    # DNS record API defaults to ANY, but make the choice explicit.
    if check == "dnsrecord":
        params["recordtype"] = "ANY"

    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    try:
        response = session.get(url, params=params, timeout=TIMEOUT_SECONDS)
        http_status = response.status_code
        content_type = response.headers.get("Content-Type", "")

        try:
            body: Any = response.json()
        except ValueError:
            body = response.text[:5000]

        # ViewDNS can return API-level errors in a successful HTTP response.
        api_error = None
        if isinstance(body, dict):
            for key in ("error", "message", "status"):
                value = body.get(key)
                if isinstance(value, str) and any(
                    word in value.lower()
                    for word in ("invalid api", "api key", "quota", "limit exceeded", "error")
                ):
                    api_error = value
                    break

        status = "ok" if response.ok and api_error is None else "error"
        return {
            "indicator": indicator,
            "indicator_type": kind,
            "check": check,
            "status": status,
            "http_status": http_status,
            "api_error": api_error,
            "content_type": content_type,
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "response": body,
        }
    except requests.RequestException as exc:
        return {
            "indicator": indicator,
            "indicator_type": kind,
            "check": check,
            "status": "request_error",
            "http_status": None,
            "api_error": str(exc),
            "content_type": None,
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "response": None,
        }


def write_outputs(results: list[dict[str, Any]], output_prefix: Path) -> tuple[Path, Path]:
    json_path = output_prefix.with_suffix(".json")
    csv_path = output_prefix.with_suffix(".csv")

    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, ensure_ascii=False)

    fields = [
        "indicator", "indicator_type", "check", "status", "http_status",
        "api_error", "content_type", "checked_at_utc", "response_json"
    ]
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in results:
            row = {key: item.get(key) for key in fields if key != "response_json"}
            row["response_json"] = json.dumps(item.get("response"), ensure_ascii=False)
            writer.writerow(row)

    return json_path, csv_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enrich IP addresses and domains with ViewDNS.info APIs."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="Input .txt or .csv file")
    source.add_argument("--indicator", help="Single IP address, domain, or URL")

    parser.add_argument(
        "--checks",
        help="Comma-separated API checks. Options: " + ", ".join(ENDPOINTS),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("viewdns_results"),
        help="Output filename prefix (default: viewdns_results)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Seconds to wait between API requests (default: 0.5)",
    )
    parser.add_argument(
        "--retries", type=int, default=2,
        help="Retries for transient HTTP errors (default: 2)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    api_key = os.getenv(API_KEY_ENV, "").strip()
    if not api_key:
        print(
            f"ERROR: API key not found. Set the {API_KEY_ENV} environment variable.\n"
            "Do not hard-code your API key into this script.",
            file=sys.stderr,
        )
        return 2

    if args.input:
        if not args.input.is_file():
            print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
            return 2
        indicators = load_indicators(args.input)
    else:
        indicators = [normalize_indicator(args.indicator)]

    if not indicators:
        print("ERROR: No indicators found in the input.", file=sys.stderr)
        return 2

    requested: list[str] | None = None
    if args.checks:
        requested = [item.strip().lower() for item in args.checks.split(",") if item.strip()]
        unknown = sorted(set(requested) - set(ENDPOINTS))
        if unknown:
            print(f"ERROR: Unknown check(s): {', '.join(unknown)}", file=sys.stderr)
            print("Available checks: " + ", ".join(ENDPOINTS), file=sys.stderr)
            return 2

    results: list[dict[str, Any]] = []
    session = requests.Session()
    session.headers.update({"User-Agent": "ViewDNS-IOC-Enrichment/1.0"})

    for index, indicator in enumerate(indicators, start=1):
        kind = indicator_type(indicator)
        if kind == "invalid":
            results.append({
                "indicator": indicator,
                "indicator_type": "invalid",
                "check": "validation",
                "status": "skipped",
                "http_status": None,
                "api_error": "Not a valid IP address or hostname",
                "content_type": None,
                "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                "response": None,
            })
            print(f"[{index}/{len(indicators)}] Skipping invalid indicator: {indicator}")
            continue

        checks = select_checks(kind, requested)
        print(f"[{index}/{len(indicators)}] {indicator} ({kind}) — checks: {', '.join(checks)}")

        for check_index, check in enumerate(checks):
            # IP-only and domain-only endpoint parameters are enforced to avoid bad requests.
            if check in ("iplocation", "spamdblookup", "reversedns") and kind != "ip":
                results.append({
                    "indicator": indicator, "indicator_type": kind, "check": check,
                    "status": "skipped", "http_status": None,
                    "api_error": "This API check requires an IP address",
                    "content_type": None,
                    "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                    "response": None,
                })
                continue
            if check in ("dnsrecord", "iphistory") and kind != "domain":
                results.append({
                    "indicator": indicator, "indicator_type": kind, "check": check,
                    "status": "skipped", "http_status": None,
                    "api_error": "This API check requires a domain name",
                    "content_type": None,
                    "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                    "response": None,
                })
                continue

            result = None
            for attempt in range(max(0, args.retries) + 1):
                result = request_endpoint(session, api_key, check, indicator, kind)
                status_code = result.get("http_status")
                if result["status"] == "ok" or status_code not in (429, 500, 502, 503, 504):
                    break
                if attempt < max(0, args.retries):
                    time.sleep(min(2 ** attempt, 8))
            results.append(result)

            if result["status"] == "ok":
                print(f"    {check}: OK")
            else:
                print(f"    {check}: {result['status']} (HTTP {result.get('http_status')})")
            if check_index < len(checks) - 1 and args.delay > 0:
                time.sleep(args.delay)

    json_path, csv_path = write_outputs(results, args.output)
    ok_count = sum(1 for result in results if result["status"] == "ok")
    error_count = sum(1 for result in results if result["status"] in ("error", "request_error"))
    skipped_count = sum(1 for result in results if result["status"] == "skipped")

    print("\nCompleted.")
    print(f"API checks successful: {ok_count}")
    print(f"Errors: {error_count} | Skipped: {skipped_count}")
    print(f"JSON report: {json_path.resolve()}")
    print(f"CSV report:  {csv_path.resolve()}")
    print("Note: API responses are infrastructure/reputation context, not a definitive malware verdict.")
    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
