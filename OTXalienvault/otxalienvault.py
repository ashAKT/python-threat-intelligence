#!/usr/bin/env python3
"""Simple AlienVault OTX IOC lookup for triage and further investigation.

Input:  OTXalienvault/indicators.csv (required column: indicator; optional: type)
Output: OTXalienvault/otx_results.csv

Repository-root .env:
  OTX_API_KEY=your_api_key
  OTX_WORKERS=5

This script queries only the OTX general endpoint. It intentionally excludes
noisy pulse names/tags and extra detailed sections. A pulse association is a
lead for investigation, not proof that an IOC is malicious.
"""

import csv
import ipaddress
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

API_KEY = os.getenv("OTX_API_KEY", "").strip()
WORKERS = max(1, min(10, int(os.getenv("OTX_WORKERS", "5"))))
TIMEOUT = 20
BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
INPUT_FILE = PROJECT_DIR / "indicators.csv"
OUTPUT_FILE = PROJECT_DIR / "otx_results.csv"

TYPE_CONFIG = {
    "IP": "IPv4", "IPV4": "IPv4", "IPV6": "IPv6",
    "DOMAIN": "domain", "HOSTNAME": "hostname", "URL": "url",
    "MD5": "file", "SHA1": "file", "SHA256": "file",
    "FILEHASH-MD5": "file", "FILEHASH-SHA1": "file", "FILEHASH-SHA256": "file",
    "CVE": "cve",
}
FIELDS = [
    "indicator", "indicator_type", "lookup_status", "pulse_count",
    "reputation", "country", "asn", "otx_link", "error",
]
_thread_local = threading.local()


def get_session():
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        session.headers.update({
            "X-OTX-API-KEY": API_KEY,
            "Accept": "application/json",
            "User-Agent": "python-for-cybersecurity-otx-simple/1.0",
        })
        _thread_local.session = session
    return _thread_local.session


def detect_type(value):
    try:
        parsed_ip = ipaddress.ip_address(value)
        return "IPV4" if parsed_ip.version == 4 else "IPV6"
    except ValueError:
        pass
    if re.fullmatch(r"(?i)[a-f0-9]{32}", value):
        return "MD5"
    if re.fullmatch(r"(?i)[a-f0-9]{40}", value):
        return "SHA1"
    if re.fullmatch(r"(?i)[a-f0-9]{64}", value):
        return "SHA256"
    if re.match(r"(?i)^https?://", value):
        return "URL"
    if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,}", value):
        return "CVE"
    return "DOMAIN"


def read_indicators():
    with INPUT_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or "indicator" not in reader.fieldnames:
            raise ValueError("Input CSV must contain an 'indicator' column.")
        rows, seen = [], set()
        for row in reader:
            indicator = (row.get("indicator") or "").strip()
            if not indicator or indicator in seen:
                continue
            seen.add(indicator)
            kind = (row.get("type") or "").strip().upper() or detect_type(indicator)
            rows.append((indicator, kind))
        return rows


def lookup(item):
    indicator, kind = item
    output = {field: "" for field in FIELDS}
    output["indicator"] = indicator  # Preserve the exact input IOC.
    output["indicator_type"] = kind

    api_type = TYPE_CONFIG.get(kind)
    if not api_type:
        output.update(lookup_status="INVALID_TYPE", error=f"Unsupported type: {kind}")
        return output

    endpoint = f"{BASE_URL}/{api_type}/{quote(indicator, safe='')}/general"
    output["otx_link"] = f"https://otx.alienvault.com/indicator/{api_type}/{quote(indicator, safe='')}"
    try:
        response = get_session().get(endpoint, timeout=TIMEOUT)
        if response.status_code == 404:
            output["lookup_status"] = "NOT_FOUND"
            return output
        if response.status_code == 429:
            output.update(lookup_status="RATE_LIMITED", error=f"HTTP 429; Retry-After={response.headers.get('Retry-After', 'unspecified')}")
            return output
        if response.status_code in (401, 403):
            output.update(lookup_status="AUTH_ERROR", error=f"HTTP {response.status_code}")
            return output
        response.raise_for_status()
        data = response.json()
    except requests.Timeout:
        output.update(lookup_status="ERROR", error="Request timed out")
        return output
    except requests.RequestException as exc:
        output.update(lookup_status="ERROR", error=str(exc))
        return output
    except ValueError:
        output.update(lookup_status="ERROR", error="Invalid JSON response")
        return output

    pulse_info = data.get("pulse_info") or {}
    pulse_count = pulse_info.get("count", len(pulse_info.get("pulses") or []))
    base = data.get("base_indicator") or {}
    output["pulse_count"] = pulse_count
    output["reputation"] = data.get("reputation", base.get("reputation", ""))
    output["country"] = base.get("country_name") or base.get("country", "")
    output["asn"] = base.get("asn", "")
    output["lookup_status"] = "FOUND_WITH_PULSES" if pulse_count else "FOUND_NO_PULSES"
    return output


def main():
    if not API_KEY:
        sys.exit("Missing OTX_API_KEY in repository-root .env file.")
    if not INPUT_FILE.exists():
        sys.exit(f"Input file not found: {INPUT_FILE}")
    try:
        rows = read_indicators()
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))
    if not rows:
        sys.exit("No valid indicators found in indicators.csv.")

    print(f"Loaded {len(rows)} unique indicators. Running simple OTX lookup with {WORKERS} workers.")
    with OUTPUT_FILE.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for index, output in enumerate(pool.map(lookup, rows), 1):
                writer.writerow(output)
                file.flush()
                print(f"[{index}/{len(rows)}] {output['indicator']} -> {output['lookup_status']}", flush=True)
    print(f"Results saved to: {OUTPUT_FILE}")
    print("Note: pulse_count is a triage clue, not a verdict. Review the OTX link and validate with other sources.")


if __name__ == "__main__":
    main()
