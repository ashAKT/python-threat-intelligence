
#!/usr/bin/env python3
"""
Hybrid Analysis Hash Lookup Tool

Features:
- MD5, SHA-1 and SHA-256 lookups
- CSV or TXT input
- CSV summary output
- Raw JSON response output
- Safe handling of missing reports and API errors

Environment variable:
    HYBRID_ANALYSIS_KEY

Repository layout:
    python-threat-intelligence/
    ├── .env
    └── hybridanalysis/
        ├── hybridanalysis.py
        └── indicators.csv
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_URL = "https://www.hybrid-analysis.com/api/v2"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parent
ENV_FILE = REPO_DIR / ".env"

load_dotenv(ENV_FILE)

API_KEY = os.getenv("HYBRID_ANALYSIS_KEY")

TIMEOUT = 30

HEADERS = {
    "api-key": API_KEY or "",
    "user-agent": "Falcon Sandbox",
    "accept": "application/json",
}


# --------------------------------------------------
# API request
# --------------------------------------------------

def api_request(method, endpoint, **kwargs):
    """Send a request and return a sanitized result."""

    try:
        response = requests.request(
            method,
            f"{BASE_URL}/{endpoint.lstrip('/')}",
            headers=HEADERS,
            timeout=TIMEOUT,
            **kwargs,
        )
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status_code": None,
            "error": str(exc),
            "data": None,
        }

    try:
        data = response.json()
    except ValueError:
        data = {"response_text": response.text[:4000]}

    error = None

    if not response.ok:
        if isinstance(data, dict):
            error = data.get("message") or data.get("error")

        error = error or response.reason

    return {
        "ok": response.ok,
        "status_code": response.status_code,
        "error": error,
        "data": data,
    }


# --------------------------------------------------
# Input handling
# --------------------------------------------------

def classify_hash(value):
    """Return a supported hash type, or None."""

    value = value.strip()

    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5"

    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA1"

    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256"

    return None


def load_indicators(filename):
    """Read unique indicators from CSV or TXT."""

    path = Path(filename)

    if not path.is_absolute():
        path = Path.cwd() / path

    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    indicators = []

    if path.suffix.lower() == ".csv":
        with path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                raise ValueError("CSV must contain a header row.")

            columns = {
                name.strip().lower(): name
                for name in reader.fieldnames
                if name
            }

            preferred = [
                "indicator",
                "ioc",
                "value",
                "hash",
                "file_hash",
                "md5",
                "sha1",
                "sha256",
            ]

            column = next(
                (
                    columns[name]
                    for name in preferred
                    if name in columns
                ),
                reader.fieldnames[0],
            )

            for row in reader:
                value = (row.get(column) or "").strip()

                if value and value not in indicators:
                    indicators.append(value)

    else:
        with path.open("r", encoding="utf-8-sig") as file:
            for line in file:
                value = line.strip()

                if (
                    value
                    and not value.startswith("#")
                    and value not in indicators
                ):
                    indicators.append(value)

    return indicators


# --------------------------------------------------
# Verdict extraction
# --------------------------------------------------

def extract_verdict(data):
    """Extract a verdict from hash lookup results."""

    if isinstance(data, dict):
        verdict = data.get("verdict")

        if verdict:
            return str(verdict)

        reports = data.get("reports", [])

        if isinstance(reports, list):
            for report in reports:
                if not isinstance(report, dict):
                    continue

                state = str(report.get("state", "")).upper()

                # Ignore failed reports without a usable verdict.
                if state in {"ERROR", "FAILED"}:
                    continue

                verdict = report.get("verdict")

                if verdict:
                    return str(verdict)

    return "Unknown"


# --------------------------------------------------
# Hash lookup
# --------------------------------------------------

def lookup_hash(value):
    """Look up a file hash in Hybrid Analysis."""

    result = api_request(
        "GET",
        "search/hash",
        params={"hash": value},
    )

    data = result["data"]

    if not result["ok"]:
        return {
            "status": (
                f"API Error ({result['status_code']})"
                if result["status_code"] is not None
                else "Connection Error"
            ),
            "verdict": "Unknown",
            "details": result,
        }

    if not isinstance(data, dict):
        return {
            "status": "Unexpected API Response",
            "verdict": "Unknown",
            "details": result,
        }

    reports = data.get("reports", [])

    if not isinstance(reports, list):
        reports = []

    verdict = extract_verdict(data)

    if reports:
        status = "Report Found"
    else:
        status = "No Reports Found"

    return {
        "status": status,
        "verdict": verdict,
        "details": result,
    }


# --------------------------------------------------
# Process indicators
# --------------------------------------------------

def process_indicator(value):
    """Process supported hashes; skip other indicator types."""

    hash_type = classify_hash(value)

    if not hash_type:
        return {
            "indicator": value,
            "type": "unsupported",
            "status": "Skipped - Hash Only Mode",
            "verdict": "Unknown",
            "details": {},
        }

    result = lookup_hash(value)

    return {
        "indicator": value,
        "type": hash_type,
        "status": result["status"],
        "verdict": result["verdict"],
        "details": result["details"],
    }


# --------------------------------------------------
# Save results
# --------------------------------------------------

def save_results(results):
    """Write summary CSV and raw JSON."""

    csv_path = SCRIPT_DIR / "hybrid_analysis_results.csv"
    json_path = SCRIPT_DIR / "hybrid_analysis_raw.json"

    with csv_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        fields = [
            "indicator",
            "type",
            "status",
            "verdict",
        ]

        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for item in results:
            writer.writerow({
                field: item.get(field, "")
                for field in fields
            })

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(
            results,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return csv_path, json_path


# --------------------------------------------------
# API key check
# --------------------------------------------------

def check_key():
    """Check authentication without printing credentials."""

    result = api_request("GET", "key/current")

    print(f"HTTP status: {result['status_code']}")

    if not result["ok"]:
        print(f"API key check failed: {result['error']}")
        return 1

    data = result["data"]

    if isinstance(data, dict):
        print("API key accepted.")
        print(
            "Auth level:",
            data.get("auth_level_name", "Unknown"),
        )
    else:
        print("Unexpected API response.")

    return 0


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Hybrid Analysis hash lookup utility"
    )

    parser.add_argument(
        "input",
        nargs="?",
        help="Input CSV or TXT file",
    )

    parser.add_argument(
        "--check-key",
        action="store_true",
        help="Verify the API key without printing it",
    )

    args = parser.parse_args()

    print(f"[INFO] Repository: {REPO_DIR}")
    print(f"[INFO] Environment file: {ENV_FILE}")

    if not API_KEY:
        print(
            "[ERROR] HYBRID_ANALYSIS_KEY is missing from .env",
            file=sys.stderr,
        )
        return 1

    if args.check_key:
        return check_key()

    if not args.input:
        parser.error("Provide an input CSV or TXT file.")

    try:
        indicators = load_indicators(args.input)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if not indicators:
        print("[ERROR] No indicators found.")
        return 1

    results = []

    for index, value in enumerate(indicators, start=1):
        print(f"\n[{index}/{len(indicators)}] {value}")

        item = process_indicator(value)
        results.append(item)

        print(f"    Type:    {item['type']}")
        print(f"    Status:  {item['status']}")
        print(f"    Verdict: {item['verdict']}")

        details = item.get("details", {})

        if details and not details.get("ok", True):
            print(f"    Detail:  {details.get('error')}")

    csv_path, json_path = save_results(results)

    supported = sum(
        item["type"] != "unsupported"
        for item in results
    )
    skipped = len(results) - supported

    print("\n[INFO] Processing complete.")
    print(f"[INFO] Total indicators: {len(results)}")
    print(f"[INFO] Hashes processed: {supported}")
    print(f"[INFO] Non-hash indicators skipped: {skipped}")
    print(f"[INFO] CSV: {csv_path}")
    print(f"[INFO] JSON: {json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
