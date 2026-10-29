
import os
import re
import csv
import time
import base64
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv

# --------------------------------------------------
# Configuration
# --------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_ROOT / "VTLookup" / "ioc.csv"
OUTPUT_FILE = PROJECT_ROOT / "VTLookup" / "results.csv"

load_dotenv(PROJECT_ROOT / ".env")
API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "VT_API_KEY not found. Check your root .env file "
        "or environment variables."
    )

BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 30
REQUEST_DELAY = 20

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY,
}

FIELDNAMES = [
    "IOC",
    "IOC Type",
    "SHA256",
    "MD5",
    "File Name",
    "File Type",
    "File Size (bytes)",
    "Malicious Detections",
    "Suspicious Detections",
    "Undetected",
    "Harmless",
    "Reputation",
    "Threat Classification",
    "Country",
    "ASN",
    "AS Owner",
    "Network",
    "URL Title",
    "First Submission",
    "Last Analysis",
    "Verdict",
    "Status",
]

# --------------------------------------------------
# Utility functions
# --------------------------------------------------
def format_timestamp(value):
    if not value:
        return ""

    try:
        return datetime.fromtimestamp(
            int(value), timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OverflowError, OSError):
        return ""


def classify_ioc(value):
    """Classify an IOC as file_hash, ip, domain, url, or invalid."""
    value = value.strip().strip("\"'")

    if not value or value.startswith("#"):
        return "invalid"

    # IP address
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    # MD5, SHA-1, SHA-256, SHA-512
    if re.fullmatch(
        r"(?i)([a-f0-9]{32}|[a-f0-9]{40}|"
        r"[a-f0-9]{64}|[a-f0-9]{128})",
        value,
    ):
        return "file_hash"

    # URL
    if value.lower().startswith(("http://", "https://")):
        try:
            parsed = urlsplit(value)
            if parsed.hostname and parsed.scheme.lower() in (
                "http", "https"
            ):
                return "url"
        except ValueError:
            pass
        return "invalid"

    # Domain
    domain = value.rstrip(".")

    if (
        len(domain) <= 253
        and "." in domain
        and not any(char.isspace() for char in domain)
        and all(
            label
            and len(label) <= 63
            and re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
                label,
            )
            for label in domain.split(".")
        )
    ):
        return "domain"

    return "invalid"


def url_id(value):
    """
    Generate the VirusTotal URL ID by URL-safe Base64-encoding
    the URL itself, without trailing padding.
    """
    return base64.urlsafe_b64encode(
        value.encode("utf-8")
    ).decode("ascii").rstrip("=")


def get_verdict(malicious, suspicious):
    if malicious >= 6:
        return "Highly Malicious"
    if malicious >= 3:
        return "Malicious"
    if malicious > 0 or suspicious > 0:
        return "Suspicious"
    return "No detections reported"


# --------------------------------------------------
# Read IOC input
# --------------------------------------------------
def read_iocs():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        sample = file.read(4096)
        file.seek(0)

        if not sample.strip():
            print("Warning: IOC input file is empty.")
            return []

        try:
            dialect = csv.Sniffer().sniff(
                sample, delimiters=",;\t"
            )
        except csv.Error:
            dialect = csv.excel

        rows = list(csv.reader(file, dialect))

    if not rows:
        print("Warning: No rows found in IOC input.")
        return []

    recognized_headers = {
        "ioc",
        "hash",
        "indicator",
        "value",
        "ip",
        "ip address",
        "domain",
        "url",
        "file hash",
        "file_hash",
        "observable",
        "indicator value",
        "ioc value",
    }

    first_row = [
        cell.strip().lstrip("\ufeff") for cell in rows[0]
    ]
    normalized = [cell.lower() for cell in first_row]

    # Detect a recognized header.
    header_positions = [
        i for i, cell in enumerate(normalized)
        if cell in recognized_headers
    ]

    if header_positions:
        column_index = header_positions[0]
        data_rows = rows[1:]
        print(
            f"Using input column: {first_row[column_index]}"
        )
    else:
        # No recognizable header: treat all cells as IOC values.
        column_index = None
        data_rows = rows
        print(
            "No recognized header detected; treating input "
            "cells as IOC values."
        )

    iocs = []

    for row in data_rows:
        if not row:
            continue

        if column_index is None:
            candidates = row
        elif column_index < len(row):
            candidates = [row[column_index]]
        else:
            candidates = []

        for candidate in candidates:
            value = candidate.strip().strip("\"'")

            if value and not value.startswith("#"):
                iocs.append(value)

    # Deduplicate while preserving order.
    iocs = list(dict.fromkeys(iocs))

    print(f"Loaded {len(iocs)} unique IOC(s).")

    if not iocs:
        print("Warning: No indicators found in the input file.")

    return iocs


# --------------------------------------------------
# VirusTotal enrichment
# --------------------------------------------------
def make_row(ioc, ioc_type):
    row = {field: "" for field in FIELDNAMES}
    row["IOC"] = ioc
    row["IOC Type"] = ioc_type
    return row


def enrich(ioc, ioc_type):
    row = make_row(ioc, ioc_type)

    if ioc_type == "file_hash":
        endpoint = f"/files/{ioc}"
    elif ioc_type == "ip":
        endpoint = f"/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        endpoint = f"/domains/{ioc}"
    elif ioc_type == "url":
        endpoint = f"/urls/{url_id(ioc)}"
    else:
        row["Status"] = "Skipped: unsupported or invalid IOC"
        print(f"Skipping invalid IOC: {ioc}")
        return row, False

    print(f"Checking {ioc_type}: {ioc}", flush=True)

    try:
        response = requests.get(
            BASE_URL + endpoint,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 404:
            row["Status"] = "Report not found"
            return row, True

        if response.status_code == 429:
            row["Status"] = "Rate limit exceeded"
            print("VirusTotal rate limit reached.")
            return row, True

        if response.status_code in (401, 403):
            row["Status"] = (
                f"API access error: HTTP {response.status_code}"
            )
            print(row["Status"])
            return row, True

        response.raise_for_status()

        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})

        row["Malicious Detections"] = stats.get("malicious", "")
        row["Suspicious Detections"] = stats.get("suspicious", "")
        row["Undetected"] = stats.get("undetected", "")
        row["Harmless"] = stats.get("harmless", "")
        row["Reputation"] = attributes.get("reputation", "")

        classification = attributes.get(
            "popular_threat_classification", {}
        )
        row["Threat Classification"] = classification.get(
            "suggested_threat_label", ""
        )

        row["First Submission"] = format_timestamp(
            attributes.get("first_submission_date")
        )
        row["Last Analysis"] = format_timestamp(
            attributes.get("last_analysis_date")
        )

        if ioc_type == "file_hash":
            row["SHA256"] = attributes.get("sha256", "")
            row["MD5"] = attributes.get("md5", "")
            row["File Name"] = attributes.get("meaningful_name", "")
            row["File Type"] = attributes.get("type_description", "")
            row["File Size (bytes)"] = attributes.get("size", "")

        elif ioc_type == "ip":
            row["Country"] = attributes.get("country", "")
            row["ASN"] = attributes.get("asn", "")
            row["AS Owner"] = attributes.get("as_owner", "")
            row["Network"] = attributes.get("network", "")

        elif ioc_type == "domain":
            row["Country"] = attributes.get("country", "")
            row["ASN"] = attributes.get("asn", "")
            row["AS Owner"] = attributes.get("as_owner", "")
            row["Network"] = attributes.get("network", "")

        elif ioc_type == "url":
            row["URL Title"] = attributes.get("title", "")

        malicious = stats.get("malicious", 0) or 0
        suspicious = stats.get("suspicious", 0) or 0

        row["Verdict"] = get_verdict(malicious, suspicious)
        row["Status"] = "Success"

        print(
            f"  Malicious: {malicious} | "
            f"Suspicious: {suspicious} | "
            f"Verdict: {row['Verdict']}",
            flush=True,
        )

    except requests.Timeout:
        row["Status"] = "Request timed out"

    except requests.RequestException as error:
        row["Status"] = f"Request error: {error}"
        print(f"Request failed: {error}")

    except (ValueError, KeyError, TypeError) as error:
        row["Status"] = f"Response parsing error: {error}"
        print(f"Could not parse response: {error}")

    return row, True


# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    iocs = read_iocs()
    results = []

    for index, ioc in enumerate(iocs, start=1):
        ioc_type = classify_ioc(ioc)

        print(f"\n[{index}/{len(iocs)}]", flush=True)

        row, request_made = enrich(ioc, ioc_type)
        results.append(row)

        if request_made and index < len(iocs):
            time.sleep(REQUEST_DELAY)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=FIELDNAMES,
        )
        writer.writeheader()
        writer.writerows(results)

    print(f"\nCompleted. Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
