
import csv
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote

import requests

BASE_URL = "https://www.hybrid-analysis.com/api/v2"
API_KEY = os.getenv("HYBRID_ANALYSIS_KEY")

INPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else "hashes.csv"
OUTPUT_FILE = "hybrid_analysis_results.csv"
RAW_FILE = "hybrid_analysis_raw.json"

HEADERS = {
    "api-key": API_KEY or "",
    "user-agent": "Falcon Sandbox",
    "accept": "application/json",
}

HASH_PATTERN = re.compile(
    r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$"
)

FIELDS = [
    "input_hash",
    "report_found",
    "verdict",
    "threat_score",
    "threat_level",
    "av_detect",
    "vx_family",
    "sha256",
    "md5",
    "sha1",
    "job_id",
    "environment_id",
    "environment_description",
    "analysis_start_time",
    "report_url",
    "error",
]


def load_hashes(filename):
    """Load unique hashes from a CSV or TXT file."""
    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    hashes = []

    if path.suffix.lower() == ".csv":
        with path.open(
            "r", encoding="utf-8-sig", newline=""
        ) as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                return []

            columns = {
                name.strip().lower(): name
                for name in reader.fieldnames
                if name
            }

            preferred = ("hash", "sha256", "sha1", "md5")
            column = next(
                (columns[name] for name in preferred if name in columns),
                reader.fieldnames[0],
            )

            for row in reader:
                value = (row.get(column) or "").strip()
                if value:
                    hashes.append(value)
    else:
        with path.open("r", encoding="utf-8-sig") as file:
            hashes = [
                line.strip()
                for line in file
                if line.strip()
                and not line.lstrip().startswith("#")
            ]

    return list(dict.fromkeys(hashes))


def request_json(session, endpoint, params=None):
    """Make an API request and return JSON or a diagnostic error."""
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"

    try:
        response = session.get(
            url,
            params=params,
            timeout=30,
        )

        if response.status_code == 401:
            return None, "HTTP 401: Invalid or missing API key"

        if response.status_code == 403:
            return None, "HTTP 403: API access forbidden"

        if response.status_code == 404:
            return None, "HTTP 404: Report or endpoint not found"

        if response.status_code == 429:
            return None, "HTTP 429: API rate limit exceeded"

        response.raise_for_status()

        try:
            return response.json(), None
        except ValueError:
            return None, "API returned a non-JSON response"

    except requests.RequestException as exc:
        return None, f"Request error: {exc}"


def as_report_list(data):
    """Normalize common search response formats."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        for key in ("result", "data", "reports"):
            value = data.get(key)
            if isinstance(value, list):
                return [
                    item for item in value
                    if isinstance(item, dict)
                ]

        # A single report may be returned as an object.
        return [data]

    return []


def fetch_summary(session, report):
    """
    Fetch a detailed report summary using job_id, or
    SHA256:environment_id if the job ID is unavailable.
    """
    job_id = report.get("job_id")
    sha256 = report.get("sha256")
    environment_id = report.get("environment_id")

    if job_id:
        report_id = str(job_id)
    elif sha256 and environment_id is not None:
        report_id = f"{sha256}:{environment_id}"
    else:
        return None, "No usable report ID in search result"

    endpoint = f"report/{quote(report_id, safe=':')}/summary"
    return request_json(session, endpoint)


def first_value(data, *keys):
    """Return the first nonempty value among possible field names."""
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return ""


def lookup_hash(session, file_hash):
    """Search for a hash and enrich results with detailed summaries."""
    if not HASH_PATTERN.fullmatch(file_hash):
        return [], {
            "error": "Invalid MD5, SHA-1, or SHA-256 format"
        }

    search_data, search_error = request_json(
        session,
        "search/hash",
        params={"hash": file_hash},
    )

    if search_error:
        return [], {
            "search_error": search_error,
            "search_response": search_data,
        }

    reports = as_report_list(search_data)

    if not reports:
        return [], {
            "search_response": search_data,
            "message": "No existing reports returned",
        }

    rows = []
    raw_reports = []

    for report in reports:
        raw_entry = {"search_result": report}

        # Search results may not contain the complete verdict.
        summary, summary_error = fetch_summary(session, report)

        if isinstance(summary, dict):
            raw_entry["summary"] = summary
            # Summary fields take precedence when populated.
            combined = {**report, **summary}
        else:
            combined = report
            raw_entry["summary_error"] = summary_error

        raw_reports.append(raw_entry)

        sha256 = first_value(combined, "sha256")
        job_id = first_value(combined, "job_id")
        environment_id = first_value(combined, "environment_id")

        verdict = first_value(
            combined,
            "verdict",
            "classification",
            "threat_classification",
        )

        # Do not label an absent verdict as benign or malicious.
        if not verdict:
            verdict = "Unknown"

        report_url = (
            f"https://www.hybrid-analysis.com/sample/{sha256}"
            if sha256 else ""
        )

        rows.append({
            "input_hash": file_hash,
            "report_found": True,
            "verdict": verdict,
            "threat_score": first_value(
                combined, "threat_score", "score"
            ),
            "threat_level": first_value(combined, "threat_level"),
            "av_detect": first_value(combined, "av_detect"),
            "vx_family": first_value(
                combined, "vx_family", "family"
            ),
            "sha256": sha256,
            "md5": first_value(combined, "md5"),
            "sha1": first_value(combined, "sha1"),
            "job_id": job_id,
            "environment_id": environment_id,
            "environment_description": first_value(
                combined, "environment_description"
            ),
            "analysis_start_time": first_value(
                combined, "analysis_start_time"
            ),
            "report_url": report_url,
            "error": (
                f"Summary unavailable: {summary_error}"
                if summary_error else ""
            ),
        })

    return rows, {
        "search_response": search_data,
        "reports": raw_reports,
    }


def main():
    if not API_KEY:
        sys.exit(
            "ERROR: HYBRID_ANALYSIS_KEY is not set.\n"
            "Set it before running this script."
        )

    try:
        hashes = load_hashes(INPUT_FILE)
    except (OSError, csv.Error) as exc:
        sys.exit(f"ERROR reading input file: {exc}")

    if not hashes:
        sys.exit("No hashes found in the input file.")

    print(f"Loaded {len(hashes)} unique indicators.")

    session = requests.Session()
    session.headers.update(HEADERS)

    all_rows = []
    raw_data = {}

    for index, file_hash in enumerate(hashes, start=1):
        print(f"\n[{index}/{len(hashes)}] Checking {file_hash}")

        rows, raw = lookup_hash(session, file_hash)
        raw_data[file_hash] = raw

        if not rows:
            error = raw.get("search_error") or raw.get("message", "")
            print(f"    No report rows: {error}")

            all_rows.append({
                "input_hash": file_hash,
                "report_found": False,
                "verdict": "Unknown",
                "error": error or "No usable report returned",
            })
        else:
            for row in rows:
                print(f"    Verdict: {row['verdict']}")
                print(f"    SHA-256: {row['sha256'] or 'Unavailable'}")

                if row["error"]:
                    print(f"    Note: {row['error']}")

                all_rows.append(row)

        # Avoid continuing after an explicit API rate-limit response.
        if "HTTP 429" in str(raw.get("search_error", "")):
            print("Rate limit reached; stopping remaining lookups.")
            break

        if index < len(hashes):
            time.sleep(1)

    with open(
        OUTPUT_FILE, "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)

    with open(RAW_FILE, "w", encoding="utf-8") as file:
        json.dump(raw_data, file, indent=2, default=str)

    print("\nLookup complete.")
    print(f"CSV results: {OUTPUT_FILE}")
    print(f"Raw API responses: {RAW_FILE}")


if __name__ == "__main__":
    main()
