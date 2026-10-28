
#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import os
import sys
import time
from pathlib import Path

import requests

API_URL = "https://api.abuseipdb.com/api/v2/check"
SCRIPT_DIR = Path(__file__).resolve().parent

OUTPUT_FIELDS = [
    "ipAddress",
    "ipVersion",
    "query_status",
    "abuseConfidenceScore",
    "totalReports",
    "numDistinctUsers",
    "lastReportedAt",
    "countryCode",
    "isp",
    "usageType",
    "domain",
    "isWhitelisted",
    "error",
]


def get_ioc_type(indicator):
    """Identify IP addresses, URLs, hashes, and domain-like indicators."""

    value = indicator.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if value.lower().startswith(("http://", "https://")):
        return "url"

    if len(value) in (32, 40, 64, 128):
        if all(c in "0123456789abcdefABCDEF" for c in value):
            return {
                32: "md5",
                40: "sha1",
                64: "sha256",
                128: "sha512",
            }[len(value)]

    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
        except ValueError:
            pass

    return "domain"


def select_input_file(filename=None):
    """
    Use a specified file or discover TXT/CSV files beside this script.
    If several files are available, ask the user to select one.
    """

    if filename:
        path = Path(filename).expanduser()

        if not path.is_absolute():
            path = Path.cwd() / path

        if not path.is_file():
            sys.exit(f"ERROR: Input file not found: {path}")

        if path.suffix.lower() not in (".txt", ".csv"):
            sys.exit("ERROR: Input file must have a .txt or .csv extension.")

        return path

    excluded_names = {
        "abuseipdb_results.csv",
        "results.csv",
    }

    files = sorted(
        path
        for path in SCRIPT_DIR.iterdir()
        if path.is_file()
        and path.suffix.lower() in (".txt", ".csv")
        and path.name.lower() not in excluded_names
        and not path.name.startswith("~$")
    )

    if not files:
        sys.exit(
            f"ERROR: No input .txt or .csv files found in {SCRIPT_DIR}"
        )

    if len(files) == 1:
        print(f"Input file selected: {files[0].name}")
        return files[0]

    print("\nAvailable input files:")
    for index, path in enumerate(files, start=1):
        print(f"  {index}. {path.name}")

    while True:
        try:
            choice = int(input("\nSelect input file number: ").strip())

            if 1 <= choice <= len(files):
                return files[choice - 1]

            print(f"Enter a number between 1 and {len(files)}.")

        except ValueError:
            print("Invalid selection. Enter a number.")
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nInput selection cancelled.")


def load_indicators(file_path):
    """Load unique indicators from a TXT or CSV file."""

    indicators = []

    if file_path.suffix.lower() == ".txt":
        for line in file_path.read_text(
            encoding="utf-8-sig"
        ).splitlines():
            line = line.split("#", 1)[0].strip()

            if line:
                indicators.extend(
                    item.strip()
                    for item in line.replace(";", ",").split(",")
                    if item.strip()
                )

    elif file_path.suffix.lower() == ".csv":
        with file_path.open(
            "r", newline="", encoding="utf-8-sig"
        ) as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                raise ValueError("CSV must contain a header row.")

            columns = {
                name.strip().lower(): name
                for name in reader.fieldnames
                if name
            }

            column = next(
                (
                    columns[name]
                    for name in ("ipaddress", "ip", "ioc", "indicator")
                    if name in columns
                ),
                None,
            )

            if not column:
                raise ValueError(
                    "CSV must contain a column named "
                    "ipAddress, ip, ioc, or indicator."
                )

            for row in reader:
                value = (row.get(column) or "").strip()

                if value and not value.startswith("#"):
                    indicators.append(value)

    return list(dict.fromkeys(indicators))


def empty_result(indicator, status, error, ip_version=""):
    """Create a consistent output row."""

    result = {field: "" for field in OUTPUT_FIELDS}
    result["ipAddress"] = indicator
    result["ipVersion"] = ip_version
    result["query_status"] = status
    result["error"] = error
    return result


def check_ip(session, indicator, max_age):
    """Query AbuseIPDB for a single public IPv4 or IPv6 address."""

    try:
        ip = ipaddress.ip_address(indicator.strip())
    except ValueError:
        return empty_result(
            indicator,
            "SKIPPED_UNSUPPORTED_TYPE",
            "AbuseIPDB check endpoint requires a single IP address",
        )

    if not ip.is_global:
        return empty_result(
            indicator,
            "SKIPPED_NON_PUBLIC_IP",
            "IP is not globally routable",
            ip.version,
        )

    try:
        response = session.get(
            API_URL,
            params={
                "ipAddress": str(ip),
                "maxAgeInDays": max_age,
            },
            timeout=20,
        )

        if response.status_code == 429:
            return empty_result(
                indicator,
                "RATE_LIMITED",
                "AbuseIPDB rate limit reached",
                ip.version,
            )

        if not response.ok:
            return empty_result(
                indicator,
                "ERROR",
                f"HTTP {response.status_code}: {response.text[:300]}",
                ip.version,
            )

        data = response.json().get("data", {})

        result = empty_result(
            indicator,
            "SUCCESS",
            "",
            ip.version,
        )

        for field in OUTPUT_FIELDS:
            if field in data and field not in ("error", "ipVersion"):
                value = data[field]
                result[field] = "" if value is None else value

        result["ipVersion"] = ip.version
        return result

    except (requests.RequestException, ValueError) as exc:
        return empty_result(
            indicator,
            "ERROR",
            str(exc)[:300],
            ip.version,
        )


def print_result(index, total, indicator, ioc_type, result):
    """Print a concise, numbered result similar to the GitHub Actions log."""

    prefix = f"[{index}/{total}] {indicator} ({ioc_type}) : "

    if result["query_status"] == "SUCCESS":
        print(
            prefix
            + "Abuse confidence score: "
            + str(result["abuseConfidenceScore"])
            + " | Reports: "
            + str(result["totalReports"])
        )

    elif result["query_status"] == "SKIPPED_UNSUPPORTED_TYPE":
        print(
            prefix
            + "Skipped [AbuseIPDB supports only IP addresses]"
        )

    elif result["query_status"] == "SKIPPED_NON_PUBLIC_IP":
        print(prefix + "Skipped [Non-public IP address]")

    else:
        print(
            prefix
            + result["query_status"]
            + " ["
            + result["error"]
            + "]"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Enrich IPv4 and IPv6 indicators using AbuseIPDB."
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        default=None,
        help="Optional TXT/CSV input file; otherwise select from this script's directory",
    )

    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output CSV path (default: abuseipdb_results.csv beside the script)",
    )

    parser.add_argument(
        "--max-age",
        type=int,
        choices=range(1, 366),
        default=90,
        metavar="DAYS",
        help="Report lookback in days, 1-365 (default: 90)",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between API requests (default: 1)",
    )

    args = parser.parse_args()

    if args.delay < 0:
        parser.error("--delay must be >= 0")

    api_key = os.environ.get("ABUSEIPDB_API_KEY")

    if not api_key:
        sys.exit(
            "ERROR: ABUSEIPDB_API_KEY environment variable is not set."
        )

    try:
        input_path = select_input_file(args.input_file)
        indicators = load_indicators(input_path)
    except (OSError, ValueError) as exc:
        sys.exit(f"ERROR: {exc}")

    if not indicators:
        sys.exit("ERROR: No indicators found in the input file.")

    output_path = (
        Path(args.output).expanduser()
        if args.output
        else SCRIPT_DIR / "abuseipdb_results.csv"
    )

    if not output_path.is_absolute():
        output_path = Path.cwd() / output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({
        "Key": api_key,
        "Accept": "application/json",
        "User-Agent": "SOC-AbuseIPDB-Lookup/1.0",
    })

    total = len(indicators)
    results = []

    print("Run AbuseIPDB IOC enrichment")
    print(
        f"Loaded {total} unique indicators from {input_path.name}"
    )

    for index, indicator in enumerate(indicators, start=1):
        ioc_type = get_ioc_type(indicator)

        if ioc_type != "ip":
            result = empty_result(
                indicator,
                "SKIPPED_UNSUPPORTED_TYPE",
                "AbuseIPDB supports single IP addresses only",
            )
        else:
            result = check_ip(session, indicator, args.max_age)

        results.append(result)
        print_result(index, total, indicator, ioc_type, result)

        if result["query_status"] == "RATE_LIMITED":
            print("Rate limit reached; remaining indicators not queried.")

            for remaining in indicators[index:]:
                results.append(
                    empty_result(
                        remaining,
                        "NOT_QUERIED",
                        "Not queried after rate limit",
                    )
                )
            break

        if index < total and result["query_status"] != "RATE_LIMITED":
            time.sleep(args.delay)

    with output_path.open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(results)

    successful = sum(
        result["query_status"] == "SUCCESS"
        for result in results
    )

    skipped = sum(
        result["query_status"].startswith("SKIPPED")
        for result in results
    )

    errors = sum(
        result["query_status"] in (
            "ERROR",
            "RATE_LIMITED",
            "NOT_QUERIED",
        )
        for result in results
    )

    print(f"\nCompleted. Wrote {len(results)} results to:")
    print(output_path.resolve())
    print(
        f"Summary: {successful} successful, "
        f"{skipped} skipped, {errors} errors/not queried."
    )


if __name__ == "__main__":
    main()
