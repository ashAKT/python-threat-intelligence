
import csv
import ipaddress
import time
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "ips.txt"
OUTPUT_FILE = BASE_DIR / "ip_enrichment_results.csv"
API_URL = "https://free.freeipapi.com/api/v1/json/"

FIELDS = [
    "ipAddress",
    "ipVersion",
    "countryName",
    "countryCode",
    "regionName",
    "regionCode",
    "cityName",
    "zipCode",
    "latitude",
    "longitude",
    "asn",
    "asnOrganization",
    "isProxy",
    "status",
    "error",
]


def read_ips(file_path):
    unique_ips = []
    seen = set()

    with file_path.open("r", encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            value = line.strip()

            if not value or value.startswith("#"):
                continue

            # Allow a CSV file with a header named "ip" or "ipAddress".
            if line_number == 1 and value.lower() in {
                "ip", "ipaddress", "ip_address"
            }:
                continue

            # Also accept comma-separated IPs.
            for item in value.split(","):
                ip = item.strip().strip('"').strip("'")
                if not ip:
                    continue

                try:
                    ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    print(f"Skipping invalid IP on line {line_number}: {ip}")
                    continue

                if ip not in seen:
                    seen.add(ip)
                    unique_ips.append(ip)

    return unique_ips


def lookup_ip(session, ip):
    url = f"{API_URL}{ip}"

    try:
        response = session.get(url, timeout=20)

        if response.status_code == 429:
            return {
                "ipAddress": ip,
                "status": "Rate limited",
                "error": "HTTP 429 - API rate limit reached",
            }, True

        response.raise_for_status()
        data = response.json()

        if data.get("error"):
            return {
                "ipAddress": ip,
                "status": "API error",
                "error": data.get("message", "API returned an error"),
            }, False

        result = {
            field: data.get(field, "")
            for field in FIELDS
            if field not in {"status", "error"}
        }
        result["ipAddress"] = data.get("ipAddress", ip)
        result["status"] = "Success"
        result["error"] = ""
        return result, False

    except requests.exceptions.RequestException as exc:
        return {
            "ipAddress": ip,
            "status": "Request failed",
            "error": str(exc),
        }, False
    except ValueError as exc:
        return {
            "ipAddress": ip,
            "status": "Invalid JSON",
            "error": str(exc),
        }, False


def main():
    if not INPUT_FILE.exists():
        print(f"Input file not found: {INPUT_FILE}")
        return

    ips = read_ips(INPUT_FILE)

    if not ips:
        print("No valid IP addresses found in ips.txt.")
        return

    print(f"Loaded {len(ips)} unique IP addresses.")

    with requests.Session() as session, OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()

        for index, ip in enumerate(ips, start=1):
            print(f"[{index}/{len(ips)}] Looking up {ip}...", flush=True)

            result, rate_limited = lookup_ip(session, ip)
            writer.writerow(result)
            output.flush()

            print(
                f"  Status: {result.get('status')} "
                f"| Organization: {result.get('asnOrganization', 'N/A')}",
                flush=True,
            )

            if rate_limited:
                print(
                    "Rate limit reached. Stopping to avoid further requests. "
                    "Check the provider's usage limits before resuming."
                )
                break

            # Small delay between requests; adjust to the provider's limits.
            if index < len(ips):
                time.sleep(1)

    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
