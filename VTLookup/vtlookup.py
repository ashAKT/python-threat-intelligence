
import os
import time as time_module
import requests
import csv
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load the .env file from the project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# Retrieve the API key
api_key = os.getenv("VT_API_KEY")

if not api_key:
    raise RuntimeError(
        "VT_API_KEY not found. Check your root .env file."
    )

# Read hashes from hashes.csv
hashes = []

with open(
    PROJECT_ROOT / "VTLookup" / "hashes.csv",
    "r",
    newline="",
    encoding="utf-8-sig"
) as f:
    data = csv.DictReader(f)

    if not data.fieldnames or "hash" not in data.fieldnames:
        raise ValueError(
            "hashes.csv must contain a column named 'hash'."
        )

    for row in data:
        file_hash = (row.get("hash") or "").strip()
        if file_hash:
            hashes.append(file_hash)

headers = {
    "accept": "application/json",
    "x-apikey": api_key,
}

final_data = []

def format_timestamp(timestamp):
    if not timestamp:
        return "Not available"

    return datetime.fromtimestamp(
        timestamp, timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")


for index, file_hash in enumerate(hashes, start=1):
    temp = {
        "hash": file_hash,
        "SHA256": "",
        "MD5": "",
        "File Name": "",
        "File Type": "",
        "File Size (bytes)": "",
        "Malicious Detections": "",
        "Suspicious Detections": "",
        "Undetected": "",
        "Reputation": "",
        "Threat Classification": "",
        "First Submission": "",
        "Last Analysis": "",
        "Verdict": "",
        "Status": "",
    }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    print(f"Checking hash: {file_hash}", flush=True)

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code == 404:
            temp["Status"] = "Report not found"

        elif response.status_code == 429:
            temp["Status"] = "Rate limit exceeded"
            print("VirusTotal rate limit reached.")

        else:
            response.raise_for_status()

            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})

            temp["SHA256"] = attributes.get("sha256", "")
            temp["MD5"] = attributes.get("md5", "")
            temp["File Name"] = attributes.get("meaningful_name", "")
            temp["File Type"] = attributes.get("type_description", "")
            temp["File Size (bytes)"] = attributes.get("size", "")
            temp["Malicious Detections"] = stats.get("malicious", "")
            temp["Suspicious Detections"] = stats.get("suspicious", "")
            temp["Undetected"] = stats.get("undetected", "")
            temp["Reputation"] = attributes.get("reputation", "")

            classification = attributes.get(
                "popular_threat_classification", {}
            )
            temp["Threat Classification"] = classification.get(
                "suggested_threat_label", ""
            )

            temp["First Submission"] = format_timestamp(
                attributes.get("first_submission_date")
            )
            temp["Last Analysis"] = format_timestamp(
                attributes.get("last_analysis_date")
            )

            # Basic triage label, not a definitive safety verdict
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious >= 6:
                temp["Verdict"] = "Highly Malicious"
            elif malicious >= 3:
                temp["Verdict"] = "Malicious"
            elif malicious > 0 or suspicious > 0:
                temp["Verdict"] = "Suspicious"
            else:
                temp["Verdict"] = "No detections reported"

            temp["Status"] = "Success"

            print(
                f"[{index}/{len(hashes)}] {file_hash}: "
                f"{malicious} malicious detections"
            )

    except requests.RequestException as error:
        temp["Status"] = f"Request error: {error}"
        print(f"Request failed for {file_hash}: {error}")

    except (ValueError, KeyError, TypeError) as error:
        temp["Status"] = f"Response parsing error: {error}"
        print(f"Could not parse response for {file_hash}: {error}")

    print(f"HTTP status: {response.status_code}", flush=True)
    
    final_data.append(temp)

    # Delay between API requests
    if index < len(hashes):
        time_module.sleep(20)


# Export results to results.csv
output_file = PROJECT_ROOT / "VTLookup" / "results.csv"

fieldnames = [
    "hash",
    "SHA256",
    "MD5",
    "File Name",
    "File Type",
    "File Size (bytes)",
    "Malicious Detections",
    "Suspicious Detections",
    "Undetected",
    "Reputation",
    "Threat Classification",
    "First Submission",
    "Last Analysis",
    "Verdict",
    "Status",
]

with open(
    output_file,
    "w",
    newline="",
    encoding="utf-8-sig"
) as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(final_data)

print(f"\nCompleted. Results saved to: {output_file}")
