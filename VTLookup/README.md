# VirusTotal IOC Lookup

Python script for enriching indicators of compromise (IOCs) using the VirusTotal API v3. It classifies and queries IP addresses, domains, URLs, and file hashes, then writes a consolidated CSV report.

## Features

- Accepts IP addresses, domains, URLs, and MD5, SHA-1, SHA-256, or SHA-512 hashes.
- Reads indicators from `ioc.csv`, supports common IOC column headers, and removes duplicates.
- Collects available detection statistics, reputation, threat classification, and relevant file/network metadata.
- Records request status and a simple triage label in the output.
- Preserves the original IOC and exports results to CSV.

## Requirements

- Python 3
- A VirusTotal API key with access to the requested endpoints
- Python packages: `requests`, `python-dotenv`

Install dependencies from the repository root:

```bash
python -m pip install requests python-dotenv
```

## Configure the API key

The script loads `.env` from the repository root and expects `VT_API_KEY`.

Create a local `.env` file in the repository root:

```dotenv
VT_API_KEY=your_virustotal_api_key
```

Alternatively, set the environment variable in your shell.

**Never commit real API keys.** Keep `.env` out of version control and use GitHub Actions secrets for automated runs.

## Input

Edit `VTLookup/ioc.csv`. The script recognizes common headers such as `ioc`, `indicator`, `hash`, `ip`, `domain`, and `url`. If no recognized header is found, it treats cell values as indicators.

Example:

```csv
ioc
8.8.8.8
example.com
https://example.org/
44d88612fea8a8f36de82e1278abb02f
```

Use indicators you are authorized to investigate. Do not include API keys or other secrets in the input file.

## Run

Run from the repository root:

```bash
python VTLookup/vtlookup.py
```

The script checks the API key and reads the input file from the configured repository path. It intentionally waits about 20 seconds between API requests; large input sets may take a while. Keep within the rate limits of your VirusTotal plan.

## Output

Results are written to `VTLookup/results.csv`. Fields include:

- IOC and detected IOC type
- SHA-256 / MD5 and file metadata where available
- Malicious, suspicious, undetected, and harmless engine counts
- Reputation and threat classification
- Country, ASN, network, or URL title where available
- First submission and last analysis timestamps
- Triage verdict and request status

A report not found in VirusTotal is not proof that the IOC is benign. The script's verdict thresholds are only a triage aid, not a definitive security determination.

## Troubleshooting

- **Missing API key:** confirm `VT_API_KEY` is set in the repository-root `.env` or process environment.
- **HTTP 401/403:** verify the API key and whether your plan permits the endpoint.
- **Rate limit:** wait and retry within your plan's quota; avoid repeatedly submitting a large batch.
- **Report not found:** the provider may not have a report for that indicator.
- **Input not recognized:** check for blank rows, a valid header, and correctly formatted indicators.

## Responsible use

Correlate VirusTotal results with SIEM, EDR, DNS, proxy, firewall, and endpoint evidence. Do not block or close an incident based solely on one reputation result. Respect provider terms, quotas, and data-handling requirements.
