# AbuseIPDB IP Reputation Lookup

A Python command-line tool for checking IPv4 and IPv6 indicators against the AbuseIPDB API and exporting the results to CSV.

## Features

- Looks up individual public IP addresses.
- Reads indicators from a text or CSV input file.
- Validates and deduplicates indicators.
- Reports abuse confidence score, report count, distinct reporters, last reported time, country, ISP, usage type, domain, and related metadata where available.
- Supports configurable report lookback, request delay, and output path.
- Records skipped inputs and request errors in the output.

AbuseIPDB's check endpoint is intended for IP addresses. Non-IP indicators are marked as unsupported rather than treated as IP reputation results.

## Requirements

- Python 3
- An AbuseIPDB API key
- Python package: `requests`

Install from the repository root:

```bash
python -m pip install requests
```

## Configure the API key

Set the environment variable `ABUSEIPDB_API_KEY`.

Linux/macOS/GitHub Codespaces:

```bash
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

Windows PowerShell:

```powershell
$env:ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
```

Do not hard-code or commit your API key. For GitHub Actions, add it as a repository secret named `ABUSEIPDB_API_KEY`.

## Input

The script accepts an optional input path. Without one, it uses its input-selection logic to locate a supported text or CSV file in the `abuseipdb` directory. The repository contains `indicators.csv`.

Example text file, one IP per line:

```text
8.8.8.8
1.1.1.1
```

## Usage

Run from the repository root:

```bash
python abuseipdb/abuseipdb.py --help
```

Check a file and write to the default output:

```bash
python abuseipdb/abuseipdb.py abuseipdb/indicators.csv
```

Set a custom output path, report lookback, and delay:

```bash
python abuseipdb/abuseipdb.py abuseipdb/indicators.csv --output abuseipdb/custom_results.csv --max-age 90 --delay 1
```

Options:

- `input_file`: optional TXT/CSV input path.
- `-o, --output`: output CSV path; default is `abuseipdb_results.csv` beside the script.
- `--max-age DAYS`: report lookback from 1 to 365 days; default is 90.
- `--delay SECONDS`: pause between requests; default is 1 second.

Use `--help` for the authoritative options supported by the current script version.

## Output

The default output is `abuseipdb/abuseipdb_results.csv`. Fields include IP address/version, query status, abuse confidence score, total reports, distinct reporters, last reported time, country code, ISP, usage type, domain, whitelist status, and error details.

## Interpreting results

An abuse confidence score reflects AbuseIPDB's reports and scoring methodology; it is not proof that the IP is currently attacking your environment. Consider report recency, source context, NAT/shared hosting, and internal firewall/proxy/EDR logs before blocking an address. A failed or rate-limited query must not be interpreted as a clean result.

## Troubleshooting

- **Missing key:** set `ABUSEIPDB_API_KEY` in the environment used to launch Python.
- **HTTP authentication error:** check the key and API plan.
- **Rate limited:** wait before retrying and reduce request frequency.
- **No output:** check that the input file exists and contains valid IP addresses.

## Responsible use

Use this tool for authorized SOC triage, threat hunting, and incident response. Respect API quotas and protect any internal indicators or report files that may be sensitive.
