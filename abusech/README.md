# abuse.ch IOC Enrichment

A Python utility for checking indicators against abuse.ch threat-intelligence services, including ThreatFox, MalwareBazaar, and URLhaus.

## Features

- Checks supported IOC types against the relevant abuse.ch service.
- Supports indicator and hash input files in CSV or text formats.
- Produces a consolidated CSV report with source, verdict, status, and available enrichment fields.
- Applies a short delay between requests and records lookup errors where available.

Service coverage depends on the indicator type and the current behavior of each upstream API.

## Requirements

- Python 3
- Python packages: `requests`, `python-dotenv`
- API credentials required by the selected abuse.ch service(s)

Install dependencies from the repository root:

```bash
python -m pip install requests python-dotenv
```

## Configure API credentials

The script reads environment variables from an `.env` file in the `abusech` directory and also checks the process environment. Configure the key(s) required by the API calls you use, for example:

```dotenv
ABUSECH_API_KEY=your_abusech_api_key
MALWAREBAZAAR_API_KEY=your_malwarebazaar_api_key
```

The exact credential requirements may vary by endpoint and provider policy. Do not commit real credentials; keep `.env` local and use repository secrets for automated workflows.

## Input files

The script looks in the `abusech` directory for supported input filenames, including:

- `indicators.csv`
- `hashes.csv`
- `indicators.txt`
- `hashes.txt`

The repository includes `indicators.csv`. Review the input format and sample rows before adding a batch. Remove duplicate or irrelevant entries where practical.

## Run

From the repository root:

```bash
python abusech/abusech.py
```

The script selects an available supported input file from its directory and writes the report to the same directory.

## Output

Results are written to `abusech/abusech_ioc_results.csv`. The report contains the indicator, indicator type, data source, verdict, query status, and other fields returned or derived by the script.

Common outcomes can include a match, no match, unsupported indicator type, authentication issue, rate limit, or request error. Use the status and error columns to distinguish a negative lookup from a failed request.

## Troubleshooting

- **Missing API key:** check the relevant environment variable(s) and the local `.env` file.
- **Authentication errors:** verify the key required for the specific abuse.ch endpoint.
- **Rate limits or timeouts:** retry later and respect the service's published limits.
- **No results:** confirm the IOC format and remember that absence from a feed is not a benign verdict.

## Responsible use

ThreatFox, MalwareBazaar, and URLhaus provide useful threat-intelligence context, but a match is not by itself proof of compromise. Correlate findings with SIEM/EDR telemetry and other sources. Follow abuse.ch usage policies and handle investigation data appropriately.
