# ViewDNS.info IOC Enrichment

A Python utility for enriching IP addresses and domain names with infrastructure intelligence from the [ViewDNS.info API](https://viewdns.info/api/documentation/).

## Features

The `viewdnsinfo_enrich.py` script supports single-indicator and bulk lookups from a text file. Available checks in the script include:

- DNS record lookup
- Domain IP history
- IP geolocation
- Reverse IP lookup
- Spam database lookup
- Abuse contact lookup
- WHOIS lookup
- Reverse DNS lookup

Endpoint availability, API limits, and returned data depend on your ViewDNS account and the service's current API documentation.

## Requirements

- Python 3
- A ViewDNS.info API key
- The Python dependencies required by the script (currently `requests`)

Install the dependency:

```bash
python -m pip install requests
```

## Configure the API key

The script expects the API key in an environment variable named `ViewDNSInfo_API_KEY`.

### Linux / macOS / GitHub Codespaces

```bash
export ViewDNSInfo_API_KEY="YOUR_ACTUAL_API_KEY"
```

### Windows PowerShell

```powershell
$env:ViewDNSInfo_API_KEY = "YOUR_ACTUAL_API_KEY"
```

Do not place your real API key directly in the source code or commit it to Git.

## Input file

The repository includes `ioc.txt`. The script accepts one IP address, domain, or URL per line. You can also create your own file, for example `iocs.txt`:

```text
8.8.8.8
example.com
https://example.org/path
```

Review the indicators in `ioc.txt` before running the script, particularly if they came from a live incident or a client environment.

## Usage

Run these commands from the `viewdnsinfo` directory.

### Show help

```bash
python viewdnsinfo_enrich.py --help
```

### Enrich the indicators in `ioc.txt`

```bash
python viewdnsinfo_enrich.py --input ioc.txt
```

### Enrich one domain

```bash
python viewdnsinfo_enrich.py --indicator example.com
```

### Select specific checks

```bash
python viewdnsinfo_enrich.py --indicator example.com --checks dnsrecord,iphistory,whois
```

### Use a slower request interval for bulk runs

```bash
python viewdnsinfo_enrich.py --input ioc.txt --delay 1.0 --output viewdns_results
```

Use the script's `--help` output as the authoritative list of supported arguments and check names for the committed version.

## Output

The script writes JSON and CSV results to the output location specified by its arguments. The repository currently contains sample/result files named `viewdns_results.json` and `viewdns_results.csv`. Inspect them carefully before committing new results, as they may contain investigation data.

For new runs, prefer a separate output prefix so existing results are not overwritten unintentionally.

## Troubleshooting

- **API key missing:** confirm the environment variable is set in the same terminal where the script is run.
- **Authentication failure:** verify the key and check that your ViewDNS plan permits the requested endpoint.
- **Quota or rate-limit response:** reduce request frequency and check your account's limits.
- **No data returned:** missing data does not prove an indicator is benign; validate the indicator and consult other sources.
- **Unexpected API response:** check the [official API documentation](https://viewdns.info/api/documentation/) for endpoint parameters and response formats.

## Security and responsible use

- Keep API keys in environment variables or a secrets manager; never commit credentials.
- Follow the ViewDNS terms of use, quotas, and rate limits.
- Use scanning and reconnaissance functionality only on systems for which you have authorization.
- Treat infrastructure and spam-database results as supporting context, not as a definitive malware verdict.
- Correlate results with SIEM/EDR telemetry and other threat-intelligence sources before making blocking or incident decisions.
