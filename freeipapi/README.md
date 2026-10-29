# FreeIPAPI IP Enrichment

A lightweight Python utility that enriches IPv4 and IPv6 addresses using the FreeIPAPI JSON endpoint.

## Features

- Reads IP addresses from a text file.
- Accepts one IP per line and comma-separated IPs.
- Skips comments, blank lines, invalid entries, and duplicate addresses.
- Collects geolocation and network metadata returned by the API.
- Exports a CSV report and stops when an HTTP 429 rate limit is reached.

## Requirements

- Python 3
- Python package: `requests`
- Network access to the FreeIPAPI service

Install the dependency from the repository root:

```bash
python -m pip install requests
```

The current script does not configure an API key. Check the provider's current documentation for any changed access requirements or usage limits.

## Input

Edit `freeipapi/ips.txt`. Put one IP address per line, or separate multiple IP addresses with commas. Blank lines and lines starting with `#` are ignored.

Example:

```text
8.8.8.8
1.1.1.1
# add more IP addresses below
```

Only valid IP addresses are processed. Domain names and URLs are not supported by this script.

## Run

From the repository root:

```bash
python freeipapi/freeipapi.py
```

The script reads `ips.txt` and writes results incrementally so that completed lookups are retained if a later request fails.

## Output

Results are saved to `freeipapi/ip_enrichment_results.csv`. Available fields include:

- IP address and IP version
- Country, region, city, postal code, latitude, and longitude
- ASN and ASN organization
- Proxy indicator when returned by the API
- Request status and error information

## Troubleshooting

- **Input file not found:** ensure `freeipapi/ips.txt` exists.
- **Invalid IP skipped:** verify the address format; the script accepts IPv4 and IPv6.
- **Rate limited:** the script stops after HTTP 429 to avoid further requests. Wait and check the provider's usage policy before rerunning.
- **Missing metadata:** geolocation and ASN fields may be unavailable or approximate.

## Security and responsible use

IP geolocation is approximate and should not be treated as the physical location of a person or device. Use these results as enrichment context only, correlate with network and endpoint telemetry, and follow the provider's terms and rate limits.
