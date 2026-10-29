# AlienVault Open Threat Exchange (OTX) IOC Lookup

This utility checks indicators against the general indicator endpoint of the AlienVault OTX API and exports a compact CSV report for security triage.

## Features

- Supports IP addresses, IPv6, domains, hostnames, URLs, file hashes, and CVE identifiers when the corresponding type is supplied or detected.
- Reads a CSV file with a required `indicator` column and an optional `type` column.
- Infers common indicator types when `type` is empty.
- Removes duplicate indicators and queries OTX using a configurable worker pool.
- Exports pulse count, reputation, country, ASN, status, error details, and an OTX indicator link.

This is a deliberately lightweight lookup: it queries the OTX **general** endpoint and does not collect detailed pulse names or tags.

## Requirements

- Python 3
- An AlienVault OTX API key
- Python packages: `requests`, `python-dotenv`

Install dependencies from the repository root:

```bash
python -m pip install requests python-dotenv
```

## Configure

The script loads `.env` from the repository root. Add:

```dotenv
OTX_API_KEY=your_otx_api_key
OTX_WORKERS=5
```

`OTX_WORKERS` is optional; the script limits the configured value to 1–10 workers. Never commit a real API key.

## Input

Edit `OTXalienvault/indicators.csv`. It must contain an `indicator` header. The optional `type` column can override automatic detection.

Example:

```csv
indicator,type
8.8.8.8,IP
example.com,DOMAIN
https://example.org/,URL
44d88612fea8a8f36de82e1278abb02f,MD5
CVE-2024-0001,CVE
```

Supported type labels include IP/IPV4, IPV6, DOMAIN, HOSTNAME, URL, MD5, SHA1, SHA256, FILEHASH-MD5, FILEHASH-SHA1, FILEHASH-SHA256, and CVE. Ensure the type value is compatible with the script's mapping.

## Run

From the repository root:

```bash
python OTXalienvault/otxalienvault.py
```

## Output

Results are saved to `OTXalienvault/otx_results.csv`. Key fields include:

- `indicator` and `indicator_type`
- `lookup_status` (for example, `FOUND_WITH_PULSES`, `FOUND_NO_PULSES`, `NOT_FOUND`, `RATE_LIMITED`, or `AUTH_ERROR`)
- `pulse_count`, `reputation`, `country`, and `asn`
- `otx_link` and `error`

A pulse association is a lead for investigation, not proof that an indicator is malicious. Likewise, no pulse association or a missing result does not prove an indicator is benign.

## Troubleshooting

- **Missing key:** set `OTX_API_KEY` in the repository-root `.env` or environment.
- **Authentication error:** validate the key and its permissions.
- **Rate limited:** review the `Retry-After` response and retry later.
- **Invalid type:** verify the optional `type` column against the supported labels.
- **No indicators loaded:** ensure the CSV has an `indicator` column and non-empty values.

## Responsible use

Use OTX as one source in a broader investigation. Validate findings against internal telemetry and other trusted intelligence sources before taking response actions. Follow the provider's terms, quotas, and data-handling requirements.
