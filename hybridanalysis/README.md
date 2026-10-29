# Hybrid Analysis Hash Lookup

A Python utility for checking file hashes against the Hybrid Analysis API v2. It is part of the repository's SOC and threat-intelligence toolkit.

## Current capabilities

- Looks up MD5, SHA-1, and SHA-256 file hashes using the Hybrid Analysis hash-search endpoint.
- Accepts a CSV or text file and removes duplicate indicators.
- Writes a compact CSV summary and a raw JSON response file.
- Reports API errors and missing reports separately from verdicts.
- Supports a key-check option that does not print the API key.

**Current scope:** this committed version is deliberately in hash-only mode. URL, domain, and IP indicators are skipped. URL quick-scan submissions and historical domain/IP searches previously returned API validation/routing errors and are not enabled in this version.

## Requirements

- Python 3
- A Hybrid Analysis API key with access to the hash-search endpoint
- Python packages: `requests` and `python-dotenv`

Install dependencies from the repository root:

    python -m pip install requests python-dotenv

## Configuration

The script loads the repository-root `.env` file and reads the `HYBRID_ANALYSIS_KEY` variable.

Create a local file named `.env` in the repository root:

    HYBRID_ANALYSIS_KEY=your_hybrid_analysis_api_key

The repository's `.gitignore` excludes `.env`. Confirm that it remains ignored before committing. Never put API keys in source files, IOC input files, screenshots, logs, or commits. If a key is exposed, revoke or rotate it and update the local environment.

## Input

The included `indicators.csv` has an `indicator` column. Put one hash per row. MD5, SHA-1, and SHA-256 are recognized by their expected hexadecimal lengths.

Example:

    indicator
    44d88612fea8a8f36de82e1278abb02f
    a57de9c615d9e7b6c4bf48d777363dcb855b4ee0513d8775d61fdc955b23586a

A plain-text input file is also supported, with one indicator per line. Lines beginning with `#` and blank lines are ignored.

## Usage

Run from the repository root:

    python -m pip install requests python-dotenv
    python hybridanalysis/hybridanalysis.py --check-key
    python hybridanalysis/hybridanalysis.py hybridanalysis/indicators.csv

Or run from this folder:

    python hybridanalysis.py --check-key
    python hybridanalysis.py indicators.csv

The `--check-key` option verifies authentication without printing the key or account email.

## Output

The script writes these files into this folder:

- **`hybrid_analysis_results.csv`** — summary with indicator, hash type, status, and verdict.
- **`hybrid_analysis_raw.json`** — detailed API response data for troubleshooting and audit.

Generated output may contain investigation indicators or provider metadata. Review it before sharing or committing it.

## Status and verdict interpretation

- **Report Found:** the API returned one or more report records.
- **No Reports Found:** the hash lookup succeeded but returned no report records.
- **API Error / Connection Error:** the request failed; investigate the status code and error details.
- **Unknown:** no usable verdict was extracted. This is not a benign verdict.
- **Skipped - Hash Only Mode:** the indicator is not a supported hash format and was not queried.

A provider verdict is a triage signal, not standalone proof of compromise. Correlate it with SIEM, EDR, endpoint, network, and other threat-intelligence evidence.

## Troubleshooting

- **API key missing:** check the spelling of `HYBRID_ANALYSIS_KEY` in the repository-root `.env` and ensure the script is run from a location where the expected repository structure exists.
- **Authentication or permission errors:** verify the key and the access level available to the account.
- **No report found:** the provider may not have a report for the hash; this does not prove the file is safe.
- **URL/domain/IP is skipped:** this is intentional in the current hash-only version.
- **Unexpected API response:** inspect the sanitized response in `hybrid_analysis_raw.json` and consult the provider's current API documentation.

## API reference

- [Hybrid Analysis API v2 documentation](https://www.hybrid-analysis.com/docs/api/v2)
- [Hybrid Analysis API v2 changelog](https://www.hybrid-analysis.com/docs/api/v2-changelog)

API routes, supported operations, account permissions, quotas, and response fields may change. URL scanning and historical domain/IP lookup should only be re-enabled after confirming the currently supported request schema for the account.

## Responsible use

Use this utility for authorized defensive analysis. Respect provider terms and quotas, protect API credentials, and avoid automatic blocking based solely on one provider result.
