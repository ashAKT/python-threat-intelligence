# MISP Threat Intelligence Collector & IOC Search

**Version:** 1.0.0  
**Status:** Initial Release  
**Language:** Python 3

## Overview

MISP Threat Intelligence Collector & IOC Search is a Python-based tool designed to collect threat indicators from supported MISP feeds, consolidate threat intelligence into searchable databases, and perform IOC matching against collected indicators.

It helps security analysts quickly identify whether an IP address, domain, URL, or file hash is present in the collected threat intelligence feeds and determine which providers reported a match.

## Features

- Collect threat intelligence from supported MISP feeds.
- Retrieve and process MISP event data.
- Cache raw feed responses and event data to reduce unnecessary downloads.
- Export collected indicators to CSV and JSON.
- Generate feed metadata and error reports.
- Search individual or multiple IOCs against the collected database.
- Accept IOC input from command-line arguments, TXT files, and CSV files.
- Perform normalized, case-insensitive exact IOC matching.
- Identify threat intelligence providers associated with matching indicators.
- Export matching records to `ioc_matches.csv`.

## Project Structure

```text
missp/
├── missp.py
├── ioc_search.py
├── ioc.csv
├── threat_indicators.csv
├── threat_indicators.json
├── misp_available_feeds.csv
├── misp_feed_metadata.json
├── threat_feed_errors.csv
├── ioc_matches.csv
├── threat_feed_events/
├── threat_feed_raw/
├── README.md
├── requirements.txt
├── .gitignore
└── .gitattributes
```

Generated databases, reports, and cache directories may not be present until the collector has been executed.

## Requirements

- Python 3
- `requests`
- Internet connectivity to access configured threat intelligence feeds
- Git and Git LFS if downloading the large IOC database from this repository

## Installation

Clone the repository:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd missp
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

If the IOC database is stored using Git LFS, install Git LFS and pull the database:

```bash
git lfs install
git lfs pull
```

## Usage

### 1. Collect threat intelligence

Run the collector:

```bash
python missp.py
```

Use the supported command-line options to control feed selection and collection behavior. Check the available options with:

```bash
python missp.py --help
```

Depending on the selected feeds and configuration, the collector generates files such as:

- `threat_indicators.csv` — collected IOC database.
- `threat_indicators.json` — JSON representation of collected indicators.
- `misp_available_feeds.csv` — feed inventory.
- `misp_feed_metadata.json` — feed metadata.
- `threat_feed_errors.csv` — feed processing errors.

### 2. Search for a single IOC

Search for an IP address, domain, URL, or file hash:

```bash
python ioc_search.py --ioc 8.8.8.8
```

Replace the example IOC with the value you want to investigate.

### 3. Search multiple IOCs

Provide a text file containing one IOC per line:

```bash
python ioc_search.py --input input_iocs.txt
```

### 4. Search IOCs from a CSV file

Specify the input CSV and the column containing the IOCs:

```bash
python ioc_search.py --input input.csv --column ioc
```

### 5. Review matching results

The search tool reports matching indicators and their associated threat intelligence providers. Matching records are exported to:

```text
ioc_matches.csv
```

Use the command-line help to review all supported options:

```bash
python ioc_search.py --help
```

## Generated Files and Caching

The collector and search utility generate local databases, reports, and cache files. These files may contain large amounts of threat intelligence data.

- `threat_indicators.csv` — primary database used by the IOC search utility.
- `threat_indicators.json` — JSON export of collected indicators.
- `misp_available_feeds.csv` — feed inventory.
- `misp_feed_metadata.json` — feed metadata.
- `threat_feed_errors.csv` — feed errors.
- `ioc_matches.csv` — search results.
- `threat_feed_events/` — cached event data.
- `threat_feed_raw/` — cached raw feed responses.

The collector should be run before IOC searches when the database is not already available.

## Git LFS

The IOC CSV database may be large. Git LFS is used to manage `threat_indicators.csv` without storing the full database directly as a regular Git object.

After cloning the repository, run:

```bash
git lfs install
git lfs pull
```

Keep generated caches and temporary reports out of version control unless there is a specific reason to publish them.

## Planned Feature: GitHub Actions IOC Search

**Status: Planned — not implemented in v1.0.0.**

A future release is intended to support manually running IOC searches from the GitHub Actions tab.

The planned workflow will allow users to:

1. Open the repository's **Actions** tab.
2. Select the **IOC Search** workflow.
3. Enter an IP address, domain, URL, or file hash.
4. Manually start the workflow.
5. Review the search results and matching threat intelligence providers.
6. Download a results artifact, if supported by the implemented workflow.

The workflow is not available in this release. When implemented, it will need access to an IOC database snapshot. Updating a local database will not automatically update the GitHub-hosted database; the updated data must be published or made available through a configured storage source.

## Limitations

- Results depend on the feeds collected and the data available in the IOC database.
- An IOC match indicates that the indicator exists in the collected threat intelligence; it does not independently confirm that a system is compromised.
- A missing match does not establish that an IOC is benign.
- Feed availability, network restrictions, and provider changes may affect collection results.
- Feed access restrictions must be respected.

## Responsible Use

Use this tool for authorized security monitoring, threat hunting, incident response, and defensive threat intelligence analysis. Validate findings using additional telemetry and trusted sources before making blocking or incident-response decisions.

## Version History

### v1.0.0

- Initial release of the MISP threat intelligence collector.
- IOC database generation in CSV and JSON formats.
- IOC search using manual input, TXT files, and CSV files.
- Threat intelligence provider attribution for matching indicators.
- CSV export of matching records.
