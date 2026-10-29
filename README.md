# Python for Cybersecurity

A collection of Python-based utilities for SOC operations, IOC enrichment, threat-intelligence lookup, infrastructure context, and defensive threat hunting. The repository contains standalone Python scripts and manually triggered GitHub Actions workflows.

> **Use responsibly:** These tools support investigation and triage. A provider hit is not, by itself, proof that a host is compromised, and no result is not proof that an indicator is benign. Validate findings against SIEM/EDR telemetry and multiple trustworthy sources. Use reconnaissance and scanning features only when authorized.

## Tool Directory

| Tool / folder | Purpose | Main inputs | Output / result |
|---|---|---|---|
| [VirusTotal IOC Lookup](VTLookup/) · [README](VTLookup/README.md) | Enrich file hashes, IPs, domains, and URLs | VTLookup/ioc.csv | VTLookup/results.csv |
| [abuse.ch IOC Enrichment](abusech/) · [README](abusech/README.md) | Query ThreatFox, MalwareBazaar, and URLhaus for supported indicators | TXT/CSV; see tool README | abusech/abusech_ioc_results.csv |
| [AbuseIPDB](abuseipdb/) · [README](abuseipdb/README.md) | IP abuse reputation, confidence scores, report counts, and network context | TXT/CSV; see script help | abuseipdb/abuseipdb_results.csv or selected output |
| [FreeIPAPI](freeipapi/) · [README](freeipapi/README.md) | IP geolocation, ASN, organization, and proxy-related fields where available | freeipapi/ips.txt | freeipapi/ip_enrichment_results.csv |
| [AlienVault OTX](OTXalienvault/) · [README](OTXalienvault/README.md) | Look up IPs, domains, URLs, hashes, and CVEs | OTXalienvault/indicators.csv | OTXalienvault/otx_results.csv |
| [MISSP — MISP feed collector and IOC search](missp/) · [README](missp/README.md) | Collect supported MISP feed data into a searchable local IOC database | Feed configuration and IOC inputs | Local database and ioc_matches.csv; see README |
| [ViewDNS.info enrichment](viewdnsinfo/) · [README](viewdnsinfo/README.md) | DNS, historical IP, WHOIS, reverse lookup, spam-database, and related infrastructure context supported by the account | viewdnsinfo/ioc.txt or CLI input | CSV and JSON reports |
| [Hybrid Analysis hash lookup](hybridanalysis/) · [README](hybridanalysis/README.md) | Look up MD5, SHA-1, and SHA-256 file hashes in Hybrid Analysis | hybridanalysis/indicators.csv or TXT | hybrid_analysis_results.csv and hybrid_analysis_raw.json |

Each project README describes setup, configuration, inputs, outputs, usage, and troubleshooting. Use a script's --help output as the authoritative list of supported arguments where available. API fields, access, rate limits, and results depend on the provider and your account.

## Quick Start

### 1. Clone the repository

    git clone https://github.com/ashAKT/python-threat-intelligence.git
    cd python-threat-intelligence

Use an isolated Python virtual environment if possible.

**Linux / macOS / GitHub Codespaces**

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip

**Windows PowerShell**

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip

Install the dependencies needed by the project you plan to use. Common packages include requests and python-dotenv; MISSP has its own requirements file.

    python -m pip install requests python-dotenv
    python -m pip install -r missp/requirements.txt

### 2. Configure API keys securely

Do not put actual API keys or tokens into source code, IOC files, reports, screenshots, or commits. Use local environment variables or a repository-root .env file where supported, and GitHub Actions secrets for automated workflows.

| Tool | Environment variable / GitHub Actions secret |
|---|---|
| VirusTotal | VT_API_KEY |
| abuse.ch integration | ABUSECH_API_KEY where required by the configured endpoint |
| AbuseIPDB | ABUSEIPDB_API_KEY |
| AlienVault OTX | OTX_API_KEY |
| ViewDNS.info | ViewDNSInfo_API_KEY |
| Hybrid Analysis | HYBRID_ANALYSIS_KEY |
| FreeIPAPI | No key configured in the current script; check provider terms and limits |
| MISSP local IOC search | No provider API key required for local searching; feed availability/configuration varies |

Example for Linux, macOS, or Codespaces:

    export VT_API_KEY="YOUR_VIRUSTOTAL_KEY"
    export ABUSECH_API_KEY="YOUR_ABUSECH_KEY"
    export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_KEY"
    export OTX_API_KEY="YOUR_OTX_KEY"
    export ViewDNSInfo_API_KEY="YOUR_VIEWDNS_KEY"
    export HYBRID_ANALYSIS_KEY="YOUR_HYBRID_ANALYSIS_KEY"

Example for Windows PowerShell:

    $env:VT_API_KEY = "YOUR_VIRUSTOTAL_KEY"
    $env:ABUSECH_API_KEY = "YOUR_ABUSECH_KEY"
    $env:ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY"
    $env:OTX_API_KEY = "YOUR_OTX_KEY"
    $env:ViewDNSInfo_API_KEY = "YOUR_VIEWDNS_KEY"
    $env:HYBRID_ANALYSIS_KEY = "YOUR_HYBRID_ANALYSIS_KEY"

Only configure the keys for tools you intend to use. The Hybrid Analysis and VirusTotal scripts load the repository-root .env via python-dotenv. The root .gitignore excludes .env; keep it that way. If a key is exposed, revoke or rotate it and update the local environment. For GitHub Actions, create corresponding secrets under **Settings → Secrets and variables → Actions**.

## Tool Utilization

### 1. VirusTotal — file hashes, IPs, domains, and URLs

Folder: [VTLookup](VTLookup/) · Script: [vtlookup.py](VTLookup/vtlookup.py) · Guide: [VTLookup README](VTLookup/README.md)

The script classifies supported indicators and queries VirusTotal API v3. It exports detection statistics and available context to CSV.

1. Add indicators to VTLookup/ioc.csv, using a recognized header such as ioc.
2. Configure VT_API_KEY.
3. Run from the repository root:

    python VTLookup/vtlookup.py

4. Review VTLookup/results.csv for detection statistics, status, missing reports, rate limiting, or access errors.

A VirusTotal verdict is based on returned analysis statistics and local classification logic. Review detections and context before taking action.

### 2. abuse.ch — ThreatFox, MalwareBazaar, and URLhaus

Folder: [abusech](abusech/) · Script: [abusech.py](abusech/abusech.py) · Guide: [abusech README](abusech/README.md)

Use the integration to check supported IPs, domains, URLs, and hashes against configured abuse.ch services. Results may include threat type, malware family, confidence, timestamps, tags, references, and query status.

1. Add indicators to a supported input file such as indicators.csv, hashes.csv, indicators.txt, or hashes.txt, following the script's input handling.
2. Configure ABUSECH_API_KEY if required by the endpoint.
3. Run:

    python abusech/abusech.py

4. Review abusech/abusech_ioc_results.csv.

Authentication requirements differ by service and can change; consult provider documentation and the project README.

### 3. AbuseIPDB — IP abuse reputation

Folder: [abuseipdb](abuseipdb/) · Guide: [abuseipdb README](abuseipdb/README.md)

Enrich IP addresses with supported reputation data such as abuse confidence score, report count, last report date, country, ISP, usage type, and associated domain.

    python abuseipdb/abuseipdb.py --help

Set ABUSEIPDB_API_KEY, then follow the script help to specify the input file and optional output path. The current GitHub Actions workflow queries IP addresses only; other indicator types are not equivalent to an IP reputation lookup. Treat confidence and report counts as signals, not proof of malicious activity.

### 4. FreeIPAPI — IP geolocation and network context

Folder: [freeipapi](freeipapi/) · Script: [freeipapi.py](freeipapi/freeipapi.py) · Guide: [FreeIPAPI README](freeipapi/README.md)

1. Add public IP addresses to freeipapi/ips.txt, one per line; comma-separated entries are also accepted.
2. Run:

    python freeipapi/freeipapi.py

3. Review freeipapi/ip_enrichment_results.csv.

Returned fields may include geolocation, ASN, organization, and proxy information. Geolocation is approximate; VPNs, proxies, cloud hosting, mobile networks, and reassignment can make location misleading. Do not use geolocation alone to attribute activity to a person or organization.

### 5. AlienVault OTX — threat-intelligence lookup

Folder: [OTXalienvault](OTXalienvault/) · Script: [otxalienvault.py](OTXalienvault/otxalienvault.py) · Guide: [OTX README](OTXalienvault/README.md)

Use OTX to look up supported IP addresses, domains, URLs, hashes, and CVEs and obtain indicator context such as pulse associations, reputation, country, or ASN when returned by the API.

1. Add indicators to OTXalienvault/indicators.csv using the expected indicator column and optional type column.
2. Configure OTX_API_KEY.
3. Run:

    python OTXalienvault/otxalienvault.py

4. Review OTXalienvault/otx_results.csv.

A pulse association is an investigative lead, not conclusive evidence that the IOC is malicious.

### 6. MISSP — MISP feed collection and IOC search

Folder: [missp](missp/) · Guide: [MISSP README](missp/README.md)

MISSP retrieves supported MISP feed data, caches it, and provides a searchable local IOC database. Searching supports IPs, domains, URLs, and hashes according to the local database fields.

From the missp/ directory:

    python missp.py --help
    python missp.py
    python ioc_search.py --help
    python ioc_search.py --ioc 8.8.8.8
    python ioc_search.py --input input_iocs.txt
    python ioc_search.py --input input.csv --column ioc

Run the collector before searching if the local database has not been generated or refreshed. See the project README for feed configuration, caching, Git LFS, database format, and options. A match means an IOC exists in the collected database; no match does not mean safe.

### 7. ViewDNS.info — DNS and infrastructure enrichment

Folder: [viewdnsinfo](viewdnsinfo/) · Script: [viewdnsinfo_enrich.py](viewdnsinfo/viewdnsinfo_enrich.py) · Guide: [ViewDNS README](viewdnsinfo/README.md)

ViewDNS enriches domains and IPs with infrastructure context supported by the account, such as DNS records, IP history, IP location, reverse IP/DNS, WHOIS, spam-database lookup, and abuse contacts.

Configure ViewDNSInfo_API_KEY, then run from the repository root:

    python viewdnsinfo/viewdnsinfo_enrich.py --help
    python viewdnsinfo/viewdnsinfo_enrich.py --input viewdnsinfo/ioc.txt
    python viewdnsinfo/viewdnsinfo_enrich.py --indicator example.com

Review the generated JSON and CSV reports. Confirm current API parameters and account quota in the [official ViewDNS documentation](https://viewdns.info/api/documentation/).

### 8. Hybrid Analysis — file hash lookup

Folder: [hybridanalysis](hybridanalysis/) · Script: [hybridanalysis.py](hybridanalysis/hybridanalysis.py) · Guide: [Hybrid Analysis README](hybridanalysis/README.md)

The currently committed version is deliberately **hash-only**. It queries MD5, SHA-1, and SHA-256 hashes using the Hybrid Analysis hash-search endpoint, skips URL/domain/IP indicators, and writes a CSV summary plus raw JSON response data.

1. Add hashes to hybridanalysis/indicators.csv under the indicator header, or provide a text file with one hash per line.
2. Set HYBRID_ANALYSIS_KEY in the repository-root .env.
3. Install dependencies and verify the key:

    python -m pip install requests python-dotenv
    python hybridanalysis/hybridanalysis.py --check-key

4. Run the lookup:

    python hybridanalysis/hybridanalysis.py hybridanalysis/indicators.csv

Outputs are written to hybridanalysis/hybrid_analysis_results.csv and hybridanalysis/hybrid_analysis_raw.json. A missing report or Unknown verdict does not mean the hash is benign. URL quick scans and historical domain/IP searches are not enabled in the committed hash-only script because the requests tested returned API validation/routing errors; see the project README and confirm the current schema with Hybrid Analysis before re-enabling them.

## GitHub Actions — run lookups from the Actions tab

The repository includes manually triggered workflows in .github/workflows/. The currently present workflows include:

| Workflow | Purpose | Required Actions secret |
|---|---|---|
| [VirusTotal IOC Lookup](.github/workflows/virustotal-lookup.yml) | Submit mixed IOCs for VirusTotal enrichment | VT_API_KEY |
| [abuse.ch lookup](.github/workflows/abuse-ch.yml) | Query configured abuse.ch services | ABUSECH_API_KEY |
| [AbuseIPDB Lookup](.github/workflows/abuseipdb-lookup.yml) | Enrich submitted IP indicators | ABUSEIPDB_API_KEY |
| [FreeIPAPI IP Lookup](.github/workflows/freeipapi-lookup.yml) | Enrich submitted IP addresses | No key referenced by current workflow |
| [AlienVault OTX Lookup](.github/workflows/otx-alienvault-lookup.yml) | Submit mixed IOCs to OTX | OTX_API_KEY |
| [MISSP IOC Search](.github/workflows/missp-ioc-search.yml) | Search the collected MISP IOC database | No API secret referenced by current workflow |

To run a workflow, open the repository's **Actions** tab, select the workflow, choose **Run workflow**, provide the requested indicators, and review the run logs. Download generated artifacts if the workflow uploaded them. Add required keys under **Settings → Secrets and variables → Actions**. Do not paste API keys into workflow inputs. Workflow artifacts may have limited retention. Missing secrets, provider errors, quotas, and rate limits can affect results.

## Recommended SOC investigation workflow

1. **Normalize and validate** the indicator (IP, domain, URL, hash, or CVE) and preserve its source and timestamp.
2. **Enrich with suitable providers:** VirusTotal for supported hashes/URLs/domains/IPs; abuse.ch for supported malware and URL indicators; AbuseIPDB for IP reputation; OTX and MISSP for threat-intelligence matches; FreeIPAPI for IP context; ViewDNS for domain/infrastructure pivots; Hybrid Analysis for file hashes.
3. **Compare evidence** such as report counts, timestamps, malware-family labels, DNS history, ASN, and provider sources. Consider conflicts and data freshness.
4. **Correlate with internal telemetry** such as DNS, proxy, firewall, EDR, authentication, and SIEM logs.
5. **Document analyst reasoning**, separating confirmed observations from hypotheses. Escalate or block only under your organization's incident-response process.

## Repository layout

    .
    ├── .github/workflows/   # Manually triggered lookup workflows
    ├── OTXalienvault/       # AlienVault OTX IOC lookup
    ├── VTLookup/            # VirusTotal IOC lookup
    ├── abusech/             # ThreatFox, MalwareBazaar, URLhaus
    ├── abuseipdb/           # AbuseIPDB IP reputation
    ├── freeipapi/           # IP geolocation and ASN enrichment
    ├── hybridanalysis/      # Hybrid Analysis hash lookup
    ├── missp/               # MISP feed collector and IOC search
    ├── viewdnsinfo/         # ViewDNS infrastructure enrichment
    ├── references.txt       # Reference links
    └── README.md            # Repository overview and utilization guide

Sample inputs and output reports are kept within individual tool folders. Review reports before committing or sharing them because they may contain investigative indicators and metadata. Avoid committing large generated reports or sensitive incident information unless necessary.

## Security, privacy, and reliability

- Store secrets in environment variables, a local ignored .env, or GitHub Actions secrets; never commit credentials.
- Rotate any credential that is accidentally exposed.
- Follow provider terms, rate limits, API access rules, and data-handling requirements.
- Handle timeouts, rate limits, missing fields, and unexpected external API responses.
- An indicator's absence from a provider database is not a benign verdict.
- Geolocation and WHOIS data may be incomplete or inaccurate; registration privacy and shared hosting limit attribution.
- Use multiple sources and internal telemetry; avoid automatic blocking based on a single provider's rating.
- Use reconnaissance and scanning features only for authorized defensive purposes.

## References

| Project | Official documentation / resource |
|---|---|
| VirusTotal | [API documentation](https://docs.virustotal.com/) · [API v3 reference](https://docs.virustotal.com/reference/overview) |
| abuse.ch | [abuse.ch services](https://abuse.ch/) · [API/authentication reference](https://hunting.abuse.ch/api/) |
| AbuseIPDB | [API documentation](https://docs.abuseipdb.com/) |
| FreeIPAPI | [FreeIPAPI website and API details](https://freeipapi.com/) |
| AlienVault OTX | [OTX portal](https://otx.alienvault.com/) · [API documentation](https://otx.alienvault.com/api) |
| MISP | [MISP project](https://www.misp-project.org/) · [MISP documentation](https://www.misp-project.org/documentation/) |
| ViewDNS.info | [API documentation](https://viewdns.info/api/documentation/) |
| Hybrid Analysis | [API v2 documentation](https://www.hybrid-analysis.com/docs/api/v2) · [API v2 changelog](https://www.hybrid-analysis.com/docs/api/v2-changelog) |
| MXToolbox (reference resource) | [API reference](https://mxtoolbox.com/api/api-reference) |

> **Note:** Provider APIs, authentication requirements, quotas, and available fields may change. Consult the provider's current official documentation before relying on an integration.
