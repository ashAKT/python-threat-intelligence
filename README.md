# Python for Cybersecurity

A collection of Python-based utilities for SOC operations, IOC enrichment, threat intelligence lookup, and defensive threat hunting. The repository combines standalone scripts with manually triggered GitHub Actions workflows for repeatable lookups.

> **Use responsibly:** These tools support investigation and triage. A provider hit is not, by itself, proof that a host is compromised, and no result is not proof that an indicator is benign. Validate findings against SIEM/EDR telemetry and multiple trustworthy sources. Use reconnaissance and scanning features only when authorized.

## Tool Directory

| Tool / folder | Purpose | Main inputs | Output / result |
|---|---|---|---|
| [VirusTotal IOC Lookup](VTLookup/) | Enrich file hashes, IPs, domains, and URLs using VirusTotal | `VTLookup/ioc.csv` | `VTLookup/results.csv` |
| [abuse.ch IOC Enrichment](abusech/) | Query ThreatFox, MalwareBazaar, and URLhaus for supported indicators | Indicators/hashes TXT or CSV; see script | `abusech/abusech_ioc_results.csv` |
| [AbuseIPDB](abuseipdb/) | Check IP abuse reputation, confidence score, reports, ISP, and related context | TXT/CSV of indicators; see script help | `abuseipdb/abuseipdb_results.csv` or selected output |
| [FreeIPAPI](freeipapi/) | Retrieve IP geolocation, ASN, and proxy-related fields supported by the API | `freeipapi/ips.txt` | `freeipapi/ip_enrichment_results.csv` |
| [AlienVault OTX](OTXalienvault/) | Look up IPs, domains, URLs, hashes, and CVEs in OTX | `OTXalienvault/indicators.csv` | `OTXalienvault/otx_results.csv` |
| [MISSP — MISP Threat Intelligence Collector & IOC Search](missp/) | Collect supported MISP feed data into a searchable IOC database and search for matches | Feed collection configuration and individual/list IOCs | IOC database and `ioc_matches.csv`; see [tool README](missp/README.md) |
| [ViewDNS.info Enrichment](viewdnsinfo/) | Enrich IPs/domains with DNS, historical IP, WHOIS, reverse lookup, spam-database and related infrastructure context supported by your account | `viewdnsinfo/ioc.txt` or command-line input | `viewdnsinfo/viewdns_results.csv` and `viewdnsinfo/viewdns_results.json` |

The folders contain the scripts, inputs, and tool-specific documentation. Read each folder's README where available and use each script's `--help` output for its exact supported arguments. API fields, access, rate limits, and results depend on the external provider and your account.

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/ashAKT/python_for_cybersecurity.git
cd python_for_cybersecurity
```

Use an isolated Python virtual environment if possible:

**Linux / macOS / GitHub Codespaces**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

**Windows PowerShell**
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

Install dependencies needed by the particular tool. Common packages include `requests` and `python-dotenv`; the MISSP tool has its own requirements file.

```bash
python -m pip install requests python-dotenv
python -m pip install -r missp/requirements.txt
```

### 2. Configure API keys securely

Do not put actual API keys or tokens into source code, IOC files, reports, or commits. Use environment variables locally and GitHub Actions secrets for workflows.

| Tool | Environment variable / GitHub Actions secret |
|---|---|
| VirusTotal | `VT_API_KEY` |
| abuse.ch (ThreatFox / MalwareBazaar / URLhaus integration) | `ABUSECH_API_KEY` where required by the configured integration |
| AbuseIPDB | `ABUSEIPDB_API_KEY` |
| AlienVault OTX | `OTX_API_KEY` |
| ViewDNS.info | `ViewDNSInfo_API_KEY` |
| FreeIPAPI | No key configured in the current script; check the provider's current terms and limits |

Set a key for the current terminal session:

**Linux / macOS / GitHub Codespaces**
```bash
export VT_API_KEY="YOUR_VIRUSTOTAL_KEY"
export ABUSECH_API_KEY="YOUR_ABUSECH_KEY"
export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_KEY"
export OTX_API_KEY="YOUR_OTX_KEY"
export ViewDNSInfo_API_KEY="YOUR_VIEWDNS_KEY"
```

**Windows PowerShell**
```powershell
$env:VT_API_KEY = "YOUR_VIRUSTOTAL_KEY"
$env:ABUSECH_API_KEY = "YOUR_ABUSECH_KEY"
$env:ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY"
$env:OTX_API_KEY = "YOUR_OTX_KEY"
$env:ViewDNSInfo_API_KEY = "YOUR_VIEWDNS_KEY"
```

Only set the variables for the tools you intend to use. Some scripts load a repository-root `.env` file via `python-dotenv`; if you use one, keep it local and verify it is excluded by `.gitignore`. Never commit real credentials. For GitHub Actions, create the corresponding secrets in **Settings → Secrets and variables → Actions**.

## Tool Utilization

### 1. VirusTotal — files, IPs, domains, and URLs

Folder: [`VTLookup/`](VTLookup/)  
Script: [`vtlookup.py`](VTLookup/vtlookup.py)

The script detects supported IOC types and queries VirusTotal for file hashes, IP addresses, domains, and URLs. It exports detection statistics and available context to CSV.

1. Add one IOC per row to `VTLookup/ioc.csv` (the script recognizes common IOC headers such as `ioc`).
2. Configure `VT_API_KEY`.
3. Run from the repository root:

```bash
python VTLookup/vtlookup.py
```

4. Review `VTLookup/results.csv`. Check the status column for missing reports, rate limiting, or API access errors.

A VirusTotal verdict is based on the returned analysis statistics and the script's local classification logic. Review detections and context before taking action.

### 2. abuse.ch — ThreatFox, MalwareBazaar, and URLhaus

Folder: [`abusech/`](abusech/)  
Script: [`abusech.py`](abusech/abusech.py)

Use this tool to check supported IPs, domains, URLs, and hashes against abuse.ch threat-intelligence services. The resulting records can include verdict/status, threat type, malware family, confidence, timestamps, tags, and references when available.

1. Place indicators in a supported input file such as `indicators.csv`, `hashes.csv`, `indicators.txt`, or `hashes.txt`, following the script's input handling.
2. Configure `ABUSECH_API_KEY` if required by the endpoints used.
3. Run:

```bash
python abusech/abusech.py
```

4. Review `abusech/abusech_ioc_results.csv`, paying attention to source, query status, and error fields.

Check current service documentation and key requirements before using the script because API authentication policies may vary by service.

### 3. AbuseIPDB — IP abuse reputation

Folder: [`abuseipdb/`](abuseipdb/)  
Script: [`abuseipdb.py`](abuseipdb/abuseipdb.py)

Use this tool to enrich IP addresses with supported abuse-reputation data, such as abuse confidence score, report count, last report date, country, ISP, usage type, and associated domain.

```bash
python abuseipdb/abuseipdb.py --help
```

Set `ABUSEIPDB_API_KEY`, then follow the script's help to specify an input file and optional output path. The current GitHub Actions workflow accepts pasted indicators but queries IP addresses only; other indicator types are not equivalent to an IP reputation lookup.

Interpret report counts and confidence as reputation signals rather than automatic proof of malicious activity.

### 4. FreeIPAPI — IP geolocation and network context

Folder: [`freeipapi/`](freeipapi/)  
Script: [`freeipapi.py`](freeipapi/freeipapi.py)

Use this tool to look up public IP addresses and export returned geolocation, ASN, organization, and proxy fields where available.

1. Add IP addresses to `freeipapi/ips.txt`, one per line (comma-separated entries are also accepted).
2. Run:

```bash
python freeipapi/freeipapi.py
```

3. Review `freeipapi/ip_enrichment_results.csv`.

IP geolocation is approximate. VPNs, proxies, cloud hosting, mobile networks, and address reassignment can make a location misleading. Do not use geolocation alone to attribute activity to a person or organization.

### 5. AlienVault OTX — threat intelligence lookup

Folder: [`OTXalienvault/`](OTXalienvault/)  
Script: [`otxalienvault.py`](OTXalienvault/otxalienvault.py)

Use OTX to look up supported IP addresses, domains, URLs, hashes, and CVEs and obtain indicator context such as pulse associations, reputation, country, or ASN when returned by the API.

1. Add indicators to `OTXalienvault/indicators.csv` using the expected `indicator` column (and optional `type` column).
2. Configure `OTX_API_KEY`.
3. Run:

```bash
python OTXalienvault/otxalienvault.py
```

4. Review `OTXalienvault/otx_results.csv`.

A pulse association is an investigative lead, not conclusive evidence that the IOC is malicious.

### 6. MISSP — MISP feed collection and IOC search

Folder: [`missp/`](missp/)  
Documentation: [`missp/README.md`](missp/README.md)

The collector retrieves supported MISP threat-intelligence feed data, caches data, and produces a database that can be searched for exact IOC matches. The search tool supports IPs, domains, URLs, and file hashes according to the local IOC database's fields.

From the `missp/` directory:

```bash
python missp.py --help
python missp.py
python ioc_search.py --help
python ioc_search.py --ioc 8.8.8.8
python ioc_search.py --input input_iocs.txt
python ioc_search.py --input input.csv --column ioc
```

Run the collector before searching if the local threat database has not been generated or updated. Review [MISSP's README](missp/README.md) for feed configuration, cache files, Git LFS, database format, limitations, and supported options. A match means the IOC exists in the collected database; no match does not mean safe.

### 7. ViewDNS.info — DNS and infrastructure enrichment

Folder: [`viewdnsinfo/`](viewdnsinfo/)  
Documentation: [`viewdnsinfo/README.md`](viewdnsinfo/README.md)  
Script: [`viewdnsinfo_enrich.py`](viewdnsinfo/viewdnsinfo_enrich.py)

ViewDNS enriches domains and IPs with infrastructure-oriented context supported by the account, such as DNS records, IP history, IP location, reverse IP/DNS, WHOIS, spam database lookup, and abuse contacts.

Configure `ViewDNSInfo_API_KEY`, then run from the repository root:

```bash
python viewdnsinfo/viewdnsinfo_enrich.py --help
python viewdnsinfo/viewdnsinfo_enrich.py --input viewdnsinfo/ioc.txt
python viewdnsinfo/viewdnsinfo_enrich.py --indicator example.com
```

Review the JSON and CSV reports generated by the script. Confirm the current API parameters and account quota in the [official ViewDNS documentation](https://viewdns.info/api/documentation/). Use the tool README for supported flags and detailed setup.

## GitHub Actions — run lookups from the Actions tab

The repository includes manually triggered workflows in [`.github/workflows/`](.github/workflows/). The currently present workflows are:

| Workflow file | Purpose | Required Actions secret |
|---|---|---|
| [VirusTotal IOC Lookup](.github/workflows/virustotal-lookup.yml) | Submit mixed IOCs for VirusTotal enrichment | `VT_API_KEY` |
| [abuse.ch lookup](.github/workflows/abuse-ch.yml) | Query configured abuse.ch services | `ABUSECH_API_KEY` |
| [AbuseIPDB Lookup](.github/workflows/abuseipdb-lookup.yml) | Enrich submitted IP indicators | `ABUSEIPDB_API_KEY` |
| [FreeIPAPI IP Lookup](.github/workflows/freeipapi-lookup.yml) | Enrich submitted IP addresses | No key referenced by current workflow |
| [AlienVault OTX Lookup](.github/workflows/otx-alienvault-lookup.yml) | Submit mixed IOCs to OTX | `OTX_API_KEY` |
| [MISSP IOC Search](.github/workflows/missp-ioc-search.yml) | Search the collected MISP IOC database | No API secret referenced by current workflow |

To run a workflow:

1. Open the repository's **Actions** tab.
2. Select a workflow from the list above.
3. Choose **Run workflow**.
4. Supply the requested IPs or IOCs in the supported comma-, space-, or newline-separated format.
5. Review the run logs, then download the generated artifact if the run uploaded one.

Create the required API key under **Settings → Secrets and variables → Actions** before running workflows that use a secret. Do not paste API keys into workflow inputs. Artifacts are configured with limited retention (currently seven days in the workflows above). Failed lookups, quota limitations, missing secrets, or provider errors can affect results.

## Recommended SOC investigation workflow

1. **Normalize and validate** the indicator (IP, domain, URL, hash, or CVE) and preserve its original source and timestamp.
2. **Enrich across suitable providers**: for example, VirusTotal for hashes/URLs/domains/IPs; abuse.ch for supported malware and URL indicators; AbuseIPDB for IP abuse reputation; OTX and MISSP for threat-intelligence matches; FreeIPAPI for IP context; ViewDNS for domain and infrastructure pivots.
3. **Compare evidence** such as report counts, timestamps, malware-family labels, DNS history, ASN, and provider sources. Consider conflicts and data freshness.
4. **Correlate with internal telemetry** such as DNS, proxy, firewall, EDR, authentication, and SIEM logs.
5. **Document analyst reasoning** and distinguish confirmed observations from hypotheses. Escalate or block only under your organization's incident-response process.

## Repository layout

```text
.
├── .github/workflows/       # Manual GitHub Actions lookup workflows
├── OTXalienvault/           # AlienVault OTX IOC lookup
├── VTLookup/                # VirusTotal IOC lookup
├── abusech/                 # ThreatFox, MalwareBazaar, URLhaus enrichment
├── abuseipdb/               # AbuseIPDB IP reputation
├── freeipapi/               # IP geolocation / ASN enrichment
├── missp/                   # MISP feed collector and IOC search
├── viewdnsinfo/             # ViewDNS domain/IP infrastructure enrichment
├── references.txt           # Reference links
└── README.md                # Repository overview and utilization guide
```

Sample inputs and output reports are kept within individual tool folders. Review reports before committing or sharing them because they may contain investigative indicators and metadata. Avoid committing large generated reports or sensitive incident information unless necessary.

## Security, privacy, and reliability

- Store secrets in environment variables or GitHub Actions secrets; rotate any credential accidentally committed.
- Follow provider terms, rate limits, and API access rules.
- Validate external API responses and handle timeouts, rate limits, and missing fields.
- An indicator's absence from a provider database is not a benign verdict.
- Geolocation and WHOIS data may be incomplete or inaccurate; registration privacy and shared hosting limit attribution.
- Use results as one source of evidence. Avoid automatic blocking based on a single provider's rating.
- Use all reconnaissance features only for authorized defensive purposes.

## References

- [VirusTotal API documentation](https://docs.virustotal.com/)
- [abuse.ch](https://abuse.ch/)
- [AbuseIPDB API documentation](https://docs.abuseipdb.com/)
- [FreeIPAPI](https://freeipapi.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [MISP project](https://www.misp-project.org/)
- [ViewDNS.info API documentation](https://viewdns.info/api/documentation/)
