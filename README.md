# Python for Cybersecurity

A collection of Python utilities and experiments for cybersecurity, threat intelligence, and security operations workflows.

## ViewDNS IOC Enrichment

The ViewDNS enrichment script can query ViewDNS.info for infrastructure context about IP addresses and domains. Depending on your API plan and supported endpoints, it can collect DNS records, historical IP information, WHOIS details, IP location, spam-database results, reverse IP/DNS information, and abuse contacts.

> **Important:** ViewDNS results provide investigation context, not a definitive malware verdict. Correlate results with trusted threat-intelligence sources and SIEM/EDR telemetry. API availability and request limits depend on your ViewDNS subscription.

### Requirements

- Python 3.10 or later recommended
- `requests`
- A ViewDNS.info API key

Install the dependency:

```bash
python -m pip install requests
```

If the script's folder contains a `requirements.txt`, you can instead install its dependencies with:

```bash
python -m pip install -r requirements.txt
```

### Configure the API key

The script reads the API key from the environment variable `ViewDNSInfo_API_KEY`. Do not hard-code the key in source files or commit it to Git.

**Linux / macOS / GitHub Codespaces:**

```bash
export ViewDNSInfo_API_KEY="YOUR_ACTUAL_API_KEY"
```

**Windows PowerShell:**

```powershell
$env:ViewDNSInfo_API_KEY = "YOUR_ACTUAL_API_KEY"
```

### Usage

Run these commands from the directory containing the ViewDNS script, or replace the script name with its repository-relative path.

Enrich a single domain:

```bash
python viewdns_enrich.py --indicator example.com
```

Enrich indicators from a text file (one IP address, domain, or URL per line):

```bash
python viewdns_enrich.py --input iocs.txt
```

Run selected checks:

```bash
python viewdns_enrich.py --indicator example.com --checks dnsrecord,iphistory,whois
```

Slow down requests for larger lists:

```bash
python viewdns_enrich.py --input iocs.txt --delay 1.0 --output reports/viewdns_results
```

Available checks in the script may include:

- `dnsrecord` — DNS record lookup
- `iphistory` — historical IP addresses for a domain
- `iplocation` — IP location information
- `reverseip` — domains associated with an IP/host
- `spamdblookup` — supported spam-database checks
- `abuselookup` — abuse contact lookup
- `whois` — domain registration information
- `reversedns` — reverse DNS lookup

Use `python viewdns_enrich.py --help` to see options available in the committed version of the script.

### Output

The script is designed to write:

- A JSON report containing the API responses
- A CSV report that can be opened in Excel

Check console output for failed requests, unsupported endpoints, authentication issues, or quota errors. Validate endpoint names and parameters against the [official ViewDNS API documentation](https://viewdns.info/api/documentation/).

### Security and responsible use

- Keep API keys in environment variables or an approved secrets manager.
- Never commit real API keys, access tokens, or other secrets.
- Respect ViewDNS terms of service, endpoint quotas, and rate limits.
- Use network scanning and reconnaissance features only on systems for which you have authorization.
- Treat missing data as unknown, not as proof that an indicator is benign.
