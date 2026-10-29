# Telegram Threat Intelligence Monitor

A Python-based Telegram OSINT helper that discovers candidate public channels, scans recent messages in accessible channels, and flags posts that contain configured client identifiers together with specific potential data-exposure indicators.

> **Important:** This is a collection and triage aid, not proof of a breach. Validate every finding with an analyst and trusted sources. Telegram search is limited; this tool does not search every public channel or perform unrestricted global post search.

## Features

- Discover candidate public channels using configurable threat-intelligence and client keywords.
- Scan recent messages in discovered channels, configured channels, and channels/supergroups visible in your Telegram dialogs.
- Match client watchlist identifiers against specific exposure phrases to reduce alerts from ordinary company mentions.
- Redact common sensitive patterns and URLs from stored message text.
- Export potential findings to CSV and JSON.
- Save discovered channel metadata separately.

## Files

| File | Purpose |
|---|---|
| `telegram_monitor.py` | Main discovery, scanning, matching, and reporting script |
| `config.json` | Discovery terms, client watchlist, and scan options |
| `telegram_test.py` | Simple Telegram authentication/connectivity test |
| `discovered_channels.json` | Generated channel discovery metadata |
| `telegram_findings.csv` | Generated findings report for spreadsheet review |
| `telegram_findings.json` | Generated structured findings report |
| `telegram_threat_intel.session` | Local Telethon authentication session; **never commit this file** |

## Requirements

- Python 3.10 or newer recommended.
- A Telegram account.
- Telegram API credentials from [my.telegram.org](https://my.telegram.org/apps).

Install dependencies from the repository root:

```bash
python -m pip install telethon python-dotenv
```

## Configure credentials

Create a `.env` file in the **repository root** (the parent directory of `telegram/`):

```dotenv
TELEGRAM_API_ID=your_numeric_api_id
TELEGRAM_API_HASH=your_api_hash
```

Use your actual credentials locally. Never paste them into source code, commit them, or share your Telethon session file. The first authenticated run may ask you to sign in to Telegram and enter a login code in your terminal.

## Configure the monitor

Edit `telegram/config.json`.

- `known_channels`: Optional usernames or channel references to scan explicitly. Use an empty list for automatic discovery plus accessible dialogs.
- `discovery_keywords`: Terms used to discover candidate channels through Telegram chat search.
- `client_watchlist`: Client names and identifiers to match. Replace the example values with approved identifiers, or use an empty list for a generic public configuration.
- `messages_per_channel`: Maximum number of recent messages to inspect per channel in each run.
- `max_discovered_channels_per_keyword`: Limit for new candidate channels retained for each discovery term.
- `scan_existing_dialogs`: Include channels and supergroups visible in your Telegram dialogs.
- `store_message_text`: Whether to store a redacted excerpt of matching messages.
- `store_source_message_link`: Whether to include links to matching messages when a public channel username is available.

Example client watchlist entry:

```json
{
  "name": "Example Client",
  "keywords": [
    "example.com",
    "Example Client",
    "ExampleClient"
  ]
}
```

Use only client identifiers you are authorized to monitor. If client details are confidential, keep them in a local configuration that is not committed to the repository.

## Run

From the repository root:

```bash
python telegram/telegram_test.py
python telegram/telegram_monitor.py
```

The test script checks whether Telegram authentication works. The monitor then discovers candidate channels, scans messages, and writes reports.

## Generated output

After a run, the following files are created in the `telegram/` directory:

- `discovered_channels.json` — candidate channels and the search terms that found them.
- `telegram_findings.csv` — spreadsheet-friendly findings.
- `telegram_findings.json` — structured findings.

These reports may contain sensitive operational information. Review them before sharing and keep them out of public Git commits unless you have explicitly approved their contents.

## Detection and limitations

- Channel discovery uses Telegram chat search; it is not exhaustive and may return no results for some terms.
- The script scans only the configured number of recent messages in channels it can access. It does not search all historical messages automatically.
- Global Telegram post search may require Telegram Premium or may be restricted for the account.
- Detection is based on text matching. It can miss paraphrases, obfuscated names, images, attachments, and messages that do not contain configured terms.
- Redaction is best-effort and cannot guarantee that all personal data, credentials, tokens, or secrets are removed.
- A keyword match is an unverified lead, not confirmation that a client has been compromised.
- Respect Telegram's terms, rate limits, channel access restrictions, privacy, and applicable law. Handle possible leaked credentials or personal information carefully; do not use exposed secrets to access systems.

## Security and Git hygiene

Add local credentials, session files, and generated reports to the repository's `.gitignore`:

```gitignore
.env
*.session
*.session-journal
telegram/discovered_channels.json
telegram/telegram_findings.csv
telegram/telegram_findings.json
```

If a Telegram session or API credential is accidentally committed or shared, revoke the exposed session/credential where applicable and rotate it before continuing.
