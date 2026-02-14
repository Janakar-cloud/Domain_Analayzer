### Domain Intelligence
Domain Intelligence is a Windows‑friendly Python application that helps security and IT teams understand what is exposed on their organization’s domains. It looks up public records, checks certificates, and reviews website content to highlight potential risks and areas to fix. You can run it locally, view results in a simple web UI, and export reports.

## What It Does (Plain English)
- Finds subdomains that were issued certificates in the past.
- Lists DNS records (addresses, mail servers, text records).
- Checks the website’s TLS certificate (who issued it, when it expires).
- Looks up domain registration details (whois, age, expiry).
- Optionally calls SSL Labs to get a TLS grade quickly.
- Follows redirects to see if the site hops around or downgrades security.
- Scans homepage and a few same‑site links for secrets accidentally exposed (API keys, tokens).
- Flags subdomains that might be at risk of takeover.
- Saves clear, exportable reports and small evidence snapshots.

## Quick Start (Windows)
- Prerequisites: Python 3.9+ and PowerShell
- Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

- Start the backend API (FastAPI) and the frontend (Streamlit):

```powershell
# Backend (port 8000)
python -m uvicorn src.server:app --host 127.0.0.1 --port 8000 --reload

# Frontend (port 8501)
streamlit run src/webui/app.py --server.port 8501
```

- Use the UI at http://127.0.0.1:8501. Enter domains (one per line), choose options, and run a scan.
- Or call the API directly:

```powershell
$body = @{ domains=@("example.com"); output_formats=@("json","csv","html"); skip_modules=@(); workers=12; fast_mode=$true } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scan -ContentType "application/json" -Body $body
```

## Performance Tuning (No Skipping)
- Fast Mode: caps timeouts and SSL Labs polling while keeping all modules on.
- Advanced Tuning: in the UI expander, adjust per‑module limits (CT timeout and max subdomains, DNS/TLS/WHOIS/Redirect timeouts, SSL Labs poll/attempts/cache age).
- Concurrency: increase Workers to scan multiple domains faster.

## Configuration
- Edit [config.yaml](config.yaml) to set defaults: enabled modules, timeouts, rate limits, output paths, and rules.
- API keys go in .env.local (optional): ABUSEIPDB_KEY, OTX_KEY, VT_KEY, CRIMINALIP_KEY, URLSCAN_KEY.
- Proxies: set `proxy.enabled` and HTTP/HTTPS proxy URLs if needed.
- Outputs: reports saved under `output/`, evidence under `evidence/`.

## Technical Architecture
- Backend: FastAPI (`src/server.py`) exposes `/health` and `/scan`.
- Frontend: Streamlit (`src/webui/app.py`) provides tabs for Posture, DNS, Certificate, Reputation, Findings.
- Scanner: Orchestrates modules concurrently per domain (`src/scanner.py`), applies rate limiting and collects results.
- Modules: Pluggable analyzers in `src/modules/` for CT, DNS, TLS, WHOIS, SSL Labs, redirects, content scan, takeover detection, and threat intel (local + optional external).
- Reporters: JSON/CSV/HTML in `src/reporters/` produce machine‑readable and human‑friendly outputs.
- Config: `src/core/config.py` loads YAML + .env and provides module settings (including Fast Mode overrides at runtime).

## Module Logic (How It Works)
- Certificate Transparency (`ct_enumeration`): queries crt.sh JSON, extracts names, filters valid subdomains, caps by `max_subdomains`, and adds findings for sensitive naming.
- DNS Enumeration (`dns_enumeration`): uses dnspython with resolver timeouts to collect A, AAAA, CNAME, NS, MX, TXT, SOA; analyzes SPF/DMARC/DKIM, nameserver sufficiency, and dangling CNAMEs.
- TLS Inspection (`tls_inspection`): connects via Python `ssl` to read cert details (CN, SANs, issuer, validity), flags expiry, mismatches, weak algorithms/keys, and self‑signed certs.
- WHOIS Lookup (`whois_lookup`): wraps python‑whois in a thread to enforce a timeout; parses registrar, org, country, dates, and age; flags newly registered or expiring domains and DNSSEC status.
- SSL Labs (`ssllabs`): calls the public API; prefers cached results; polls with capped attempts; maps grade to severity and lists protocols and known TLS vulnerabilities.
- Redirect Analysis (`redirect_analysis`): follows redirects with SSL verification; summarizes hop count and potential downgrade risks.
- Content Scanner (`content_scanner`):
	- Fetches homepage (and shallow same‑origin links if deep scan is on), with SSRF‑safe IP validation.
	- Caps body size and request timeout; records headers, hash, and snippets.
	- Uses curated regex patterns and entropy scoring to flag probable secrets; assigns confidence (low/medium/high) and stores `raw_data.hits` for UI table rendering.
	- Adds findings with severity based on strongest detected confidence.
- Takeover Detection (`takeover_detection`): checks for dangling CNAMEs (targets that do not resolve) as potential takeover candidates.
- Local Reputation (`threat_intel.local_reputation`): risk score from TLS expiry, WHOIS age, risky TLDs, redirects, takeover risk, and content scan severity; adds an overall reputation finding.
- External Threat Intel (optional): AbuseIPDB, OTX, VirusTotal, CriminalIP, URLScan integrate when keys are provided.

## Reporting (How Reports Are Generated)
- For each domain, modules run under the scanner and populate a `DomainResult` (subdomains, DNS, TLS cert, WHOIS, redirects, final URL, findings, errors, modules executed).
- Reporters then serialize:
	- JSON: complete structured results per domain, including evidence and `raw_data.hits`.
	- CSV: flattened summary rows; plus a per‑domain full asset inventory CSV.
	- HTML: human‑readable dashboard with severity coloring and sections aligned to the UI.
- Outputs land in `output/` with timestamped filenames; evidence files (headers, hash, snippets) go under `evidence/<domain>/`.

## Security & Compliance
- SSRF protection: only fetches if resolved IPs are public/non‑reserved.
- HTML safety: UI escapes content and renders a compact table for content hits.
- Rate limiting: module‑level caps reduce provider load and avoid bans.
- Legal use: run only against domains you own/manage or have explicit permission to test.

## API Reference
- `GET /health` → `{ "status": "ok" }`
- `POST /scan` → fields:
	- `domains: List[str]`
	- `output_formats: ["json","csv","html"]`
	- `skip_modules: List[str]` (optional)
	- `workers: int` (concurrency)
	- `fast_mode: bool` (keep modules on, shorten timeouts/polling)
	- Content overrides: `content_scanner_deep_scan: bool`, `content_scanner_link_limit: int`, `content_scanner_timeout_ms: int`
	- Advanced overrides: `ct_timeout`, `ct_max_subdomains`, `dns_timeout`, `tls_timeout`, `whois_timeout`, `redirect_timeout`, `ssllabs_timeout`, `ssllabs_poll_interval_seconds`, `ssllabs_max_attempts`, `ssllabs_max_age`
- Response contains `reports`, `summary` (severity counts, totals), and full `results`.

## CLI Usage
- Single domain:

```powershell
python cli.py --domain example.com
```

- Bulk domains from file:

```powershell
python cli.py --input domains.txt
```

- Generate reports for previous results:

```powershell
python cli.py report --output csv html
```

## Deployment (Windows VM)
- Use scripts for convenience:

```powershell
# Setup
.\scripts\deploy.ps1 -Setup

# Start backend
.\scripts\deploy.ps1 -StartBackend

# Start frontend
.\scripts\deploy.ps1 -StartFrontend
```

## Required API Keys (Optional)
- AbuseIPDB: ABUSEIPDB_KEY
- AlienVault OTX: OTX_KEY
- VirusTotal: VT_KEY
- CriminalIP: CRIMINALIP_KEY
- URLScan: URLSCAN_KEY (needed for private scans)
- Note: Local reputation and content scanning run without external keys; SSL Labs requires no key.

## Repo Cleanup
- Generated artifacts are ignored by .gitignore (`output/`, `evidence/`, `logs/`).
- To purge local artifacts:

```powershell
.\scripts\cleanup_repo.ps1
```

## Troubleshooting
- SSL Labs slow or unavailable: enable Fast Mode, reduce `ssllabs_max_attempts`, and increase `ssllabs_max_age` to favor cache.
- WHOIS stalls: the module enforces its own timeout; if registries are slow, results may be partial.
- YAML rules errors: use proper quoting in `local_rules.yaml` and keep regexes simple; the app logs parse warnings.
- Proxy usage: set `proxy.enabled` and HTTP/HTTPS URLs in `config.yaml`.

## Use Cases
- External attack surface discovery
- Shadow IT and forgotten subdomain identification
- Certificate lifecycle monitoring
- Email security posture assessment (SPF/DMARC)
- Threat hunting and SOC investigations
- Continuous external asset inventory

## Disclaimer
This tool is intended for authorized internal security testing only. Do not use it against domains you do not own or manage. Misuse may violate laws or provider terms of service.


