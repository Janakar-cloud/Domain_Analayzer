# Domain Intelligence – Comprehensive Guide

This guide explains how to install, configure, run, and operate Domain Intelligence on Windows. It also documents the architecture, module logic, performance tuning, reporting, security controls, and troubleshooting. The content is written for security/IT teams and includes step-by-step instructions.

## 1. Purpose and Scope (Plain English)
- Understand what is publicly exposed on your organization’s domains.
- Find subdomains, DNS records, certificate details, registration data, redirects, and potential secrets.
- Run locally, view results in a web UI, export reports. No personal accounts or logins are required.
- External threat-intel APIs are optional and disabled by default; the tool works inbuilt-only.

## 2. System Requirements
- Windows 10/11 (PowerShell 5.1 or PowerShell 7)
- Python 3.9+ (recommended 3.12/3.13)
- Internet access to public endpoints (crt.sh, DNS resolvers, SSL Labs if enabled)
- Optional: Microsoft Visual C++ Redistributable (for `cryptography`)

## 3. Installation (Windows)
### 3.1 Install Python
1. Download Python from https://www.python.org.
2. During install, check “Add Python to PATH”.
3. Verify:

```powershell
python --version
pip --version
```

### 3.2 Create Virtual Environment and Install Dependencies
From the repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
```

## 4. Configuration
### 4.1 Defaults
- Edit [config.yaml](../config.yaml) to choose modules, timeouts, rate limits, output directories.
- Tuned defaults favor speed while keeping all modules enabled (SSL Labs polling is capped; cached results preferred).

### 4.2 API Keys (Optional)
- For inbuilt-only operation, leave `.env.local` empty or omit it.
- If you later enable external providers, add keys in the repo root `.env.local`:
  - ABUSEIPDB_KEY, OTX_KEY, VT_KEY, CRIMINALIP_KEY, URLSCAN_KEY

### 4.3 Proxy Support
- In [config.yaml](../config.yaml), set `proxy.enabled: true` and specify `http`/`https` URLs for corporate proxies.

## 5. Running the Application
### 5.1 Backend API (FastAPI)

```powershell
python -m uvicorn src.server:app --host 127.0.0.1 --port 8000 --reload
```

Health check: open http://127.0.0.1:8000/health → returns `{ "status": "ok" }`.

### 5.2 Frontend UI (Streamlit)

```powershell
streamlit run src/webui/app.py --server.port 8501
```

Open http://127.0.0.1:8501, enter domains (one per line), enable “Fast Mode (no skipping)” for quicker results, set `Workers` (e.g., 10–12), and run a scan.

## 6. Command-Line Interface (CLI)
Run one-off scans or batch mode:

```powershell
python cli.py --domain example.com
python cli.py --input domains.txt
python cli.py report --output csv html
```

## 7. Performance Tuning (No Skipping)
- **Fast Mode**: keeps all modules enabled but reduces timeouts/polling; favors SSL Labs cache.
- **Advanced Tuning (UI Expander)**:
  - CT timeout and max subdomains
  - DNS/TLS/WHOIS/Redirect timeouts
  - SSL Labs HTTP timeout, poll interval, max attempts, cache age
- **Workers**: increase concurrency for multiple domains; start with 10–20.
- **Content Caps**: deep scan optional; set shallow link limit (5–10) and request timeout (5–6s).

## 8. Inbuilt-Only Operation (No Personal APIs)
- External threat-intel connectors are optional and disabled by default.
- Data sources used without accounts:
  - crt.sh (Certificate Transparency)
  - Public DNS resolvers
  - TLS handshake inspection
  - WHOIS registries
  - Direct HTTP fetch with SSL verification
  - Inbuilt content scanner (regex + entropy)

## 9. Architecture and Module Logic
### 9.1 Components
- **Backend**: FastAPI (`src/server.py`) exposes `/health` and `/scan`.
- **Frontend**: Streamlit (`src/webui/app.py`) tabs for Posture, DNS, Certificate, Reputation, Findings.
- **Scanner**: `src/scanner.py` orchestrates modules per domain concurrently.
- **Modules**: `src/modules/` includes:
  - `ct_enumeration`: crt.sh JSON, filter valid subdomains, cap by `max_subdomains`.
  - `dns_enumeration`: dnspython; collect A/AAAA/CNAME/NS/MX/TXT/SOA; analyze SPF/DMARC/DKIM; nameserver sufficiency; dangling CNAME.
  - `tls_inspection`: Python `ssl`; parse cert CN/SAN/issuer/validity; flag expiry; mismatches; weak algs/keys; self-signed.
  - `whois_lookup`: python-whois with a thread timeout; parse registrar/org/country/dates/age; flag newly registered/expiring; DNSSEC.
  - `ssllabs`: public API; prefer cached results; cap polling attempts; map grade to severity; protocols and vulnerabilities.
  - `redirect_analysis`: follow redirects with SSL verification; summarize hops and risks.
  - `content_scanner`: SSRF-safe fetch; cap body size and timeout; regex + entropy; confidence levels; evidence snippets; `raw_data.hits` for UI.
  - `takeover_detection`: identify dangling CNAMEs (targets that do not resolve).
  - `threat_intel/local_reputation`: risk score across TLS expiry, WHOIS age, TLD risk, redirects, takeover, content severity.

### 9.2 Security Controls
- SSRF safety: only fetch when resolved IPs are public and non-reserved.
- SSL verification: enabled in redirect analysis; TLS checks use controlled timeouts.
- HTML safety: UI renders content safely; content hits shown with compact table and truncated tokens.
- Rate limiting: module-level caps; fast mode reduces external polling and overall runtime.

## 10. Reporting and Evidence
- **JSON**: complete structured results per domain (subdomains, DNS, TLS, WHOIS, redirects, findings, `raw_data.hits`, errors, modules executed).
- **CSV**: flattened summaries; plus per-domain full asset inventory CSV.
- **HTML**: human-readable dashboard with severity coloring.
- Files written to `output/` with timestamps; evidence in `evidence/<domain>/` (headers, hash, snippets).

## 11. API Reference
- `GET /health` → `{ "status": "ok" }`
- `POST /scan` → request fields:
  - `domains: List[str]`
  - `output_formats: ["json","csv","html"]`
  - `skip_modules: List[str]` (optional)
  - `workers: int`
  - `fast_mode: bool`
  - Content overrides: `content_scanner_deep_scan`, `content_scanner_link_limit`, `content_scanner_timeout_ms`
  - Advanced overrides: `ct_timeout`, `ct_max_subdomains`, `dns_timeout`, `tls_timeout`, `whois_timeout`, `redirect_timeout`, `ssllabs_timeout`, `ssllabs_poll_interval_seconds`, `ssllabs_max_attempts`, `ssllabs_max_age`

Example:

```powershell
$body = @{ domains=@("example.com"); output_formats=@("json","csv","html"); skip_modules=@(); workers=12; fast_mode=$true; content_scanner_deep_scan=$true; content_scanner_link_limit=10; content_scanner_timeout_ms=6000 } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scan -ContentType "application/json" -Body $body
```

## 12. Troubleshooting
- **Cryptography build**: install latest Visual C++ Redistributable; upgrade `pip`, `wheel`, `setuptools`.
- **WHOIS slow/stalls**: timeout wrapper prevents hangs; partial results possible depending on registry.
- **SSL Labs delays**: enable Fast Mode, lower `ssllabs_max_attempts`, increase `ssllabs_max_age` to prefer cached results.
- **YAML rules parse**: use proper quoting in `local_rules.yaml` for regexes; check logs for warnings.
- **Proxies**: enable in [config.yaml](../config.yaml) and verify outbound access to crt.sh/SSL Labs.
- **Tests**: run `pytest -q` to validate.

## 13. Runbook Quick Actions
- Start everything:

```powershell
.\scriptsuild.ps1 # optional if present
.\scriptsuild.ps1 -Setup
.\scriptsuild.ps1 -StartBackend
.\scriptsuild.ps1 -StartFrontend
```

- Cleanup artifacts:

```powershell
.\scriptsackup.ps1 # optional
.\scriptsackup.ps1 -Cleanup
```

Or use provided scripts:

```powershell
.\scripts\\deploy.ps1 -Setup
.\scripts\\deploy.ps1 -StartBackend
.\scripts\\deploy.ps1 -StartFrontend
.\scripts\\cleanup_repo.ps1
```

## 14. Appendix
### 14.1 Requirements
See [requirements.txt](../requirements.txt). Core packages:
- requests, pyyaml, python-dotenv
- dnspython
- python-whois
- cryptography
- fastapi, uvicorn, streamlit
- pytest, pytest-cov

### 14.2 Directory Structure
- Repo root: config, CLI, requirements, README
- `src/`: core, modules, reporters, scanner, server, web UI
- `output/`: reports
- `evidence/`: per-domain evidence
- `scripts/`: deploy/cleanup helper scripts

## 15. Disclaimer
Run only against domains you own/manage or have explicit permission to test. Misuse may violate laws or provider terms of service.
