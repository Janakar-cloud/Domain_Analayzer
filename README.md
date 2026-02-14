### Domains Intelligence
Domains Intelligence is a Python‑based security tool that performs automated external asset discovery and threat assessment for organizational domains. It combines passive reconnaissance (Certificate Transparency logs, WHOIS, DNS records) with active enrichment (TLS certificate inspection, SSLLabs grading, reputation checks via AbuseIPDB, AlienVault OTX, VirusTotal, and URLScan).
This project is designed for internal use by security teams to continuously monitor internet‑facing assets, identify misconfigurations, and assess risk posture in a safe, audit‑friendly way.

## Features
- Certificate Transparency Enumeration — Discover hidden subdomains via crt.sh.
- DNS Record Collection — A, AAAA, CNAME, NS, MX, TXT, SPF, DMARC.
- TLS Certificate Inspection — Extract CN, O, SANs, Issuer, validity dates; flag expired certs.
- WHOIS Enrichment — Registrar, registrant organization, age, location.
- SSLLabs Integration — Domain rating, protocol support, SSL/TLS issues.
- Threat Intelligence APIs — AbuseIPDB, AlienVault OTX, VirusTotal, CriminalIP.
- URLScan.io — Reputation checks and screenshots.
- Redirect Chain Analysis — Detect excessive hops, insecure redirects.
ABUSEIPDB_KEY=...
OTX_KEY=...
VT_KEY=...
CRIMINALIP_KEY=...
URLSCAN_KEY=...
DOMAIN_INTEL_API=http://127.0.0.1:8000
- Subdomain Takeover Heuristics — Identify dangling CNAMEs pointing to SaaS providers.
- Reporting — Export results to CSV/JSON/HTML with severity scoring and evidence snapshots.

## Security & Compliance
- Safe by design: Passive recon only, no intrusive scanning.
- Secrets management: API keys stored in .env.local, never committed.
- Rate limiting: Built‑in backoff and concurrency caps to avoid bans.
- Audit logging: Structured JSON logs for traceability.
- Legal use: Only run against domains you own/manage or have explicit permission to test.
## Production Deployment (Windows VM)
- Copy repo to VM and open PowerShell in the repo directory.
- Use the deployment script:
	- Setup venv and install deps:
		.\\scripts\\deploy.ps1 -Setup
	- Start backend API (FastAPI on port 8000):
		.\\scripts\\deploy.ps1 -StartBackend
	- Start frontend (Streamlit on port 8501):
		.\\scripts\\deploy.ps1 -StartFrontend

### Required API Keys
- AbuseIPDB: `ABUSEIPDB_KEY`
- AlienVault OTX: `OTX_KEY`
- VirusTotal: `VT_KEY`
- CriminalIP: `CRIMINALIP_KEY`
- URLScan (optional for private scans): `URLSCAN_KEY`
Notes: Local reputation module runs without external keys. SSL Labs requires no key.

### Repo Cleanup
- Generated artifacts are ignored by .gitignore (`output/`, `evidence/`, `logs/`).
- Run the cleanup script to remove local artifacts:
	.\\scripts\\cleanup_repo.ps1

## Getting Started
# Prerequisites
- Python 3.9+
- Install dependencies:
pip install -r requirements.txt


## Configuration
- Edit config.yaml to set target domains, rate limits, and enabled modules.
- Add API keys to .env.local:
ABUSEIPDB_KEY=...
OTX_KEY=...
VT_KEY=...
URLSCAN_KEY=...


## Usage
- Single domain:
python cli.py --domain example.com
- Bulk domains (file input):
python cli.py --input domains.txt
- Generate reports:
python cli.py report --output csv html



## Outputs
- CSV/JSON — Structured domain intelligence.
- HTML Dashboard — Interactive view with severity badges.
- Evidence Folder — Screenshots, raw API responses, logs.

## Use Cases
- External attack surface discovery
- Shadow IT and forgotten subdomain identification
- Certificate lifecycle monitoring
- Email security posture assessment (SPF/DMARC)
- Threat hunting and SOC investigations
- Continuous external asset inventory

Disclaimer
This tool is intended for authorized internal security testing only. Do not use it against domains you do not own or manage. Misuse may violate laws or provider terms of service.


