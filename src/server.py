"""FastAPI backend for Domain Intelligence.

Provides endpoints to trigger scans and retrieve report paths.
"""

from typing import List, Optional, Dict, Any

from fastapi import FastAPI
from pydantic import BaseModel

from .scanner import Scanner
from .core.config import Config


app = FastAPI(title="Domain Intelligence API", version="1.0.0")


class ScanRequest(BaseModel):
    domains: List[str]
    output_formats: Optional[List[str]] = None  # ["json", "csv", "html"]
    skip_modules: Optional[List[str]] = None  # e.g., ["ssllabs", "whois_lookup"]
    workers: Optional[int] = None
    config_path: Optional[str] = None
    env_path: Optional[str] = None
    # Runtime overrides for content scanner performance tuning
    content_scanner_deep_scan: Optional[bool] = None
    content_scanner_link_limit: Optional[int] = None
    content_scanner_timeout_ms: Optional[int] = None
    # Fast mode to reduce per-module timeouts/polling without skipping modules
    fast_mode: Optional[bool] = None
    # Advanced per-module tuning overrides
    ssllabs_poll_interval_seconds: Optional[int] = None
    ssllabs_max_attempts: Optional[int] = None
    ssllabs_timeout: Optional[int] = None
    ssllabs_max_age: Optional[int] = None
    ct_timeout: Optional[int] = None
    ct_max_subdomains: Optional[int] = None
    dns_timeout: Optional[int] = None
    tls_timeout: Optional[int] = None
    redirect_timeout: Optional[int] = None
    whois_timeout: Optional[int] = None


class ScanResponse(BaseModel):
    success: bool
    reports: List[str]
    summary: Dict[str, Any]
    results: List[Dict[str, Any]]


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    # Load configuration
    cfg = Config(config_path=req.config_path, env_path=req.env_path)

    # Apply runtime options: output formats
    if req.output_formats:
        # Ensure formats are valid and unique
        formats = [f for f in req.output_formats if f in ["json", "csv", "html"]]
        cfg._config.setdefault("output", {})["formats"] = formats

    # Apply runtime options: skip modules by disabling them in config
    if req.skip_modules:
        cfg._config.setdefault("modules", {})
        for m in req.skip_modules:
            cfg._config.setdefault("modules", {}).setdefault(m, {})
            cfg._config["modules"][m]["enabled"] = False

    # Apply runtime overrides: content scanner tuning
    cs = cfg._config.setdefault("modules", {}).setdefault("content_scanner", {})
    if req.content_scanner_deep_scan is not None:
        cs["deep_scan"] = bool(req.content_scanner_deep_scan)
    if req.content_scanner_link_limit is not None:
        cs["shallow_links_limit"] = int(req.content_scanner_link_limit)
    if req.content_scanner_timeout_ms is not None:
        # Convert ms to seconds for module config
        cs["timeout_seconds"] = max(1, int(req.content_scanner_timeout_ms) // 1000)

    # Apply fast mode overrides (keep modules enabled but cap runtime)
    if req.fast_mode:
        mods = cfg._config.setdefault("modules", {})
        # CT: faster HTTP timeout
        mods.setdefault("ct_enumeration", {})["timeout"] = 5
        # DNS: resolver timeout
        mods.setdefault("dns_enumeration", {})["timeout"] = 5
        # TLS: socket/connect timeout
        mods.setdefault("tls_inspection", {})["timeout"] = 5
        # Redirect analysis
        mods.setdefault("redirect_analysis", {})["timeout"] = 5
        # WHOIS: module-level timeout (used by thread wrapper)
        mods.setdefault("whois_lookup", {})["timeout"] = 8
        # SSL Labs: shorter polling and HTTP timeout; prefer cache
        ssc = mods.setdefault("ssllabs", {})
        ssc["timeout"] = 8
        ssc["poll_interval_seconds"] = 2
        ssc["max_attempts"] = 5
        ssc["max_age"] = 48

    # Apply advanced overrides if provided
    mods = cfg._config.setdefault("modules", {})
    if req.ct_timeout is not None:
        mods.setdefault("ct_enumeration", {})["timeout"] = int(req.ct_timeout)
    if req.ct_max_subdomains is not None:
        mods.setdefault("ct_enumeration", {})["max_subdomains"] = int(req.ct_max_subdomains)
    if req.dns_timeout is not None:
        mods.setdefault("dns_enumeration", {})["timeout"] = int(req.dns_timeout)
    if req.tls_timeout is not None:
        mods.setdefault("tls_inspection", {})["timeout"] = int(req.tls_timeout)
    if req.redirect_timeout is not None:
        mods.setdefault("redirect_analysis", {})["timeout"] = int(req.redirect_timeout)
    if req.whois_timeout is not None:
        mods.setdefault("whois_lookup", {})["timeout"] = int(req.whois_timeout)
    # SSL Labs specific
    ssl_cfg = mods.setdefault("ssllabs", {})
    if req.ssllabs_timeout is not None:
        ssl_cfg["timeout"] = int(req.ssllabs_timeout)
    if req.ssllabs_poll_interval_seconds is not None:
        ssl_cfg["poll_interval_seconds"] = int(req.ssllabs_poll_interval_seconds)
    if req.ssllabs_max_attempts is not None:
        ssl_cfg["max_attempts"] = int(req.ssllabs_max_attempts)
    if req.ssllabs_max_age is not None:
        ssl_cfg["max_age"] = int(req.ssllabs_max_age)

    # Initialize scanner
    scanner = Scanner(cfg)

    # Run scan (concurrent across domains)
    results = scanner.scan_domains(req.domains, max_workers=req.workers)

    # Generate reports and collect paths
    formats = req.output_formats or cfg.output_formats
    report_paths = [str(p) for p in scanner.generate_reports(results, formats)]

    # Build summary
    total_findings = sum(len(r.findings) for r in results)
    severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for r in results:
        for f in r.findings:
            severity_counts[f.severity.value] += 1

    summary = {
        "domains": len(results),
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "output_formats": formats,
    }
    serialized_results = [r.to_dict() for r in results]

    return ScanResponse(success=True, reports=report_paths, summary=summary, results=serialized_results)
