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
