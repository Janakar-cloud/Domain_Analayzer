"""HTML report generator."""

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..core.domain import DomainResult, Severity
from .base import BaseReporter


class HTMLReporter(BaseReporter):
    """Generate HTML dashboard reports."""

    format_name = "html"
    extension = ".html"

    # Severity colors
    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d",
    }

    SEVERITY_BADGES = {
        "critical": "danger",
        "high": "warning",
        "medium": "secondary",
        "low": "info",
        "info": "light",
    }

    def generate(self, results: List[DomainResult], filename: Optional[str] = None) -> Path:
        """
        Generate HTML report.

        Args:
            results: List of DomainResult objects
            filename: Optional custom filename

        Returns:
            Path to generated report
        """
        if not filename:
            filename = self.generate_filename()
        
        content = self._build_html(results)
        return self.save(content, filename)

    def _build_html(self, results: List[DomainResult]) -> str:
        """
        Build HTML content.

        Args:
            results: List of DomainResult objects

        Returns:
            HTML content as string
        """
        # Calculate summary
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
        
        for result in results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
        
        # Generate domain cards
        domain_cards = "\n".join(self._generate_domain_card(r) for r in results)
        
        # Generate findings table
        findings_rows = self._generate_findings_table(results)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Intelligence Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {{
            --severity-critical: {self.SEVERITY_COLORS['critical']};
            --severity-high: {self.SEVERITY_COLORS['high']};
            --severity-medium: {self.SEVERITY_COLORS['medium']};
            --severity-low: {self.SEVERITY_COLORS['low']};
            --severity-info: {self.SEVERITY_COLORS['info']};
        }}
        body {{ background-color: #f8f9fa; }}
        .severity-badge {{
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            color: white;
            font-weight: 600;
        }}
        .severity-critical {{ background-color: var(--severity-critical); }}
        .severity-high {{ background-color: var(--severity-high); }}
        .severity-medium {{ background-color: var(--severity-medium); color: #212529; }}
        .severity-low {{ background-color: var(--severity-low); }}
        .severity-info {{ background-color: var(--severity-info); }}
        .stat-card {{
            border-left: 4px solid;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); }}
        .stat-critical {{ border-left-color: var(--severity-critical); }}
        .stat-high {{ border-left-color: var(--severity-high); }}
        .stat-medium {{ border-left-color: var(--severity-medium); }}
        .stat-low {{ border-left-color: var(--severity-low); }}
        .stat-info {{ border-left-color: var(--severity-info); }}
        .domain-card {{ margin-bottom: 1.5rem; }}
        .finding-item {{ 
            border-left: 3px solid;
            padding-left: 1rem;
            margin-bottom: 1rem;
        }}
        .finding-critical {{ border-left-color: var(--severity-critical); }}
        .finding-high {{ border-left-color: var(--severity-high); }}
        .finding-medium {{ border-left-color: var(--severity-medium); }}
        .finding-low {{ border-left-color: var(--severity-low); }}
        .finding-info {{ border-left-color: var(--severity-info); }}
        .evidence-box {{
            background-color: #f1f3f4;
            border-radius: 0.25rem;
            padding: 0.75rem;
            font-family: monospace;
            font-size: 0.875rem;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .navbar-brand {{ font-weight: 700; }}
        .table-findings {{ font-size: 0.9rem; }}
        .nav-pills .nav-link.active {{ background-color: #0d6efd; }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="bi bi-shield-check me-2"></i>Domain Intelligence
            </a>
            <span class="navbar-text text-light">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </span>
        </div>
    </nav>

    <div class="container">
        <!-- Summary Cards -->
        <div class="row mb-4">
            <div class="col-md-2">
                <div class="card stat-card stat-info">
                    <div class="card-body text-center">
                        <h3 class="mb-0">{len(results)}</h3>
                        <small class="text-muted">Domains</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card stat-critical">
                    <div class="card-body text-center">
                        <h3 class="mb-0">{severity_counts['critical']}</h3>
                        <small class="text-muted">Critical</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card stat-high">
                    <div class="card-body text-center">
                        <h3 class="mb-0">{severity_counts['high']}</h3>
                        <small class="text-muted">High</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card stat-medium">
                    <div class="card-body text-center">
                        <h3 class="mb-0">{severity_counts['medium']}</h3>
                        <small class="text-muted">Medium</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card stat-low">
                    <div class="card-body text-center">
                        <h3 class="mb-0">{severity_counts['low']}</h3>
                        <small class="text-muted">Low</small>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card stat-card stat-info">
                    <div class="card-body text-center">
                        <h3 class="mb-0">{total_findings}</h3>
                        <small class="text-muted">Total Findings</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <ul class="nav nav-pills mb-4" id="reportTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="domains-tab" data-bs-toggle="pill" 
                        data-bs-target="#domains" type="button" role="tab">
                    <i class="bi bi-globe me-1"></i>Domains
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="findings-tab" data-bs-toggle="pill" 
                        data-bs-target="#findings" type="button" role="tab">
                    <i class="bi bi-exclamation-triangle me-1"></i>All Findings
                </button>
            </li>
        </ul>

        <!-- Tab Content -->
        <div class="tab-content" id="reportTabContent">
            <!-- Domains Tab -->
            <div class="tab-pane fade show active" id="domains" role="tabpanel">
                {domain_cards}
            </div>

            <!-- Findings Tab -->
            <div class="tab-pane fade" id="findings" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover table-findings">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Domain</th>
                                        <th>Finding</th>
                                        <th>Category</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {findings_rows}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="mt-5 py-3 bg-dark text-light text-center">
        <small>Domain Intelligence Report • Generated by Security Team</small>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""

    def _generate_domain_card(self, result: DomainResult) -> str:
        """Generate HTML card for a domain result."""
        # Severity badge for overall score
        if result.severity_score >= 80:
            score_class = "critical"
        elif result.severity_score >= 50:
            score_class = "high"
        elif result.severity_score >= 25:
            score_class = "medium"
        elif result.severity_score > 0:
            score_class = "low"
        else:
            score_class = "info"
        
        # Generate findings HTML
        findings_html = ""
        for finding in sorted(result.findings, key=lambda f: f.severity, reverse=True):
            sev = finding.severity.value
            evidence_html = ""
            if finding.evidence:
                evidence_html = f'<div class="evidence-box mt-2">{self._escape_html(finding.evidence)}</div>'
            
            remediation_html = ""
            if finding.remediation:
                remediation_html = f'<p class="mb-0 mt-2 text-muted"><small><i class="bi bi-lightbulb me-1"></i>{self._escape_html(finding.remediation)}</small></p>'
            
            findings_html += f"""
            <div class="finding-item finding-{sev}">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <span class="severity-badge severity-{sev}">{sev.upper()}</span>
                        <strong class="ms-2">{self._escape_html(finding.title)}</strong>
                    </div>
                    <small class="text-muted">{finding.category}</small>
                </div>
                <p class="mb-0 mt-1">{self._escape_html(finding.description)}</p>
                {evidence_html}
                {remediation_html}
            </div>"""
        
        # Domain info
        tls_info = "N/A"
        if result.tls_certificate:
            cert = result.tls_certificate
            tls_status = "🔴 Expired" if cert.is_expired else f"✅ Valid ({cert.days_until_expiry} days)"
            tls_info = f"{cert.issuer} - {tls_status}"
        
        whois_info = "N/A"
        if result.whois_info:
            whois_info = f"{result.whois_info.registrar or 'Unknown'} ({result.whois_info.domain_age_days or '?'} days old)"
        
        ips_html = ", ".join(result.resolved_ips[:5]) if result.resolved_ips else "No IPs resolved"
        
        return f"""
        <div class="card domain-card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0">
                    <i class="bi bi-globe2 me-2"></i>{self._escape_html(result.domain)}
                </h5>
                <span class="severity-badge severity-{score_class}">Score: {result.severity_score}</span>
            </div>
            <div class="card-body">
                <div class="row mb-3">
                    <div class="col-md-4">
                        <small class="text-muted d-block">Resolved IPs</small>
                        <span>{ips_html}</span>
                    </div>
                    <div class="col-md-4">
                        <small class="text-muted d-block">TLS Certificate</small>
                        <span>{self._escape_html(tls_info)}</span>
                    </div>
                    <div class="col-md-4">
                        <small class="text-muted d-block">WHOIS</small>
                        <span>{self._escape_html(whois_info)}</span>
                    </div>
                </div>
                
                <h6 class="border-bottom pb-2">
                    <i class="bi bi-exclamation-circle me-1"></i>
                    Findings ({len(result.findings)})
                </h6>
                {findings_html if findings_html else '<p class="text-muted">No findings</p>'}
            </div>
            <div class="card-footer text-muted">
                <small>Scanned: {result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')} | 
                Subdomains: {len(result.subdomains)} | 
                Modules: {', '.join(result.modules_executed)}</small>
            </div>
        </div>"""

    def _generate_findings_table(self, results: List[DomainResult]) -> str:
        """Generate HTML table rows for all findings."""
        rows = []
        
        # Collect and sort all findings
        all_findings = []
        for result in results:
            for finding in result.findings:
                all_findings.append((result.domain, finding))
        
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda x: severity_order.get(x[1].severity.value, 5))
        
        for domain, finding in all_findings:
            sev = finding.severity.value
            rows.append(f"""
                <tr>
                    <td><span class="severity-badge severity-{sev}">{sev.upper()}</span></td>
                    <td>{self._escape_html(domain)}</td>
                    <td>
                        <strong>{self._escape_html(finding.title)}</strong>
                        <br><small class="text-muted">{self._escape_html(finding.description)}</small>
                    </td>
                    <td><small>{finding.category}</small></td>
                </tr>""")
        
        return "\n".join(rows)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
