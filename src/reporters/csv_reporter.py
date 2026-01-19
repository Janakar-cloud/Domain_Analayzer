"""CSV report generator."""

import csv
import io
from pathlib import Path
from typing import List, Optional

from ..core.domain import DomainResult
from .base import BaseReporter


class CSVReporter(BaseReporter):
    """Generate CSV reports."""

    format_name = "csv"
    extension = ".csv"

    def generate(self, results: List[DomainResult], filename: Optional[str] = None) -> Path:
        """
        Generate CSV report.

        Args:
            results: List of DomainResult objects
            filename: Optional custom filename

        Returns:
            Path to generated report
        """
        if not filename:
            filename = self.generate_filename()
        
        content = self._build_csv(results)
        return self.save(content, filename)

    def _build_csv(self, results: List[DomainResult]) -> str:
        """
        Build CSV content.

        Args:
            results: List of DomainResult objects

        Returns:
            CSV content as string
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Domain",
            "Scan Timestamp",
            "Subdomains Count",
            "Resolved IPs",
            "TLS CN",
            "TLS Issuer",
            "TLS Expires",
            "TLS Expired",
            "WHOIS Registrar",
            "WHOIS Created",
            "WHOIS Expires",
            "Domain Age (days)",
            "SSLLabs Grade",
            "Severity Score",
            "Critical Findings",
            "High Findings",
            "Medium Findings",
            "Low Findings",
            "Info Findings",
            "Takeover Candidate",
            "Errors",
        ])
        
        # Write data rows
        for result in results:
            # Count findings by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
            
            # Extract certificate info
            tls_cn = result.tls_certificate.subject_cn if result.tls_certificate else ""
            tls_issuer = result.tls_certificate.issuer if result.tls_certificate else ""
            tls_expires = result.tls_certificate.not_after.isoformat() if result.tls_certificate and result.tls_certificate.not_after else ""
            tls_expired = result.tls_certificate.is_expired if result.tls_certificate else ""
            
            # Extract WHOIS info
            whois_registrar = result.whois_info.registrar if result.whois_info else ""
            whois_created = result.whois_info.creation_date.isoformat() if result.whois_info and result.whois_info.creation_date else ""
            whois_expires = result.whois_info.expiration_date.isoformat() if result.whois_info and result.whois_info.expiration_date else ""
            domain_age = result.whois_info.domain_age_days if result.whois_info else ""
            
            # Extract SSLLabs grade
            ssllabs_grade = result.ssllabs_result.grade if result.ssllabs_result else ""
            
            writer.writerow([
                result.domain,
                result.scan_timestamp.isoformat(),
                len(result.subdomains),
                "; ".join(result.resolved_ips),
                tls_cn,
                tls_issuer,
                tls_expires,
                tls_expired,
                whois_registrar,
                whois_created,
                whois_expires,
                domain_age,
                ssllabs_grade,
                result.severity_score,
                severity_counts["critical"],
                severity_counts["high"],
                severity_counts["medium"],
                severity_counts["low"],
                severity_counts["info"],
                result.is_takeover_candidate,
                "; ".join(result.errors) if result.errors else "",
            ])
        
        return output.getvalue()

    def generate_findings_csv(self, results: List[DomainResult], filename: Optional[str] = None) -> Path:
        """
        Generate a detailed CSV report with one row per finding.

        Args:
            results: List of DomainResult objects
            filename: Optional custom filename

        Returns:
            Path to generated report
        """
        if not filename:
            filename = self.generate_filename(prefix="findings")
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Domain",
            "Finding Title",
            "Severity",
            "Category",
            "Description",
            "Evidence",
            "Remediation",
        ])
        
        # Write findings
        for result in results:
            for finding in result.findings:
                writer.writerow([
                    result.domain,
                    finding.title,
                    finding.severity.value,
                    finding.category,
                    finding.description,
                    finding.evidence or "",
                    finding.remediation or "",
                ])
        
        return self.save(output.getvalue(), filename)
