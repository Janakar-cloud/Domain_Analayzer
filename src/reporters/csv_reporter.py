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
            "domain",
            "CN",
            "O",
            "Issuer CN",
            "Issuer O",
            "Not Before",
            "Not After",
            "cert_error",
            "A",
            "CNAME",
            "NS",
            "MX",
            "TXT",
            "SPF",
            "DMARC",
        ])
        
        # Write data rows
        for result in results:
            # Extract certificate info
            tls_cn = result.tls_certificate.subject_cn if result.tls_certificate else ""
            tls_org = result.tls_certificate.organization if result.tls_certificate else ""
            tls_issuer = result.tls_certificate.issuer if result.tls_certificate else ""
            tls_issuer_org = result.tls_certificate.issuer_org if result.tls_certificate else ""
            tls_not_before = result.tls_certificate.not_before.isoformat() if result.tls_certificate and result.tls_certificate.not_before else ""
            tls_expires = result.tls_certificate.not_after.isoformat() if result.tls_certificate and result.tls_certificate.not_after else ""
            tls_error = result.cert_error or ""

            def _records(record_type: str) -> str:
                values = [r.value for r in result.dns_records if r.record_type == record_type]
                return "; ".join(values)
            
            a_records = _records("A")
            cname_records = _records("CNAME")
            ns_records = _records("NS")
            mx_records = _records("MX")
            txt_records = _records("TXT")
            
            writer.writerow([
                result.domain,
                tls_cn,
                tls_org,
                tls_issuer,
                tls_issuer_org,
                tls_not_before,
                tls_expires,
                tls_error,
                a_records,
                cname_records,
                ns_records,
                mx_records,
                txt_records,
                result.spf_record or "",
                result.dmarc_record or "",
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
