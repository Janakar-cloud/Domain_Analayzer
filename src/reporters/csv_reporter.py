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
        Build CSV content matching the asset inventory format.
        
        Output columns:
        Certificate Fields: domain, CN, O, Issuer CN, Issuer O, Not Before, Not After, cert_error
        DNS Fields: A, CNAME, NS, MX, TXT, SPF, DMARC

        Args:
            results: List of DomainResult objects

        Returns:
            CSV content as string
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header - matching the required asset inventory format
        writer.writerow([
            # Certificate fields
            "domain",
            "CN",
            "O",
            "Issuer CN",
            "Issuer O",
            "Not Before",
            "Not After",
            "cert_error",
            # DNS fields
            "A",
            "CNAME",
            "NS",
            "MX",
            "TXT",
            "SPF",
            "DMARC",
            # Additional useful fields
            "SANs",
            "Subdomains Count",
        ])
        
        # Write data rows - one per domain (including discovered subdomains)
        all_domains = self._collect_all_domains(results)
        
        for domain_data in all_domains:
            result = domain_data["result"]
            domain = domain_data["domain"]
            
            # Extract certificate info
            cert = result.tls_certificate if domain == result.domain else None
            cn = cert.subject_cn if cert else ""
            org = cert.organization if cert else ""
            issuer_cn = cert.issuer if cert else ""
            issuer_org = cert.issuer_org if cert else ""
            not_before = cert.not_before.strftime("%Y-%m-%d %H:%M:%S") if cert and cert.not_before else ""
            not_after = cert.not_after.strftime("%Y-%m-%d %H:%M:%S") if cert and cert.not_after else ""
            cert_error = "; ".join([e for e in result.errors if "tls" in e.lower() or "ssl" in e.lower() or "cert" in e.lower()]) if domain == result.domain else ""
            sans = "; ".join(cert.san) if cert and cert.san else ""
            
            # Extract DNS records
            dns_by_type = self._group_dns_records(result.dns_records if domain == result.domain else [])
            a_records = "; ".join(dns_by_type.get("A", []))
            cname_records = "; ".join(dns_by_type.get("CNAME", []))
            ns_records = "; ".join(dns_by_type.get("NS", []))
            mx_records = "; ".join(dns_by_type.get("MX", []))
            txt_records = "; ".join(dns_by_type.get("TXT", []))
            
            # Extract SPF and DMARC from TXT records
            spf_record = ""
            dmarc_record = ""
            for txt in dns_by_type.get("TXT", []):
                if txt.lower().startswith("v=spf1"):
                    spf_record = txt
                if txt.lower().startswith("v=dmarc1"):
                    dmarc_record = txt
            
            # Check DMARC separately (it's queried from _dmarc subdomain)
            if not dmarc_record and domain == result.domain:
                dmarc_record = self._find_dmarc_from_findings(result)
            
            writer.writerow([
                domain,
                cn,
                org,
                issuer_cn,
                issuer_org,
                not_before,
                not_after,
                cert_error,
                a_records,
                cname_records,
                ns_records,
                mx_records,
                txt_records,
                spf_record,
                dmarc_record,
                sans,
                len(result.subdomains) if domain == result.domain else 0,
            ])
        
        return output.getvalue()

    def _collect_all_domains(self, results: List[DomainResult]) -> List[dict]:
        """Collect main domains and optionally subdomains."""
        all_domains = []
        
        for result in results:
            # Add main domain
            all_domains.append({"domain": result.domain, "result": result})
            
            # Optionally add subdomains (can be configured)
            # For now, just include the main domain with subdomain count
        
        return all_domains

    def _group_dns_records(self, dns_records) -> dict:
        """Group DNS records by type."""
        grouped = {}
        for record in dns_records:
            record_type = record.record_type
            if record_type not in grouped:
                grouped[record_type] = []
            grouped[record_type].append(record.value)
        return grouped

    def _find_dmarc_from_findings(self, result: DomainResult) -> str:
        """Extract DMARC record from findings evidence if available."""
        for finding in result.findings:
            if "dmarc" in finding.title.lower() and finding.evidence:
                if "v=dmarc1" in finding.evidence.lower():
                    return finding.evidence
        return ""

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

    def generate_full_asset_inventory(self, results: List[DomainResult], filename: Optional[str] = None) -> Path:
        """
        Generate a full asset inventory CSV with one row per discovered subdomain.
        
        This matches the exact format specified in the requirements:
        - domain, CN, O, Issuer CN, Issuer O, Not Before, Not After, cert_error
        - A, CNAME, NS, MX, TXT, SPF, DMARC

        Args:
            results: List of DomainResult objects
            filename: Optional custom filename (default: {domain}_full_asset_inventory.csv)

        Returns:
            Path to generated report
        """
        if not filename and results:
            # Use first domain for filename like: cloud.com_full_asset_inventory.csv
            filename = f"{results[0].domain}_full_asset_inventory.csv"
        elif not filename:
            filename = self.generate_filename(prefix="full_asset_inventory")
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header - exact format from requirements
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
        
        # Write data rows - one per domain including all discovered subdomains
        for result in results:
            # First, write the main domain
            self._write_inventory_row(writer, result.domain, result, is_main=True)
            
            # Then write all discovered subdomains
            for subdomain in result.subdomains:
                self._write_inventory_row(writer, subdomain, result, is_main=False)
        
        return self.save(output.getvalue(), filename)

    def _write_inventory_row(self, writer, domain: str, result: DomainResult, is_main: bool = False) -> None:
        """Write a single row to the asset inventory CSV."""
        # Certificate info (only for main domain that was scanned)
        cert = result.tls_certificate if is_main else None
        cn = cert.subject_cn if cert else ""
        org = cert.organization if cert else ""
        issuer_cn = cert.issuer if cert else ""
        issuer_org = cert.issuer_org if cert else ""
        not_before = cert.not_before.strftime("%Y-%m-%d %H:%M:%S") if cert and cert.not_before else ""
        not_after = cert.not_after.strftime("%Y-%m-%d %H:%M:%S") if cert and cert.not_after else ""
        cert_error = "; ".join([e for e in result.errors if any(k in e.lower() for k in ["tls", "ssl", "cert", "443"])]) if is_main else ""
        
        # DNS records (only for main domain)
        dns_by_type = self._group_dns_records(result.dns_records) if is_main else {}
        a_records = "; ".join(dns_by_type.get("A", []))
        cname_records = "; ".join(dns_by_type.get("CNAME", []))
        ns_records = "; ".join(dns_by_type.get("NS", []))
        mx_records = "; ".join(dns_by_type.get("MX", []))
        txt_records = "; ".join([t for t in dns_by_type.get("TXT", []) if not t.lower().startswith("v=spf1") and not t.lower().startswith("v=dmarc1")])
        
        # Extract SPF and DMARC
        spf_record = ""
        dmarc_record = ""
        for txt in dns_by_type.get("TXT", []):
            if txt.lower().startswith("v=spf1"):
                spf_record = txt
        
        # DMARC is queried from _dmarc subdomain
        if is_main:
            dmarc_record = self._find_dmarc_from_findings(result)
        
        writer.writerow([
            domain,
            cn,
            org,
            issuer_cn,
            issuer_org,
            not_before,
            not_after,
            cert_error,
            a_records,
            cname_records,
            ns_records,
            mx_records,
            txt_records,
            spf_record,
            dmarc_record,
        ])
