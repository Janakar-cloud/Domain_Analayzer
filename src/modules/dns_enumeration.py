"""DNS enumeration module."""

from typing import Dict, List, Optional, Set

import dns.resolver
import dns.exception

from ..core.domain import DNSRecord, DomainResult, Finding, Severity
from .base import BaseModule


class DNSEnumerationModule(BaseModule):
    """
    Enumerate DNS records for a domain.
    
    Collects A, AAAA, CNAME, NS, MX, TXT, SOA records and performs
    security analysis on the results.
    """

    name = "dns_enumeration"
    description = "Collect DNS records (A, AAAA, CNAME, NS, MX, TXT, SOA)"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._resolver = None

    @property
    def resolver(self) -> dns.resolver.Resolver:
        """Get configured DNS resolver."""
        if self._resolver is None:
            self._resolver = dns.resolver.Resolver()
            
            # Configure nameservers
            nameservers = self.get_setting("nameservers", ["8.8.8.8", "8.8.4.4"])
            self._resolver.nameservers = nameservers
            
            # Configure timeout
            self._resolver.timeout = self.get_setting("timeout", 10)
            self._resolver.lifetime = self.get_setting("timeout", 10)
            
        return self._resolver

    @property
    def record_types(self) -> List[str]:
        """Get list of record types to query."""
        return self.get_setting("record_types", ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"])

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Query DNS records for the domain.

        Args:
            domain: Domain to query
            result: DomainResult to populate
        """
        self.rate_limit("dns")
        
        records_found = {}
        
        for record_type in self.record_types:
            records = self._query_record(domain, record_type)
            if records:
                records_found[record_type] = records
                result.dns_records.extend(records)
        
        # Extract resolved IPs
        for record in result.dns_records:
            if record.record_type in ("A", "AAAA"):
                if record.value not in result.resolved_ips:
                    result.resolved_ips.append(record.value)
        
        self.logger.info(f"Found {len(result.dns_records)} DNS records for {domain}")
        
        # Analyze DNS configuration
        self._analyze_dns_security(domain, records_found, result)

    def _query_record(self, domain: str, record_type: str) -> List[DNSRecord]:
        """
        Query a specific DNS record type.

        Args:
            domain: Domain to query
            record_type: DNS record type

        Returns:
            List of DNSRecord objects
        """
        records = []
        
        try:
            answers = self.resolver.resolve(domain, record_type)
            
            for rdata in answers:
                value = self._format_record_value(rdata, record_type)
                records.append(DNSRecord(
                    record_type=record_type,
                    name=domain,
                    value=value,
                    ttl=answers.ttl,
                ))
                
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No {record_type} records for {domain}")
        except dns.resolver.NoNameservers:
            self.logger.warning(f"No nameservers available for {domain}")
        except dns.exception.Timeout:
            self.logger.warning(f"Timeout querying {record_type} for {domain}")
        except Exception as e:
            self.logger.debug(f"Error querying {record_type} for {domain}: {e}")
        
        return records

    def _format_record_value(self, rdata, record_type: str) -> str:
        """Format DNS record value based on type."""
        if record_type == "MX":
            return f"{rdata.preference} {rdata.exchange}"
        elif record_type == "SOA":
            return f"{rdata.mname} {rdata.rname} {rdata.serial}"
        elif record_type == "TXT":
            # Join TXT record strings
            return "".join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
        else:
            return str(rdata)

    def _analyze_dns_security(
        self, 
        domain: str, 
        records: Dict[str, List[DNSRecord]], 
        result: DomainResult
    ) -> None:
        """
        Analyze DNS records for security issues.

        Args:
            domain: Domain being analyzed
            records: Dictionary of record type -> records
            result: DomainResult to add findings to
        """
        # Check for SPF records
        self._check_spf(domain, records.get("TXT", []), result)
        
        # Check for DMARC records
        self._check_dmarc(domain, result)
        
        # Check for DKIM (common selector)
        self._check_dkim(domain, result)
        
        # Check nameserver configuration
        self._check_nameservers(records.get("NS", []), result)
        
        # Check for dangling CNAMEs (potential takeover)
        self._check_dangling_cname(records.get("CNAME", []), result)

    def _check_spf(self, domain: str, txt_records: List[DNSRecord], result: DomainResult) -> None:
        """Check SPF configuration."""
        spf_records = [r for r in txt_records if r.value.lower().startswith("v=spf1")]
        
        if not spf_records:
            result.add_finding(Finding(
                title="Missing SPF Record",
                description=f"No SPF record found for {domain}",
                severity=Severity.MEDIUM,
                category="email_security",
                remediation="Add an SPF record to prevent email spoofing. Example: v=spf1 include:_spf.google.com ~all",
                references=["https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"],
            ))
            result.spf_record = None
        elif len(spf_records) > 1:
            result.add_finding(Finding(
                title="Multiple SPF Records",
                description=f"Found {len(spf_records)} SPF records for {domain}",
                severity=Severity.MEDIUM,
                category="email_security",
                evidence="\n".join([r.value for r in spf_records]),
                remediation="Merge multiple SPF records into a single record. Multiple SPF records can cause delivery issues.",
            ))
            result.spf_record = spf_records[0].value if spf_records else None
        else:
            spf_value = spf_records[0].value.lower()
            result.spf_record = spf_records[0].value
            
            # Check for weak SPF
            if "+all" in spf_value:
                result.add_finding(Finding(
                    title="Weak SPF Record (+all)",
                    description="SPF record uses +all which allows any server to send email",
                    severity=Severity.HIGH,
                    category="email_security",
                    evidence=spf_records[0].value,
                    remediation="Change +all to ~all (softfail) or -all (hardfail)",
                ))
            elif "?all" in spf_value:
                result.add_finding(Finding(
                    title="Neutral SPF Record (?all)",
                    description="SPF record uses ?all which provides no protection",
                    severity=Severity.MEDIUM,
                    category="email_security",
                    evidence=spf_records[0].value,
                    remediation="Change ?all to ~all (softfail) or -all (hardfail)",
                ))

    def _check_dmarc(self, domain: str, result: DomainResult) -> None:
        """Check DMARC configuration."""
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records = self._query_record(dmarc_domain, "TXT")
        dmarc_records = [r for r in dmarc_records if "v=dmarc1" in r.value.lower()]
        
        if not dmarc_records:
            result.add_finding(Finding(
                title="Missing DMARC Record",
                description=f"No DMARC record found for {domain}",
                severity=Severity.MEDIUM,
                category="email_security",
                remediation="Add a DMARC record to enable email authentication reporting. Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
                references=["https://dmarc.org/overview/"],
            ))
            result.dmarc_record = None
        else:
            dmarc_value = dmarc_records[0].value.lower()
            result.dmarc_record = dmarc_records[0].value
            
            # Check for none policy
            if "p=none" in dmarc_value:
                result.add_finding(Finding(
                    title="DMARC Policy Set to None",
                    description="DMARC is configured but not enforcing (p=none)",
                    severity=Severity.LOW,
                    category="email_security",
                    evidence=dmarc_records[0].value,
                    remediation="Consider changing DMARC policy to 'quarantine' or 'reject' after monitoring reports.",
                ))

    def _check_dkim(self, domain: str, result: DomainResult) -> None:
        """Check for common DKIM selectors."""
        common_selectors = ["default", "google", "selector1", "selector2", "k1", "dkim"]
        
        dkim_found = False
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = self._query_record(dkim_domain, "TXT")
            if records:
                dkim_found = True
                break
        
        if not dkim_found:
            result.add_finding(Finding(
                title="No DKIM Records Found (Common Selectors)",
                description=f"Could not find DKIM records for common selectors",
                severity=Severity.INFO,
                category="email_security",
                remediation="Ensure DKIM is configured. Note: DKIM may be using non-standard selectors.",
            ))

    def _check_nameservers(self, ns_records: List[DNSRecord], result: DomainResult) -> None:
        """Check nameserver configuration."""
        if len(ns_records) < 2:
            result.add_finding(Finding(
                title="Insufficient Nameservers",
                description=f"Only {len(ns_records)} nameserver(s) configured",
                severity=Severity.LOW,
                category="dns_configuration",
                remediation="Configure at least 2 nameservers for redundancy.",
            ))
        else:
            # Detect single-provider NS concentration for resiliency awareness
            providers = set(r.value.split(".")[-2:] for r in ns_records if r.value)
            if len(providers) == 1:
                result.add_finding(Finding(
                    title="Nameservers Single Provider",
                    description="All nameservers appear to be hosted by a single provider",
                    severity=Severity.INFO,
                    category="dns_configuration",
                    remediation="Consider distributing NS across multiple providers to reduce single point of failure.",
                ))
        
        # Check for nameservers in same /24 (simplified check)
        ns_values = [r.value.rstrip('.') for r in ns_records]
        if ns_values:
            result.add_finding(Finding(
                title="Nameserver Configuration",
                description=f"Found {len(ns_values)} nameservers",
                severity=Severity.INFO,
                category="dns_configuration",
                evidence=", ".join(ns_values),
            ))

    def _check_dangling_cname(self, cname_records: List[DNSRecord], result: DomainResult) -> None:
        """Check for dangling CNAMEs that might be takeover candidates."""
        for record in cname_records:
            target = record.value.rstrip('.')
            
            # Try to resolve the CNAME target
            try:
                self.resolver.resolve(target, "A")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                result.add_finding(Finding(
                    title="Dangling CNAME Record",
                    description=f"CNAME {record.name} points to {target} which does not resolve",
                    severity=Severity.MEDIUM,
                    category="subdomain_takeover",
                    evidence=f"{record.name} -> {target} (NXDOMAIN)",
                    remediation="Remove the dangling CNAME or reconfigure the target. This may be a subdomain takeover risk.",
                ))
            except Exception:
                pass  # Other errors, skip
