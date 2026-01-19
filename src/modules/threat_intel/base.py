"""Base class for threat intelligence modules."""

from abc import abstractmethod
from typing import Optional

import requests

from ...core.domain import DomainResult, ThreatIntelResult
from ...core.security import IPValidator
from ..base import BaseModule


class BaseThreatIntelModule(BaseModule):
    """Base class for threat intelligence API integrations."""

    # API key configuration name
    api_key_name: str = ""
    
    # Rate limit service name
    rate_limit_service: str = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.user_agent,
        })
        # SSRF protection: validate IPs before external requests
        self._ip_validator = IPValidator()

    @property
    def api_key(self) -> str:
        """Get API key for this service."""
        return self.config.get_api_key(self.api_key_name)

    @property
    def has_api_key(self) -> bool:
        """Check if API key is configured."""
        return self.config.has_api_key(self.api_key_name)

    @property
    def is_enabled(self) -> bool:
        """Check if module is enabled and has required API key."""
        base_enabled = super().is_enabled
        if not base_enabled:
            return False
        
        if not self.has_api_key:
            self.logger.debug(f"{self.name} disabled: No API key configured")
            return False
        
        return True

    def rate_limit(self, service: Optional[str] = None) -> None:
        """Apply rate limiting."""
        super().rate_limit(service or self.rate_limit_service or self.name)

    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """
        Look up threat intelligence for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            ThreatIntelResult or None
        """
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Look up threat intelligence for a domain.

        Args:
            domain: Domain to look up

        Returns:
            ThreatIntelResult or None
        """
        pass

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Execute threat intel lookup for domain and resolved IPs.

        Args:
            domain: Domain to analyze
            result: DomainResult to populate
        """
        # Look up domain
        self.rate_limit()
        domain_result = self.lookup_domain(domain)
        if domain_result:
            result.threat_intel.append(domain_result)
            self._add_threat_findings(domain_result, domain, result)
        
        # Look up resolved IPs (with SSRF protection)
        safe_ips = []
        for ip in result.resolved_ips[:5]:  # Limit to first 5 IPs
            is_safe, reason = IPValidator.is_safe_for_external_request(ip)
            if is_safe:
                safe_ips.append(ip)
            else:
                self.logger.warning(f"Skipping IP {ip} for threat intel lookup: {reason}")
        
        for ip in safe_ips:
            self.rate_limit()
            ip_result = self.lookup_ip(ip)
            if ip_result:
                result.threat_intel.append(ip_result)
                self._add_threat_findings(ip_result, ip, result)

    def _add_threat_findings(
        self, 
        intel: ThreatIntelResult, 
        target: str, 
        result: DomainResult
    ) -> None:
        """
        Add findings based on threat intelligence results.

        Args:
            intel: Threat intel result
            target: Domain or IP that was looked up
            result: DomainResult to add findings to
        """
        from ...core.domain import Finding, Severity
        
        if intel.is_malicious:
            severity = Severity.HIGH
            if intel.abuse_score and intel.abuse_score >= 80:
                severity = Severity.CRITICAL
            elif intel.confidence_score and intel.confidence_score >= 0.8:
                severity = Severity.CRITICAL
            
            categories_str = ", ".join(intel.categories) if intel.categories else "Unknown"
            
            result.add_finding(Finding(
                title=f"Malicious Indicator Detected ({intel.source})",
                description=f"{target} flagged as malicious by {intel.source}",
                severity=severity,
                category="threat_intelligence",
                evidence=(
                    f"Source: {intel.source}\n"
                    f"Categories: {categories_str}\n"
                    f"Abuse Score: {intel.abuse_score or 'N/A'}\n"
                    f"Reports: {intel.reports_count}"
                ),
                remediation="Investigate this indicator and consider blocking if confirmed malicious.",
            ))
        elif intel.reports_count > 0:
            result.add_finding(Finding(
                title=f"Suspicious Activity Reported ({intel.source})",
                description=f"{target} has {intel.reports_count} reports in {intel.source}",
                severity=Severity.MEDIUM if intel.reports_count > 5 else Severity.LOW,
                category="threat_intelligence",
                evidence=f"Source: {intel.source}\nReports: {intel.reports_count}",
            ))
