"""WHOIS lookup module."""

from datetime import datetime, timezone
from typing import List, Optional

import whois

from ..core.domain import DomainResult, Finding, Severity, WHOISInfo
from .base import BaseModule


class WHOISModule(BaseModule):
    """
    WHOIS lookup for domain registration information.
    
    Extracts registrar, registrant, dates, and performs age analysis.
    """

    name = "whois_lookup"
    description = "Retrieve WHOIS registration information"

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Perform WHOIS lookup for the domain.

        Args:
            domain: Domain to lookup
            result: DomainResult to populate
        """
        self.rate_limit("whois")
        
        whois_info = self._lookup_whois(domain)
        
        if whois_info:
            result.whois_info = whois_info
            self._analyze_whois(whois_info, domain, result)
        else:
            result.add_error(f"Could not retrieve WHOIS information for {domain}")

    def _lookup_whois(self, domain: str) -> Optional[WHOISInfo]:
        """
        Perform WHOIS lookup.

        Args:
            domain: Domain to lookup

        Returns:
            WHOISInfo object or None
        """
        try:
            w = whois.whois(domain)
            
            if not w or not w.domain_name:
                return None
            
            # Parse dates
            creation_date = self._parse_whois_date(w.creation_date)
            expiration_date = self._parse_whois_date(w.expiration_date)
            updated_date = self._parse_whois_date(w.updated_date)
            
            # Calculate domain age
            domain_age_days = None
            if creation_date:
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                domain_age_days = (now - creation_date).days
            
            # Parse name servers
            name_servers = []
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    name_servers = [ns.lower() for ns in w.name_servers if ns]
                else:
                    name_servers = [w.name_servers.lower()]
            
            # Parse status
            status = []
            if w.status:
                if isinstance(w.status, list):
                    status = list(w.status)
                else:
                    status = [w.status]
            
            return WHOISInfo(
                registrar=w.registrar,
                registrant_org=getattr(w, 'org', None) or getattr(w, 'registrant_org', None),
                registrant_country=getattr(w, 'country', None) or getattr(w, 'registrant_country', None),
                creation_date=creation_date,
                expiration_date=expiration_date,
                updated_date=updated_date,
                name_servers=name_servers,
                dnssec=getattr(w, 'dnssec', None),
                status=status,
                domain_age_days=domain_age_days,
            )
            
        except whois.parser.PywhoisError as e:
            self.logger.warning(f"WHOIS error for {domain}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error looking up WHOIS for {domain}: {e}")
            return None

    def _parse_whois_date(self, date_value) -> Optional[datetime]:
        """Parse WHOIS date field which may be a list or single value."""
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value
        
        if isinstance(date_value, str):
            try:
                return datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            except ValueError:
                pass
        
        return None

    def _analyze_whois(self, info: WHOISInfo, domain: str, result: DomainResult) -> None:
        """
        Analyze WHOIS information for security insights.

        Args:
            info: WHOISInfo to analyze
            domain: Domain being analyzed
            result: DomainResult to add findings to
        """
        # Check domain age (newly registered domains are often suspicious)
        if info.domain_age_days is not None:
            if info.domain_age_days < 30:
                result.add_finding(Finding(
                    title="Newly Registered Domain",
                    description=f"Domain was registered {info.domain_age_days} days ago",
                    severity=Severity.MEDIUM,
                    category="domain_reputation",
                    evidence=f"Creation date: {info.creation_date}",
                    remediation="Newly registered domains may indicate phishing or fraud. Verify domain ownership.",
                ))
            elif info.domain_age_days < 90:
                result.add_finding(Finding(
                    title="Recently Registered Domain",
                    description=f"Domain was registered {info.domain_age_days} days ago",
                    severity=Severity.LOW,
                    category="domain_reputation",
                    evidence=f"Creation date: {info.creation_date}",
                ))
        
        # Check for expiring domain
        if info.expiration_date:
            now = datetime.now(timezone.utc)
            exp_date = info.expiration_date
            if exp_date.tzinfo is None:
                exp_date = exp_date.replace(tzinfo=timezone.utc)
            
            days_until_expiry = (exp_date - now).days
            
            if days_until_expiry < 0:
                result.add_finding(Finding(
                    title="Domain Registration Expired",
                    description=f"Domain registration expired {abs(days_until_expiry)} days ago",
                    severity=Severity.HIGH,
                    category="domain_management",
                    evidence=f"Expiration date: {info.expiration_date}",
                    remediation="Renew the domain registration immediately to prevent takeover.",
                ))
            elif days_until_expiry <= 30:
                result.add_finding(Finding(
                    title="Domain Registration Expiring Soon",
                    description=f"Domain registration expires in {days_until_expiry} days",
                    severity=Severity.MEDIUM,
                    category="domain_management",
                    evidence=f"Expiration date: {info.expiration_date}",
                    remediation="Renew the domain registration to prevent service disruption.",
                ))
        
        # Check DNSSEC
        if info.dnssec and info.dnssec.lower() in ['unsigned', 'no', 'inactive']:
            result.add_finding(Finding(
                title="DNSSEC Not Enabled",
                description="Domain does not have DNSSEC enabled",
                severity=Severity.LOW,
                category="dns_security",
                remediation="Consider enabling DNSSEC to protect against DNS spoofing attacks.",
            ))
        
        # Check for privacy protection (may indicate legitimate business or suspicious activity)
        privacy_indicators = ['privacy', 'proxy', 'redacted', 'whoisguard', 'domains by proxy']
        registrar_lower = (info.registrar or '').lower()
        org_lower = (info.registrant_org or '').lower()
        
        is_privacy_protected = any(
            ind in registrar_lower or ind in org_lower 
            for ind in privacy_indicators
        )
        
        if is_privacy_protected:
            result.add_finding(Finding(
                title="WHOIS Privacy Protection Enabled",
                description="Domain uses WHOIS privacy protection service",
                severity=Severity.INFO,
                category="domain_reputation",
                evidence=f"Registrant: {info.registrant_org or 'N/A'}",
            ))
        
        # Add informational finding with WHOIS details
        result.add_finding(Finding(
            title="WHOIS Information",
            description=f"Registration details for {domain}",
            severity=Severity.INFO,
            category="domain_information",
            evidence=(
                f"Registrar: {info.registrar or 'N/A'}\n"
                f"Organization: {info.registrant_org or 'N/A'}\n"
                f"Country: {info.registrant_country or 'N/A'}\n"
                f"Created: {info.creation_date or 'N/A'}\n"
                f"Expires: {info.expiration_date or 'N/A'}\n"
                f"Age: {info.domain_age_days or 'N/A'} days"
            ),
        ))
