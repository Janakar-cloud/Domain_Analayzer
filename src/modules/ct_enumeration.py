"""Certificate Transparency enumeration module."""

import re
from typing import List, Optional, Set
from urllib.parse import quote

import requests

from ..core.domain import DomainResult, Finding, Severity
from .base import BaseModule


class CTEnumerationModule(BaseModule):
    """
    Enumerate subdomains via Certificate Transparency logs.
    
    Uses crt.sh to discover certificates issued for a domain and its subdomains.
    """

    name = "ct_enumeration"
    description = "Discover subdomains via Certificate Transparency logs (crt.sh)"

    CRTSH_URL = "https://crt.sh/"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "application/json",
        })

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Query crt.sh for certificates and extract subdomains.

        Args:
            domain: Domain to search
            result: DomainResult to populate
        """
        self.rate_limit("crtsh")
        
        subdomains = self._query_crtsh(domain)
        
        if subdomains:
            # Filter and clean subdomains
            valid_subdomains = self._filter_subdomains(subdomains, domain)
            result.subdomains.extend(valid_subdomains)
            
            self.logger.info(f"Found {len(valid_subdomains)} unique subdomains for {domain}")
            
            # Add informational finding
            result.add_finding(Finding(
                title="Certificate Transparency Enumeration",
                description=f"Discovered {len(valid_subdomains)} subdomains via CT logs",
                severity=Severity.INFO,
                category="reconnaissance",
                evidence=f"Subdomains: {', '.join(list(valid_subdomains)[:10])}{'...' if len(valid_subdomains) > 10 else ''}",
            ))
            
            # Check for interesting patterns
            self._analyze_subdomains(valid_subdomains, result)
        else:
            self.logger.warning(f"No subdomains found for {domain}")

    def _query_crtsh(self, domain: str) -> Optional[List[dict]]:
        """
        Query crt.sh API for certificate data.

        Args:
            domain: Domain to search

        Returns:
            List of certificate records or None
        """
        try:
            # Query for certificates matching the domain
            url = f"{self.CRTSH_URL}?q=%.{quote(domain)}&output=json"
            
            response = self.session.get(
                url,
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.debug(f"No certificates found for {domain}")
                return None
            else:
                self.logger.warning(f"crt.sh returned status {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            self.logger.warning(f"Timeout querying crt.sh for {domain}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error querying crt.sh: {e}")
            return None
        except ValueError as e:
            self.logger.error(f"Error parsing crt.sh response: {e}")
            return None

    def _filter_subdomains(self, certs: List[dict], base_domain: str) -> Set[str]:
        """
        Extract and filter valid subdomains from certificate data.

        Args:
            certs: Certificate records from crt.sh
            base_domain: Base domain to filter by

        Returns:
            Set of unique subdomains
        """
        subdomains = set()
        base_domain_lower = base_domain.lower()
        
        for cert in certs:
            # Extract from common_name
            cn = cert.get("common_name", "")
            if cn:
                self._process_name(cn, base_domain_lower, subdomains)
            
            # Extract from name_value (SANs)
            names = cert.get("name_value", "")
            if names:
                for name in names.split("\n"):
                    self._process_name(name.strip(), base_domain_lower, subdomains)
        
        return subdomains

    def _process_name(self, name: str, base_domain: str, subdomains: Set[str]) -> None:
        """
        Process a certificate name and add valid subdomains.

        Args:
            name: Certificate name to process
            base_domain: Base domain for filtering
            subdomains: Set to add valid subdomains to
        """
        name = name.lower().strip()
        
        # Skip wildcards for now (we'll note them separately)
        if name.startswith("*."):
            name = name[2:]
        
        # Validate the subdomain
        if self._is_valid_subdomain(name, base_domain):
            subdomains.add(name)

    def _is_valid_subdomain(self, name: str, base_domain: str) -> bool:
        """
        Check if a name is a valid subdomain.

        Args:
            name: Name to check
            base_domain: Base domain

        Returns:
            True if valid subdomain
        """
        # Must end with base domain
        if not name.endswith(base_domain):
            return False
        
        # Must be valid hostname format
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', name):
            return False
        
        # Exclude very long names (likely invalid)
        if len(name) > 253:
            return False
        
        return True

    def _analyze_subdomains(self, subdomains: Set[str], result: DomainResult) -> None:
        """
        Analyze subdomains for interesting patterns.

        Args:
            subdomains: Set of discovered subdomains
            result: DomainResult to add findings to
        """
        # Check for potentially sensitive subdomains
        sensitive_patterns = {
            "admin": "Administrative interface",
            "staging": "Staging environment",
            "dev": "Development environment",
            "test": "Test environment",
            "internal": "Internal service",
            "api": "API endpoint",
            "vpn": "VPN service",
            "mail": "Mail server",
            "ftp": "FTP server",
            "db": "Database server",
            "backup": "Backup service",
            "jenkins": "CI/CD server",
            "gitlab": "Source control",
            "jira": "Issue tracking",
            "confluence": "Documentation",
        }
        
        found_sensitive = []
        for subdomain in subdomains:
            for pattern, desc in sensitive_patterns.items():
                if pattern in subdomain.lower():
                    found_sensitive.append((subdomain, desc))
                    break
        
        if found_sensitive:
            result.add_finding(Finding(
                title="Potentially Sensitive Subdomains Discovered",
                description=f"Found {len(found_sensitive)} subdomains with potentially sensitive names",
                severity=Severity.LOW,
                category="reconnaissance",
                evidence="\n".join([f"- {s}: {d}" for s, d in found_sensitive[:10]]),
                remediation="Review these subdomains to ensure they are not exposing sensitive services to the internet.",
            ))

        # Check for large number of subdomains (possible shadow IT)
        if len(subdomains) > 50:
            result.add_finding(Finding(
                title="Large Number of Subdomains",
                description=f"Discovered {len(subdomains)} subdomains, which may indicate shadow IT or unmanaged assets",
                severity=Severity.INFO,
                category="asset_management",
                remediation="Review all subdomains to ensure they are authorized and properly managed.",
            ))
