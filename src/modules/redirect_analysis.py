"""Redirect chain analysis module."""

from typing import List, Optional
from urllib.parse import urlparse

import requests

from ..core.domain import DomainResult, Finding, RedirectInfo, Severity
from .base import BaseModule


class RedirectAnalysisModule(BaseModule):
    """
    Analyze HTTP redirect chains.
    
    Detects excessive redirects, HTTP to HTTPS upgrades, and insecure redirects.
    """

    name = "redirect_analysis"
    description = "Analyze HTTP redirect chains for security issues"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.user_agent,
        })
        # Disable automatic redirects to track chain manually
        self.session.max_redirects = 0

    @property
    def verify_ssl(self) -> bool:
        """Get SSL verification setting. Defaults to True for security."""
        return self.get_setting("verify_ssl", True)

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Analyze redirect chain for the domain.

        Args:
            domain: Domain to analyze
            result: DomainResult to populate
        """
        self.rate_limit()
        
        # Start with HTTP to check for HTTPS redirect
        http_chain = self._follow_redirects(f"http://{domain}")
        https_chain = self._follow_redirects(f"https://{domain}")
        
        # Use the more complete chain
        chain = http_chain if len(http_chain) > len(https_chain) else https_chain
        
        if chain:
            result.redirect_chain = chain
            result.final_url = chain[-1].url if chain else None
            self._analyze_chain(chain, domain, result)

    def _follow_redirects(self, url: str) -> List[RedirectInfo]:
        """
        Follow redirect chain and record each hop.

        Args:
            url: Starting URL

        Returns:
            List of RedirectInfo objects
        """
        chain = []
        max_redirects = self.get_setting("max_redirects", 10)
        current_url = url
        
        for _ in range(max_redirects + 1):
            try:
                response = self.session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=self.get_setting("timeout", 15),
                    proxies=self.config.proxy_settings,
                    verify=self.verify_ssl,  # SSL verification enabled by default
                )
                
                parsed = urlparse(current_url)
                is_https = parsed.scheme == "https"
                
                redirect_info = RedirectInfo(
                    url=current_url,
                    status_code=response.status_code,
                    location=response.headers.get("Location"),
                    is_https=is_https,
                )
                chain.append(redirect_info)
                
                # Check for redirect
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if location:
                        # Handle relative URLs
                        if location.startswith("/"):
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        elif not location.startswith(("http://", "https://")):
                            location = f"{parsed.scheme}://{parsed.netloc}/{location}"
                        current_url = location
                    else:
                        break
                else:
                    # Not a redirect, end of chain
                    break
                    
            except requests.exceptions.SSLError as e:
                self.logger.debug(f"SSL error following redirect to {current_url}: {e}")
                chain.append(RedirectInfo(
                    url=current_url,
                    status_code=0,
                    location=None,
                    is_https=current_url.startswith("https"),
                ))
                break
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Error following redirect to {current_url}: {e}")
                break
        
        return chain

    def _analyze_chain(
        self, 
        chain: List[RedirectInfo], 
        domain: str, 
        result: DomainResult
    ) -> None:
        """
        Analyze redirect chain for security issues.

        Args:
            chain: List of RedirectInfo objects
            domain: Original domain
            result: DomainResult to add findings to
        """
        if not chain:
            return
        
        # Check for HTTP to HTTPS redirect
        first_hop = chain[0]
        if first_hop.url.startswith("http://"):
            # Check if it redirects to HTTPS
            redirects_to_https = any(r.is_https for r in chain[1:])
            
            if redirects_to_https:
                result.add_finding(Finding(
                    title="HTTP to HTTPS Redirect Configured",
                    description="Site properly redirects HTTP traffic to HTTPS",
                    severity=Severity.INFO,
                    category="transport_security",
                ))
            else:
                result.add_finding(Finding(
                    title="No HTTP to HTTPS Redirect",
                    description="Site does not redirect HTTP traffic to HTTPS",
                    severity=Severity.MEDIUM,
                    category="transport_security",
                    remediation="Configure server to redirect all HTTP requests to HTTPS.",
                ))
        
        # Check for HTTPS to HTTP downgrade
        https_to_http = False
        for i in range(len(chain) - 1):
            if chain[i].is_https and not chain[i + 1].is_https:
                https_to_http = True
                break
        
        if https_to_http:
            result.add_finding(Finding(
                title="Insecure Redirect (HTTPS to HTTP)",
                description="Redirect chain downgrades from HTTPS to HTTP",
                severity=Severity.HIGH,
                category="transport_security",
                evidence=self._format_chain(chain),
                remediation="Ensure all redirects stay on HTTPS to prevent downgrade attacks.",
            ))
        
        # Check for excessive redirects
        if len(chain) > 3:
            severity = Severity.MEDIUM if len(chain) > 5 else Severity.LOW
            result.add_finding(Finding(
                title="Excessive Redirect Chain",
                description=f"Redirect chain has {len(chain)} hops",
                severity=severity,
                category="performance",
                evidence=self._format_chain(chain),
                remediation="Reduce redirect hops for better performance and user experience.",
            ))
        
        # Check for redirect loops
        urls_seen = set()
        for r in chain:
            if r.url in urls_seen:
                result.add_finding(Finding(
                    title="Redirect Loop Detected",
                    description="Redirect chain contains a loop",
                    severity=Severity.HIGH,
                    category="configuration",
                    evidence=self._format_chain(chain),
                    remediation="Fix server configuration to eliminate redirect loops.",
                ))
                break
            urls_seen.add(r.url)
        
        # Check for cross-domain redirects
        original_domain = domain.lower()
        cross_domain_redirects = []
        
        for r in chain:
            parsed = urlparse(r.url)
            hop_domain = parsed.netloc.lower()
            
            # Check if it's a different domain
            if hop_domain and not hop_domain.endswith(original_domain):
                cross_domain_redirects.append(hop_domain)
        
        if cross_domain_redirects:
            unique_domains = list(set(cross_domain_redirects))
            result.add_finding(Finding(
                title="Cross-Domain Redirects",
                description=f"Redirect chain includes external domains",
                severity=Severity.LOW,
                category="configuration",
                evidence=f"External domains: {', '.join(unique_domains)}",
            ))
        
        # Add informational finding with full chain
        result.add_finding(Finding(
            title="Redirect Chain Summary",
            description=f"Redirect chain with {len(chain)} hop(s)",
            severity=Severity.INFO,
            category="configuration",
            evidence=self._format_chain(chain),
        ))

    def _format_chain(self, chain: List[RedirectInfo]) -> str:
        """Format redirect chain for display."""
        lines = []
        for i, r in enumerate(chain):
            status = f"[{r.status_code}]" if r.status_code else "[Error]"
            https = "🔒" if r.is_https else "⚠️"
            lines.append(f"{i + 1}. {https} {status} {r.url}")
        return "\n".join(lines)
