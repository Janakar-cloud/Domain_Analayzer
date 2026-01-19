"""Subdomain takeover detection module."""

import re
from typing import Dict, List, Optional, Tuple

import dns.resolver
import dns.exception
import requests

from ..core.domain import DomainResult, Finding, Severity
from .base import BaseModule


class TakeoverDetectionModule(BaseModule):
    """
    Detect potential subdomain takeover vulnerabilities.
    
    Checks for dangling CNAMEs pointing to services that may be claimable.
    """

    name = "takeover_detection"
    description = "Detect potential subdomain takeover vulnerabilities"

    # Known vulnerable services and their indicators
    # Format: service_name -> (cname_patterns, fingerprints, severity)
    VULNERABLE_SERVICES: Dict[str, Tuple[List[str], List[str], Severity]] = {
        "GitHub Pages": (
            [r"\.github\.io$"],
            ["There isn't a GitHub Pages site here.", "For root URLs"],
            Severity.HIGH,
        ),
        "Heroku": (
            [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
            ["No such app", "no-such-app"],
            Severity.HIGH,
        ),
        "Amazon S3": (
            [r"\.s3\.amazonaws\.com$", r"\.s3-website[\.-]"],
            ["NoSuchBucket", "The specified bucket does not exist"],
            Severity.HIGH,
        ),
        "Amazon CloudFront": (
            [r"\.cloudfront\.net$"],
            ["Bad request", "ERROR: The request could not be satisfied"],
            Severity.MEDIUM,
        ),
        "Microsoft Azure": (
            [r"\.azurewebsites\.net$", r"\.cloudapp\.azure\.com$", r"\.azure-api\.net$", 
             r"\.azureedge\.net$", r"\.blob\.core\.windows\.net$", r"\.trafficmanager\.net$"],
            ["Error 404 - Web app not found", "The resource you are looking for has been removed"],
            Severity.HIGH,
        ),
        "Zendesk": (
            [r"\.zendesk\.com$"],
            ["Help Center Closed", "Oops, this help center no longer exists"],
            Severity.HIGH,
        ),
        "Shopify": (
            [r"\.myshopify\.com$"],
            ["Sorry, this shop is currently unavailable", "Only one step left!"],
            Severity.HIGH,
        ),
        "Tumblr": (
            [r"\.tumblr\.com$"],
            ["Whatever you were looking for doesn't currently exist at this address"],
            Severity.MEDIUM,
        ),
        "Wordpress": (
            [r"\.wordpress\.com$"],
            ["Do you want to register"],
            Severity.MEDIUM,
        ),
        "Ghost": (
            [r"\.ghost\.io$"],
            ["The thing you were looking for is no longer here"],
            Severity.MEDIUM,
        ),
        "Surge": (
            [r"\.surge\.sh$"],
            ["project not found"],
            Severity.HIGH,
        ),
        "Bitbucket": (
            [r"\.bitbucket\.io$"],
            ["Repository not found"],
            Severity.HIGH,
        ),
        "Pantheon": (
            [r"\.pantheonsite\.io$"],
            ["The gods are wise, but do not know of the site"],
            Severity.HIGH,
        ),
        "Fastly": (
            [r"\.fastly\.net$"],
            ["Fastly error: unknown domain"],
            Severity.MEDIUM,
        ),
        "Unbounce": (
            [r"\.unbouncepages\.com$"],
            ["The requested URL was not found on this server"],
            Severity.MEDIUM,
        ),
        "HelpScout": (
            [r"\.helpscoutdocs\.com$"],
            ["No settings were found for this company"],
            Severity.MEDIUM,
        ),
        "Cargo": (
            [r"\.cargocollective\.com$"],
            ["404 Not Found"],
            Severity.LOW,
        ),
        "Statuspage": (
            [r"\.statuspage\.io$"],
            ["You are being redirected", "Status page pushed a resolve"],
            Severity.MEDIUM,
        ),
        "Uservoice": (
            [r"\.uservoice\.com$"],
            ["This UserVoice subdomain is currently available!"],
            Severity.HIGH,
        ),
        "Readme": (
            [r"\.readme\.io$"],
            ["Project doesnt exist"],
            Severity.MEDIUM,
        ),
        "Netlify": (
            [r"\.netlify\.app$", r"\.netlify\.com$"],
            ["Not found - Request ID:"],
            Severity.HIGH,
        ),
        "Vercel": (
            [r"\.vercel\.app$", r"\.now\.sh$"],
            ["The deployment you are trying to access"],
            Severity.HIGH,
        ),
        "Fly.io": (
            [r"\.fly\.dev$"],
            ["404 Not Found"],
            Severity.HIGH,
        ),
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 10
        self._resolver.lifetime = 10
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.user_agent,
        })

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Check for subdomain takeover vulnerabilities.

        Args:
            domain: Domain to check
            result: DomainResult to populate
        """
        # Check the main domain
        self._check_domain(domain, result)
        
        # Check all discovered subdomains
        for subdomain in result.subdomains:
            self.rate_limit()
            self._check_domain(subdomain, result)

    def _check_domain(self, domain: str, result: DomainResult) -> None:
        """
        Check a single domain for takeover vulnerability.

        Args:
            domain: Domain to check
            result: DomainResult to add findings to
        """
        # Get CNAME record
        cname_target = self._get_cname(domain)
        
        if not cname_target:
            return
        
        # Check if CNAME points to a vulnerable service
        for service_name, (patterns, fingerprints, severity) in self.VULNERABLE_SERVICES.items():
            for pattern in patterns:
                if re.search(pattern, cname_target, re.IGNORECASE):
                    # Found a potentially vulnerable service
                    is_vulnerable = self._check_fingerprint(domain, fingerprints)
                    
                    if is_vulnerable:
                        result.is_takeover_candidate = True
                        result.takeover_type = service_name
                        
                        result.add_finding(Finding(
                            title=f"Subdomain Takeover Vulnerability ({service_name})",
                            description=f"Domain {domain} has a CNAME pointing to {service_name} that appears to be claimable",
                            severity=severity,
                            category="subdomain_takeover",
                            evidence=f"CNAME: {domain} -> {cname_target}\nService response indicates unclaimed resource",
                            remediation=(
                                f"Either claim the {service_name} resource or remove the CNAME record. "
                                f"An attacker could claim this resource and serve malicious content."
                            ),
                            references=[
                                "https://github.com/EdOverflow/can-i-take-over-xyz",
                            ],
                        ))
                    else:
                        # CNAME exists but service responds normally
                        result.add_finding(Finding(
                            title=f"External Service CNAME ({service_name})",
                            description=f"Domain {domain} points to {service_name}",
                            severity=Severity.INFO,
                            category="configuration",
                            evidence=f"CNAME: {domain} -> {cname_target}",
                        ))
                    
                    return  # Found a match, no need to check other services

    def _get_cname(self, domain: str) -> Optional[str]:
        """
        Get CNAME record for a domain.

        Args:
            domain: Domain to query

        Returns:
            CNAME target or None
        """
        try:
            answers = self._resolver.resolve(domain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as e:
            self.logger.debug(f"Error getting CNAME for {domain}: {e}")
        
        return None

    def _check_fingerprint(self, domain: str, fingerprints: List[str]) -> bool:
        """
        Check if HTTP response contains vulnerability fingerprints.

        Args:
            domain: Domain to check
            fingerprints: List of strings to look for

        Returns:
            True if vulnerable fingerprint found
        """
        for scheme in ["https", "http"]:
            try:
                response = self.session.get(
                    f"{scheme}://{domain}",
                    timeout=10,
                    allow_redirects=True,
                    verify=False,
                    proxies=self.config.proxy_settings,
                )
                
                content = response.text.lower()
                
                for fingerprint in fingerprints:
                    if fingerprint.lower() in content:
                        return True
                        
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                self.logger.debug(f"Error checking fingerprint for {domain}: {e}")
        
        return False

    def check_nxdomain_cname(self, domain: str) -> Optional[str]:
        """
        Check for NXDOMAIN on CNAME target (dangling DNS).

        Args:
            domain: Domain to check

        Returns:
            CNAME target if dangling, None otherwise
        """
        cname_target = self._get_cname(domain)
        
        if not cname_target:
            return None
        
        # Try to resolve the CNAME target
        try:
            self._resolver.resolve(cname_target, "A")
            return None  # Target resolves, not dangling
        except dns.resolver.NXDOMAIN:
            return cname_target  # Target doesn't exist, dangling!
        except Exception:
            return None
