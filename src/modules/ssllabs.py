"""SSL Labs integration module."""

import time
from typing import Any, Dict, Optional

import requests

from ..core.domain import DomainResult, Finding, Severity, SSLLabsResult
from .base import BaseModule


class SSLLabsModule(BaseModule):
    """
    SSL Labs API integration for TLS configuration assessment.
    
    Uses the Qualys SSL Labs API to get detailed TLS analysis including
    protocol support, vulnerabilities, and overall grade.
    """

    name = "ssllabs"
    description = "SSL Labs assessment for TLS configuration grading"

    API_BASE = "https://api.ssllabs.com/api/v3"
    
    # Grade severity mapping
    GRADE_SEVERITY = {
        "A+": Severity.INFO,
        "A": Severity.INFO,
        "A-": Severity.LOW,
        "B": Severity.LOW,
        "C": Severity.MEDIUM,
        "D": Severity.MEDIUM,
        "E": Severity.HIGH,
        "F": Severity.HIGH,
        "T": Severity.HIGH,  # Trust issues
        "M": Severity.HIGH,  # Certificate name mismatch
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.user_agent,
        })

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Run SSL Labs assessment.

        Args:
            domain: Domain to assess
            result: DomainResult to populate
        """
        self.rate_limit("ssllabs")
        
        ssllabs_result = self._analyze_domain(domain)
        
        if ssllabs_result:
            result.ssllabs_result = ssllabs_result
            self._add_findings(ssllabs_result, domain, result)
        else:
            result.add_error(f"Could not complete SSL Labs assessment for {domain}")

    def _analyze_domain(self, domain: str) -> Optional[SSLLabsResult]:
        """
        Run SSL Labs analysis.

        Args:
            domain: Domain to analyze

        Returns:
            SSLLabsResult or None
        """
        max_age = self.get_setting("max_age", 24)
        
        try:
            # Start analysis or get cached results
            response = self._api_request("analyze", {
                "host": domain,
                "publish": "off",
                "fromCache": "on",
                "maxAge": max_age,
                "all": "done",
            })
            
            if not response:
                return None
            
            # Poll until complete
            status = response.get("status")
            attempts = 0
            # Make polling tunable to reduce scan time
            poll_interval = int(self.get_setting("poll_interval_seconds", 5))
            max_attempts = int(self.get_setting("max_attempts", 12))  # ~60s default
            
            while status not in ("READY", "ERROR") and attempts < max_attempts:
                time.sleep(max(1, poll_interval))
                self.rate_limit("ssllabs")
                
                response = self._api_request("analyze", {
                    "host": domain,
                    "all": "done",
                })
                
                if not response:
                    return None
                
                status = response.get("status")
                attempts += 1
                
                self.logger.debug(f"SSL Labs status for {domain}: {status}")
            
            if status == "ERROR":
                error_msg = response.get("statusMessage", "Unknown error")
                self.logger.warning(f"SSL Labs error for {domain}: {error_msg}")
                return None
            
            if status != "READY":
                self.logger.warning(f"SSL Labs timed out for {domain} (status={status})")
                return None
            
            return self._parse_result(response)
            
        except Exception as e:
            self.logger.error(f"Error running SSL Labs for {domain}: {e}")
            return None

    def _api_request(self, endpoint: str, params: Dict[str, Any]) -> Optional[Dict]:
        """
        Make an API request to SSL Labs.

        Args:
            endpoint: API endpoint
            params: Query parameters

        Returns:
            Response JSON or None
        """
        try:
            url = f"{self.API_BASE}/{endpoint}"
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                self.logger.warning("SSL Labs rate limit exceeded")
                return None
            else:
                self.logger.warning(f"SSL Labs returned status {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"SSL Labs request error: {e}")
            return None

    def _parse_result(self, data: Dict) -> SSLLabsResult:
        """
        Parse SSL Labs API response.

        Args:
            data: API response data

        Returns:
            SSLLabsResult object
        """
        endpoints = data.get("endpoints", [])
        
        # Get best grade from all endpoints
        grades = []
        protocols = set()
        vulnerabilities = []
        has_warnings = False
        is_exceptional = False
        
        for endpoint in endpoints:
            grade = endpoint.get("grade")
            if grade:
                grades.append(grade)
            
            if endpoint.get("hasWarnings"):
                has_warnings = True
            
            if endpoint.get("isExceptional"):
                is_exceptional = True
            
            # Parse details
            details = endpoint.get("details", {})
            
            # Get protocols
            for proto in details.get("protocols", []):
                proto_str = f"{proto.get('name', '')} {proto.get('version', '')}"
                protocols.add(proto_str.strip())
            
            # Check for vulnerabilities
            vuln_checks = [
                ("poodle", "POODLE"),
                ("poodleTls", "POODLE TLS"),
                ("drownVulnerable", "DROWN"),
                ("heartbleed", "Heartbleed"),
                ("freak", "FREAK"),
                ("logjam", "Logjam"),
                ("zombiePoodle", "Zombie POODLE"),
                ("goldenDoodle", "GOLDENDOODLE"),
                ("zeroLengthPaddingOracle", "0-Length Padding Oracle"),
                ("sleepingPoodle", "Sleeping POODLE"),
                ("ticketBleed", "TicketBleed"),
                ("bleichenbacher", "ROBOT"),
            ]
            
            for key, name in vuln_checks:
                value = details.get(key)
                if value and value not in (0, -1, False, "N/A"):
                    if name not in vulnerabilities:
                        vulnerabilities.append(name)
        
        # Determine best grade
        grade_order = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]
        best_grade = None
        for g in grade_order:
            if g in grades:
                best_grade = g
                break
        
        if not best_grade and grades:
            best_grade = grades[0]
        
        return SSLLabsResult(
            grade=best_grade,
            has_warnings=has_warnings,
            is_exceptional=is_exceptional,
            protocols=sorted(protocols),
            vulnerabilities=vulnerabilities,
            details=data,
        )

    def _add_findings(self, ssllabs: SSLLabsResult, domain: str, result: DomainResult) -> None:
        """
        Add findings based on SSL Labs results.

        Args:
            ssllabs: SSLLabsResult to analyze
            domain: Domain being analyzed
            result: DomainResult to add findings to
        """
        # Grade finding
        if ssllabs.grade:
            severity = self.GRADE_SEVERITY.get(ssllabs.grade, Severity.MEDIUM)
            
            if ssllabs.grade in ("A+", "A"):
                title = f"Excellent SSL/TLS Configuration (Grade: {ssllabs.grade})"
                description = "SSL Labs assessment shows excellent TLS configuration"
            elif ssllabs.grade in ("A-", "B"):
                title = f"Good SSL/TLS Configuration (Grade: {ssllabs.grade})"
                description = "SSL Labs assessment shows good TLS configuration with minor issues"
            else:
                title = f"Poor SSL/TLS Configuration (Grade: {ssllabs.grade})"
                description = "SSL Labs assessment indicates TLS configuration issues"
            
            result.add_finding(Finding(
                title=title,
                description=description,
                severity=severity,
                category="tls_security",
                evidence=f"Grade: {ssllabs.grade}\nProtocols: {', '.join(ssllabs.protocols)}",
                remediation="Review SSL Labs report for specific recommendations." if severity > Severity.LOW else None,
                references=["https://www.ssllabs.com/ssltest/"],
            ))
        
        # Vulnerability findings
        for vuln in ssllabs.vulnerabilities:
            result.add_finding(Finding(
                title=f"TLS Vulnerability: {vuln}",
                description=f"SSL Labs detected vulnerability: {vuln}",
                severity=Severity.HIGH,
                category="tls_vulnerability",
                remediation=f"Mitigate {vuln} vulnerability by updating TLS configuration.",
            ))
        
        # Protocol warnings
        weak_protocols = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]
        found_weak = [p for p in ssllabs.protocols if any(w in p for w in weak_protocols)]
        
        if found_weak:
            result.add_finding(Finding(
                title="Deprecated TLS Protocols Enabled",
                description="Server supports deprecated TLS protocols",
                severity=Severity.MEDIUM,
                category="tls_security",
                evidence=f"Weak protocols: {', '.join(found_weak)}",
                remediation="Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1. Only support TLS 1.2 and TLS 1.3.",
            ))
