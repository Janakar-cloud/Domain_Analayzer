"""CriminalIP integration module."""

from datetime import datetime
from typing import Optional

import requests

from ...core.domain import ThreatIntelResult
from .base import BaseThreatIntelModule


class CriminalIPModule(BaseThreatIntelModule):
    """
    CriminalIP API integration for IP and domain threat intelligence.
    
    CriminalIP provides comprehensive threat data including:
    - IP reputation and risk scoring
    - Domain malware/phishing detection
    - Open port and vulnerability information
    - Abuse history and threat categories
    """

    name = "criminalip"
    description = "IP and domain threat intelligence via CriminalIP"
    api_key_name = "criminalip"
    rate_limit_service = "criminalip"

    API_BASE = "https://api.criminalip.io/v1"

    # Risk level mappings
    RISK_LEVELS = {
        "critical": 5,
        "dangerous": 4,
        "moderate": 3,
        "low": 2,
        "safe": 1,
    }

    # Category mappings for threat types
    THREAT_CATEGORIES = {
        "malware": "Malware Distribution",
        "phishing": "Phishing",
        "spam": "Spam Source",
        "scanner": "Malicious Scanner",
        "bruteforce": "Brute Force Attack",
        "botnet": "Botnet",
        "proxy": "Malicious Proxy",
        "tor": "Tor Exit Node",
        "vpn": "VPN",
        "mining": "Cryptomining",
        "c2": "Command & Control",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers.update({
            "x-api-key": self.api_key,
            "Accept": "application/json",
        })

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """
        Look up IP reputation in CriminalIP.

        Args:
            ip: IP address to check

        Returns:
            ThreatIntelResult or None
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/asset/ip/report",
                params={"ip": ip},
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == 200:
                    return self._parse_ip_response(data.get("data", {}), ip)
                else:
                    self.logger.warning(f"CriminalIP API error: {data.get('message', 'Unknown error')}")
            elif response.status_code == 401:
                self.logger.error("CriminalIP API key is invalid")
            elif response.status_code == 429:
                self.logger.warning("CriminalIP rate limit exceeded")
            elif response.status_code == 404:
                # IP not found in database - return clean result
                return ThreatIntelResult(
                    source="CriminalIP",
                    is_malicious=False,
                    reports_count=0,
                    details={"ip": ip, "status": "not_found"},
                )
            else:
                self.logger.warning(f"CriminalIP returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"CriminalIP request error: {e}")
        
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Look up domain reputation in CriminalIP.

        Args:
            domain: Domain to check

        Returns:
            ThreatIntelResult or None
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/domain/report",
                params={"query": domain},
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == 200:
                    return self._parse_domain_response(data.get("data", {}), domain)
                else:
                    self.logger.warning(f"CriminalIP API error: {data.get('message', 'Unknown error')}")
            elif response.status_code == 401:
                self.logger.error("CriminalIP API key is invalid")
            elif response.status_code == 429:
                self.logger.warning("CriminalIP rate limit exceeded")
            elif response.status_code == 404:
                return ThreatIntelResult(
                    source="CriminalIP",
                    is_malicious=False,
                    reports_count=0,
                    details={"domain": domain, "status": "not_found"},
                )
            else:
                self.logger.warning(f"CriminalIP returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"CriminalIP request error: {e}")
        
        return None

    def _parse_ip_response(self, data: dict, ip: str) -> ThreatIntelResult:
        """
        Parse CriminalIP IP response.

        Args:
            data: API response data
            ip: IP that was looked up

        Returns:
            ThreatIntelResult
        """
        # Extract score information
        score_info = data.get("score", {})
        inbound_score = score_info.get("inbound", 0)
        outbound_score = score_info.get("outbound", 0)
        
        # Use the higher of the two scores
        risk_score = max(inbound_score, outbound_score)
        
        # Determine if malicious based on score (scale is typically 0-100)
        is_malicious = risk_score >= 70
        
        # Calculate confidence (normalize to 0-1)
        confidence = risk_score / 100.0 if risk_score else 0.0
        
        # Extract categories from issues
        categories = set()
        tags = set()
        
        issues = data.get("issues", {})
        if issues.get("is_malicious"):
            categories.add("Malicious")
        if issues.get("is_scanner"):
            categories.add("Scanner")
            tags.add("scanner")
        if issues.get("is_vpn"):
            categories.add("VPN")
            tags.add("vpn")
        if issues.get("is_proxy"):
            categories.add("Proxy")
            tags.add("proxy")
        if issues.get("is_tor"):
            categories.add("Tor Exit Node")
            tags.add("tor")
        if issues.get("is_hosting"):
            tags.add("hosting")
        if issues.get("is_cloud"):
            tags.add("cloud")
        if issues.get("is_mobile"):
            tags.add("mobile")
        if issues.get("is_darkweb"):
            categories.add("Dark Web")
            tags.add("darkweb")
        if issues.get("is_snort"):
            categories.add("IDS Alert")
            tags.add("snort")
        
        # Extract abuse information
        abuse_info = data.get("abuse", {})
        abuse_count = abuse_info.get("abuse_count", 0)
        
        # Get whois information
        whois_info = data.get("whois", {})
        
        return ThreatIntelResult(
            source="CriminalIP",
            is_malicious=is_malicious,
            confidence_score=confidence,
            abuse_score=risk_score,
            categories=list(categories)[:10],
            tags=list(tags)[:20],
            reports_count=abuse_count,
            details={
                "ip": ip,
                "inbound_score": inbound_score,
                "outbound_score": outbound_score,
                "country": whois_info.get("country"),
                "as_name": whois_info.get("as_name"),
                "as_number": whois_info.get("as_no"),
                "org": whois_info.get("org_name"),
                "hostname": data.get("hostname"),
                "open_ports": len(data.get("port", {}).get("data", [])),
            },
        )

    def _parse_domain_response(self, data: dict, domain: str) -> ThreatIntelResult:
        """
        Parse CriminalIP domain response.

        Args:
            data: API response data
            domain: Domain that was looked up

        Returns:
            ThreatIntelResult
        """
        # Extract main domain info
        main_info = data.get("main", {})
        
        # Check for malicious indicators
        is_phishing = main_info.get("is_phishing", False)
        is_malware = main_info.get("is_malware", False)
        is_suspicious = main_info.get("is_suspicious", False)
        
        is_malicious = is_phishing or is_malware
        
        # Build categories
        categories = set()
        tags = set()
        
        if is_phishing:
            categories.add("Phishing")
            tags.add("phishing")
        if is_malware:
            categories.add("Malware")
            tags.add("malware")
        if is_suspicious:
            categories.add("Suspicious")
            tags.add("suspicious")
        
        # Extract certificate info if available
        cert_info = data.get("certificate", {})
        
        # Calculate confidence based on detection sources
        detection_count = sum([is_phishing, is_malware, is_suspicious])
        confidence = min(1.0, detection_count * 0.4) if detection_count else 0.0
        
        # Get connected IPs info
        connected_ips = data.get("connected_ip", {}).get("data", [])
        
        return ThreatIntelResult(
            source="CriminalIP",
            is_malicious=is_malicious,
            confidence_score=confidence,
            categories=list(categories)[:10],
            tags=list(tags)[:20],
            reports_count=detection_count,
            details={
                "domain": domain,
                "is_phishing": is_phishing,
                "is_malware": is_malware,
                "is_suspicious": is_suspicious,
                "connected_ips_count": len(connected_ips),
                "has_valid_cert": bool(cert_info),
                "title": main_info.get("title"),
                "favicon_hash": main_info.get("favicon_hash"),
            },
        )

    def get_ip_summary(self, ip: str) -> Optional[dict]:
        """
        Get a quick summary for an IP address.

        Args:
            ip: IP address to check

        Returns:
            Summary dictionary or None
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/ip/summary",
                params={"ip": ip},
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == 200:
                    return data.get("data", {})
                    
        except requests.exceptions.RequestException as e:
            self.logger.error(f"CriminalIP summary request error: {e}")
        
        return None
