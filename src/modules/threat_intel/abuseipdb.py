"""AbuseIPDB integration module."""

from datetime import datetime
from typing import Optional

import requests

from ...core.domain import ThreatIntelResult
from .base import BaseThreatIntelModule


class AbuseIPDBModule(BaseThreatIntelModule):
    """
    AbuseIPDB API integration for IP reputation checking.
    
    Checks if IP addresses have been reported for malicious activity.
    """

    name = "abuseipdb"
    description = "IP reputation checking via AbuseIPDB"
    api_key_name = "abuseipdb"
    rate_limit_service = "abuseipdb"

    API_BASE = "https://api.abuseipdb.com/api/v2"

    # AbuseIPDB category mappings
    CATEGORIES = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers.update({
            "Key": self.api_key,
            "Accept": "application/json",
        })

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """
        Check IP reputation in AbuseIPDB.

        Args:
            ip: IP address to check

        Returns:
            ThreatIntelResult or None
        """
        max_age_days = self._module_config.get("max_age_days", 90)
        
        try:
            response = self.session.get(
                f"{self.API_BASE}/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True,
                },
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                return self._parse_response(data, ip)
            elif response.status_code == 401:
                self.logger.error("AbuseIPDB API key is invalid")
            elif response.status_code == 429:
                self.logger.warning("AbuseIPDB rate limit exceeded")
            else:
                self.logger.warning(f"AbuseIPDB returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"AbuseIPDB request error: {e}")
        
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        AbuseIPDB doesn't directly support domain lookups.
        Returns None - domain checks are done via resolved IPs.
        """
        return None

    def _parse_response(self, data: dict, ip: str) -> ThreatIntelResult:
        """
        Parse AbuseIPDB response.

        Args:
            data: API response data
            ip: IP that was looked up

        Returns:
            ThreatIntelResult
        """
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        
        # Parse categories from reports
        categories = set()
        for report in data.get("reports", []):
            for cat_id in report.get("categories", []):
                if cat_id in self.CATEGORIES:
                    categories.add(self.CATEGORIES[cat_id])
        
        # Parse last seen
        last_reported = data.get("lastReportedAt")
        last_seen = None
        if last_reported:
            try:
                last_seen = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
            except ValueError:
                pass
        
        # Determine if malicious (score >= 25 is commonly used threshold)
        is_malicious = abuse_score >= 25
        
        return ThreatIntelResult(
            source="AbuseIPDB",
            is_malicious=is_malicious,
            abuse_score=abuse_score,
            categories=list(categories),
            last_seen=last_seen,
            reports_count=total_reports,
            details={
                "ip": ip,
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "country": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
            },
        )
