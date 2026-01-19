"""VirusTotal integration module."""

import base64
from datetime import datetime
from typing import Optional

import requests

from ...core.domain import ThreatIntelResult
from .base import BaseThreatIntelModule


class VirusTotalModule(BaseThreatIntelModule):
    """
    VirusTotal API integration.
    
    Checks IP addresses and domains against VirusTotal's database
    of security vendor detections.
    """

    name = "virustotal"
    description = "Multi-vendor threat detection via VirusTotal"
    api_key_name = "virustotal"
    rate_limit_service = "virustotal"

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers.update({
            "x-apikey": self.api_key,
        })

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """
        Look up IP in VirusTotal.

        Args:
            ip: IP address to look up

        Returns:
            ThreatIntelResult or None
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/ip_addresses/{ip}",
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                return self._parse_response(data, ip, "ip")
            elif response.status_code == 404:
                return ThreatIntelResult(
                    source="VirusTotal",
                    is_malicious=False,
                    reports_count=0,
                )
            elif response.status_code == 401:
                self.logger.error("VirusTotal API key is invalid")
            elif response.status_code == 429:
                self.logger.warning("VirusTotal rate limit exceeded")
            else:
                self.logger.warning(f"VirusTotal returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal request error: {e}")
        
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Look up domain in VirusTotal.

        Args:
            domain: Domain to look up

        Returns:
            ThreatIntelResult or None
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/domains/{domain}",
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                return self._parse_response(data, domain, "domain")
            elif response.status_code == 404:
                return ThreatIntelResult(
                    source="VirusTotal",
                    is_malicious=False,
                    reports_count=0,
                )
            elif response.status_code == 401:
                self.logger.error("VirusTotal API key is invalid")
            elif response.status_code == 429:
                self.logger.warning("VirusTotal rate limit exceeded")
            else:
                self.logger.warning(f"VirusTotal returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal request error: {e}")
        
        return None

    def _parse_response(self, data: dict, indicator: str, indicator_type: str) -> ThreatIntelResult:
        """
        Parse VirusTotal response.

        Args:
            data: API response data
            indicator: IP or domain that was looked up
            indicator_type: 'ip' or 'domain'

        Returns:
            ThreatIntelResult
        """
        attributes = data.get("attributes", {})
        
        # Get last analysis stats
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        harmless_count = stats.get("harmless", 0)
        total_vendors = malicious_count + suspicious_count + harmless_count + stats.get("undetected", 0)
        
        # Determine if malicious (threshold: 3+ vendors flagging as malicious)
        is_malicious = malicious_count >= 3
        
        # Calculate confidence score
        if total_vendors > 0:
            confidence = (malicious_count + suspicious_count * 0.5) / total_vendors
        else:
            confidence = 0.0
        
        # Extract categories from analysis results
        categories = set()
        last_analysis = attributes.get("last_analysis_results", {})
        
        for vendor, result in last_analysis.items():
            if result.get("category") in ("malicious", "suspicious"):
                vendor_result = result.get("result", "")
                if vendor_result:
                    categories.add(vendor_result)
        
        # Get last analysis date
        last_analysis_date = attributes.get("last_analysis_date")
        last_seen = None
        if last_analysis_date:
            try:
                last_seen = datetime.fromtimestamp(last_analysis_date)
            except (ValueError, OSError):
                pass
        
        # Extract tags
        tags = attributes.get("tags", [])
        
        # Additional context based on indicator type
        details = {
            "indicator": indicator,
            "type": indicator_type,
            "malicious_votes": malicious_count,
            "suspicious_votes": suspicious_count,
            "harmless_votes": harmless_count,
            "total_vendors": total_vendors,
        }
        
        if indicator_type == "ip":
            details.update({
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "country": attributes.get("country"),
                "continent": attributes.get("continent"),
            })
        elif indicator_type == "domain":
            details.update({
                "registrar": attributes.get("registrar"),
                "creation_date": attributes.get("creation_date"),
                "reputation": attributes.get("reputation", 0),
                "popularity_ranks": attributes.get("popularity_ranks", {}),
            })
        
        return ThreatIntelResult(
            source="VirusTotal",
            is_malicious=is_malicious,
            confidence_score=confidence,
            categories=list(categories)[:10],
            tags=tags[:20] if tags else [],
            last_seen=last_seen,
            reports_count=malicious_count + suspicious_count,
            details=details,
        )

    def scan_url(self, url: str) -> Optional[str]:
        """
        Submit a URL for scanning.

        Args:
            url: URL to scan

        Returns:
            Analysis ID or None
        """
        try:
            response = self.session.post(
                f"{self.API_BASE}/urls",
                data={"url": url},
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                return response.json().get("data", {}).get("id")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal URL scan error: {e}")
        
        return None

    def get_url_report(self, url: str) -> Optional[dict]:
        """
        Get analysis report for a URL.

        Args:
            url: URL to get report for

        Returns:
            Analysis report or None
        """
        # URL ID is base64 encoded URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        
        try:
            response = self.session.get(
                f"{self.API_BASE}/urls/{url_id}",
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                return response.json().get("data", {})
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"VirusTotal URL report error: {e}")
        
        return None
