"""AlienVault OTX integration module."""

from datetime import datetime
from typing import List, Optional

import requests

from ...core.domain import ThreatIntelResult
from .base import BaseThreatIntelModule


class AlienVaultOTXModule(BaseThreatIntelModule):
    """
    AlienVault OTX (Open Threat Exchange) integration.
    
    Provides threat intelligence for IPs and domains based on
    community-contributed indicators.
    """

    name = "alienvault_otx"
    description = "Threat intelligence via AlienVault OTX"
    api_key_name = "otx"
    rate_limit_service = "alienvault_otx"

    API_BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers.update({
            "X-OTX-API-KEY": self.api_key,
        })

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """
        Look up IP in AlienVault OTX.

        Args:
            ip: IP address to look up

        Returns:
            ThreatIntelResult or None
        """
        # Determine IP version
        ip_type = "IPv6" if ":" in ip else "IPv4"
        
        try:
            # Get general info
            response = self.session.get(
                f"{self.API_BASE}/indicators/{ip_type}/{ip}/general",
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_ip_response(data, ip)
            elif response.status_code == 404:
                return ThreatIntelResult(
                    source="AlienVault OTX",
                    is_malicious=False,
                    reports_count=0,
                )
            else:
                self.logger.warning(f"OTX returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"OTX request error: {e}")
        
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Look up domain in AlienVault OTX.

        Args:
            domain: Domain to look up

        Returns:
            ThreatIntelResult or None
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/indicators/domain/{domain}/general",
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_domain_response(data, domain)
            elif response.status_code == 404:
                return ThreatIntelResult(
                    source="AlienVault OTX",
                    is_malicious=False,
                    reports_count=0,
                )
            else:
                self.logger.warning(f"OTX returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"OTX request error: {e}")
        
        return None

    def _parse_ip_response(self, data: dict, ip: str) -> ThreatIntelResult:
        """Parse OTX IP response."""
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        
        # Extract tags and categories from pulses
        tags = set()
        categories = set()
        
        for pulse in pulses[:10]:  # Limit processing
            tags.update(pulse.get("tags", []))
            if pulse.get("targeted_countries"):
                categories.add("Targeted Attack")
            if pulse.get("malware_families"):
                categories.add("Malware")
        
        # Determine if malicious based on pulse count
        is_malicious = pulse_count >= 3
        
        # Calculate confidence based on pulse count
        confidence = min(1.0, pulse_count / 10.0) if pulse_count > 0 else 0.0
        
        return ThreatIntelResult(
            source="AlienVault OTX",
            is_malicious=is_malicious,
            confidence_score=confidence,
            categories=list(categories)[:10],
            tags=list(tags)[:20],
            reports_count=pulse_count,
            details={
                "ip": ip,
                "reputation": data.get("reputation", 0),
                "asn": data.get("asn"),
                "country": data.get("country_name"),
            },
        )

    def _parse_domain_response(self, data: dict, domain: str) -> ThreatIntelResult:
        """Parse OTX domain response."""
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        
        # Extract tags and categories
        tags = set()
        categories = set()
        
        for pulse in pulses[:10]:
            tags.update(pulse.get("tags", []))
            if "phishing" in str(pulse).lower():
                categories.add("Phishing")
            if "malware" in str(pulse).lower():
                categories.add("Malware")
            if "c2" in str(pulse).lower() or "command" in str(pulse).lower():
                categories.add("C2/Botnet")
        
        is_malicious = pulse_count >= 3
        confidence = min(1.0, pulse_count / 10.0) if pulse_count > 0 else 0.0
        
        # Check for Alexa ranking (legitimate sites usually have rankings)
        alexa_rank = data.get("alexa")
        if alexa_rank and int(alexa_rank) < 100000:
            # Popular site, less likely to be malicious
            is_malicious = False
            confidence *= 0.5
        
        return ThreatIntelResult(
            source="AlienVault OTX",
            is_malicious=is_malicious,
            confidence_score=confidence,
            categories=list(categories)[:10],
            tags=list(tags)[:20],
            reports_count=pulse_count,
            details={
                "domain": domain,
                "alexa_rank": alexa_rank,
                "whois": data.get("whois"),
            },
        )

    def get_pulses_for_indicator(self, indicator: str, indicator_type: str) -> List[dict]:
        """
        Get detailed pulse information for an indicator.

        Args:
            indicator: IP or domain
            indicator_type: 'IPv4', 'IPv6', or 'domain'

        Returns:
            List of pulse dictionaries
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/indicators/{indicator_type}/{indicator}/general",
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("pulse_info", {}).get("pulses", [])
                
        except Exception as e:
            self.logger.error(f"Error getting OTX pulses: {e}")
        
        return []
