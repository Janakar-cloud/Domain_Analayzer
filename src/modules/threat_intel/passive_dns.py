"""Passive DNS history module (SecurityTrails)."""

from typing import Dict, List, Optional

import requests

from ...core.domain import ThreatIntelResult
from .base import BaseThreatIntelModule


class PassiveDNSModule(BaseThreatIntelModule):
    """
    Retrieve passive DNS history for domains.

    Uses SecurityTrails historical DNS endpoint to gather previously
    observed A-record values and timelines.
    """

    name = "passive_dns"
    description = "Passive DNS historical record lookups"
    api_key_name = "securitytrails"
    rate_limit_service = "securitytrails"

    API_BASE = "https://api.securitytrails.com/v1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers.update({
            "APIKEY": self.api_key,
            "Accept": "application/json",
        })

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Passive DNS lookups in this module are domain-focused."""
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Look up historical A records for a domain.

        Args:
            domain: Domain name

        Returns:
            ThreatIntelResult
        """
        endpoint = f"{self.API_BASE}/history/{domain}/dns/a"

        try:
            response = self.session.get(
                endpoint,
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )

            if response.status_code == 200:
                return self._parse_response(response.json() or {}, domain)
            if response.status_code == 401:
                self.logger.error("SecurityTrails API key is invalid")
                return None
            if response.status_code == 404:
                return ThreatIntelResult(
                    source="SecurityTrails PassiveDNS",
                    is_malicious=False,
                    reports_count=0,
                    details={
                        "domain": domain,
                        "status": "not_found",
                        "historical_a_records": [],
                    },
                )
            if response.status_code == 429:
                self.logger.warning("SecurityTrails rate limit exceeded")
                return None

            self.logger.warning(f"SecurityTrails returned status {response.status_code}")

        except requests.exceptions.RequestException as exc:
            self.logger.error(f"SecurityTrails request error: {exc}")

        return None

    def _parse_response(self, data: Dict, domain: str) -> ThreatIntelResult:
        """Parse SecurityTrails historical DNS response."""
        records = data.get("records", []) or []

        historical_ips = set()
        timeline: List[Dict[str, object]] = []

        for record in records:
            values = record.get("values", []) or []
            resolved_values: List[str] = []

            for value in values:
                ip = None
                if isinstance(value, dict):
                    ip = value.get("ip") or value.get("value") or value.get("address")
                elif value is not None:
                    ip = str(value)

                if ip:
                    historical_ips.add(str(ip))
                    resolved_values.append(str(ip))

            if resolved_values:
                timeline.append({
                    "first_seen": record.get("first_seen"),
                    "last_seen": record.get("last_seen"),
                    "values": resolved_values[:20],
                })

        return ThreatIntelResult(
            source="SecurityTrails PassiveDNS",
            is_malicious=False,
            confidence_score=None,
            categories=["Passive DNS"],
            # Keep 0 to avoid false-positive suspicious findings for normal history.
            reports_count=0,
            details={
                "domain": domain,
                "historical_a_records": sorted(historical_ips),
                "history_count": len(timeline),
                "timeline": timeline[:30],
            },
        )
