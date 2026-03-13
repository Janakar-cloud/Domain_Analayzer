"""Google Safe Browsing integration module."""

from typing import Dict, List, Optional

import requests

from ...core.domain import ThreatIntelResult
from .base import BaseThreatIntelModule


class GoogleSafeBrowsingModule(BaseThreatIntelModule):
    """
    Google Safe Browsing integration for phishing/malware URL checks.

    Uses threatMatches:find endpoint to assess URLs under a domain.
    """

    name = "google_safe_browsing"
    description = "Google Safe Browsing phishing/malware detection"
    api_key_name = "google_safe_browsing"
    rate_limit_service = "google_safe_browsing"

    API_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Google Safe Browsing works on URLs, not IP indicators."""
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Check common URLs for a domain against Google Safe Browsing.

        Args:
            domain: Domain to check

        Returns:
            ThreatIntelResult
        """
        urls = [f"https://{domain}/", f"http://{domain}/"]
        threat_types = self.get_setting(
            "threat_types",
            [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
        )

        all_matches: List[Dict] = []

        for url in urls:
            payload = {
                "client": {
                    "clientId": "domain-intelligence",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": threat_types,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }

            try:
                response = self.session.post(
                    self.API_BASE,
                    params={"key": self.api_key},
                    json=payload,
                    timeout=self.timeout,
                    proxies=self.config.proxy_settings,
                )

                if response.status_code == 200:
                    body = response.json() or {}
                    for match in body.get("matches", []):
                        normalized = {
                            "url": url,
                            "threatType": match.get("threatType"),
                            "platformType": match.get("platformType"),
                            "threatEntryType": match.get("threatEntryType"),
                            "cacheDuration": match.get("cacheDuration"),
                        }
                        all_matches.append(normalized)
                elif response.status_code == 401:
                    self.logger.error("Google Safe Browsing API key is invalid")
                    return None
                elif response.status_code == 429:
                    self.logger.warning("Google Safe Browsing rate limit exceeded")
                else:
                    self.logger.warning(
                        f"Google Safe Browsing returned status {response.status_code}"
                    )

            except requests.exceptions.RequestException as exc:
                self.logger.error(f"Google Safe Browsing request error: {exc}")

        categories = sorted(
            {m.get("threatType") for m in all_matches if m.get("threatType")}
        )
        platforms = sorted(
            {m.get("platformType") for m in all_matches if m.get("platformType")}
        )

        return ThreatIntelResult(
            source="Google Safe Browsing",
            is_malicious=bool(all_matches),
            confidence_score=min(1.0, len(all_matches) / 3.0) if all_matches else 0.0,
            categories=categories[:10],
            reports_count=len(all_matches),
            details={
                "domain": domain,
                "checked_urls": urls,
                "platforms": platforms,
                "matches": all_matches[:20],
            },
        )
