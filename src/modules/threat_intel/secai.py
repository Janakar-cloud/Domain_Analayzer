"""SecAI integration module."""

from datetime import datetime
from typing import Any, Dict, List, Optional, cast

import requests

from ...core.config import Config
from ...core.domain import ThreatIntelResult
from ...core.rate_limiter import RateLimiter
from .base import BaseThreatIntelModule


class SecAIModule(BaseThreatIntelModule):
    """
    SecAI threat intelligence integration.

    This module is intentionally tolerant of API response shape differences.
    Endpoint paths and auth style are configurable under modules.threat_intel.secai.
    """

    name = "secai"
    description = "Domain/IP reputation via SecAI"
    api_key_name = "secai"
    rate_limit_service = "secai"

    API_BASE = "https://api.secai.ai/v1"

    def __init__(
        self,
        config: Config,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        super().__init__(config, rate_limiter)

        auth_header = self.get_setting("auth_header", "Authorization")
        auth_scheme = self.get_setting("auth_scheme", "Bearer")

        if auth_scheme:
            self.session.headers.update({auth_header: f"{auth_scheme} {self.api_key}"})
        else:
            self.session.headers.update({auth_header: self.api_key})

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Look up IP in SecAI."""
        endpoint = self.get_setting("ip_endpoint", "/reputation/ip/{ip}")
        return self._lookup_indicator(ip, "ip", endpoint)

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """Look up domain in SecAI."""
        endpoint = self.get_setting("domain_endpoint", "/reputation/domain/{domain}")
        return self._lookup_indicator(domain, "domain", endpoint)

    def _lookup_indicator(
        self,
        indicator: str,
        indicator_type: str,
        endpoint_template: str,
    ) -> Optional[ThreatIntelResult]:
        """Query SecAI and normalize response."""
        url = self._build_url(endpoint_template, indicator)
        method = str(self.get_setting("method", "GET")).upper()
        query_name = self.get_setting("query_param")

        params: Optional[Dict[str, str]] = None
        payload: Optional[Dict[str, str]] = None
        if query_name:
            params = {str(query_name): indicator}

        if method == "POST":
            payload = {
                "indicator": indicator,
                "indicator_type": indicator_type,
            }

        try:
            if method == "POST":
                response = self.session.post(
                    url,
                    json=payload,
                    params=params,
                    timeout=self.timeout,
                    proxies=self.config.proxy_settings,
                )
            else:
                response = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                    proxies=self.config.proxy_settings,
                )

            if response.status_code == 200:
                return self._parse_response(response.json() or {}, indicator, indicator_type)
            if response.status_code == 404:
                return ThreatIntelResult(
                    source="SecAI",
                    is_malicious=False,
                    reports_count=0,
                    details={
                        "indicator": indicator,
                        "type": indicator_type,
                        "status": "not_found",
                    },
                )
            if response.status_code == 401:
                self.logger.error("SecAI API key is invalid")
            elif response.status_code == 429:
                self.logger.warning("SecAI rate limit exceeded")
            else:
                self.logger.warning(f"SecAI returned status {response.status_code}")

        except requests.exceptions.RequestException as exc:
            self.logger.error(f"SecAI request error: {exc}")

        return None

    def _build_url(self, template: str, indicator: str) -> str:
        """Build full endpoint URL from template and indicator."""
        formatted = str(template).format(domain=indicator, ip=indicator, indicator=indicator)
        if formatted.startswith("http://") or formatted.startswith("https://"):
            return formatted

        base_url = str(self.get_setting("base_url", self.API_BASE)).rstrip("/")
        return f"{base_url}/{formatted.lstrip('/')}"

    def _parse_response(self, data: Dict[str, Any], indicator: str, indicator_type: str) -> ThreatIntelResult:
        """Parse SecAI response into canonical ThreatIntelResult."""
        payload = self._unwrap_payload(data)

        confidence = self._extract_score(payload)
        abuse_score = self._extract_abuse_score(payload)
        reports_count = self._extract_reports_count(payload)
        is_malicious = self._extract_is_malicious(payload, confidence, abuse_score, reports_count)

        categories = self._extract_list(payload, ["categories", "threat_types", "labels", "classification"])
        tags = self._extract_list(payload, ["tags", "signals", "indicators"])
        last_seen = self._extract_datetime(payload)

        details: Dict[str, Any] = {
            "indicator": indicator,
            "type": indicator_type,
            "verdict": payload.get("verdict") or payload.get("risk_level"),
            "country": payload.get("country") or payload.get("country_code"),
            "asn": payload.get("asn") or payload.get("as_number"),
            "as_name": payload.get("as_name") or payload.get("as_owner") or payload.get("provider"),
            "raw": {k: v for k, v in payload.items() if k not in {"categories", "tags", "signals", "indicators"}},
        }

        return ThreatIntelResult(
            source="SecAI",
            is_malicious=is_malicious,
            confidence_score=confidence,
            abuse_score=abuse_score,
            categories=categories[:10],
            tags=tags[:20],
            last_seen=last_seen,
            reports_count=reports_count,
            details=details,
        )

    def _unwrap_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Unwrap common envelope keys used by APIs."""
        for key in ("data", "result", "payload"):
            candidate = data.get(key)
            if isinstance(candidate, dict):
                return cast(Dict[str, Any], candidate)
        return data

    def _extract_score(self, payload: Dict[str, Any]) -> Optional[float]:
        """Extract and normalize confidence score to 0..1."""
        for key in ("confidence_score", "confidence", "score", "risk_score", "threat_score"):
            value = payload.get(key)
            if value is None:
                continue
            try:
                score = float(value)
                if score > 1.0:
                    score = score / 100.0
                if score < 0:
                    score = 0.0
                if score > 1:
                    score = 1.0
                return score
            except (TypeError, ValueError):
                continue
        return None

    def _extract_abuse_score(self, payload: Dict[str, Any]) -> Optional[int]:
        """Extract abuse/risk score on 0..100 scale when present."""
        for key in ("abuse_score", "risk", "risk_score", "threat_score"):
            value = payload.get(key)
            if value is None:
                continue
            try:
                score = int(float(value))
                if score < 0:
                    score = 0
                if score > 100:
                    score = 100
                return score
            except (TypeError, ValueError):
                continue
        return None

    def _extract_reports_count(self, payload: Dict[str, Any]) -> int:
        """Extract report count, falling back to detections/matches lengths."""
        for key in ("reports_count", "report_count", "detections", "threat_count", "matches"):
            value = payload.get(key)
            if isinstance(value, int):
                return max(0, value)
            if isinstance(value, list):
                return len(cast(List[Any], value))
            if isinstance(value, str):
                try:
                    return max(0, int(value))
                except ValueError:
                    continue
        return 0

    def _extract_is_malicious(
        self,
        payload: Dict[str, Any],
        confidence: Optional[float],
        abuse_score: Optional[int],
        reports_count: int,
    ) -> bool:
        """Decide maliciousness from explicit verdict or score thresholds."""
        explicit = payload.get("is_malicious")
        if isinstance(explicit, bool):
            return explicit

        verdict = str(payload.get("verdict", "")).strip().lower()
        if verdict in {"malicious", "high", "critical", "phishing", "malware", "unsafe"}:
            return True
        if verdict in {"clean", "safe", "benign", "low", "none"}:
            return False

        if abuse_score is not None and abuse_score >= 60:
            return True
        if confidence is not None and confidence >= 0.65:
            return True
        return reports_count >= 3

    def _extract_list(self, payload: Dict[str, Any], keys: List[str]) -> List[str]:
        """Extract normalized list values from first matching key."""
        for key in keys:
            value = payload.get(key)
            if value is None:
                continue
            if isinstance(value, list):
                values = cast(List[Any], value)
                return [str(v).strip() for v in values if str(v).strip()]
            if isinstance(value, str):
                return [part.strip() for part in value.split(",") if part.strip()]
        return []

    def _extract_datetime(self, payload: Dict[str, Any]) -> Optional[datetime]:
        """Extract datetime from common timestamp keys."""
        for key in ("last_seen", "updated_at", "timestamp", "observed_at"):
            value = payload.get(key)
            if not value:
                continue
            if isinstance(value, datetime):
                return value
            if isinstance(value, (int, float)):
                try:
                    return datetime.fromtimestamp(value)
                except (OSError, OverflowError, ValueError):
                    continue
            if isinstance(value, str):
                text = value.strip()
                try:
                    return datetime.fromisoformat(text.replace("Z", "+00:00"))
                except ValueError:
                    continue
        return None
