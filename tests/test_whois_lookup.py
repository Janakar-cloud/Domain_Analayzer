"""Tests for WHOIS module RDAP-first behavior."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from src.core.config import Config
from src.core.domain import DomainResult, WHOISInfo
from src.modules.whois_lookup import WHOISModule


class _MockResponse:
    def __init__(self, status_code: int, payload: Dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Dict[str, Any]:
        return self._payload


def _sample_rdap_payload() -> Dict[str, Any]:
    return {
        "objectClassName": "domain",
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "ns1.example.com"},
            {"ldhName": "ns2.example.com"},
        ],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Example Registrar Inc"]],
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["org", {}, "text", "Example Corp"],
                        ["adr", {}, "text", ["", "", "", "City", "State", "", "US"]],
                    ],
                ],
            },
        ],
    }


def test_execute_uses_rdap_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = Config()
    module = WHOISModule(cfg, rate_limiter=None)
    result = DomainResult(domain="example.com")

    def _mock_get(*_args: Any, **_kwargs: Any) -> _MockResponse:
        return _MockResponse(200, _sample_rdap_payload())

    def _raise_if_called(_domain: str) -> Optional[WHOISInfo]:
        raise AssertionError("WHOIS fallback should not be called when RDAP succeeds")

    monkeypatch.setattr("src.modules.whois_lookup.requests.get", _mock_get)
    monkeypatch.setattr(module, "_lookup_whois", _raise_if_called)

    module.execute("example.com", result)

    assert result.whois_info is not None
    info = result.whois_info
    assert info.lookup_source == "RDAP"
    assert info.registrar == "Example Registrar Inc"
    assert info.registrant_org == "Example Corp"
    assert info.registrant_country == "US"
    assert info.dnssec == "signed"
    assert sorted(info.name_servers) == ["ns1.example.com", "ns2.example.com"]
    assert info.creation_date == datetime(2010, 1, 1, tzinfo=timezone.utc)
    assert info.expiration_date == datetime(2030, 1, 1, tzinfo=timezone.utc)


def test_execute_falls_back_to_whois(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = Config()
    module = WHOISModule(cfg, rate_limiter=None)
    result = DomainResult(domain="example.com")

    fallback_info = WHOISInfo(
        registrar="Fallback Registrar",
        creation_date=datetime(2020, 1, 1, tzinfo=timezone.utc),
        expiration_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
        lookup_source="WHOIS",
    )

    def _rdap_none(_domain: str) -> Optional[WHOISInfo]:
        return None

    def _whois_fallback(_domain: str) -> Optional[WHOISInfo]:
        return fallback_info

    monkeypatch.setattr(module, "_lookup_rdap", _rdap_none)
    monkeypatch.setattr(module, "_lookup_whois", _whois_fallback)

    module.execute("example.com", result)

    assert result.whois_info is not None
    assert result.whois_info.lookup_source == "WHOIS"
    assert any(f.title == "WHOIS Information" for f in result.findings)


def test_execute_prefers_rdap(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = Config()
    module = WHOISModule(cfg, rate_limiter=None)
    result = DomainResult(domain="example.com")

    rdap_info = WHOISInfo(
        registrar="RDAP Registrar",
        creation_date=datetime(2019, 1, 1, tzinfo=timezone.utc),
        expiration_date=datetime(2029, 1, 1, tzinfo=timezone.utc),
        lookup_source="RDAP",
    )

    def _rdap_success(_domain: str) -> Optional[WHOISInfo]:
        return rdap_info

    monkeypatch.setattr(module, "_lookup_rdap", _rdap_success)

    def _raise_if_called(_domain: str) -> Optional[WHOISInfo]:
        raise AssertionError("WHOIS fallback should not be called when RDAP succeeds")

    monkeypatch.setattr(module, "_lookup_whois", _raise_if_called)

    module.execute("example.com", result)

    assert result.whois_info is not None
    assert result.whois_info.lookup_source == "RDAP"
