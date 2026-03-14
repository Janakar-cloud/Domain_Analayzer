"""Tests for ASN and Gemini risk scoring helpers."""

from typing import Any, Dict, List

from src.core.risk_scoring import (
    calculate_asn_reputation,
    parse_gemini_risk_payload,
    score_to_risk_level,
)


def test_score_to_risk_level_thresholds() -> None:
    assert score_to_risk_level(0) == "Low"
    assert score_to_risk_level(24) == "Low"
    assert score_to_risk_level(25) == "Medium"
    assert score_to_risk_level(54) == "Medium"
    assert score_to_risk_level(55) == "High"
    assert score_to_risk_level(79) == "High"
    assert score_to_risk_level(80) == "Critical"


def test_calculate_asn_reputation_returns_none_without_asn() -> None:
    payload: List[Dict[str, Any]] = [
        {
            "source": "VirusTotal",
            "is_malicious": True,
            "confidence_score": 0.9,
            "details": {"country": "US"},
        }
    ]

    assert calculate_asn_reputation(payload) is None


def test_calculate_asn_reputation_scores_malicious_signals() -> None:
    payload: List[Dict[str, Any]] = [
        {
            "source": "VirusTotal",
            "is_malicious": True,
            "confidence_score": 0.9,
            "abuse_score": 80,
            "reports_count": 5,
            "categories": ["Malware"],
            "details": {"asn": 15169},
        },
        {
            "source": "AbuseIPDB",
            "is_malicious": False,
            "confidence_score": 0.2,
            "abuse_score": 20,
            "reports_count": 1,
            "details": {"as_number": "AS15169"},
        },
    ]

    result = calculate_asn_reputation(payload)

    assert result is not None
    assert result["asns"] == ["AS15169"]
    assert result["level"] == "Critical"
    assert result["score"] == 100
    assert "VirusTotal" in result["sources"]
    assert "AbuseIPDB" in result["sources"]
    assert any("malicious" in signal for signal in result["signals"])
    assert result["per_asn"][0]["asn"] == "AS15169"


def test_parse_gemini_risk_payload_from_fenced_json() -> None:
    text = """```json
    {
      "risk_score": 74,
      "risk_level": "High",
      "executive_summary": "Elevated domain risk from multiple intel feeds.",
      "priorities": ["Block suspicious hosts", "Review exposed services"]
    }
    ```"""

    parsed = parse_gemini_risk_payload(text)

    assert parsed is not None
    assert parsed["risk_score"] == 74
    assert parsed["risk_level"] == "High"
    assert parsed["executive_summary"].startswith("Elevated domain risk")
    assert parsed["priorities"] == ["Block suspicious hosts", "Review exposed services"]


def test_parse_gemini_risk_payload_derives_level_when_missing() -> None:
    parsed = parse_gemini_risk_payload('{"risk_score": 19, "executive_summary": "Low immediate risk."}')

    assert parsed is not None
    assert parsed["risk_score"] == 19
    assert parsed["risk_level"] == "Low"


def test_parse_gemini_risk_payload_returns_none_for_non_json() -> None:
    assert parse_gemini_risk_payload("This is not JSON") is None
