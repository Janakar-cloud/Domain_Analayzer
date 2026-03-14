"""Risk scoring helpers for ASN and AI assessment outputs."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, cast


HIGH_RISK_TERMS = {
    "malicious",
    "phishing",
    "malware",
    "ransomware",
    "botnet",
    "c2",
    "command-and-control",
    "fraud",
    "abuse",
}


def clamp_score(value: Any) -> int:
    """Clamp a score-like value to 0..100."""
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, score))


def score_to_risk_level(score: int) -> str:
    """Convert numeric score into a normalized risk level."""
    if score >= 80:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _normalize_asn(value: Any) -> Optional[str]:
    if value is None:
        return None

    text = str(value).strip().upper()
    if not text:
        return None

    if text.startswith("AS"):
        return text

    if text.isdigit():
        return f"AS{text}"

    return text


def _extract_numeric(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _coerce_str_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []

    values: List[str] = []
    for item in cast(List[Any], value):
        text = str(item).strip()
        if text:
            values.append(text)
    return values


def calculate_asn_reputation(threat_intel: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Build a dedicated ASN reputation score from collected threat-intel signals."""
    per_asn: Dict[str, Dict[str, Any]] = {}

    for item in threat_intel or []:
        details_raw = item.get("details")
        details: Dict[str, Any] = cast(Dict[str, Any], details_raw) if isinstance(details_raw, dict) else {}
        asn = _normalize_asn(details.get("asn") or details.get("as_number"))
        if not asn:
            continue

        source = str(item.get("source") or "Unknown")
        score = 0
        signals: Set[str] = set()

        if bool(item.get("is_malicious")):
            score += 35
            signals.add("malicious verdict")

        confidence = _extract_numeric(item.get("confidence_score"))
        if confidence is not None:
            normalized_confidence = max(0.0, min(1.0, confidence))
            score += int(normalized_confidence * 40)
            if normalized_confidence >= 0.65:
                signals.add("high confidence")

        abuse_score = _extract_numeric(item.get("abuse_score"))
        if abuse_score is not None:
            normalized_abuse = max(0.0, min(100.0, abuse_score))
            score += int(normalized_abuse * 0.25)
            if normalized_abuse >= 60:
                signals.add("high abuse score")

        reports_count = _extract_numeric(item.get("reports_count"))
        if reports_count is not None:
            reports_int = max(0, int(reports_count))
            score += min(reports_int * 4, 16)
            if reports_int >= 3:
                signals.add("multiple reports")

        categories = [c.lower() for c in _coerce_str_list(item.get("categories"))]
        tags = [t.lower() for t in _coerce_str_list(item.get("tags"))]
        if any(term in HIGH_RISK_TERMS for term in categories + tags):
            score += 12
            signals.add("high-risk category")

        score = clamp_score(score)

        existing = per_asn.get(asn)
        if not existing:
            per_asn[asn] = {
                "score": score,
                "sources": {source},
                "signals": signals,
            }
        else:
            existing["score"] = max(existing["score"], score)
            existing["sources"].add(source)
            existing["signals"].update(signals)

    if not per_asn:
        return None

    per_asn_rows: List[Dict[str, Any]] = []
    for asn, data in sorted(per_asn.items()):
        score = int(data["score"])
        per_asn_rows.append(
            {
                "asn": asn,
                "score": score,
                "level": score_to_risk_level(score),
                "sources": ", ".join(sorted(data["sources"])),
                "signals": ", ".join(sorted(data["signals"])) or "none",
            }
        )

    overall_score = max(row["score"] for row in per_asn_rows)
    risky_count = sum(1 for row in per_asn_rows if row["score"] >= 55)
    if risky_count >= 2:
        overall_score = clamp_score(overall_score + 8)

    all_sources = sorted({s for row in per_asn_rows for s in row["sources"].split(", ") if s})
    all_signals = sorted({
        signal
        for row in per_asn_rows
        for signal in row["signals"].split(", ")
        if signal and signal != "none"
    })

    return {
        "score": overall_score,
        "level": score_to_risk_level(overall_score),
        "asns": [row["asn"] for row in per_asn_rows],
        "sources": all_sources,
        "signals": all_signals[:6],
        "per_asn": per_asn_rows,
    }


def _normalize_level(value: Any, score: int) -> str:
    if isinstance(value, str):
        lowered = value.strip().lower()
        mapping = {
            "low": "Low",
            "medium": "Medium",
            "med": "Medium",
            "high": "High",
            "critical": "Critical",
            "crit": "Critical",
        }
        if lowered in mapping:
            return mapping[lowered]
    return score_to_risk_level(score)


def _coerce_priorities(value: Any) -> List[str]:
    if isinstance(value, list):
        return _coerce_str_list(value)[:5]

    if isinstance(value, str):
        parts = re.split(r"[\n;]", value)
        return [part.strip(" -\t") for part in parts if part.strip()][:5]

    return []


def parse_gemini_risk_payload(text: str) -> Optional[Dict[str, Any]]:
    """Parse Gemini output into normalized risk score + summary fields."""
    raw = (text or "").strip()
    if not raw:
        return None

    candidates = [raw]

    fenced = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
    fenced = re.sub(r"\s*```$", "", fenced)
    if fenced != raw:
        candidates.append(fenced.strip())

    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if match:
        candidates.append(match.group(0).strip())

    parsed: Optional[Dict[str, Any]] = None
    for candidate in candidates:
        try:
            loaded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict):
            loaded_dict = cast(Dict[Any, Any], loaded)
            parsed = {str(k): v for k, v in loaded_dict.items()}
            break

    if not parsed:
        return None

    score_value = (
        parsed.get("risk_score")
        if "risk_score" in parsed
        else parsed.get("score", parsed.get("riskScore"))
    )
    score = clamp_score(score_value)

    summary = (
        parsed.get("executive_summary")
        if "executive_summary" in parsed
        else parsed.get("summary", parsed.get("executiveSummary"))
    )
    summary_text = str(summary).strip() if summary is not None else ""

    priorities = _coerce_priorities(parsed.get("priorities"))

    return {
        "risk_score": score,
        "risk_level": _normalize_level(parsed.get("risk_level") or parsed.get("level"), score),
        "executive_summary": summary_text,
        "priorities": priorities,
    }
