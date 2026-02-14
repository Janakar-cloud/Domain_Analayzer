"""Local heuristic reputation module (no external APIs).

Computes a risk score and categories using only locally available data:
- TLS certificate status
- SSL Labs grade (if present)
- WHOIS age
- TLD risk
- Redirect behavior
- Subdomain takeover indicators
"""

from typing import Dict, List

from ...core.domain import DomainResult, Finding, Severity, ThreatIntelResult
from ..base import BaseModule


class LocalReputationModule(BaseModule):
    name = "local_reputation"
    description = "Local heuristic reputation scoring (no external APIs)"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Nested config under modules.threat_intel.local_reputation
        cfg = self.config.get("modules.threat_intel.local_reputation", {})
        self._module_config = cfg or {}

    @property
    def is_enabled(self) -> bool:
        return bool(self._module_config.get("enabled", True))

    def get_setting(self, key: str, default=None):
        return self._module_config.get(key, default)

    def execute(self, domain: str, result: DomainResult) -> None:
        # Compute heuristic risk
        score, categories, evidence = self._compute_risk(domain, result)

        # Create a ThreatIntelResult reflecting local assessment
        intel = ThreatIntelResult(
            source="LocalHeuristics",
            is_malicious=score >= 70,
            confidence_score=score / 100.0,
            abuse_score=int(score),
            categories=categories,
            tags=[],
            reports_count=0,
            details={"evidence": evidence, "score": score},
        )
        result.threat_intel.append(intel)

        # Add a consolidated finding
        if score >= 80:
            sev = Severity.CRITICAL
        elif score >= 50:
            sev = Severity.HIGH
        elif score >= 25:
            sev = Severity.MEDIUM
        elif score > 0:
            sev = Severity.LOW
        else:
            sev = Severity.INFO

        result.add_finding(Finding(
            title="Local Reputation Assessment",
            description=f"Aggregated risk score: {score}/100",
            severity=sev,
            category="threat_intelligence",
            evidence="\n".join(evidence),
            remediation="Review the contributing factors and address high-risk items (expired TLS, takeover risk, unusual redirects).",
        ))

    def _compute_risk(self, domain: str, result: DomainResult) -> (int, List[str], List[str]):
        score = 0
        categories: List[str] = []
        evidence: List[str] = []

        # TLS certificate status
        cert = result.tls_certificate
        if cert:
            if cert.is_expired:
                score += 40
                categories.append("ExpiredTLS")
                evidence.append("TLS certificate expired")
            elif cert.days_until_expiry is not None and cert.days_until_expiry < 14:
                score += 15
                categories.append("SoonExpiringTLS")
                evidence.append(f"TLS certificate expires in {cert.days_until_expiry} days")

        # SSL Labs grade (if present)
        if result.ssllabs_result and result.ssllabs_result.grade:
            g = result.ssllabs_result.grade
            if g in ("E", "F", "T", "M"):
                score += 25
                categories.append("PoorTLSGrade")
                evidence.append(f"SSL Labs grade: {g}")
            elif g in ("C", "D"):
                score += 15
                evidence.append(f"SSL Labs grade: {g}")

        # WHOIS age
        whois = result.whois_info
        if whois and whois.domain_age_days is not None:
            if whois.domain_age_days < 30:
                score += 15
                categories.append("YoungDomain")
                evidence.append(f"Domain age: {whois.domain_age_days} days")
            elif whois.domain_age_days < 180:
                score += 5
                evidence.append(f"Domain age: {whois.domain_age_days} days")

        # TLD risk (simple heuristic)
        risky_tlds = {".xyz", ".top", ".club", ".click", ".info"}
        for tld in risky_tlds:
            if domain.endswith(tld):
                score += 10
                categories.append("RiskyTLD")
                evidence.append(f"TLD flagged: {tld}")
                break

        # Redirect behavior
        if result.redirect_chain and len(result.redirect_chain) > 5:
            score += 10
            categories.append("ExcessiveRedirects")
            evidence.append(f"Redirects count: {len(result.redirect_chain)}")

        # Subdomain takeover indicator
        if result.is_takeover_candidate:
            score += 25
            categories.append("TakeoverRisk")
            evidence.append("Potential subdomain takeover risk detected")

        # Content scanner findings influence
        for f in result.findings:
            if f.category == "content_scan":
                # Map severity to additive score
                if f.severity == Severity.HIGH:
                    score += 20
                    categories.append("SensitiveContentHigh")
                elif f.severity == Severity.MEDIUM:
                    score += 10
                    categories.append("SensitiveContentMedium")
                elif f.severity == Severity.LOW:
                    score += 5
                    categories.append("SensitiveContentLow")

        # Cap score at 100
        score = min(100, score)
        return score, categories, evidence
