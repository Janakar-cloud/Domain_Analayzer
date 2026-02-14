"""Tests for inbuilt ContentScanner and local reputation integration."""

from src.modules.content_scanner import ContentScannerModule, shannon_entropy
from src.modules.threat_intel.local_reputation import LocalReputationModule
from src.core.config import Config
from src.core.domain import DomainResult, Finding, Severity


def test_shannon_entropy_basic():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") < 1.0
    assert shannon_entropy("AKIA1234567890ABCD") > 3.0


def test_scan_text_detects_sensitive_patterns():
    cfg = Config()
    mod = ContentScannerModule(cfg, rate_limiter=None)
    sample = (
        "Here is a token: AKIAABCDEFGHIJKLMNOP and a JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    hits = mod._scan_text(sample)
    assert any(h["rule_id"] == "aws_access_key" for h in hits)
    assert any(h["rule_id"] == "jwt_token" for h in hits)
    # Check confidence assigned
    confs = {h["rule_id"]: h["confidence"] for h in hits}
    assert confs.get("aws_access_key") in {"medium", "high"}
    assert confs.get("jwt_token") in {"medium", "high"}


def test_local_reputation_score_boost_from_content_scan():
    cfg = Config()
    rep = LocalReputationModule(cfg, rate_limiter=None)
    result = DomainResult(domain="example.com")
    # simulate a content scan finding
    result.add_finding(Finding(
        title="Sensitive content indicators",
        description="Detected tokens",
        severity=Severity.HIGH,
        category="content_scan",
    ))
    score, categories, evidence = rep._compute_risk("example.com", result)
    assert score > 0
    assert any(c.startswith("SensitiveContent") for c in categories)


def test_extract_links_limits_and_same_origin():
    cfg = Config()
    mod = ContentScannerModule(cfg, rate_limiter=None)
    base = "https://example.com/root/page"
    html = (
        '<a href="/login">Login</a>'
        '<a href="/admin">Admin</a>'
        '<a href="/api/docs">API</a>'
        '<a href="/auth">Auth</a>'
        '<a href="/other1">Other1</a>'
        '<a href="https://example.com/other2">Other2</a>'
        '<a href="https://other.com/out">Out</a>'
    )
    links = mod._extract_links(html, base)
    # same-origin only
    assert all("example.com" in l for l in links)
    # limit respected
    assert len(links) <= mod.shallow_links_limit
    # risky paths come first
    assert links[0].endswith("/login")
