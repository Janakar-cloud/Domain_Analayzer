"""Tests for core domain data structures."""

import pytest
from datetime import datetime, timezone
from src.core.domain import (
    Severity, Finding, DNSRecord, TLSCertificate, 
    WHOISInfo, SSLLabsResult, ThreatIntelResult, 
    RedirectInfo, Domain, DomainResult
)


class TestSeverity:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_comparison(self):
        """Test severity ordering."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category="test_category",
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.MEDIUM,
            category="test",
            evidence="Some evidence",
            remediation="Fix it",
            references=["https://example.com"],
        )
        data = finding.to_dict()
        
        assert data["title"] == "Test Finding"
        assert data["severity"] == "medium"
        assert data["evidence"] == "Some evidence"
        assert data["remediation"] == "Fix it"
        assert len(data["references"]) == 1


class TestDNSRecord:
    """Test DNSRecord dataclass."""

    def test_dns_record_creation(self):
        """Test creating a DNS record."""
        record = DNSRecord(
            record_type="A",
            name="example.com",
            value="93.184.216.34",
            ttl=300,
        )
        assert record.record_type == "A"
        assert record.ttl == 300

    def test_dns_record_to_dict(self):
        """Test DNS record serialization."""
        record = DNSRecord(
            record_type="MX",
            name="example.com",
            value="10 mail.example.com",
            ttl=3600,
        )
        data = record.to_dict()
        
        assert data["type"] == "MX"
        assert data["value"] == "10 mail.example.com"


class TestTLSCertificate:
    """Test TLSCertificate dataclass."""

    def test_certificate_creation(self):
        """Test creating a TLS certificate."""
        cert = TLSCertificate(
            subject_cn="example.com",
            issuer="Let's Encrypt",
            issuer_org="ISRG",
            san=["example.com", "www.example.com"],
            not_before=datetime(2024, 1, 1, tzinfo=timezone.utc),
            not_after=datetime(2025, 1, 1, tzinfo=timezone.utc),
            is_expired=False,
            days_until_expiry=365,
        )
        assert cert.subject_cn == "example.com"
        assert len(cert.san) == 2
        assert cert.is_expired is False

    def test_certificate_to_dict(self):
        """Test certificate serialization."""
        cert = TLSCertificate(
            subject_cn="test.com",
            issuer="DigiCert",
            key_type="RSA",
            key_size=2048,
        )
        data = cert.to_dict()
        
        assert data["subject_cn"] == "test.com"
        assert data["key_type"] == "RSA"
        assert data["key_size"] == 2048


class TestDomainResult:
    """Test DomainResult dataclass."""

    def test_domain_result_creation(self):
        """Test creating a domain result."""
        result = DomainResult(domain="example.com")
        assert result.domain == "example.com"
        assert result.findings == []
        assert result.subdomains == []
        assert result.errors == []

    def test_add_finding(self):
        """Test adding findings."""
        result = DomainResult(domain="example.com")
        finding = Finding(
            title="Test",
            description="Test finding",
            severity=Severity.LOW,
            category="test",
        )
        result.add_finding(finding)
        
        assert len(result.findings) == 1
        assert result.findings[0].title == "Test"

    def test_add_error(self):
        """Test adding errors."""
        result = DomainResult(domain="example.com")
        result.add_error("Something failed")
        
        assert len(result.errors) == 1
        assert "failed" in result.errors[0]

    def test_severity_score_empty(self):
        """Test severity score with no findings."""
        result = DomainResult(domain="example.com")
        assert result.severity_score == 0

    def test_severity_score_calculation(self):
        """Test severity score calculation."""
        result = DomainResult(domain="example.com")
        
        # Add findings of different severities
        result.add_finding(Finding(
            title="Critical", description="", 
            severity=Severity.CRITICAL, category="test"
        ))  # 40 points
        result.add_finding(Finding(
            title="High", description="", 
            severity=Severity.HIGH, category="test"
        ))  # 25 points
        result.add_finding(Finding(
            title="Medium", description="", 
            severity=Severity.MEDIUM, category="test"
        ))  # 15 points
        
        # Total: 80 points
        assert result.severity_score == 80

    def test_severity_score_capped_at_100(self):
        """Test severity score doesn't exceed 100."""
        result = DomainResult(domain="example.com")
        
        # Add many critical findings
        for _ in range(5):
            result.add_finding(Finding(
                title="Critical", description="",
                severity=Severity.CRITICAL, category="test"
            ))
        
        # 5 * 40 = 200, but should be capped at 100
        assert result.severity_score == 100

    def test_highest_severity(self):
        """Test getting highest severity."""
        result = DomainResult(domain="example.com")
        
        result.add_finding(Finding(
            title="Low", description="",
            severity=Severity.LOW, category="test"
        ))
        result.add_finding(Finding(
            title="High", description="",
            severity=Severity.HIGH, category="test"
        ))
        result.add_finding(Finding(
            title="Medium", description="",
            severity=Severity.MEDIUM, category="test"
        ))
        
        assert result.highest_severity == Severity.HIGH

    def test_highest_severity_none(self):
        """Test highest severity with no findings."""
        result = DomainResult(domain="example.com")
        assert result.highest_severity is None

    def test_to_dict(self):
        """Test result serialization."""
        result = DomainResult(domain="example.com")
        result.subdomains = ["sub.example.com"]
        result.resolved_ips = ["93.184.216.34"]
        result.add_finding(Finding(
            title="Test", description="Test",
            severity=Severity.INFO, category="test"
        ))
        
        data = result.to_dict()
        
        assert data["domain"] == "example.com"
        assert len(data["subdomains"]) == 1
        assert len(data["resolved_ips"]) == 1
        assert len(data["findings"]) == 1
        assert data["severity_score"] == 1


class TestThreatIntelResult:
    """Test ThreatIntelResult dataclass."""

    def test_threat_intel_creation(self):
        """Test creating threat intel result."""
        result = ThreatIntelResult(
            source="VirusTotal",
            is_malicious=True,
            confidence_score=0.85,
            abuse_score=75,
            categories=["Malware", "Phishing"],
            reports_count=10,
        )
        
        assert result.source == "VirusTotal"
        assert result.is_malicious is True
        assert result.confidence_score == 0.85
        assert len(result.categories) == 2

    def test_threat_intel_to_dict(self):
        """Test threat intel serialization."""
        result = ThreatIntelResult(
            source="AbuseIPDB",
            is_malicious=False,
            abuse_score=15,
            reports_count=2,
        )
        
        data = result.to_dict()
        
        assert data["source"] == "AbuseIPDB"
        assert data["is_malicious"] is False
        assert data["abuse_score"] == 15
