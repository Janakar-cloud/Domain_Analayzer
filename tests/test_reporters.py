"""Tests for reporter modules - JSON, CSV, HTML."""

import pytest
import json
import csv
import io
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone

from src.core.domain import DomainResult, Finding, Severity, TLSCertificate, WHOISInfo
from src.reporters.json_reporter import JSONReporter
from src.reporters.csv_reporter import CSVReporter
from src.reporters.html_reporter import HTMLReporter


class MockConfig:
    """Mock configuration for testing."""
    
    def __init__(self, output_dir=None):
        self._output_dir = output_dir or tempfile.mkdtemp()
    
    @property
    def output_dir(self):
        return Path(self._output_dir)
    
    def get(self, key, default=None):
        if key == "output.timestamp_format":
            return "%Y-%m-%d_%H-%M-%S"
        return default


@pytest.fixture
def mock_config():
    """Create mock config with temp directory."""
    config = MockConfig()
    yield config
    # Cleanup temp files
    import shutil
    if Path(config._output_dir).exists():
        shutil.rmtree(config._output_dir)


@pytest.fixture
def sample_results():
    """Create sample DomainResult objects for testing."""
    results = []
    
    # Result with findings
    result1 = DomainResult(
        domain="example.com",
        scan_timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )
    result1.subdomains = ["www.example.com", "mail.example.com"]
    result1.resolved_ips = ["93.184.216.34"]
    result1.tls_certificate = TLSCertificate(
        subject_cn="example.com",
        issuer="DigiCert",
        not_after=datetime(2025, 1, 15, tzinfo=timezone.utc),
        is_expired=False,
        days_until_expiry=365,
    )
    result1.whois_info = WHOISInfo(
        registrar="Example Registrar",
        creation_date=datetime(2010, 1, 1, tzinfo=timezone.utc),
        domain_age_days=5000,
    )
    result1.add_finding(Finding(
        title="Critical Issue",
        description="Something critical",
        severity=Severity.CRITICAL,
        category="security",
        evidence="Evidence here",
        remediation="Fix it immediately",
    ))
    result1.add_finding(Finding(
        title="Medium Issue",
        description="Something medium",
        severity=Severity.MEDIUM,
        category="configuration",
    ))
    result1.modules_executed = ["dns_enumeration", "tls_inspection"]
    results.append(result1)
    
    # Result without issues
    result2 = DomainResult(
        domain="clean.example.org",
        scan_timestamp=datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc),
    )
    result2.resolved_ips = ["192.0.2.1"]
    result2.add_finding(Finding(
        title="Info Finding",
        description="Just informational",
        severity=Severity.INFO,
        category="info",
    ))
    result2.modules_executed = ["dns_enumeration"]
    results.append(result2)
    
    return results


class TestJSONReporter:
    """Test JSON report generation."""

    def test_generate_report(self, mock_config, sample_results):
        """Test generating a JSON report."""
        reporter = JSONReporter(mock_config)
        path = reporter.generate(sample_results)
        
        assert path.exists()
        assert path.suffix == ".json"
        
        # Verify content is valid JSON
        with open(path) as f:
            data = json.load(f)
        
        assert "metadata" in data
        assert "summary" in data
        assert "results" in data

    def test_report_metadata(self, mock_config, sample_results):
        """Test report metadata."""
        reporter = JSONReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            data = json.load(f)
        
        assert data["metadata"]["tool"] == "Domain Intelligence"
        assert data["metadata"]["version"] == "1.0.0"
        assert "generated_at" in data["metadata"]

    def test_report_summary(self, mock_config, sample_results):
        """Test report summary statistics."""
        reporter = JSONReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            data = json.load(f)
        
        summary = data["summary"]
        assert summary["total_domains"] == 2
        assert summary["total_findings"] == 3
        assert summary["severity_breakdown"]["critical"] == 1
        assert summary["severity_breakdown"]["medium"] == 1
        assert summary["severity_breakdown"]["info"] == 1

    def test_report_results_content(self, mock_config, sample_results):
        """Test report results content."""
        reporter = JSONReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            data = json.load(f)
        
        results = data["results"]
        assert len(results) == 2
        
        # Check first domain
        example_result = next(r for r in results if r["domain"] == "example.com")
        assert len(example_result["subdomains"]) == 2
        assert example_result["resolved_ips"] == ["93.184.216.34"]
        assert len(example_result["findings"]) == 2

    def test_custom_filename(self, mock_config, sample_results):
        """Test generating report with custom filename."""
        reporter = JSONReporter(mock_config)
        path = reporter.generate(sample_results, filename="custom_report.json")
        
        assert path.name == "custom_report.json"


class TestCSVReporter:
    """Test CSV report generation."""

    def test_generate_report(self, mock_config, sample_results):
        """Test generating a CSV report."""
        reporter = CSVReporter(mock_config)
        path = reporter.generate(sample_results)
        
        assert path.exists()
        assert path.suffix == ".csv"

    def test_csv_headers(self, mock_config, sample_results):
        """Test CSV has correct headers."""
        reporter = CSVReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path, newline='') as f:
            reader = csv.reader(f)
            headers = next(reader)
        
        expected_headers = [
            "Domain", "Scan Timestamp", "Subdomains Count", "Resolved IPs",
            "SPF", "DMARC",
            "TLS CN", "TLS Issuer", "TLS Expires", "TLS Expired",
            "WHOIS Registrar", "WHOIS Created", "WHOIS Expires", "Domain Age (days)",
            "SSLLabs Grade", "Severity Score", "Critical Findings", "High Findings",
            "Medium Findings", "Low Findings", "Info Findings", "Takeover Candidate",
            "Errors"
        ]
        assert headers == expected_headers

    def test_csv_data_rows(self, mock_config, sample_results):
        """Test CSV data rows."""
        reporter = CSVReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path, newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 2
        
        example_row = next(r for r in rows if r["Domain"] == "example.com")
        assert example_row["Subdomains Count"] == "2"
        assert example_row["TLS CN"] == "example.com"
        assert example_row["SPF"] == ""
        assert example_row["DMARC"] == ""
        assert example_row["Critical Findings"] == "1"
        assert example_row["Medium Findings"] == "1"


class TestHTMLReporter:
    """Test HTML report generation."""

    def test_generate_report(self, mock_config, sample_results):
        """Test generating an HTML report."""
        reporter = HTMLReporter(mock_config)
        path = reporter.generate(sample_results)
        
        assert path.exists()
        assert path.suffix == ".html"

    def test_html_structure(self, mock_config, sample_results):
        """Test HTML report has basic structure."""
        reporter = HTMLReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            content = f.read()
        
        assert "<!DOCTYPE html>" in content
        assert "<html" in content
        assert "</html>" in content
        assert "Domain Intelligence" in content

    def test_html_contains_domains(self, mock_config, sample_results):
        """Test HTML report contains domain information."""
        reporter = HTMLReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            content = f.read()
        
        assert "example.com" in content
        assert "clean.example.org" in content

    def test_html_contains_findings(self, mock_config, sample_results):
        """Test HTML report contains findings."""
        reporter = HTMLReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            content = f.read()
        
        assert "Critical Issue" in content
        assert "Medium Issue" in content

    def test_html_xss_prevention(self, mock_config):
        """Test HTML report escapes XSS payloads."""
        result = DomainResult(domain="test.com")
        result.add_finding(Finding(
            title='<script>alert("XSS")</script>',
            description='"><img src=x onerror=alert(1)>',
            severity=Severity.HIGH,
            category="test",
            evidence="<script>evil()</script>",
        ))
        
        reporter = HTMLReporter(mock_config)
        path = reporter.generate([result])
        
        with open(path) as f:
            content = f.read()
        
        # Raw script tags should not be present (XSS prevention)
        assert "<script>alert" not in content
        # The < and > are escaped, preventing XSS execution
        assert "<img src=x" not in content
        
        # Should be escaped
        assert "&lt;script&gt;" in content

    def test_html_escape_method(self, mock_config):
        """Test the _escape_html method directly."""
        reporter = HTMLReporter(mock_config)
        
        # Test various XSS payloads
        assert reporter._escape_html("<script>") == "&lt;script&gt;"
        assert reporter._escape_html('"onclick="') == "&quot;onclick=&quot;"  # = doesn't need escaping for XSS
        assert reporter._escape_html("it's") == "it&#39;s"
        assert reporter._escape_html("a & b") == "a &amp; b"

    def test_html_severity_badges(self, mock_config, sample_results):
        """Test HTML report has severity badges."""
        reporter = HTMLReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            content = f.read()
        
        assert "severity-critical" in content
        assert "severity-medium" in content
        assert "severity-info" in content

    def test_html_summary_stats(self, mock_config, sample_results):
        """Test HTML report has summary statistics."""
        reporter = HTMLReporter(mock_config)
        path = reporter.generate(sample_results)
        
        with open(path) as f:
            content = f.read()
        
        # Should show count of domains
        assert ">2<" in content  # 2 domains
        # Should show finding counts
        assert "Critical" in content
        assert "Medium" in content


class TestReporterFilenames:
    """Test filename generation for reporters."""

    def test_json_filename_generation(self, mock_config):
        """Test JSON filename generation."""
        reporter = JSONReporter(mock_config)
        filename = reporter.generate_filename()
        
        assert filename.startswith("domain_intel_")
        assert filename.endswith(".json")

    def test_csv_filename_generation(self, mock_config):
        """Test CSV filename generation."""
        reporter = CSVReporter(mock_config)
        filename = reporter.generate_filename()
        
        assert filename.startswith("domain_intel_")
        assert filename.endswith(".csv")

    def test_html_filename_generation(self, mock_config):
        """Test HTML filename generation."""
        reporter = HTMLReporter(mock_config)
        filename = reporter.generate_filename()
        
        assert filename.startswith("domain_intel_")
        assert filename.endswith(".html")

    def test_custom_prefix(self, mock_config):
        """Test custom filename prefix."""
        reporter = JSONReporter(mock_config)
        filename = reporter.generate_filename(prefix="custom_scan")
        
        assert filename.startswith("custom_scan_")
