"""Tests for security utilities - SSRF protection, input validation, HTML escaping."""

import pytest
from src.core.security import IPValidator, DomainValidator, HTMLSanitizer


class TestIPValidator:
    """Test IP validation for SSRF protection."""

    def test_private_ipv4_class_a(self):
        """Test Class A private range (10.x.x.x)."""
        assert IPValidator.is_private_ip("10.0.0.1") is True
        assert IPValidator.is_private_ip("10.255.255.255") is True

    def test_private_ipv4_class_b(self):
        """Test Class B private range (172.16-31.x.x)."""
        assert IPValidator.is_private_ip("172.16.0.1") is True
        assert IPValidator.is_private_ip("172.31.255.255") is True
        assert IPValidator.is_private_ip("172.15.0.1") is False  # Not in range

    def test_private_ipv4_class_c(self):
        """Test Class C private range (192.168.x.x)."""
        assert IPValidator.is_private_ip("192.168.0.1") is True
        assert IPValidator.is_private_ip("192.168.255.255") is True

    def test_public_ipv4(self):
        """Test public IP addresses are not flagged as private."""
        assert IPValidator.is_private_ip("8.8.8.8") is False
        assert IPValidator.is_private_ip("1.1.1.1") is False
        assert IPValidator.is_private_ip("203.0.113.1") is False

    def test_loopback_ipv4(self):
        """Test loopback addresses."""
        assert IPValidator.is_loopback("127.0.0.1") is True
        assert IPValidator.is_loopback("127.255.255.255") is True
        assert IPValidator.is_loopback("8.8.8.8") is False

    def test_loopback_ipv6(self):
        """Test IPv6 loopback."""
        assert IPValidator.is_loopback("::1") is True

    def test_link_local_ipv4(self):
        """Test link-local addresses."""
        assert IPValidator.is_link_local("169.254.0.1") is True
        assert IPValidator.is_link_local("169.254.255.255") is True
        assert IPValidator.is_link_local("169.253.0.1") is False

    def test_multicast(self):
        """Test multicast addresses."""
        assert IPValidator.is_multicast("224.0.0.1") is True
        assert IPValidator.is_multicast("239.255.255.255") is True
        assert IPValidator.is_multicast("223.255.255.255") is False

    def test_cloud_metadata_ipv4(self):
        """Test AWS/GCP/Azure metadata endpoint detection."""
        assert IPValidator.is_cloud_metadata("169.254.169.254") is True
        assert IPValidator.is_cloud_metadata("169.254.170.2") is True
        assert IPValidator.is_cloud_metadata("169.254.169.253") is False

    def test_safe_for_external_request_blocks_private(self):
        """Test SSRF protection blocks private IPs."""
        is_safe, reason = IPValidator.is_safe_for_external_request("10.0.0.1")
        assert is_safe is False
        assert "Private" in reason or "private" in reason.lower()

    def test_safe_for_external_request_blocks_loopback(self):
        """Test SSRF protection blocks loopback."""
        is_safe, reason = IPValidator.is_safe_for_external_request("127.0.0.1")
        assert is_safe is False
        assert "oopback" in reason

    def test_safe_for_external_request_blocks_metadata(self):
        """Test SSRF protection blocks cloud metadata."""
        is_safe, reason = IPValidator.is_safe_for_external_request("169.254.169.254")
        assert is_safe is False
        # Link-local addresses (including cloud metadata IPs) are blocked as private
        assert "private" in reason.lower() or "metadata" in reason.lower() or "link-local" in reason.lower()

    def test_safe_for_external_request_allows_public(self):
        """Test SSRF protection allows public IPs."""
        is_safe, reason = IPValidator.is_safe_for_external_request("8.8.8.8")
        assert is_safe is True
        assert reason is None

        is_safe, reason = IPValidator.is_safe_for_external_request("1.1.1.1")
        assert is_safe is True
        assert reason is None

    def test_safe_for_external_request_invalid_ip(self):
        """Test SSRF protection handles invalid IPs."""
        is_safe, reason = IPValidator.is_safe_for_external_request("not-an-ip")
        assert is_safe is False
        assert "Invalid" in reason

    def test_filter_safe_ips(self):
        """Test filtering a list of IPs."""
        ip_list = [
            "8.8.8.8",      # Public - keep
            "10.0.0.1",     # Private - remove
            "127.0.0.1",    # Loopback - remove
            "1.1.1.1",      # Public - keep
            "192.168.1.1",  # Private - remove
        ]
        safe_ips = IPValidator.filter_safe_ips(ip_list)
        assert safe_ips == ["8.8.8.8", "1.1.1.1"]


class TestDomainValidator:
    """Test domain validation."""

    def test_valid_domain(self):
        """Test valid domain names."""
        is_valid, reason = DomainValidator.is_valid_domain("example.com")
        assert is_valid is True
        assert reason is None

        is_valid, reason = DomainValidator.is_valid_domain("sub.example.com")
        assert is_valid is True

        is_valid, reason = DomainValidator.is_valid_domain("sub.sub.example.com")
        assert is_valid is True

    def test_invalid_domain_empty(self):
        """Test empty domain."""
        is_valid, reason = DomainValidator.is_valid_domain("")
        assert is_valid is False
        assert "empty" in reason.lower()

    def test_invalid_domain_too_long(self):
        """Test domain exceeding max length."""
        long_domain = "a" * 250 + ".com"
        is_valid, reason = DomainValidator.is_valid_domain(long_domain)
        assert is_valid is False
        assert "length" in reason.lower()

    def test_invalid_domain_single_label(self):
        """Test single-label domain (no TLD)."""
        is_valid, reason = DomainValidator.is_valid_domain("localhost")
        assert is_valid is False
        assert "label" in reason.lower()

    def test_invalid_domain_special_chars(self):
        """Test domain with invalid characters."""
        is_valid, reason = DomainValidator.is_valid_domain("exam ple.com")
        assert is_valid is False

        is_valid, reason = DomainValidator.is_valid_domain("example$.com")
        assert is_valid is False

    def test_safe_domain_blocks_localhost(self):
        """Test internal domains are blocked."""
        is_safe, reason = DomainValidator.is_safe_domain("localhost.localdomain")
        assert is_safe is False

    def test_safe_domain_blocks_internal_tld(self):
        """Test internal TLDs are blocked."""
        is_safe, reason = DomainValidator.is_safe_domain("server.local")
        assert is_safe is False
        assert ".local" in reason

        is_safe, reason = DomainValidator.is_safe_domain("app.internal")
        assert is_safe is False

    def test_safe_domain_allows_public(self):
        """Test public domains are allowed."""
        is_safe, reason = DomainValidator.is_safe_domain("google.com")
        assert is_safe is True
        assert reason is None

        is_safe, reason = DomainValidator.is_safe_domain("github.io")
        assert is_safe is True


class TestHTMLSanitizer:
    """Test HTML sanitization for XSS prevention."""

    def test_escape_html_tags(self):
        """Test HTML tag escaping."""
        assert HTMLSanitizer.escape("<script>") == "&lt;script&gt;"
        assert HTMLSanitizer.escape("</script>") == "&lt;&#x2F;script&gt;"

    def test_escape_html_attributes(self):
        """Test attribute escaping."""
        assert HTMLSanitizer.escape('"onclick="alert(1)"') == "&quot;onclick&#x3D;&quot;alert(1)&quot;"

    def test_escape_ampersand(self):
        """Test ampersand escaping."""
        assert HTMLSanitizer.escape("A & B") == "A &amp; B"
        assert HTMLSanitizer.escape("&lt;") == "&amp;lt;"

    def test_escape_single_quotes(self):
        """Test single quote escaping."""
        assert HTMLSanitizer.escape("it's") == "it&#39;s"

    def test_escape_xss_payloads(self):
        """Test common XSS payloads are neutralized."""
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "javascript:alert(1)",
            '<a href="javascript:alert(1)">click</a>',
        ]
        
        for payload in payloads:
            escaped = HTMLSanitizer.escape(payload)
            assert "<script" not in escaped.lower()
            assert "onerror" not in escaped or "&#x3D;" in escaped
            assert "onload" not in escaped or "&#x3D;" in escaped

    def test_escape_empty_string(self):
        """Test empty string handling."""
        assert HTMLSanitizer.escape("") == ""
        assert HTMLSanitizer.escape(None) == ""

    def test_escape_attribute(self):
        """Test attribute escaping with newlines."""
        text = 'value\nwith\nnewlines'
        escaped = HTMLSanitizer.escape_attribute(text)
        assert "\n" not in escaped
        assert "&#10;" in escaped

    def test_escape_url_safe_schemes(self):
        """Test URL escaping allows safe schemes."""
        assert HTMLSanitizer.escape_url("https://example.com") != ""
        assert HTMLSanitizer.escape_url("http://example.com") != ""
        assert HTMLSanitizer.escape_url("mailto:test@example.com") != ""

    def test_escape_url_blocks_javascript(self):
        """Test URL escaping blocks javascript scheme."""
        assert HTMLSanitizer.escape_url("javascript:alert(1)") == ""

    def test_escape_url_blocks_data(self):
        """Test URL escaping blocks data scheme."""
        assert HTMLSanitizer.escape_url("data:text/html,<script>alert(1)</script>") == ""


class TestSSRFProtectionIntegration:
    """Integration tests for SSRF protection in real scenarios."""

    def test_common_ssrf_targets_blocked(self):
        """Test common SSRF attack targets are blocked."""
        ssrf_targets = [
            "127.0.0.1",           # Localhost
            "0.0.0.0",             # All interfaces
            "10.0.0.1",            # AWS internal
            "172.16.0.1",          # Docker default
            "192.168.1.1",         # Router
            "169.254.169.254",     # AWS metadata
            "169.254.170.2",       # AWS ECS metadata
            "::1",                 # IPv6 localhost
        ]
        
        for target in ssrf_targets:
            is_safe, _ = IPValidator.is_safe_for_external_request(target)
            assert is_safe is False, f"SSRF target {target} should be blocked"

    def test_legitimate_public_ips_allowed(self):
        """Test legitimate public IPs are allowed."""
        public_ips = [
            "8.8.8.8",       # Google DNS
            "1.1.1.1",       # Cloudflare DNS
            "208.67.222.222", # OpenDNS
            "93.184.216.34", # example.com
        ]
        
        for ip in public_ips:
            is_safe, reason = IPValidator.is_safe_for_external_request(ip)
            assert is_safe is True, f"Public IP {ip} should be allowed: {reason}"
