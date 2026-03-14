"""Tests for TLS certificate email extraction."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.core.config import Config
from src.modules.tls_inspection import TLSInspectionModule


def _build_test_certificate_der() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "admin@example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("example.com"),
                    x509.DNSName("www.example.com"),
                    x509.RFC822Name("security@example.com"),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_certificate_extracts_structured_email_fields() -> None:
    cfg = Config()
    module = TLSInspectionModule(cfg, rate_limiter=None)

    cert_dict = {
        "subject": ((('commonName', 'example.com'),), (('organizationName', 'Example Org'),), (('emailAddress', 'admin@example.com'),)),
        "issuer": ((('commonName', 'example.com'),), (('organizationName', 'Example Org'),), (('emailAddress', 'admin@example.com'),)),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"), ("email", "security@example.com")),
        "notBefore": "Jan 01 00:00:00 2024 GMT",
        "notAfter": "Jan 01 00:00:00 2026 GMT",
        "serialNumber": "01",
    }

    parsed = module._parse_certificate(cert_dict, _build_test_certificate_der())

    assert parsed.subject_emails == ["admin@example.com"]
    assert parsed.issuer_emails == ["admin@example.com"]
    assert parsed.san_emails == ["security@example.com"]
    assert parsed.email_addresses == ["admin@example.com", "security@example.com"]
    assert parsed.san == ["example.com", "www.example.com"]