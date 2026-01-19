"""TLS certificate inspection module."""

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from ..core.domain import DomainResult, Finding, Severity, TLSCertificate
from .base import BaseModule


class TLSInspectionModule(BaseModule):
    """
    Inspect TLS certificates for a domain.
    
    Extracts certificate information including CN, SANs, issuer, validity dates,
    and flags potential issues like expired or soon-to-expire certificates.
    """

    name = "tls_inspection"
    description = "Inspect TLS certificates and extract security information"

    # Known weak signature algorithms
    WEAK_SIGNATURE_ALGORITHMS = [
        "md5",
        "sha1",
        "md2",
        "md4",
    ]

    # Minimum recommended key sizes
    MIN_KEY_SIZES = {
        "RSA": 2048,
        "DSA": 2048,
        "EC": 256,
    }

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Inspect TLS certificate for the domain.

        Args:
            domain: Domain to inspect
            result: DomainResult to populate
        """
        self.rate_limit()
        
        ports = self.get_setting("ports", [443])
        
        for port in ports:
            cert_info = self._get_certificate(domain, port)
            
            if cert_info:
                result.tls_certificate = cert_info
                self._analyze_certificate(cert_info, domain, result)
                break  # Use first successful port
            else:
                result.add_error(f"Could not retrieve TLS certificate from {domain}:{port}")

    def _get_certificate(self, domain: str, port: int = 443) -> Optional[TLSCertificate]:
        """
        Retrieve TLS certificate from a domain.

        Args:
            domain: Domain to connect to
            port: Port number

        Returns:
            TLSCertificate object or None
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We want to inspect even invalid certs
            
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        return self._parse_certificate(cert, cert_binary)
                    
        except socket.timeout:
            self.logger.warning(f"Timeout connecting to {domain}:{port}")
        except socket.gaierror as e:
            self.logger.warning(f"DNS resolution failed for {domain}: {e}")
        except ssl.SSLError as e:
            self.logger.warning(f"SSL error for {domain}:{port}: {e}")
        except ConnectionRefusedError:
            self.logger.warning(f"Connection refused to {domain}:{port}")
        except Exception as e:
            self.logger.error(f"Error getting certificate from {domain}:{port}: {e}")
        
        return None

    def _parse_certificate(self, cert: dict, cert_binary: bytes) -> TLSCertificate:
        """
        Parse certificate data into TLSCertificate object.

        Args:
            cert: Certificate dictionary from ssl
            cert_binary: Binary certificate data

        Returns:
            TLSCertificate object
        """
        # Extract subject CN
        subject = dict(x[0] for x in cert.get("subject", []))
        subject_cn = subject.get("commonName", "")
        
        # Extract issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_cn = issuer.get("commonName", "")
        issuer_org = issuer.get("organizationName", "")
        
        # Extract organization
        org = subject.get("organizationName", "")
        
        # Extract SANs
        san_list = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_list.append(san_value)
        
        # Parse dates
        not_before = self._parse_cert_date(cert.get("notBefore"))
        not_after = self._parse_cert_date(cert.get("notAfter"))
        
        # Calculate expiry
        now = datetime.now(timezone.utc)
        is_expired = False
        days_until_expiry = None
        
        if not_after:
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            is_expired = not_after < now
            days_until_expiry = (not_after - now).days
        
        # Extract serial number
        serial = cert.get("serialNumber", "")
        
        # Get signature algorithm and key info from binary cert if possible
        sig_alg, key_type, key_size = self._extract_crypto_info(cert_binary)
        
        return TLSCertificate(
            subject_cn=subject_cn,
            issuer=issuer_cn,
            issuer_org=issuer_org,
            organization=org,
            san=san_list,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial,
            signature_algorithm=sig_alg,
            key_type=key_type,
            key_size=key_size,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
        )

    def _parse_cert_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse certificate date string."""
        if not date_str:
            return None
        
        try:
            # Format: 'Sep 10 00:00:00 2024 GMT'
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            try:
                # Alternative format
                return datetime.strptime(date_str, "%Y%m%d%H%M%SZ")
            except ValueError:
                self.logger.debug(f"Could not parse date: {date_str}")
                return None

    def _extract_crypto_info(self, cert_binary: bytes) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """
        Extract cryptographic information from binary certificate.

        Args:
            cert_binary: Binary certificate data

        Returns:
            Tuple of (signature_algorithm, key_type, key_size)
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
            
            cert = x509.load_der_x509_certificate(cert_binary)
            
            # Get signature algorithm
            sig_alg = cert.signature_algorithm_oid._name
            
            # Get key info
            public_key = cert.public_key()
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_type = "RSA"
                key_size = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_type = "EC"
                key_size = public_key.curve.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_type = "DSA"
                key_size = public_key.key_size
            else:
                key_type = type(public_key).__name__
                key_size = None
            
            return sig_alg, key_type, key_size
            
        except ImportError:
            self.logger.debug("cryptography library not available for detailed cert parsing")
            return None, None, None
        except Exception as e:
            self.logger.debug(f"Error extracting crypto info: {e}")
            return None, None, None

    def _analyze_certificate(
        self, 
        cert: TLSCertificate, 
        domain: str, 
        result: DomainResult
    ) -> None:
        """
        Analyze certificate for security issues.

        Args:
            cert: TLSCertificate to analyze
            domain: Domain being analyzed
            result: DomainResult to add findings to
        """
        # Check for expired certificate
        if cert.is_expired:
            result.add_finding(Finding(
                title="Expired TLS Certificate",
                description=f"The TLS certificate for {domain} has expired",
                severity=Severity.CRITICAL,
                category="tls_security",
                evidence=f"Expired on: {cert.not_after}",
                remediation="Renew the TLS certificate immediately.",
            ))
        
        # Check for soon-to-expire certificate
        elif cert.days_until_expiry is not None:
            warn_days = self.get_setting("check_expiry_days", 30)
            
            if cert.days_until_expiry <= warn_days:
                severity = Severity.HIGH if cert.days_until_expiry <= 7 else Severity.MEDIUM
                result.add_finding(Finding(
                    title="TLS Certificate Expiring Soon",
                    description=f"The TLS certificate expires in {cert.days_until_expiry} days",
                    severity=severity,
                    category="tls_security",
                    evidence=f"Expires on: {cert.not_after}",
                    remediation="Renew the TLS certificate before expiration.",
                ))
        
        # Check for CN/SAN mismatch
        if not self._domain_matches_cert(domain, cert):
            result.add_finding(Finding(
                title="Certificate Domain Mismatch",
                description=f"The domain {domain} does not match certificate CN or SANs",
                severity=Severity.HIGH,
                category="tls_security",
                evidence=f"CN: {cert.subject_cn}, SANs: {', '.join(cert.san[:5])}",
                remediation="Obtain a certificate that includes this domain.",
            ))
        
        # Check for weak signature algorithm
        if cert.signature_algorithm:
            sig_alg_lower = cert.signature_algorithm.lower()
            for weak_alg in self.WEAK_SIGNATURE_ALGORITHMS:
                if weak_alg in sig_alg_lower:
                    result.add_finding(Finding(
                        title="Weak Certificate Signature Algorithm",
                        description=f"Certificate uses weak signature algorithm: {cert.signature_algorithm}",
                        severity=Severity.HIGH,
                        category="tls_security",
                        remediation="Replace with a certificate using SHA-256 or stronger.",
                    ))
                    break
        
        # Check for weak key
        if cert.key_type and cert.key_size:
            min_size = self.MIN_KEY_SIZES.get(cert.key_type, 0)
            if cert.key_size < min_size:
                result.add_finding(Finding(
                    title="Weak Certificate Key Size",
                    description=f"Certificate {cert.key_type} key size ({cert.key_size} bits) is below recommended minimum ({min_size} bits)",
                    severity=Severity.MEDIUM,
                    category="tls_security",
                    remediation=f"Use at least {min_size}-bit {cert.key_type} keys.",
                ))
        
        # Check for self-signed certificate
        if cert.subject_cn == cert.issuer:
            result.add_finding(Finding(
                title="Self-Signed Certificate",
                description="The certificate appears to be self-signed",
                severity=Severity.MEDIUM,
                category="tls_security",
                remediation="Use a certificate from a trusted Certificate Authority.",
            ))
        
        # Add informational finding with certificate details
        result.add_finding(Finding(
            title="TLS Certificate Information",
            description=f"Certificate details for {domain}",
            severity=Severity.INFO,
            category="tls_security",
            evidence=(
                f"Subject: {cert.subject_cn}\n"
                f"Issuer: {cert.issuer}\n"
                f"Valid: {cert.not_before} to {cert.not_after}\n"
                f"Key: {cert.key_type} {cert.key_size} bits\n"
                f"SANs: {len(cert.san)} entries"
            ),
        ))

    def _domain_matches_cert(self, domain: str, cert: TLSCertificate) -> bool:
        """
        Check if domain matches certificate CN or SANs.

        Args:
            domain: Domain to check
            cert: Certificate to check against

        Returns:
            True if domain matches
        """
        domain_lower = domain.lower()
        
        # Check exact match with CN
        if cert.subject_cn.lower() == domain_lower:
            return True
        
        # Check wildcard match with CN
        if self._wildcard_match(cert.subject_cn.lower(), domain_lower):
            return True
        
        # Check SANs
        for san in cert.san:
            san_lower = san.lower()
            if san_lower == domain_lower:
                return True
            if self._wildcard_match(san_lower, domain_lower):
                return True
        
        return False

    def _wildcard_match(self, pattern: str, domain: str) -> bool:
        """
        Check if a wildcard pattern matches a domain.

        Args:
            pattern: Certificate pattern (may include wildcard)
            domain: Domain to match

        Returns:
            True if matches
        """
        if not pattern.startswith("*."):
            return False
        
        # *.example.com matches sub.example.com but not sub.sub.example.com
        pattern_suffix = pattern[2:]  # Remove *.
        
        if domain.endswith(pattern_suffix):
            # Check that there's exactly one label before the pattern
            prefix = domain[:-len(pattern_suffix)]
            if prefix.endswith("."):
                prefix = prefix[:-1]
            return "." not in prefix
        
        return False
