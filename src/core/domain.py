"""Domain and result data structures for Domain Intelligence."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """A security finding or observation."""
    title: str
    description: str
    severity: Severity
    category: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class DNSRecord:
    """DNS record data."""
    record_type: str
    name: str
    value: str
    ttl: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
        }


@dataclass
class TLSCertificate:
    """TLS certificate information."""
    subject_cn: str
    issuer: str
    issuer_org: Optional[str] = None
    organization: Optional[str] = None
    san: List[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    is_expired: bool = False
    days_until_expiry: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_cn": self.subject_cn,
            "issuer": self.issuer,
            "issuer_org": self.issuer_org,
            "organization": self.organization,
            "san": self.san,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "serial_number": self.serial_number,
            "signature_algorithm": self.signature_algorithm,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "is_expired": self.is_expired,
            "days_until_expiry": self.days_until_expiry,
        }


@dataclass
class WHOISInfo:
    """WHOIS registration information."""
    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    status: List[str] = field(default_factory=list)
    domain_age_days: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registrar": self.registrar,
            "registrant_org": self.registrant_org,
            "registrant_country": self.registrant_country,
            "creation_date": self.creation_date.isoformat() if self.creation_date else None,
            "expiration_date": self.expiration_date.isoformat() if self.expiration_date else None,
            "updated_date": self.updated_date.isoformat() if self.updated_date else None,
            "name_servers": self.name_servers,
            "dnssec": self.dnssec,
            "status": self.status,
            "domain_age_days": self.domain_age_days,
        }


@dataclass
class SSLLabsResult:
    """SSL Labs assessment result."""
    grade: Optional[str] = None
    grade_trust_ignored: Optional[str] = None
    has_warnings: bool = False
    is_exceptional: bool = False
    protocols: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grade": self.grade,
            "grade_trust_ignored": self.grade_trust_ignored,
            "has_warnings": self.has_warnings,
            "is_exceptional": self.is_exceptional,
            "protocols": self.protocols,
            "vulnerabilities": self.vulnerabilities,
        }


@dataclass
class ThreatIntelResult:
    """Threat intelligence result from external APIs."""
    source: str
    is_malicious: bool = False
    confidence_score: Optional[float] = None
    abuse_score: Optional[int] = None
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    last_seen: Optional[datetime] = None
    reports_count: int = 0
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "is_malicious": self.is_malicious,
            "confidence_score": self.confidence_score,
            "abuse_score": self.abuse_score,
            "categories": self.categories,
            "tags": self.tags,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "reports_count": self.reports_count,
        }


@dataclass
class RedirectInfo:
    """HTTP redirect chain information."""
    url: str
    status_code: int
    location: Optional[str] = None
    is_https: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "location": self.location,
            "is_https": self.is_https,
        }


@dataclass
class Domain:
    """Domain being analyzed."""
    name: str
    parent_domain: Optional[str] = None
    discovered_from: Optional[str] = None  # e.g., "ct_logs", "dns", "manual"
    
    def __hash__(self):
        return hash(self.name)
    
    def __eq__(self, other):
        if isinstance(other, Domain):
            return self.name == other.name
        return False

    @property
    def is_subdomain(self) -> bool:
        """Check if this is a subdomain."""
        return self.parent_domain is not None and self.name != self.parent_domain


@dataclass
class DomainResult:
    """Complete analysis result for a domain."""
    domain: str
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Core results
    subdomains: List[str] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    tls_certificate: Optional[TLSCertificate] = None
    cert_error: Optional[str] = None
    
    # Enrichment results
    whois_info: Optional[WHOISInfo] = None
    ssllabs_result: Optional[SSLLabsResult] = None
    threat_intel: List[ThreatIntelResult] = field(default_factory=list)
    
    # Redirect analysis
    redirect_chain: List[RedirectInfo] = field(default_factory=list)
    final_url: Optional[str] = None
    
    # Findings
    findings: List[Finding] = field(default_factory=list)
    
    # Takeover detection
    is_takeover_candidate: bool = False
    takeover_type: Optional[str] = None
    
    # Metadata
    errors: List[str] = field(default_factory=list)
    scan_duration_seconds: Optional[float] = None
    modules_executed: List[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)

    @property
    def severity_score(self) -> int:
        """Calculate overall severity score (0-100)."""
        if not self.findings:
            return 0
        
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 15,
            Severity.LOW: 5,
            Severity.INFO: 1,
        }
        
        score = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(100, score)

    @property
    def highest_severity(self) -> Optional[Severity]:
        """Get the highest severity finding."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "domain": self.domain,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "subdomains": self.subdomains,
            "dns_records": [r.to_dict() for r in self.dns_records],
            "resolved_ips": self.resolved_ips,
            "tls_certificate": self.tls_certificate.to_dict() if self.tls_certificate else None,
            "cert_error": self.cert_error,
            "whois_info": self.whois_info.to_dict() if self.whois_info else None,
            "ssllabs_result": self.ssllabs_result.to_dict() if self.ssllabs_result else None,
            "threat_intel": [t.to_dict() for t in self.threat_intel],
            "redirect_chain": [r.to_dict() for r in self.redirect_chain],
            "final_url": self.final_url,
            "findings": [f.to_dict() for f in self.findings],
            "is_takeover_candidate": self.is_takeover_candidate,
            "takeover_type": self.takeover_type,
            "errors": self.errors,
            "scan_duration_seconds": self.scan_duration_seconds,
            "modules_executed": self.modules_executed,
            "severity_score": self.severity_score,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "spf_record": self.spf_record,
            "dmarc_record": self.dmarc_record,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainResult":
        """Create from dictionary."""
        result = cls(
            domain=data["domain"],
            scan_timestamp=datetime.fromisoformat(data["scan_timestamp"]),
        )
        # Additional parsing can be added as needed
        return result
