"""Error Response Codes System for Domain Intelligence."""

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


class ErrorCategory(Enum):
    """Error categories for classification."""
    AUTHENTICATION = "AUTH"
    VALIDATION = "VALID"
    SCAN = "SCAN"
    DATABASE = "DB"
    NETWORK = "NET"
    EMAIL = "EMAIL"
    CONFIGURATION = "CONFIG"
    SYSTEM = "SYS"


@dataclass
class ErrorResponse:
    """Structured error response."""
    code: str
    message: str
    category: ErrorCategory
    details: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "category": self.category.value,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }
    
    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class ErrorCodes:
    """Centralized error codes for the application."""
    
    # Authentication Errors (AUTH-001 to AUTH-099)
    AUTH_INVALID_CREDENTIALS = ErrorResponse(
        code="AUTH-001",
        message="Invalid username or password",
        category=ErrorCategory.AUTHENTICATION
    )
    AUTH_SESSION_EXPIRED = ErrorResponse(
        code="AUTH-002",
        message="Session has expired. Please login again",
        category=ErrorCategory.AUTHENTICATION
    )
    AUTH_RATE_LIMITED = ErrorResponse(
        code="AUTH-003",
        message="Too many login attempts. Please try again later",
        category=ErrorCategory.AUTHENTICATION
    )
    AUTH_ACCOUNT_LOCKED = ErrorResponse(
        code="AUTH-004",
        message="Account is locked due to multiple failed attempts",
        category=ErrorCategory.AUTHENTICATION
    )
    AUTH_USER_NOT_FOUND = ErrorResponse(
        code="AUTH-005",
        message="User not found",
        category=ErrorCategory.AUTHENTICATION
    )
    AUTH_PASSWORD_WEAK = ErrorResponse(
        code="AUTH-006",
        message="Password does not meet security requirements",
        category=ErrorCategory.AUTHENTICATION
    )
    
    # Validation Errors (VALID-001 to VALID-099)
    VALID_INVALID_DOMAIN = ErrorResponse(
        code="VALID-001",
        message="Invalid domain format",
        category=ErrorCategory.VALIDATION
    )
    VALID_EMPTY_INPUT = ErrorResponse(
        code="VALID-002",
        message="Input cannot be empty",
        category=ErrorCategory.VALIDATION
    )
    VALID_DOMAIN_TOO_LONG = ErrorResponse(
        code="VALID-003",
        message="Domain name exceeds maximum length (253 characters)",
        category=ErrorCategory.VALIDATION
    )
    VALID_INVALID_CHARACTERS = ErrorResponse(
        code="VALID-004",
        message="Domain contains invalid characters",
        category=ErrorCategory.VALIDATION
    )
    VALID_INVALID_EMAIL = ErrorResponse(
        code="VALID-005",
        message="Invalid email address format",
        category=ErrorCategory.VALIDATION
    )
    VALID_MISSING_REQUIRED = ErrorResponse(
        code="VALID-006",
        message="Required field is missing",
        category=ErrorCategory.VALIDATION
    )
    
    # Scan Errors (SCAN-001 to SCAN-099)
    SCAN_FAILED = ErrorResponse(
        code="SCAN-001",
        message="Scan failed to complete",
        category=ErrorCategory.SCAN
    )
    SCAN_TIMEOUT = ErrorResponse(
        code="SCAN-002",
        message="Scan timed out",
        category=ErrorCategory.SCAN
    )
    SCAN_MODULE_ERROR = ErrorResponse(
        code="SCAN-003",
        message="One or more scan modules encountered errors",
        category=ErrorCategory.SCAN
    )
    SCAN_NO_RESULTS = ErrorResponse(
        code="SCAN-004",
        message="Scan completed but returned no results",
        category=ErrorCategory.SCAN
    )
    SCAN_RATE_LIMITED = ErrorResponse(
        code="SCAN-005",
        message="Scan rate limit exceeded. Please wait before scanning again",
        category=ErrorCategory.SCAN
    )
    
    # Database Errors (DB-001 to DB-099)
    DB_CONNECTION_FAILED = ErrorResponse(
        code="DB-001",
        message="Failed to connect to database",
        category=ErrorCategory.DATABASE
    )
    DB_QUERY_FAILED = ErrorResponse(
        code="DB-002",
        message="Database query failed",
        category=ErrorCategory.DATABASE
    )
    DB_RECORD_NOT_FOUND = ErrorResponse(
        code="DB-003",
        message="Record not found in database",
        category=ErrorCategory.DATABASE
    )
    DB_DUPLICATE_ENTRY = ErrorResponse(
        code="DB-004",
        message="Duplicate entry exists",
        category=ErrorCategory.DATABASE
    )
    DB_INTEGRITY_ERROR = ErrorResponse(
        code="DB-005",
        message="Database integrity constraint violated",
        category=ErrorCategory.DATABASE
    )
    
    # Network Errors (NET-001 to NET-099)
    NET_CONNECTION_FAILED = ErrorResponse(
        code="NET-001",
        message="Network connection failed",
        category=ErrorCategory.NETWORK
    )
    NET_TIMEOUT = ErrorResponse(
        code="NET-002",
        message="Network request timed out",
        category=ErrorCategory.NETWORK
    )
    NET_DNS_RESOLUTION_FAILED = ErrorResponse(
        code="NET-003",
        message="DNS resolution failed",
        category=ErrorCategory.NETWORK
    )
    NET_SSL_ERROR = ErrorResponse(
        code="NET-004",
        message="SSL/TLS connection error",
        category=ErrorCategory.NETWORK
    )
    
    # Email Errors (EMAIL-001 to EMAIL-099)
    EMAIL_SEND_FAILED = ErrorResponse(
        code="EMAIL-001",
        message="Failed to send email",
        category=ErrorCategory.EMAIL
    )
    EMAIL_AUTH_FAILED = ErrorResponse(
        code="EMAIL-002",
        message="Email authentication failed",
        category=ErrorCategory.EMAIL
    )
    EMAIL_CONNECTION_FAILED = ErrorResponse(
        code="EMAIL-003",
        message="Failed to connect to email server",
        category=ErrorCategory.EMAIL
    )
    EMAIL_INVALID_RECIPIENT = ErrorResponse(
        code="EMAIL-004",
        message="Invalid recipient email address",
        category=ErrorCategory.EMAIL
    )
    
    # Configuration Errors (CONFIG-001 to CONFIG-099)
    CONFIG_INVALID = ErrorResponse(
        code="CONFIG-001",
        message="Invalid configuration",
        category=ErrorCategory.CONFIGURATION
    )
    CONFIG_MISSING = ErrorResponse(
        code="CONFIG-002",
        message="Required configuration is missing",
        category=ErrorCategory.CONFIGURATION
    )
    
    # System Errors (SYS-001 to SYS-099)
    SYS_INTERNAL_ERROR = ErrorResponse(
        code="SYS-001",
        message="Internal system error",
        category=ErrorCategory.SYSTEM
    )
    SYS_RESOURCE_UNAVAILABLE = ErrorResponse(
        code="SYS-002",
        message="System resource unavailable",
        category=ErrorCategory.SYSTEM
    )
    SYS_FILE_NOT_FOUND = ErrorResponse(
        code="SYS-003",
        message="File not found",
        category=ErrorCategory.SYSTEM
    )
    SYS_PERMISSION_DENIED = ErrorResponse(
        code="SYS-004",
        message="Permission denied",
        category=ErrorCategory.SYSTEM
    )

    @classmethod
    def with_details(cls, error: ErrorResponse, details: str) -> ErrorResponse:
        """Create a copy of an error with additional details."""
        return ErrorResponse(
            code=error.code,
            message=error.message,
            category=error.category,
            details=details
        )


def format_error(error: ErrorResponse) -> str:
    """Format error for display."""
    if error.details:
        return f"[{error.code}] {error.message}: {error.details}"
    return f"[{error.code}] {error.message}"
