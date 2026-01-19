"""Input Validation Utilities for Domain Intelligence."""

import re
from typing import Tuple, Optional, List
from .errors import ErrorCodes, ErrorResponse, format_error


class DomainValidator:
    """Validate domain names."""
    
    # Domain regex pattern
    DOMAIN_PATTERN = re.compile(
        r'^(?=.{1,253}$)'  # Total length check
        r'(?!-)'  # Cannot start with hyphen
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'  # Subdomains
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'  # Domain
        r'(?:\.[a-zA-Z]{2,})$'  # TLD
    )
    
    # Simple pattern for basic validation
    SIMPLE_DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,}$'
    )
    
    # Reserved/invalid TLDs
    INVALID_TLDS = {'localhost', 'local', 'internal', 'invalid', 'test'}
    
    @classmethod
    def validate(cls, domain: str) -> Tuple[bool, Optional[ErrorResponse]]:
        """
        Validate a domain name.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            Tuple of (is_valid, error_response)
        """
        if not domain:
            return False, ErrorCodes.VALID_EMPTY_INPUT
        
        # Strip whitespace and convert to lowercase
        domain = domain.strip().lower()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove trailing slash and path
        domain = domain.split('/')[0]
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Check length
        if len(domain) > 253:
            return False, ErrorCodes.VALID_DOMAIN_TOO_LONG
        
        # Check for empty after cleaning
        if not domain:
            return False, ErrorCodes.VALID_EMPTY_INPUT
        
        # Check for invalid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_CHARACTERS,
                f"Domain '{domain}' contains invalid characters"
            )
        
        # Check consecutive dots
        if '..' in domain:
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                "Domain cannot contain consecutive dots"
            )
        
        # Check if starts or ends with dot or hyphen
        if domain.startswith('.') or domain.endswith('.'):
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                "Domain cannot start or end with a dot"
            )
        
        if domain.startswith('-') or domain.endswith('-'):
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                "Domain cannot start or end with a hyphen"
            )
        
        # Check for valid TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                "Domain must have at least one dot"
            )
        
        tld = parts[-1]
        if len(tld) < 2:
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                "TLD must be at least 2 characters"
            )
        
        # Check for reserved TLDs
        if tld in cls.INVALID_TLDS:
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                f"'{tld}' is a reserved/invalid TLD"
            )
        
        # Check each label
        for label in parts:
            if not label:
                return False, ErrorCodes.with_details(
                    ErrorCodes.VALID_INVALID_DOMAIN,
                    "Domain contains empty label"
                )
            if len(label) > 63:
                return False, ErrorCodes.with_details(
                    ErrorCodes.VALID_INVALID_DOMAIN,
                    f"Label '{label[:20]}...' exceeds 63 characters"
                )
            if label.startswith('-') or label.endswith('-'):
                return False, ErrorCodes.with_details(
                    ErrorCodes.VALID_INVALID_DOMAIN,
                    f"Label '{label}' cannot start or end with hyphen"
                )
        
        return True, None
    
    @classmethod
    def clean(cls, domain: str) -> str:
        """Clean and normalize a domain name."""
        domain = domain.strip().lower()
        
        # Remove protocol
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://', 1)[1]
        
        # Remove path
        domain = domain.split('/')[0]
        
        # Remove port
        domain = domain.split(':')[0]
        
        # Remove www prefix (optional)
        # if domain.startswith('www.'):
        #     domain = domain[4:]
        
        return domain
    
    @classmethod
    def validate_list(cls, domains: List[str]) -> Tuple[List[str], List[Tuple[str, ErrorResponse]]]:
        """
        Validate a list of domains.
        
        Returns:
            Tuple of (valid_domains, invalid_domains_with_errors)
        """
        valid = []
        invalid = []
        
        for domain in domains:
            cleaned = cls.clean(domain)
            is_valid, error = cls.validate(cleaned)
            
            if is_valid:
                valid.append(cleaned)
            else:
                invalid.append((domain, error))
        
        return valid, invalid


class EmailValidator:
    """Validate email addresses."""
    
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    @classmethod
    def validate(cls, email: str) -> Tuple[bool, Optional[ErrorResponse]]:
        """Validate an email address."""
        if not email:
            return False, ErrorCodes.VALID_EMPTY_INPUT
        
        email = email.strip().lower()
        
        if len(email) > 254:
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_EMAIL,
                "Email address too long"
            )
        
        if not cls.EMAIL_PATTERN.match(email):
            return False, ErrorCodes.VALID_INVALID_EMAIL
        
        return True, None


class URLValidator:
    """Validate URLs."""
    
    URL_PATTERN = re.compile(
        r'^https?://'  # Protocol
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*'  # Subdomains
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'  # Domain
        r'(?:\.[a-zA-Z]{2,})'  # TLD
        r'(?::\d{1,5})?'  # Port
        r'(?:/[^\s]*)?$'  # Path
    )
    
    @classmethod
    def validate(cls, url: str) -> Tuple[bool, Optional[ErrorResponse]]:
        """Validate a URL."""
        if not url:
            return False, ErrorCodes.VALID_EMPTY_INPUT
        
        url = url.strip()
        
        if not url.startswith(('http://', 'https://')):
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                "URL must start with http:// or https://"
            )
        
        if not cls.URL_PATTERN.match(url):
            return False, ErrorCodes.with_details(
                ErrorCodes.VALID_INVALID_DOMAIN,
                "Invalid URL format"
            )
        
        return True, None


class PasswordValidator:
    """Validate password strength."""
    
    @classmethod
    def validate(cls, password: str, min_length: int = 8) -> Tuple[bool, Optional[ErrorResponse]]:
        """
        Validate password strength.
        
        Requirements:
        - Minimum length (default 8)
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        """
        if not password:
            return False, ErrorCodes.VALID_EMPTY_INPUT
        
        errors = []
        
        if len(password) < min_length:
            errors.append(f"at least {min_length} characters")
        
        if not re.search(r'[A-Z]', password):
            errors.append("one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("one lowercase letter")
        
        if not re.search(r'\d', password):
            errors.append("one digit")
        
        if errors:
            return False, ErrorCodes.with_details(
                ErrorCodes.AUTH_PASSWORD_WEAK,
                f"Password must contain: {', '.join(errors)}"
            )
        
        return True, None


def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """Simple domain validation helper."""
    is_valid, error = DomainValidator.validate(domain)
    if error:
        return False, format_error(error)
    return True, None


def validate_domains(domains: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validate multiple domains.
    
    Returns:
        Tuple of (valid_domains, error_messages)
    """
    valid, invalid = DomainValidator.validate_list(domains)
    errors = [f"{domain}: {format_error(error)}" for domain, error in invalid]
    return valid, errors
