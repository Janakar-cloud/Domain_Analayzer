"""Security utilities for Domain Intelligence."""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse


class IPValidator:
    """Validates IP addresses for security concerns like SSRF."""
    
    # RFC 1918 Private IPv4 ranges
    PRIVATE_IPV4_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    
    # Loopback
    LOOPBACK_RANGES = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]
    
    # Link-local
    LINK_LOCAL_RANGES = [
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("fe80::/10"),
    ]
    
    # Multicast
    MULTICAST_RANGES = [
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("ff00::/8"),
    ]
    
    # Reserved/Special
    RESERVED_RANGES = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
        ipaddress.ip_network("192.0.0.0/24"),   # IETF Protocol Assignments
        ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
        ipaddress.ip_network("198.51.100.0/24"),# TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"), # TEST-NET-3
        ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
        ipaddress.ip_network("240.0.0.0/4"),    # Reserved for future use
        ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    ]
    
    # Cloud metadata endpoints (commonly targeted in SSRF)
    CLOUD_METADATA_IPS = [
        ipaddress.ip_address("169.254.169.254"),  # AWS, GCP, Azure metadata
        ipaddress.ip_address("169.254.170.2"),    # AWS ECS metadata
        ipaddress.ip_address("fd00:ec2::254"),    # AWS IPv6 metadata
    ]

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """
        Check if an IP address is in a private range.
        
        Args:
            ip_str: IP address string
            
        Returns:
            True if private, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            
            for network in cls.PRIVATE_IPV4_RANGES:
                if ip in network:
                    return True
            
            # Check IPv6 private ranges
            if isinstance(ip, ipaddress.IPv6Address):
                if ip.is_private:
                    return True
                    
            return False
        except ValueError:
            return False

    @classmethod
    def is_loopback(cls, ip_str: str) -> bool:
        """Check if IP is a loopback address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_loopback
        except ValueError:
            return False

    @classmethod
    def is_link_local(cls, ip_str: str) -> bool:
        """Check if IP is a link-local address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_link_local
        except ValueError:
            return False

    @classmethod
    def is_multicast(cls, ip_str: str) -> bool:
        """Check if IP is a multicast address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_multicast
        except ValueError:
            return False

    @classmethod
    def is_reserved(cls, ip_str: str) -> bool:
        """Check if IP is in a reserved range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            
            if ip.is_reserved:
                return True
                
            for network in cls.RESERVED_RANGES:
                if ip in network:
                    return True
                    
            return False
        except ValueError:
            return False

    @classmethod
    def is_cloud_metadata(cls, ip_str: str) -> bool:
        """Check if IP is a cloud metadata endpoint."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip in cls.CLOUD_METADATA_IPS
        except ValueError:
            return False

    @classmethod
    def is_safe_for_external_request(cls, ip_str: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP address is safe to make external requests to.
        
        This prevents SSRF attacks by blocking requests to internal networks.
        
        Args:
            ip_str: IP address string
            
        Returns:
            Tuple of (is_safe, reason_if_not_safe)
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"
        
        # Check for loopback
        if ip.is_loopback:
            return False, f"Loopback address blocked: {ip_str}"
        
        # Check for private ranges
        if ip.is_private:
            return False, f"Private IP address blocked: {ip_str}"
        
        # Check for link-local
        if ip.is_link_local:
            return False, f"Link-local address blocked: {ip_str}"
        
        # Check for multicast
        if ip.is_multicast:
            return False, f"Multicast address blocked: {ip_str}"
        
        # Check for reserved
        if ip.is_reserved:
            return False, f"Reserved address blocked: {ip_str}"
        
        # Check for cloud metadata endpoints
        if ip in cls.CLOUD_METADATA_IPS:
            return False, f"Cloud metadata endpoint blocked: {ip_str}"
        
        # Check our additional reserved ranges
        for network in cls.RESERVED_RANGES:
            if ip in network:
                return False, f"Reserved range blocked: {ip_str}"
        
        return True, None

    @classmethod
    def filter_safe_ips(cls, ip_list: list) -> list:
        """
        Filter a list of IPs to only include safe external IPs.
        
        Args:
            ip_list: List of IP address strings
            
        Returns:
            Filtered list of safe IPs
        """
        safe_ips = []
        for ip in ip_list:
            is_safe, _ = cls.is_safe_for_external_request(ip)
            if is_safe:
                safe_ips.append(ip)
        return safe_ips


class DomainValidator:
    """Validates domain names for security and format."""
    
    # Maximum domain length per RFC
    MAX_DOMAIN_LENGTH = 253
    MAX_LABEL_LENGTH = 63
    
    # Valid domain pattern
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'  # Middle characters
        r'\.)*'  # Subdomains
        r'[a-zA-Z0-9]'  # TLD first char
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'  # TLD rest
    )
    
    # Internal/reserved domains that should be blocked
    BLOCKED_DOMAINS = [
        "localhost",
        "localhost.localdomain",
        "local",
        "internal",
        "corp",
        "home",
        "lan",
        "intranet",
    ]
    
    # Blocked TLDs (internal use)
    BLOCKED_TLDS = [
        "local",
        "localhost",
        "internal",
        "corp",
        "home",
        "lan",
        "intranet",
        "test",
        "invalid",
        "example",
    ]

    @classmethod
    def is_valid_domain(cls, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a domain name format.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            Tuple of (is_valid, reason_if_invalid)
        """
        if not domain:
            return False, "Domain is empty"
        
        domain = domain.lower().strip()
        
        # Check length
        if len(domain) > cls.MAX_DOMAIN_LENGTH:
            return False, f"Domain exceeds maximum length ({cls.MAX_DOMAIN_LENGTH})"
        
        # Check each label length
        labels = domain.split('.')
        for label in labels:
            if len(label) > cls.MAX_LABEL_LENGTH:
                return False, f"Label '{label}' exceeds maximum length ({cls.MAX_LABEL_LENGTH})"
            if not label:
                return False, "Empty label in domain"
        
        # Need at least one dot for a valid domain
        if len(labels) < 2:
            return False, "Domain must have at least two labels"
        
        # Check pattern
        if not cls.DOMAIN_PATTERN.match(domain):
            return False, "Domain contains invalid characters"
        
        return True, None

    @classmethod
    def is_safe_domain(cls, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a domain is safe to scan (not internal/reserved).
        
        Args:
            domain: Domain name to check
            
        Returns:
            Tuple of (is_safe, reason_if_not_safe)
        """
        # First validate format
        is_valid, reason = cls.is_valid_domain(domain)
        if not is_valid:
            return False, reason
        
        domain = domain.lower().strip()
        
        # Check blocked domains
        if domain in cls.BLOCKED_DOMAINS:
            return False, f"Internal domain blocked: {domain}"
        
        # Check blocked TLDs
        tld = domain.split('.')[-1]
        if tld in cls.BLOCKED_TLDS:
            return False, f"Internal TLD blocked: .{tld}"
        
        # Check if it's an IP address (not a domain)
        try:
            ipaddress.ip_address(domain)
            return False, "IP addresses should use IP lookup, not domain scan"
        except ValueError:
            pass  # Good, it's not an IP
        
        return True, None


class HTMLSanitizer:
    """Sanitize strings for safe HTML output."""
    
    @staticmethod
    def escape(text: str) -> str:
        """
        Escape HTML special characters to prevent XSS.
        
        Args:
            text: Text to escape
            
        Returns:
            HTML-escaped string
        """
        if not text:
            return ""
        
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
            .replace("/", "&#x2F;")
            .replace("`", "&#x60;")
            .replace("=", "&#x3D;")
        )
    
    @staticmethod
    def escape_attribute(text: str) -> str:
        """
        Escape text for use in HTML attributes.
        
        Args:
            text: Text to escape
            
        Returns:
            Escaped string safe for HTML attributes
        """
        if not text:
            return ""
        
        # Standard HTML escape
        text = HTMLSanitizer.escape(text)
        
        # Additional escapes for attributes
        text = text.replace("\n", "&#10;")
        text = text.replace("\r", "&#13;")
        text = text.replace("\t", "&#9;")
        
        return text
    
    @staticmethod
    def escape_url(url: str) -> str:
        """
        Escape and validate a URL for safe HTML output.
        
        Args:
            url: URL to escape
            
        Returns:
            Escaped URL or empty string if unsafe
        """
        if not url:
            return ""
        
        # Parse the URL
        try:
            parsed = urlparse(url)
        except Exception:
            return ""
        
        # Only allow safe schemes
        safe_schemes = ["http", "https", "mailto"]
        if parsed.scheme.lower() not in safe_schemes:
            return ""
        
        # Escape the URL
        return HTMLSanitizer.escape(url)
