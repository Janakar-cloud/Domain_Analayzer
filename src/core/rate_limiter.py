"""Rate limiting utilities for Domain Intelligence."""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Optional

from .logger import get_logger


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit."""
    requests_per_minute: int
    burst_size: Optional[int] = None  # Allow bursts up to this size

    def __post_init__(self):
        if self.burst_size is None:
            self.burst_size = min(self.requests_per_minute, 5)


class TokenBucket:
    """Token bucket rate limiter implementation."""

    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket.

        Args:
            rate: Tokens added per second
            capacity: Maximum tokens in bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, tokens: int = 1, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        """
        Acquire tokens from the bucket.

        Args:
            tokens: Number of tokens to acquire
            blocking: Whether to block until tokens are available
            timeout: Maximum time to wait (if blocking)

        Returns:
            True if tokens were acquired, False otherwise
        """
        start_time = time.monotonic()

        while True:
            with self.lock:
                # Add new tokens based on elapsed time
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_update = now

                # Try to acquire tokens
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

                if not blocking:
                    return False

                # Calculate wait time
                wait_time = (tokens - self.tokens) / self.rate

            # Check timeout
            if timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed + wait_time > timeout:
                    return False
                wait_time = min(wait_time, timeout - elapsed)

            time.sleep(min(wait_time, 0.1))  # Sleep in small increments

    def available(self) -> float:
        """Get number of available tokens."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            return min(self.capacity, self.tokens + elapsed * self.rate)


class RateLimiter:
    """
    Rate limiter that manages multiple services with different limits.
    
    Uses token bucket algorithm for smooth rate limiting with burst support.
    """

    def __init__(self, default_rpm: int = 60):
        """
        Initialize rate limiter.

        Args:
            default_rpm: Default requests per minute for unconfigured services
        """
        self.default_rpm = default_rpm
        self._buckets: Dict[str, TokenBucket] = {}
        self._configs: Dict[str, RateLimitConfig] = {}
        self._stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"acquired": 0, "blocked": 0})
        self._lock = threading.Lock()
        self.logger = get_logger("rate_limiter")

    def configure(self, service: str, requests_per_minute: int, burst_size: Optional[int] = None) -> None:
        """
        Configure rate limit for a service.

        Args:
            service: Service name
            requests_per_minute: Maximum requests per minute
            burst_size: Maximum burst size
        """
        with self._lock:
            config = RateLimitConfig(requests_per_minute, burst_size)
            self._configs[service] = config
            
            # Create token bucket
            rate = requests_per_minute / 60.0  # Tokens per second
            capacity = config.burst_size or min(requests_per_minute, 5)
            self._buckets[service] = TokenBucket(rate, capacity)
            
            self.logger.debug(f"Configured rate limit for {service}: {requests_per_minute} rpm, burst: {capacity}")

    def configure_from_dict(self, limits: Dict[str, int]) -> None:
        """
        Configure multiple rate limits from a dictionary.

        Args:
            limits: Dictionary of service -> requests_per_minute
        """
        for service, rpm in limits.items():
            self.configure(service, rpm)

    def acquire(self, service: str, blocking: bool = True, timeout: Optional[float] = 30.0) -> bool:
        """
        Acquire permission to make a request to a service.

        Args:
            service: Service name
            blocking: Whether to block until permission is granted
            timeout: Maximum time to wait

        Returns:
            True if permission granted, False otherwise
        """
        bucket = self._get_or_create_bucket(service)
        
        acquired = bucket.acquire(blocking=blocking, timeout=timeout)
        
        with self._lock:
            if acquired:
                self._stats[service]["acquired"] += 1
            else:
                self._stats[service]["blocked"] += 1
                self.logger.warning(f"Rate limit exceeded for {service}")
        
        return acquired

    def _get_or_create_bucket(self, service: str) -> TokenBucket:
        """Get or create a token bucket for a service."""
        with self._lock:
            if service not in self._buckets:
                rate = self.default_rpm / 60.0
                capacity = min(self.default_rpm, 5)
                self._buckets[service] = TokenBucket(rate, capacity)
                self.logger.debug(f"Created default rate limit for {service}: {self.default_rpm} rpm")
            return self._buckets[service]

    def get_stats(self, service: Optional[str] = None) -> Dict:
        """
        Get rate limiting statistics.

        Args:
            service: Specific service or None for all

        Returns:
            Statistics dictionary
        """
        with self._lock:
            if service:
                return dict(self._stats[service])
            return {svc: dict(stats) for svc, stats in self._stats.items()}

    def reset_stats(self) -> None:
        """Reset all statistics."""
        with self._lock:
            self._stats.clear()

    def wait(self, service: str, timeout: Optional[float] = 30.0) -> None:
        """
        Wait until rate limit allows a request.

        Args:
            service: Service name
            timeout: Maximum time to wait

        Raises:
            TimeoutError: If timeout exceeded
        """
        if not self.acquire(service, blocking=True, timeout=timeout):
            raise TimeoutError(f"Rate limit timeout for {service}")


class RateLimitContext:
    """Context manager for rate-limited operations."""

    def __init__(self, limiter: RateLimiter, service: str, timeout: Optional[float] = 30.0):
        """
        Initialize context.

        Args:
            limiter: Rate limiter instance
            service: Service name
            timeout: Maximum wait time
        """
        self.limiter = limiter
        self.service = service
        self.timeout = timeout

    def __enter__(self):
        """Enter context and acquire rate limit."""
        self.limiter.wait(self.service, self.timeout)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context."""
        return False
