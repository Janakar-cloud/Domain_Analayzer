"""Tests for rate limiter functionality."""

import pytest
import time
import threading
from src.core.rate_limiter import RateLimiter, TokenBucket, RateLimitConfig


class TestTokenBucket:
    """Test the token bucket implementation."""

    def test_initial_capacity(self):
        """Test bucket starts with full capacity."""
        bucket = TokenBucket(rate=1.0, capacity=5)
        assert bucket.available() == 5

    def test_acquire_tokens(self):
        """Test acquiring tokens from bucket."""
        bucket = TokenBucket(rate=10.0, capacity=5)
        
        # Should succeed - have 5 tokens
        assert bucket.acquire(tokens=1, blocking=False) is True
        assert bucket.acquire(tokens=1, blocking=False) is True
        assert bucket.acquire(tokens=1, blocking=False) is True
        assert bucket.acquire(tokens=1, blocking=False) is True
        assert bucket.acquire(tokens=1, blocking=False) is True
        
        # Should fail - no tokens left (without waiting)
        assert bucket.acquire(tokens=1, blocking=False) is False

    def test_token_replenishment(self):
        """Test tokens are replenished over time."""
        bucket = TokenBucket(rate=10.0, capacity=5)  # 10 tokens/sec
        
        # Exhaust all tokens
        for _ in range(5):
            bucket.acquire(tokens=1, blocking=False)
        
        # Wait for replenishment (0.2 sec = ~2 tokens at 10/sec)
        time.sleep(0.25)
        
        # Should have tokens now
        assert bucket.acquire(tokens=1, blocking=False) is True

    def test_blocking_acquire(self):
        """Test blocking acquisition waits for tokens."""
        bucket = TokenBucket(rate=100.0, capacity=1)  # Fast replenishment
        
        # Take the one token
        bucket.acquire(tokens=1, blocking=False)
        
        # This should block briefly then succeed
        start = time.time()
        result = bucket.acquire(tokens=1, blocking=True, timeout=1.0)
        elapsed = time.time() - start
        
        assert result is True
        assert elapsed < 0.5  # Should be fast with 100 tokens/sec

    def test_acquire_timeout(self):
        """Test acquisition times out correctly when wait exceeds timeout."""
        # Rate of 0.1 means 1 token every 10 seconds
        bucket = TokenBucket(rate=0.1, capacity=1)
        
        # Take the one token
        bucket.acquire(tokens=1, blocking=False)
        
        # Now bucket is empty. To get 1 token at rate=0.1, we need 10 seconds.
        # With a 0.1 second timeout, the bucket should immediately return False
        # because wait_time (10s) > timeout (0.1s)
        start = time.time()
        result = bucket.acquire(tokens=1, blocking=True, timeout=0.1)
        elapsed = time.time() - start
        
        assert result is False
        # Should return quickly since it knows timeout is insufficient
        assert elapsed < 0.5


class TestRateLimitConfig:
    """Test rate limit configuration."""

    def test_default_burst_size(self):
        """Test default burst size calculation."""
        config = RateLimitConfig(requests_per_minute=60)
        assert config.burst_size == 5  # min(60, 5)
        
        config = RateLimitConfig(requests_per_minute=3)
        assert config.burst_size == 3  # min(3, 5)

    def test_custom_burst_size(self):
        """Test custom burst size."""
        config = RateLimitConfig(requests_per_minute=60, burst_size=10)
        assert config.burst_size == 10


class TestRateLimiter:
    """Test the rate limiter service."""

    def test_configure_service(self):
        """Test configuring a service."""
        limiter = RateLimiter()
        limiter.configure("test_service", requests_per_minute=60)
        
        # Should be able to acquire
        assert limiter.acquire("test_service", blocking=False) is True

    def test_configure_from_dict(self):
        """Test configuring multiple services from dict."""
        limiter = RateLimiter()
        limiter.configure_from_dict({
            "service_a": 30,
            "service_b": 60,
            "service_c": 120,
        })
        
        # All services should be configured
        assert limiter.acquire("service_a", blocking=False) is True
        assert limiter.acquire("service_b", blocking=False) is True
        assert limiter.acquire("service_c", blocking=False) is True

    def test_unconfigured_service_uses_default(self):
        """Test unconfigured service uses default rate."""
        limiter = RateLimiter(default_rpm=60)
        
        # Should auto-configure with default rate
        assert limiter.acquire("unknown_service", blocking=False) is True

    def test_rate_limiting_enforced(self):
        """Test that rate limiting is actually enforced."""
        limiter = RateLimiter()
        limiter.configure("strict_service", requests_per_minute=60, burst_size=2)
        
        # First 2 should succeed (burst)
        assert limiter.acquire("strict_service", blocking=False) is True
        assert limiter.acquire("strict_service", blocking=False) is True
        
        # Third should fail immediately (no blocking)
        assert limiter.acquire("strict_service", blocking=False) is False

    def test_wait_method(self):
        """Test the wait convenience method."""
        limiter = RateLimiter()
        limiter.configure("wait_test", requests_per_minute=6000, burst_size=5)
        
        # Exhaust burst
        for _ in range(5):
            limiter.wait("wait_test")
        
        # Next wait should block briefly
        start = time.time()
        limiter.wait("wait_test", timeout=1.0)
        elapsed = time.time() - start
        
        # Should have waited some time
        assert elapsed > 0

    def test_get_stats(self):
        """Test getting rate limiter statistics."""
        limiter = RateLimiter()
        limiter.configure("stats_test", requests_per_minute=60)
        
        # Make some acquisitions
        limiter.acquire("stats_test", blocking=False)
        limiter.acquire("stats_test", blocking=False)
        
        stats = limiter.get_stats()
        assert "stats_test" in stats
        assert stats["stats_test"]["acquired"] >= 2

    def test_thread_safety(self):
        """Test rate limiter is thread-safe."""
        limiter = RateLimiter()
        limiter.configure("thread_test", requests_per_minute=6000, burst_size=100)
        
        acquired_count = [0]
        failed_count = [0]
        lock = threading.Lock()
        
        def worker():
            for _ in range(50):
                if limiter.acquire("thread_test", blocking=False):
                    with lock:
                        acquired_count[0] += 1
                else:
                    with lock:
                        failed_count[0] += 1
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All threads completed without errors
        total = acquired_count[0] + failed_count[0]
        assert total == 250  # 5 threads * 50 iterations


class TestRateLimiterIntegration:
    """Integration tests for rate limiter with realistic scenarios."""

    def test_api_rate_limit_scenario(self):
        """Test simulating real API rate limits."""
        limiter = RateLimiter()
        
        # Configure like real APIs
        limiter.configure_from_dict({
            "virustotal": 4,     # Very restrictive
            "abuseipdb": 60,    # 1 per second
            "urlscan": 2,       # Very restrictive
        })
        
        # VirusTotal should be very restrictive
        assert limiter.acquire("virustotal", blocking=False) is True
        # Second request might fail without waiting
        
        # AbuseIPDB should be more permissive
        for _ in range(3):
            assert limiter.acquire("abuseipdb", blocking=False) is True

    def test_burst_handling(self):
        """Test burst traffic handling."""
        limiter = RateLimiter()
        limiter.configure("burst_test", requests_per_minute=30, burst_size=5)
        
        # Burst of 5 should all succeed
        burst_results = [
            limiter.acquire("burst_test", blocking=False)
            for _ in range(5)
        ]
        assert all(burst_results)
        
        # 6th should fail
        assert limiter.acquire("burst_test", blocking=False) is False
