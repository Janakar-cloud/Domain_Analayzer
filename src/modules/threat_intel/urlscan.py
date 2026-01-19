"""URLScan.io integration module."""

import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

from ...core.domain import DomainResult, Finding, Severity, ThreatIntelResult
from .base import BaseThreatIntelModule


class URLScanModule(BaseThreatIntelModule):
    """
    URLScan.io integration for URL scanning and screenshots.
    
    Scans URLs and captures screenshots for evidence collection.
    """

    name = "urlscan"
    description = "URL scanning and screenshots via URLScan.io"
    api_key_name = "urlscan"
    rate_limit_service = "urlscan"

    API_BASE = "https://urlscan.io/api/v1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers.update({
            "API-Key": self.api_key,
            "Content-Type": "application/json",
        })

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """
        Search URLScan.io for an IP.

        Args:
            ip: IP address to search

        Returns:
            ThreatIntelResult or None
        """
        return self._search(f"ip:{ip}")

    def lookup_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """
        Search URLScan.io for a domain.

        Args:
            domain: Domain to search

        Returns:
            ThreatIntelResult or None
        """
        return self._search(f"domain:{domain}")

    def _search(self, query: str) -> Optional[ThreatIntelResult]:
        """
        Search URLScan.io.

        Args:
            query: Search query

        Returns:
            ThreatIntelResult or None
        """
        try:
            response = self.session.get(
                f"{self.API_BASE}/search/",
                params={"q": query, "size": 10},
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_search_results(data, query)
            elif response.status_code == 429:
                self.logger.warning("URLScan.io rate limit exceeded")
            else:
                self.logger.warning(f"URLScan.io returned status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"URLScan.io request error: {e}")
        
        return None

    def _parse_search_results(self, data: dict, query: str) -> ThreatIntelResult:
        """
        Parse URLScan.io search results.

        Args:
            data: API response data
            query: Original search query

        Returns:
            ThreatIntelResult
        """
        results = data.get("results", [])
        
        # Analyze results for malicious indicators
        malicious_count = 0
        categories = set()
        tags = set()
        
        for result in results:
            verdicts = result.get("verdicts", {})
            
            # Check overall verdict
            overall = verdicts.get("overall", {})
            if overall.get("malicious"):
                malicious_count += 1
            
            # Collect categories
            for category in overall.get("categories", []):
                categories.add(category)
            
            # Collect tags
            for tag in overall.get("tags", []):
                tags.add(tag)
            
            # Check individual engine verdicts
            urlscan_verdict = verdicts.get("urlscan", {})
            if urlscan_verdict.get("malicious"):
                malicious_count += 1
                for cat in urlscan_verdict.get("categories", []):
                    categories.add(cat)
        
        is_malicious = malicious_count > 0
        confidence = min(1.0, malicious_count / max(len(results), 1))
        
        return ThreatIntelResult(
            source="URLScan.io",
            is_malicious=is_malicious,
            confidence_score=confidence,
            categories=list(categories)[:10],
            tags=list(tags)[:20],
            reports_count=len(results),
            details={
                "query": query,
                "total_results": data.get("total", 0),
                "malicious_results": malicious_count,
            },
        )

    def execute(self, domain: str, result: DomainResult) -> None:
        """
        Execute URLScan analysis with optional screenshot capture.

        Args:
            domain: Domain to analyze
            result: DomainResult to populate
        """
        # First do the standard search
        super().execute(domain, result)
        
        # Then scan and capture screenshot if enabled
        store_screenshots = self._module_config.get("store_screenshots", True)
        
        if store_screenshots:
            self._scan_and_screenshot(domain, result)

    def _scan_and_screenshot(self, domain: str, result: DomainResult) -> None:
        """
        Submit URL for scanning and save screenshot.

        Args:
            domain: Domain to scan
            result: DomainResult to add findings to
        """
        self.rate_limit()
        
        visibility = self._module_config.get("visibility", "public")
        url = f"https://{domain}"
        
        # Submit scan
        scan_uuid = self._submit_scan(url, visibility)
        
        if not scan_uuid:
            return
        
        # Wait for scan to complete and get results
        scan_result = self._wait_for_scan(scan_uuid)
        
        if scan_result:
            # Download screenshot
            screenshot_url = scan_result.get("task", {}).get("screenshotURL")
            if screenshot_url:
                screenshot_path = self._save_screenshot(screenshot_url, domain)
                
                if screenshot_path:
                    result.add_finding(Finding(
                        title="URLScan Screenshot Captured",
                        description=f"Screenshot saved for {domain}",
                        severity=Severity.INFO,
                        category="evidence",
                        evidence=f"Screenshot: {screenshot_path}\nURLScan: https://urlscan.io/result/{scan_uuid}/",
                    ))
            
            # Check verdicts
            verdicts = scan_result.get("verdicts", {})
            overall = verdicts.get("overall", {})
            
            if overall.get("malicious"):
                categories = overall.get("categories", [])
                result.add_finding(Finding(
                    title="URLScan Detected Malicious Content",
                    description=f"URLScan.io flagged {domain} as malicious",
                    severity=Severity.HIGH,
                    category="threat_intelligence",
                    evidence=f"Categories: {', '.join(categories)}\nReport: https://urlscan.io/result/{scan_uuid}/",
                    remediation="Investigate the URL and consider blocking access.",
                ))

    def _submit_scan(self, url: str, visibility: str = "public") -> Optional[str]:
        """
        Submit a URL for scanning.

        Args:
            url: URL to scan
            visibility: 'public' or 'private'

        Returns:
            Scan UUID or None
        """
        try:
            response = self.session.post(
                f"{self.API_BASE}/scan/",
                json={
                    "url": url,
                    "visibility": visibility,
                },
                timeout=self.timeout,
                proxies=self.config.proxy_settings,
            )
            
            if response.status_code == 200:
                return response.json().get("uuid")
            elif response.status_code == 429:
                self.logger.warning("URLScan.io rate limit exceeded")
            else:
                self.logger.warning(f"URLScan.io scan submission returned {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"URLScan.io scan submission error: {e}")
        
        return None

    def _wait_for_scan(self, uuid: str, max_wait: int = 60) -> Optional[dict]:
        """
        Wait for scan to complete and return results.

        Args:
            uuid: Scan UUID
            max_wait: Maximum seconds to wait

        Returns:
            Scan result or None
        """
        start_time = time.time()
        poll_interval = 5
        
        while time.time() - start_time < max_wait:
            try:
                response = self.session.get(
                    f"{self.API_BASE}/result/{uuid}/",
                    timeout=self.timeout,
                    proxies=self.config.proxy_settings,
                )
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    # Scan not ready yet
                    time.sleep(poll_interval)
                else:
                    self.logger.warning(f"URLScan.io result returned {response.status_code}")
                    break
                    
            except requests.exceptions.RequestException as e:
                self.logger.error(f"URLScan.io result error: {e}")
                break
        
        self.logger.warning(f"URLScan.io scan timed out for {uuid}")
        return None

    def _save_screenshot(self, url: str, domain: str) -> Optional[str]:
        """
        Download and save screenshot.

        Args:
            url: Screenshot URL
            domain: Domain name for filename

        Returns:
            Path to saved screenshot or None
        """
        try:
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                # Create evidence directory
                evidence_dir = self.config.evidence_dir
                
                # Generate filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_domain = domain.replace(".", "_").replace("/", "_")
                filename = f"{safe_domain}_{timestamp}.png"
                filepath = evidence_dir / filename
                
                # Save screenshot
                with open(filepath, "wb") as f:
                    f.write(response.content)
                
                self.logger.info(f"Screenshot saved: {filepath}")
                return str(filepath)
                
        except Exception as e:
            self.logger.error(f"Error saving screenshot: {e}")
        
        return None
