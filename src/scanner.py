"""Domain Intelligence Scanner Engine."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Type

from .core.config import Config
from .core.domain import Domain, DomainResult
from .core.logger import get_logger, setup_logger
from .core.rate_limiter import RateLimiter
from .modules.base import BaseModule
from .modules.ct_enumeration import CTEnumerationModule
from .modules.dns_enumeration import DNSEnumerationModule
from .modules.tls_inspection import TLSInspectionModule
from .modules.whois_lookup import WHOISModule
from .modules.ssllabs import SSLLabsModule
from .modules.redirect_analysis import RedirectAnalysisModule
from .modules.takeover_detection import TakeoverDetectionModule
from .modules.content_scanner import ContentScannerModule
from .modules.threat_intel import (
    AbuseIPDBModule,
    AlienVaultOTXModule,
    VirusTotalModule,
    URLScanModule,
    CriminalIPModule,
    LocalReputationModule,
)
from .reporters import JSONReporter, CSVReporter, HTMLReporter


class Scanner:
    """
    Main scanner engine that orchestrates domain analysis.
    
    Coordinates module execution, threading, rate limiting, and reporting.
    """

    # Module execution order (dependencies considered)
    MODULE_CLASSES: List[Type[BaseModule]] = [
        CTEnumerationModule,      # First: discover subdomains
        DNSEnumerationModule,     # Second: resolve DNS (needed for IP-based lookups)
        TLSInspectionModule,      # Third: check TLS (uses resolved host)
        WHOISModule,              # WHOIS lookup
        SSLLabsModule,            # SSL Labs assessment
        RedirectAnalysisModule,   # Check redirects
        ContentScannerModule,     # Homepage/shallow content scan (inbuilt-only)
        TakeoverDetectionModule,  # Check for takeover (uses DNS/subdomains)
        # Threat intelligence modules (use resolved IPs)
        LocalReputationModule,    # Local-only heuristics, runs without API keys
        AbuseIPDBModule,
        AlienVaultOTXModule,
        VirusTotalModule,
        CriminalIPModule,
        URLScanModule,
    ]

    def __init__(self, config: Optional[Config] = None, config_path: Optional[str] = None):
        """
        Initialize scanner.

        Args:
            config: Configuration instance (optional)
            config_path: Path to config file (optional)
        """
        self.config = config or Config(config_path=config_path)
        
        # Setup logging
        log_config = self.config.get("logging", {})
        self.logger = setup_logger(
            name="scanner",
            level=log_config.get("level", "INFO"),
            log_format=log_config.get("format", "json"),
            log_file=str(self.config.log_dir / "domain_intel.log"),
        )
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter()
        self.rate_limiter.configure_from_dict(self.config.rate_limits)
        
        # Initialize modules
        self.modules = self._init_modules()
        
        # Initialize reporters
        self.reporters = {
            "json": JSONReporter(self.config),
            "csv": CSVReporter(self.config),
            "html": HTMLReporter(self.config),
        }
        
        self.logger.info("Scanner initialized")

    def _init_modules(self) -> List[BaseModule]:
        """Initialize all analysis modules."""
        modules = []
        
        for module_class in self.MODULE_CLASSES:
            try:
                module = module_class(self.config, self.rate_limiter)
                modules.append(module)
                self.logger.debug(f"Initialized module: {module.name} (enabled: {module.is_enabled})")
            except Exception as e:
                self.logger.error(f"Failed to initialize {module_class.__name__}: {e}")
        
        return modules

    def scan_domain(self, domain: str, include_subdomains: bool = False) -> DomainResult:
        """
        Scan a single domain.

        Args:
            domain: Domain name to scan
            include_subdomains: Whether to scan discovered subdomains

        Returns:
            DomainResult with findings
        """
        domain = domain.lower().strip()
        self.logger.info(f"Starting scan for {domain}")
        
        start_time = time.time()
        result = DomainResult(domain=domain)
        
        # Run each module in sequence
        for module in self.modules:
            if module.is_enabled:
                try:
                    module.run(domain, result)
                except Exception as e:
                    error_msg = f"Module {module.name} failed: {e}"
                    self.logger.error(error_msg, exc_info=True)
                    result.add_error(error_msg)
        
        result.scan_duration_seconds = time.time() - start_time
        
        self.logger.info(
            f"Completed scan for {domain} in {result.scan_duration_seconds:.2f}s "
            f"({len(result.findings)} findings)"
        )
        
        return result

    def scan_domains(
        self, 
        domains: List[str], 
        max_workers: Optional[int] = None,
        include_subdomains: bool = False,
    ) -> List[DomainResult]:
        """
        Scan multiple domains with concurrent execution.

        Args:
            domains: List of domain names
            max_workers: Maximum concurrent workers
            include_subdomains: Whether to scan discovered subdomains

        Returns:
            List of DomainResult objects
        """
        if not domains:
            return []
        
        # Deduplicate domains
        domains = list(set(d.lower().strip() for d in domains if d.strip()))
        
        max_workers = max_workers or self.config.concurrency.get("max_workers", 10)
        results = []
        
        self.logger.info(f"Starting scan of {len(domains)} domains with {max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all domains
            future_to_domain = {
                executor.submit(self.scan_domain, domain, include_subdomains): domain
                for domain in domains
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Scan failed for {domain}: {e}")
                    # Create error result
                    error_result = DomainResult(domain=domain)
                    error_result.add_error(f"Scan failed: {e}")
                    results.append(error_result)
        
        # Sort results by domain name
        results.sort(key=lambda r: r.domain)
        
        self.logger.info(f"Completed scanning {len(results)} domains")
        
        return results

    def scan_from_file(
        self, 
        filepath: str, 
        max_workers: Optional[int] = None,
    ) -> List[DomainResult]:
        """
        Scan domains from a text file (one per line).

        Args:
            filepath: Path to domains file
            max_workers: Maximum concurrent workers

        Returns:
            List of DomainResult objects
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Domains file not found: {filepath}")
        
        with open(path, "r", encoding="utf-8") as f:
            domains = [
                line.strip() 
                for line in f 
                if line.strip() and not line.startswith("#")
            ]
        
        self.logger.info(f"Loaded {len(domains)} domains from {filepath}")
        
        return self.scan_domains(domains, max_workers)

    def generate_reports(
        self, 
        results: List[DomainResult], 
        formats: Optional[List[str]] = None,
        prefix: str = "domain_intel",
    ) -> List[Path]:
        """
        Generate reports in specified formats.

        Args:
            results: List of DomainResult objects
            formats: List of format names (json, csv, html)
            prefix: Filename prefix

        Returns:
            List of generated report paths
        """
        formats = formats or self.config.output_formats
        generated = []
        
        for fmt in formats:
            if fmt in self.reporters:
                try:
                    path = self.reporters[fmt].generate(results)
                    generated.append(path)
                    self.logger.info(f"Generated {fmt} report: {path}")
                    
                    # Also generate full asset inventory CSV
                    if fmt == "csv":
                        try:
                            inventory_path = self.reporters[fmt].generate_full_asset_inventory(results)
                            generated.append(inventory_path)
                            self.logger.info(f"Generated full asset inventory: {inventory_path}")
                        except Exception as e:
                            self.logger.error(f"Failed to generate asset inventory: {e}")
                except Exception as e:
                    self.logger.error(f"Failed to generate {fmt} report: {e}")
            else:
                self.logger.warning(f"Unknown report format: {fmt}")
        
        return generated

    def run(
        self,
        domains: Optional[List[str]] = None,
        domains_file: Optional[str] = None,
        output_formats: Optional[List[str]] = None,
        max_workers: Optional[int] = None,
    ) -> List[DomainResult]:
        """
        Run complete scan and generate reports.

        Args:
            domains: List of domains to scan
            domains_file: Path to file with domains
            output_formats: Report formats to generate
            max_workers: Maximum concurrent workers

        Returns:
            List of DomainResult objects
        """
        # Collect domains
        all_domains = []
        
        if domains:
            all_domains.extend(domains)
        
        if domains_file:
            with open(domains_file, "r", encoding="utf-8") as f:
                file_domains = [
                    line.strip() 
                    for line in f 
                    if line.strip() and not line.startswith("#")
                ]
                all_domains.extend(file_domains)
        
        if not all_domains:
            self.logger.warning("No domains to scan")
            return []
        
        # Run scan
        results = self.scan_domains(all_domains, max_workers)
        
        # Generate reports
        self.generate_reports(results, output_formats)
        
        return results
