#!/usr/bin/env python3
"""
Domain Intelligence - CLI Interface

A security tool for automated external asset discovery and threat assessment.
"""

import argparse
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.scanner import Scanner
from src.core.config import Config
from src.core.logger import setup_logger


def print_banner():
    """Print application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║           Domain Intelligence v1.0.0                      ║
    ║     External Asset Discovery & Threat Assessment          ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_summary(results):
    """Print scan summary to console."""
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    
    total_findings = sum(len(r.findings) for r in results)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity.value] += 1
    
    print(f"\nDomains Scanned: {len(results)}")
    print(f"Total Findings:  {total_findings}")
    print(f"\nBy Severity:")
    print(f"  🔴 Critical: {severity_counts['critical']}")
    print(f"  🟠 High:     {severity_counts['high']}")
    print(f"  🟡 Medium:   {severity_counts['medium']}")
    print(f"  🔵 Low:      {severity_counts['low']}")
    print(f"  ⚪ Info:     {severity_counts['info']}")
    
    # Show domains with issues
    issues = [(r.domain, r.severity_score) for r in results if r.severity_score > 0]
    if issues:
        print(f"\nDomains with Issues:")
        for domain, score in sorted(issues, key=lambda x: x[1], reverse=True)[:10]:
            print(f"  • {domain} (Score: {score})")
    
    print("\n" + "=" * 60)


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="domain_intel",
        description="Domain Intelligence - External Asset Discovery & Threat Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single domain
  python cli.py --domain example.com

  # Scan multiple domains
  python cli.py --domain example.com --domain example.org

  # Scan domains from a file
  python cli.py --input domains.txt

  # Generate specific report formats
  python cli.py --domain example.com --output json html

  # Use custom config file
  python cli.py --domain example.com --config custom_config.yaml

  # Verbose output
  python cli.py --domain example.com -v
        """
    )
    
    # Input options
    input_group = parser.add_argument_group("Input Options")
    input_group.add_argument(
        "-d", "--domain",
        action="append",
        dest="domains",
        metavar="DOMAIN",
        help="Domain to scan (can be specified multiple times)",
    )
    input_group.add_argument(
        "-i", "--input",
        dest="input_file",
        metavar="FILE",
        help="File containing domains to scan (one per line)",
    )
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        nargs="+",
        choices=["json", "csv", "html"],
        default=["json", "csv", "html"],
        help="Output formats (default: json csv html)",
    )
    output_group.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Output directory for reports",
    )
    
    # Configuration options
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "-c", "--config",
        dest="config_file",
        metavar="FILE",
        help="Path to config.yaml file",
    )
    config_group.add_argument(
        "--env",
        dest="env_file",
        metavar="FILE",
        help="Path to .env.local file with API keys",
    )
    
    # Execution options
    exec_group = parser.add_argument_group("Execution Options")
    exec_group.add_argument(
        "-w", "--workers",
        type=int,
        default=5,
        metavar="N",
        help="Number of concurrent workers (default: 5)",
    )
    exec_group.add_argument(
        "--no-ct",
        action="store_true",
        help="Skip Certificate Transparency enumeration",
    )
    exec_group.add_argument(
        "--no-whois",
        action="store_true",
        help="Skip WHOIS lookups",
    )
    exec_group.add_argument(
        "--no-ssllabs",
        action="store_true",
        help="Skip SSL Labs assessments",
    )
    exec_group.add_argument(
        "--no-threat-intel",
        action="store_true",
        help="Skip threat intelligence lookups",
    )
    
    # General options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and summary",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Domain Intelligence v1.0.0",
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate inputs
    if not args.domains and not args.input_file:
        parser.error("Please specify at least one domain (-d) or input file (-i)")
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    try:
        # Initialize config
        config = Config(
            config_path=args.config_file,
            env_path=args.env_file,
        )
        
        # Apply CLI overrides
        if args.no_ct:
            config._config.setdefault("modules", {}).setdefault("ct_enumeration", {})["enabled"] = False
        if args.no_whois:
            config._config.setdefault("modules", {}).setdefault("whois_lookup", {})["enabled"] = False
        if args.no_ssllabs:
            config._config.setdefault("modules", {}).setdefault("ssllabs", {})["enabled"] = False
        if args.no_threat_intel:
            for ti_module in ["abuseipdb", "alienvault_otx", "virustotal", "urlscan"]:
                config._config.setdefault("modules", {}).setdefault("threat_intel", {}).setdefault(ti_module, {})["enabled"] = False
        
        # Set log level
        if args.verbose:
            config._config.setdefault("logging", {})["level"] = "DEBUG"
        
        # Initialize scanner
        scanner = Scanner(config=config)
        
        # Collect domains
        domains = []
        if args.domains:
            domains.extend(args.domains)
        
        if args.input_file:
            with open(args.input_file, "r", encoding="utf-8") as f:
                file_domains = [
                    line.strip() 
                    for line in f 
                    if line.strip() and not line.startswith("#")
                ]
                domains.extend(file_domains)
        
        # Remove duplicates
        domains = list(set(domains))
        
        if not args.quiet:
            print(f"\nScanning {len(domains)} domain(s)...\n")
        
        # Run scan
        results = scanner.scan_domains(domains, max_workers=args.workers)
        
        # Generate reports
        report_paths = scanner.generate_reports(results, args.output)
        
        # Print summary
        if not args.quiet:
            print_summary(results)
            
            print("\n Reports generated:")
            for path in report_paths:
                print(f"   • {path}")
            print()
        
        # Exit with appropriate code
        critical_count = sum(
            1 for r in results 
            for f in r.findings 
            if f.severity.value == "critical"
        )
        
        if critical_count > 0:
            sys.exit(2)  # Critical findings
        elif any(r.errors for r in results):
            sys.exit(1)  # Errors occurred
        else:
            sys.exit(0)  # Success
            
    except FileNotFoundError as e:
        print(f" Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f" Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
