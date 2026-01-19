"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.domain import DomainResult
from .base import BaseReporter


class JSONReporter(BaseReporter):
    """Generate JSON reports."""

    format_name = "json"
    extension = ".json"

    def generate(self, results: List[DomainResult], filename: Optional[str] = None) -> Path:
        """
        Generate JSON report.

        Args:
            results: List of DomainResult objects
            filename: Optional custom filename

        Returns:
            Path to generated report
        """
        if not filename:
            filename = self.generate_filename()
        
        report = self._build_report(results)
        content = json.dumps(report, indent=2, default=str, ensure_ascii=False)
        
        return self.save(content, filename)

    def _build_report(self, results: List[DomainResult]) -> Dict[str, Any]:
        """
        Build report structure.

        Args:
            results: List of DomainResult objects

        Returns:
            Report dictionary
        """
        # Calculate summary statistics
        total_findings = sum(len(r.findings) for r in results)
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for result in results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
        
        return {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "tool": "Domain Intelligence",
                "version": "1.0.0",
            },
            "summary": {
                "total_domains": len(results),
                "total_findings": total_findings,
                "severity_breakdown": severity_counts,
                "domains_with_issues": sum(
                    1 for r in results 
                    if any(f.severity.value in ("critical", "high", "medium") for f in r.findings)
                ),
            },
            "results": [r.to_dict() for r in results],
        }
