"""
SecureFlow JSON Reporter

Generates machine-readable JSON output format:
{
    "version": "1.0",
    "summary": {
        "total_findings": N,
        "by_severity": {"CRITICAL": n, "HIGH": n, ...}
    },
    "findings": [...]
}
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Optional

from secureflow import __version__
from secureflow.core.finding import Finding


class JSONReporter:
    """Generates JSON-formatted scan reports."""

    def __init__(self, target: str) -> None:
        self.target = target

    def report(
        self,
        findings: list[Finding],
        output_file: Optional[str] = None,
    ) -> str:
        """
        Generate JSON report.

        Args:
            findings: All findings from all scanners.
            output_file: Optional file path to write the report to.

        Returns:
            The JSON string.
        """
        counter = Counter(f.severity.value for f in findings)

        report_data = {
            "version": "1.0",
            "tool": {
                "name": "SecureFlow",
                "version": __version__,
            },
            "target": self.target,
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    sev: counter.get(sev, 0)
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                },
                "by_scanner": dict(Counter(f.scanner for f in findings)),
            },
            "findings": [f.to_dict() for f in findings],
        }

        json_str = json.dumps(report_data, indent=2, default=str)

        if output_file:
            Path(output_file).write_text(json_str, encoding="utf-8")

        return json_str
