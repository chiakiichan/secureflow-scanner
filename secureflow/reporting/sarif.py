"""
SecureFlow SARIF Reporter

Generates SARIF 2.1.0 (Static Analysis Results Interchange Format) output
for integration with:
- GitHub Code Scanning / Security tab
- Azure DevOps
- Visual Studio / VSCode
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from secureflow import __version__
from secureflow.core.finding import Finding, Severity


# SARIF severity level mapping
SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SARIFReporter:
    """Generates SARIF 2.1.0-formatted scan reports."""

    def __init__(self, target: str) -> None:
        self.target = target

    def report(
        self,
        findings: list[Finding],
        output_file: Optional[str] = None,
    ) -> str:
        """
        Generate SARIF report.

        Args:
            findings: All findings from all scanners.
            output_file: Optional file path to write the report to.

        Returns:
            The SARIF JSON string.
        """
        # Collect unique rules
        rules_map: dict[str, dict] = {}
        results: list[dict] = []

        for finding in findings:
            # Build rule if not seen
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": SARIF_LEVEL_MAP.get(finding.severity, "warning")
                    },
                    "properties": {
                        "security-severity": self._severity_score(finding.severity),
                        "tags": finding.tags,
                    },
                }
                if finding.fix:
                    rules_map[finding.rule_id]["help"] = {
                        "text": finding.fix,
                        "markdown": f"**Fix:** {finding.fix}",
                    }

            # Build result
            result: dict = {
                "ruleId": finding.rule_id,
                "ruleIndex": list(rules_map.keys()).index(finding.rule_id),
                "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                "message": {"text": finding.description},
            }

            if finding.location:
                file_path = str(finding.location.file_path).replace("\\", "/")
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, finding.location.start_line),
                                "startColumn": 1,
                            },
                        }
                    }
                ]

            if finding.fix:
                result["fixes"] = [
                    {
                        "description": {"text": finding.fix},
                    }
                ]

            results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureFlow",
                            "version": __version__,
                            "informationUri": "https://github.com/secureflow/secureflow",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                    "columnKind": "utf16CodeUnits",
                }
            ],
        }

        sarif_str = json.dumps(sarif, indent=2, default=str)

        if output_file:
            Path(output_file).write_text(sarif_str, encoding="utf-8")

        return sarif_str

    @staticmethod
    def _severity_score(severity: Severity) -> str:
        """Map severity to a numeric score string for SARIF properties."""
        scores = {
            Severity.CRITICAL: "9.5",
            Severity.HIGH: "7.5",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "2.5",
            Severity.INFO: "1.0",
        }
        return scores.get(severity, "5.0")
