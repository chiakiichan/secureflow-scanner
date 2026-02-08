"""
Secrets Scanner (MVP)

Detects basic hardcoded secrets using regex patterns.
First scanner in SecureFlow-Scanner.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from secureflow.core.finding import Finding, Severity, FindingType, Location
from secureflow.core.scanner import BaseScanner

class SecretsScanner(BaseScanner):
    """
    Minimal secrets scanner.
    Detects:
    - AWS Keys
    -GitHub tokens
    """

    name = "secrets"

    PATTERNS = [
        ("SF-SEC-001", "AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
        ("SF-SEC-002", "GitHub Token", r"ghp_[A-Za-z0-9]{36}", Severity.CRITICAL),
    ]

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for file_path in self.target_path.rglob("*.py"):

            if any(ex in str(file_path) for ex in self.exclude):
                continue

            try:
                lines = file_path.read_text(errors="ignore").splitlines()
            except Exception:
                continue

            for line_no, line in enumerate(lines, start=1):
                for rule_id, title, pattern, severity in self.PATTERNS:
                    if re.search(pattern, line):
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                title=title,
                                description=f"Possible secret detected: {title}",
                                severity=severity,
                                finding_type=FindingType.SECRET,
                                scanner=self.name,
                                location=Location(
                                    file_path=file_path,
                                    start_line=line_no,
                                    snippet=line.strip(),
                                ),
                            )
                        )

        return findings