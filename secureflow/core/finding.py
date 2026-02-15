"""
SecureFlow Finding Model

A Finding represents one security issue found during scanning.
Supports secrets, dependencies, Docker, and IaC findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse a severity from a string (case-insensitive)."""
        return cls[value.upper()]

    def __ge__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return not self.__gt__(other)

    def __lt__(self, other: "Severity") -> bool:
        return not self.__ge__(other)


class FindingType(Enum):
    SECRET = "secret"
    DEPENDENCY = "dependency"
    DOCKER = "docker"
    IAC = "iac"


@dataclass
class Location:
    file_path: Path
    start_line: int
    end_line: Optional[int] = None
    snippet: Optional[str] = None


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    finding_type: FindingType
    scanner: str
    location: Optional[Location] = None
    fix: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def display(self) -> str:
        """Human-readable output for console printing."""
        loc = ""
        if self.location:
            loc = f"{self.location.file_path}:{self.location.start_line}"

        parts = [
            f"[{self.severity.value}] {self.title}",
            f"  Rule: {self.rule_id}",
            f"  Location: {loc}",
            f"  {self.description}",
        ]
        if self.fix:
            parts.append(f"  Fix: {self.fix}")
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to a dictionary for JSON serialization."""
        result: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "finding_type": self.finding_type.value,
            "scanner": self.scanner,
        }
        if self.location:
            result["location"] = {
                "file": str(self.location.file_path),
                "start_line": self.location.start_line,
                "end_line": self.location.end_line,
                "snippet": self.location.snippet,
            }
        if self.fix:
            result["fix"] = self.fix
        if self.metadata:
            result["metadata"] = self.metadata
        if self.tags:
            result["tags"] = self.tags
        return result
