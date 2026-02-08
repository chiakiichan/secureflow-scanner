"""
SecureFlow Finding Model (MVP)

A Finding represents one security issue found during scanning.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum 
from pathlib import Path 
from typing import Optional

class Severity (Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingType(Enum):
    SECRET = "secret"


@dataclass
class Location:
    file_path: Path
    start_line: int
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

    def display(self) -> str:
        """Human-readable output for console printing"""
        loc = ""
        if self.location:
            loc = f"{self.location.file_path}:{self.location.start_line}"

        return (
            f"[{self.severity.value}] {self.title}\n"
            f" Rule: {self.rule_id}\n"
            f" Location: {loc}\n"
            f" Description: {self.description}\n"
        )
