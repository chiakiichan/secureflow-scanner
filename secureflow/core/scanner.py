"""
SecureFlow Base Scanner (MVP)

A scanner is a component that inspects files and returns security findings.

Example scanners:
- SecretsScanner
- DependencyScanner
- DockerScanner (later)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from secureflow.core.finding import Finding

class BaseScanner(ABC):
    """
    Minimal scanner interface.
    Each scanner must implement scan().
    """

    name: str = "base"

    def __init__(self, target_path: Path, exclude: list[str]=None):
        self.target_path = target_path
        self.exclude = exclude or []

    @abstractmethod
    def scan(self) -> List[Finding]:
        """
        Run the scan and return findings.
        """
        raise NotImplementedError