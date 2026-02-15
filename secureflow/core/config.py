"""
SecureFlow Configuration Management

Loads and manages configuration from .secureflow.yaml files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


CONFIG_FILENAME = ".secureflow.yaml"

DEFAULT_EXCLUDE_PATHS = [
    "node_modules",
    ".git",
    "__pycache__",
    "venv",
    ".venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
    "*.egg-info",
]


@dataclass
class ScannerConfig:
    enabled: bool = True
    exclude_patterns: list[str] = field(default_factory=list)


@dataclass
class OutputConfig:
    format: str = "console"
    file: Optional[str] = None


@dataclass
class PolicyConfig:
    file: Optional[str] = None
    fail_on_severity: str = "HIGH"


@dataclass
class SecureFlowConfig:
    """Root configuration object for SecureFlow."""

    output: OutputConfig = field(default_factory=OutputConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    exclude_paths: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS))

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "SecureFlowConfig":
        """Load configuration from a YAML file, falling back to defaults."""
        if config_path is None:
            # Search in current directory
            config_path = Path.cwd() / CONFIG_FILENAME

        if not config_path.exists():
            return cls._default()

        try:
            with open(config_path) as f:
                raw = yaml.safe_load(f) or {}
        except Exception:
            return cls._default()

        return cls._from_dict(raw)

    @classmethod
    def _default(cls) -> "SecureFlowConfig":
        """Return default configuration."""
        return cls(
            scanners={
                "secrets": ScannerConfig(),
                "dependencies": ScannerConfig(),
                "docker": ScannerConfig(),
                "iac": ScannerConfig(),
            }
        )

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "SecureFlowConfig":
        """Build config from a parsed YAML dictionary."""
        output_data = data.get("output", {})
        output = OutputConfig(
            format=output_data.get("format", "console"),
            file=output_data.get("file"),
        )

        policy_data = data.get("policy", {})
        policy = PolicyConfig(
            file=policy_data.get("file"),
            fail_on_severity=policy_data.get("fail_on_severity", "HIGH"),
        )

        scanners: dict[str, ScannerConfig] = {}
        scanners_data = data.get("scanners", {})
        for name in ("secrets", "dependencies", "docker", "iac"):
            scanner_raw = scanners_data.get(name, {})
            scanners[name] = ScannerConfig(
                enabled=scanner_raw.get("enabled", True),
                exclude_patterns=scanner_raw.get("exclude_patterns", []),
            )

        exclude_paths = data.get("exclude_paths", list(DEFAULT_EXCLUDE_PATHS))

        return cls(
            output=output,
            policy=policy,
            scanners=scanners,
            exclude_paths=exclude_paths,
        )


def generate_default_config() -> str:
    """Generate a default .secureflow.yaml configuration file content."""
    return """\
# SecureFlow Configuration
# See https://github.com/secureflow/secureflow for documentation

# Output settings
output:
  format: console  # console, json, sarif
  # file: secureflow-report.json

# Policy settings
policy:
  file: .secureflow-policy.yaml
  fail_on_severity: HIGH

# Scanner settings
scanners:
  secrets:
    enabled: true
    exclude_patterns:
      - "*.test.js"
      - "*_test.py"

  dependencies:
    enabled: true

  docker:
    enabled: true

  iac:
    enabled: true

# Global exclusions
exclude_paths:
  - node_modules
  - .git
  - __pycache__
  - venv
"""


def generate_default_policy() -> str:
    """Generate a default .secureflow-policy.yaml file content."""
    return """\
# SecureFlow Security Policy
version: "1.0"
name: "Default Security Policy"

settings:
  fail_on_severity: HIGH
  default_action: warn

rules:
  # Block all critical findings
  - id: block_critical
    severity: CRITICAL
    action: fail

  # Block high severity findings
  - id: block_high
    severity: HIGH
    action: fail

  # Allow secrets in test files
  - id: allow_test_secrets
    file_patterns:
      - ".*test.*"
      - ".*spec.*"
    tags:
      - secret
    action: allow
    priority: 100

  # Suppress info findings
  - id: suppress_info
    severity: INFO
    action: suppress
"""
