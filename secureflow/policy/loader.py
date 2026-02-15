"""
SecureFlow Policy Loader

Loads security policies from YAML files.
Policies define rules for how findings should be handled:
  - fail: block the pipeline
  - warn: report but don't block
  - allow: suppress the finding
  - suppress: hide the finding entirely
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class PolicyRule:
    """A single policy rule."""

    id: str
    action: str = "warn"  # fail, warn, allow, suppress
    severity: Optional[str] = None
    file_patterns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    priority: int = 0


@dataclass
class PolicySettings:
    """Global policy settings."""

    fail_on_severity: str = "HIGH"
    default_action: str = "warn"


@dataclass
class Policy:
    """A complete security policy."""

    version: str = "1.0"
    name: str = "Default Policy"
    settings: PolicySettings = field(default_factory=PolicySettings)
    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def load(cls, policy_path: Path) -> "Policy":
        """Load a policy from a YAML file."""
        if not policy_path.exists():
            return cls()

        try:
            with open(policy_path) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            return cls()

        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict) -> "Policy":
        settings_data = data.get("settings", {})
        settings = PolicySettings(
            fail_on_severity=settings_data.get("fail_on_severity", "HIGH"),
            default_action=settings_data.get("default_action", "warn"),
        )

        rules = []
        for rule_data in data.get("rules", []):
            rules.append(
                PolicyRule(
                    id=rule_data.get("id", "unknown"),
                    action=rule_data.get("action", "warn"),
                    severity=rule_data.get("severity"),
                    file_patterns=rule_data.get("file_patterns", []),
                    tags=rule_data.get("tags", []),
                    rule_ids=rule_data.get("rule_ids", []),
                    priority=rule_data.get("priority", 0),
                )
            )

        return cls(
            version=data.get("version", "1.0"),
            name=data.get("name", "Default Policy"),
            settings=settings,
            rules=rules,
        )
