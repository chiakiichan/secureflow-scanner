"""
SecureFlow Policy Evaluation Engine

Evaluates findings against policy rules to determine:
- Which findings should fail the pipeline
- Which should be warnings
- Which should be allowed/suppressed

Rules are matched by severity, file patterns, tags, and rule IDs.
Higher-priority rules take precedence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from secureflow.core.finding import Finding, Severity
from secureflow.policy.loader import Policy, PolicyRule


@dataclass
class PolicyResult:
    """Result of evaluating findings against a policy."""

    findings: list[Finding] = field(default_factory=list)
    failed: list[Finding] = field(default_factory=list)
    warned: list[Finding] = field(default_factory=list)
    allowed: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    should_fail: bool = False


class PolicyEngine:
    """
    Evaluates security findings against a policy.
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        # Sort rules by priority (highest first)
        self._rules = sorted(policy.rules, key=lambda r: r.priority, reverse=True)

    def evaluate(
        self,
        findings: list[Finding],
        fail_on: Optional[str] = None,
    ) -> PolicyResult:
        """
        Evaluate a list of findings against the policy.

        Args:
            findings: List of findings to evaluate.
            fail_on: Override severity threshold for failing the pipeline.

        Returns:
            PolicyResult with categorized findings.
        """
        result = PolicyResult(findings=list(findings))

        # Determine fail threshold
        fail_severity = Severity.from_string(
            fail_on or self.policy.settings.fail_on_severity
        )

        for finding in findings:
            action = self._match_action(finding)

            if action == "suppress":
                result.suppressed.append(finding)
            elif action == "allow":
                result.allowed.append(finding)
            elif action == "fail" or finding.severity >= fail_severity:
                result.failed.append(finding)
                result.should_fail = True
            else:
                result.warned.append(finding)

        return result

    def _match_action(self, finding: Finding) -> str:
        """
        Find the highest-priority matching rule for a finding.
        Returns the action string, or the default action if no rule matches.
        """
        for rule in self._rules:
            if self._rule_matches(rule, finding):
                return rule.action

        return self.policy.settings.default_action

    @staticmethod
    def _rule_matches(rule: PolicyRule, finding: Finding) -> bool:
        """Check if a policy rule matches a finding."""
        # Check severity match
        if rule.severity:
            if finding.severity.value != rule.severity:
                return False

        # Check file pattern match
        if rule.file_patterns:
            if not finding.location:
                return False
            file_str = str(finding.location.file_path)
            if not any(
                re.search(pattern, file_str) for pattern in rule.file_patterns
            ):
                return False

        # Check tags match
        if rule.tags:
            if not any(tag in finding.tags for tag in rule.tags):
                return False

        # Check rule ID match
        if rule.rule_ids:
            if finding.rule_id not in rule.rule_ids:
                return False

        return True
