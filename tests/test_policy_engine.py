"""
Tests for Policy Engine
"""

from pathlib import Path

import pytest

from secureflow.core.finding import Finding, FindingCollection, FindingType, Severity
from secureflow.policy.engine import PolicyAction, PolicyEngine, PolicyRule
from secureflow.policy.loader import PolicyLoader, PolicyValidationError


class TestPolicyRule:
    """Tests for PolicyRule."""
    
    def test_rule_from_dict(self):
        """Test creating rule from dictionary."""
        data = {
            "id": "test-rule",
            "description": "Test rule",
            "severity": "HIGH",
            "action": "fail",
        }
        
        rule = PolicyRule.from_dict(data)
        
        assert rule.id == "test-rule"
        assert rule.severity == Severity.HIGH
        assert rule.action == PolicyAction.FAIL
    
    def test_rule_matches_severity(self, sample_finding: Finding):
        """Test rule matching by severity."""
        rule = PolicyRule(
            id="test",
            severity=Severity.HIGH,
            action=PolicyAction.FAIL,
        )
        
        assert rule.matches(sample_finding)
        
        sample_finding.severity = Severity.MEDIUM
        assert not rule.matches(sample_finding)
    
    def test_rule_matches_min_severity(self, sample_finding: Finding):
        """Test rule matching by minimum severity."""
        rule = PolicyRule(
            id="test",
            min_severity=Severity.MEDIUM,
            action=PolicyAction.FAIL,
        )
        
        sample_finding.severity = Severity.HIGH
        assert rule.matches(sample_finding)
        
        sample_finding.severity = Severity.LOW
        assert not rule.matches(sample_finding)
    
    def test_rule_matches_scanner(self, sample_finding: Finding):
        """Test rule matching by scanner."""
        rule = PolicyRule(
            id="test",
            scanners=["test", "secrets"],
            action=PolicyAction.FAIL,
        )
        
        sample_finding.scanner = "test"
        assert rule.matches(sample_finding)
        
        sample_finding.scanner = "other"
        assert not rule.matches(sample_finding)
    
    def test_rule_matches_tags(self, sample_finding: Finding):
        """Test rule matching by tags."""
        rule = PolicyRule(
            id="test",
            tags=["secret", "credential"],
            action=PolicyAction.FAIL,
        )
        
        sample_finding.tags = ["secret", "other"]
        assert rule.matches(sample_finding)
        
        sample_finding.tags = ["unrelated"]
        assert not rule.matches(sample_finding)
    
    def test_rule_matches_file_pattern(self, sample_finding: Finding):
        """Test rule matching by file pattern."""
        rule = PolicyRule(
            id="test",
            file_patterns=[".*test.*", ".*spec.*"],
            action=PolicyAction.ALLOW,
        )
        
        from secureflow.core.finding import Location
        sample_finding.location = Location(
            file_path=Path("src/test_utils.py"),
            start_line=1,
        )
        assert rule.matches(sample_finding)
        
        sample_finding.location = Location(
            file_path=Path("src/main.py"),
            start_line=1,
        )
        assert not rule.matches(sample_finding)
    
    def test_disabled_rule(self, sample_finding: Finding):
        """Test disabled rule doesn't match."""
        rule = PolicyRule(
            id="test",
            severity=Severity.HIGH,
            action=PolicyAction.FAIL,
            enabled=False,
        )
        
        assert not rule.matches(sample_finding)


class TestPolicyEngine:
    """Tests for PolicyEngine."""
    
    def test_evaluate_with_no_rules(self, sample_finding: Finding):
        """Test evaluation with no rules uses default behavior."""
        engine = PolicyEngine()
        engine.set_fail_on_severity(Severity.HIGH)
        
        result = engine.evaluate(sample_finding)
        
        # HIGH severity should fail by default
        assert result.action == PolicyAction.FAIL
    
    def test_evaluate_with_matching_rule(self, sample_finding: Finding):
        """Test evaluation with matching rule."""
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            id="block-high",
            severity=Severity.HIGH,
            action=PolicyAction.FAIL,
        ))
        
        result = engine.evaluate(sample_finding)
        
        assert result.action == PolicyAction.FAIL
        assert len(result.matched_rules) == 1
        assert result.matched_rules[0].id == "block-high"
    
    def test_evaluate_priority(self, sample_finding: Finding):
        """Test rule priority is respected."""
        engine = PolicyEngine()
        
        # Add lower priority rule first
        engine.add_rule(PolicyRule(
            id="warn-high",
            severity=Severity.HIGH,
            action=PolicyAction.WARN,
            priority=10,
        ))
        
        # Add higher priority rule
        engine.add_rule(PolicyRule(
            id="allow-high",
            severity=Severity.HIGH,
            action=PolicyAction.ALLOW,
            priority=100,
        ))
        
        result = engine.evaluate(sample_finding)
        
        # Higher priority rule should win
        assert result.action == PolicyAction.ALLOW
    
    def test_evaluate_all(self, sample_findings: FindingCollection):
        """Test evaluating all findings."""
        engine = PolicyEngine()
        engine.load_rules([
            {"id": "fail-critical", "severity": "CRITICAL", "action": "fail"},
            {"id": "fail-high", "severity": "HIGH", "action": "fail"},
            {"id": "warn-medium", "severity": "MEDIUM", "action": "warn"},
            {"id": "allow-low", "severity": "LOW", "action": "allow"},
        ])
        
        summary = engine.evaluate_all(sample_findings)
        
        assert summary.total_findings == 4
        assert summary.failed >= 2  # CRITICAL and HIGH
        assert summary.warned >= 1  # MEDIUM
        assert summary.allowed >= 1  # LOW
    
    def test_should_fail_pipeline(self, sample_findings: FindingCollection):
        """Test pipeline failure detection."""
        engine = PolicyEngine()
        engine.load_rules([
            {"id": "fail-critical", "severity": "CRITICAL", "action": "fail"},
        ])
        
        summary = engine.evaluate_all(sample_findings)
        
        assert summary.should_fail_pipeline
    
    def test_get_non_suppressed_findings(self, sample_findings: FindingCollection):
        """Test filtering suppressed findings."""
        engine = PolicyEngine()
        engine.load_rules([
            {"id": "suppress-low", "severity": "LOW", "action": "suppress"},
        ])
        
        filtered = engine.get_non_suppressed_findings(sample_findings)
        
        assert len(filtered) < len(sample_findings)
        for f in filtered:
            assert f.severity != Severity.LOW


class TestPolicyLoader:
    """Tests for PolicyLoader."""
    
    def test_load_policy_file(self, policy_file: Path):
        """Test loading policy from file."""
        loader = PolicyLoader()
        engine = loader.load(policy_file)
        
        rules = engine.get_rules()
        assert len(rules) >= 3
    
    def test_create_default_policy(self):
        """Test creating default policy."""
        engine = PolicyLoader.create_default_policy()
        
        rules = engine.get_rules()
        assert len(rules) >= 5
    
    def test_validate_invalid_yaml(self, temp_dir: Path):
        """Test validation catches invalid YAML."""
        policy_file = temp_dir / "bad.yaml"
        policy_file.write_text("invalid: [yaml: content")
        
        loader = PolicyLoader()
        with pytest.raises(PolicyValidationError):
            loader.load(policy_file)
    
    def test_validate_invalid_action(self, temp_dir: Path):
        """Test validation catches invalid action."""
        policy_file = temp_dir / "bad.yaml"
        policy_file.write_text('''
version: "1.0"
rules:
  - id: bad-rule
    action: invalid_action
''')
        
        loader = PolicyLoader()
        with pytest.raises(PolicyValidationError):
            loader.load(policy_file)
    
    def test_validate_missing_id(self, temp_dir: Path):
        """Test validation catches missing rule ID."""
        policy_file = temp_dir / "bad.yaml"
        policy_file.write_text('''
version: "1.0"
rules:
  - action: fail
    severity: HIGH
''')
        
        loader = PolicyLoader()
        with pytest.raises(PolicyValidationError):
            loader.load(policy_file)
    
    def test_generate_example_policy(self):
        """Test example policy generation."""
        content = PolicyLoader.generate_example_policy()
        
        assert "version" in content
        assert "rules:" in content
        assert "action: fail" in content
