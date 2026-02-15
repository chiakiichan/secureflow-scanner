"""
Tests for Reporting Module
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from secureflow.core.finding import FindingCollection
from secureflow.core.scanner import ScanResult
from secureflow.policy.engine import PolicyEvaluationSummary
from secureflow.reporting.base import ReportMetadata
from secureflow.reporting.console import ConsoleReporter
from secureflow.reporting.json_reporter import JSONReporter
from secureflow.reporting.sarif import SARIFReporter


class TestConsoleReporter:
    """Tests for ConsoleReporter."""
    
    def test_format_name(self):
        """Test reporter format name."""
        reporter = ConsoleReporter()
        assert reporter.format_name == "console"
    
    def test_generate_empty_report(self):
        """Test generating report with no findings."""
        reporter = ConsoleReporter(no_color=True)
        findings = FindingCollection()
        scan_results = []
        
        content = reporter.generate(findings, scan_results)
        
        assert "SecureFlow" in content
        assert "No security issues found" in content
    
    def test_generate_report_with_findings(self, sample_findings: FindingCollection):
        """Test generating report with findings."""
        reporter = ConsoleReporter(no_color=True)
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        content = reporter.generate(sample_findings, [scan_result])
        
        assert "CRITICAL" in content
        assert "HIGH" in content
        assert "Detailed Findings" in content
    
    def test_no_color_mode(self):
        """Test no-color mode strips ANSI codes."""
        reporter = ConsoleReporter(no_color=True)
        
        # Check that colorize returns plain text
        text = reporter._colorize("test", "\033[31m")
        assert "\033[" not in text


class TestJSONReporter:
    """Tests for JSONReporter."""
    
    def test_format_name(self):
        """Test reporter format name."""
        reporter = JSONReporter()
        assert reporter.format_name == "json"
    
    def test_generate_valid_json(self, sample_findings: FindingCollection):
        """Test generating valid JSON."""
        reporter = JSONReporter()
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        content = reporter.generate(sample_findings, [scan_result])
        
        # Should be valid JSON
        data = json.loads(content)
        
        assert "version" in data
        assert "findings" in data
        assert "summary" in data
        assert len(data["findings"]) == len(sample_findings)
    
    def test_generate_with_metadata(self, sample_findings: FindingCollection):
        """Test generating JSON with metadata."""
        reporter = JSONReporter()
        
        metadata = ReportMetadata(
            tool_name="SecureFlow",
            tool_version="1.0.0",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            target_path=Path("/test/path"),
            scanners_run=["secrets", "dependencies"],
        )
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        content = reporter.generate(sample_findings, [scan_result], metadata=metadata)
        data = json.loads(content)
        
        assert data["metadata"]["tool"]["name"] == "SecureFlow"
        assert data["metadata"]["scanners"] == ["secrets", "dependencies"]
    
    def test_exit_code_calculation(self, sample_findings: FindingCollection):
        """Test exit code is calculated correctly."""
        reporter = JSONReporter()
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        content = reporter.generate(sample_findings, [scan_result])
        data = json.loads(content)
        
        # Should fail due to HIGH/CRITICAL findings
        assert data["exit_code"] == 1


class TestSARIFReporter:
    """Tests for SARIFReporter."""
    
    def test_format_name(self):
        """Test reporter format name."""
        reporter = SARIFReporter()
        assert reporter.format_name == "sarif"
    
    def test_generate_valid_sarif(self, sample_findings: FindingCollection):
        """Test generating valid SARIF."""
        reporter = SARIFReporter()
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        content = reporter.generate(sample_findings, [scan_result])
        data = json.loads(content)
        
        # Verify SARIF structure
        assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1
        
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run
    
    def test_sarif_tool_component(self, sample_findings: FindingCollection):
        """Test SARIF tool component."""
        reporter = SARIFReporter()
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        content = reporter.generate(sample_findings, [scan_result])
        data = json.loads(content)
        
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "SecureFlow"
        assert "rules" in tool
    
    def test_sarif_results(self, sample_findings: FindingCollection):
        """Test SARIF results contain required fields."""
        reporter = SARIFReporter()
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        content = reporter.generate(sample_findings, [scan_result])
        data = json.loads(content)
        
        results = data["runs"][0]["results"]
        assert len(results) == len(sample_findings)
        
        for result in results:
            assert "ruleId" in result
            assert "level" in result
            assert "message" in result
    
    def test_sarif_severity_mapping(self):
        """Test severity to SARIF level mapping."""
        from secureflow.core.finding import Severity
        
        reporter = SARIFReporter()
        
        assert reporter._severity_to_level(Severity.CRITICAL) == "error"
        assert reporter._severity_to_level(Severity.HIGH) == "error"
        assert reporter._severity_to_level(Severity.MEDIUM) == "warning"
        assert reporter._severity_to_level(Severity.LOW) == "note"
        assert reporter._severity_to_level(Severity.INFO) == "note"
    
    def test_write_to_file(self, sample_findings: FindingCollection, temp_dir: Path):
        """Test writing SARIF to file."""
        output_path = temp_dir / "results.sarif"
        reporter = SARIFReporter(output_path)
        
        scan_result = ScanResult(
            scanner_name="test",
            findings=sample_findings,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
        )
        
        reporter.write(sample_findings, [scan_result])
        
        assert output_path.exists()
        content = output_path.read_text()
        data = json.loads(content)
        assert data["version"] == "2.1.0"
