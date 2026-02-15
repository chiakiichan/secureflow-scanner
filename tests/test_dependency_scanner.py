"""
Tests for Dependency Scanner
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secureflow.core.config import SecureFlowConfig
from secureflow.scanners.dependencies import DependencyScanner, Dependency


class TestDependencyScanner:
    """Tests for DependencyScanner."""
    
    def test_scanner_name(self, config: SecureFlowConfig):
        """Test scanner has correct name."""
        scanner = DependencyScanner(config)
        assert scanner.name == "dependencies"
    
    def test_supports_requirements_txt(self, config: SecureFlowConfig):
        """Test scanner supports requirements.txt."""
        scanner = DependencyScanner(config)
        assert scanner.supports_file(Path("requirements.txt"))
        assert scanner.supports_file(Path("requirements-dev.txt"))
        assert scanner.supports_file(Path("test-requirements.txt"))
    
    def test_supports_package_json(self, config: SecureFlowConfig):
        """Test scanner supports package.json."""
        scanner = DependencyScanner(config)
        assert scanner.supports_file(Path("package.json"))
        assert scanner.supports_file(Path("package-lock.json"))
    
    def test_supports_go_mod(self, config: SecureFlowConfig):
        """Test scanner supports go.mod."""
        scanner = DependencyScanner(config)
        assert scanner.supports_file(Path("go.mod"))
    
    def test_does_not_support_random_files(self, config: SecureFlowConfig):
        """Test scanner doesn't support random files."""
        scanner = DependencyScanner(config)
        assert not scanner.supports_file(Path("random.py"))
        assert not scanner.supports_file(Path("config.yaml"))
    
    def test_parse_requirements_txt(self, config: SecureFlowConfig, temp_dir: Path):
        """Test parsing requirements.txt."""
        req_file = temp_dir / "requirements.txt"
        req_file.write_text('''
# Comment
requests==2.28.0
django>=4.0.0
flask~=2.0.0
numpy
# Another comment
pandas==1.5.0
''')
        
        scanner = DependencyScanner(config)
        deps = scanner._parse_requirements_txt(req_file)
        
        assert len(deps) >= 3  # requests, django, flask, pandas (numpy has no version)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "django" in names
        assert "flask" in names
    
    def test_parse_package_json(self, config: SecureFlowConfig, temp_dir: Path):
        """Test parsing package.json."""
        pkg_file = temp_dir / "package.json"
        pkg_file.write_text('''
{
    "name": "test-project",
    "dependencies": {
        "express": "^4.18.0",
        "lodash": "4.17.21"
    },
    "devDependencies": {
        "jest": "^29.0.0"
    }
}
''')
        
        scanner = DependencyScanner(config)
        deps = scanner._parse_package_json(pkg_file)
        
        assert len(deps) == 3
        names = [d.name for d in deps]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names
    
    def test_parse_go_mod(self, config: SecureFlowConfig, temp_dir: Path):
        """Test parsing go.mod."""
        go_file = temp_dir / "go.mod"
        go_file.write_text('''
module example.com/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.4
)

require github.com/go-sql-driver/mysql v1.7.0
''')
        
        scanner = DependencyScanner(config)
        deps = scanner._parse_go_mod(go_file)
        
        assert len(deps) >= 2
        names = [d.name for d in deps]
        assert any("gin" in n for n in names)
    
    def test_dependency_to_osv_query(self, config: SecureFlowConfig):
        """Test converting dependency to OSV query format."""
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="PyPI",
            source_file=Path("requirements.txt"),
        )
        
        query = dep.to_osv_query()
        
        assert query["package"]["name"] == "requests"
        assert query["package"]["ecosystem"] == "PyPI"
        assert query["version"] == "2.28.0"
    
    @patch('secureflow.scanners.dependencies.urlopen')
    def test_query_osv_batch(self, mock_urlopen, config: SecureFlowConfig):
        """Test batch querying OSV API."""
        # Mock response
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"results": [{"vulns": []}]}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        
        scanner = DependencyScanner(config)
        deps = [
            Dependency(
                name="requests",
                version="2.28.0",
                ecosystem="PyPI",
                source_file=Path("requirements.txt"),
            )
        ]
        
        results = scanner._query_osv_batch(deps)
        
        # Should return empty dict (no vulnerabilities)
        assert len(results) == 0
    
    def test_finding_creation(self, config: SecureFlowConfig):
        """Test vulnerability finding creation."""
        from secureflow.scanners.dependencies import Vulnerability
        
        scanner = DependencyScanner(config)
        
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="PyPI",
            source_file=Path("requirements.txt"),
            line_number=5,
        )
        
        vuln = Vulnerability(
            id="GHSA-test-1234",
            summary="Test vulnerability",
            details="Detailed description",
            severity=Severity.HIGH,
            aliases=["CVE-2023-1234"],
            affected_versions=["2.28.0"],
            fixed_version="2.28.1",
            references=["https://example.com"],
        )
        
        finding = scanner._create_vulnerability_finding(dep, vuln, Path("requirements.txt"))
        
        assert finding.rule_id == "SF-DEP-GHSA-test-1234"
        assert "requests" in finding.title
        assert finding.severity == Severity.HIGH
        assert finding.cve_id == "CVE-2023-1234"


# Import at module level for the test
from secureflow.core.finding import Severity
