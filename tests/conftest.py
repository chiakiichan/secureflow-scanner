"""
Pytest Configuration and Fixtures

Shared fixtures for SecureFlow tests.
"""

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from secureflow.core.config import SecureFlowConfig
from secureflow.core.finding import Finding, FindingCollection, FindingType, Location, Severity


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def config() -> SecureFlowConfig:
    """Create a default configuration."""
    return SecureFlowConfig()


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        rule_id="SF-TEST-001",
        title="Test Finding",
        description="This is a test finding for unit tests",
        severity=Severity.HIGH,
        finding_type=FindingType.SECRET,
        scanner="test",
        location=Location(
            file_path=Path("test/file.py"),
            start_line=10,
            snippet="api_key = 'secret123'",
        ),
        cwe_id="CWE-798",
    )


@pytest.fixture
def sample_findings() -> FindingCollection:
    """Create a collection of sample findings."""
    findings = [
        Finding(
            rule_id="SF-TEST-001",
            title="Critical Secret",
            description="Critical severity finding",
            severity=Severity.CRITICAL,
            finding_type=FindingType.SECRET,
            scanner="secrets",
        ),
        Finding(
            rule_id="SF-TEST-002",
            title="High Vulnerability",
            description="High severity finding",
            severity=Severity.HIGH,
            finding_type=FindingType.VULNERABILITY,
            scanner="dependencies",
        ),
        Finding(
            rule_id="SF-TEST-003",
            title="Medium Issue",
            description="Medium severity finding",
            severity=Severity.MEDIUM,
            finding_type=FindingType.MISCONFIGURATION,
            scanner="iac",
        ),
        Finding(
            rule_id="SF-TEST-004",
            title="Low Warning",
            description="Low severity finding",
            severity=Severity.LOW,
            finding_type=FindingType.CONTAINER,
            scanner="docker",
        ),
    ]
    return FindingCollection(findings)


@pytest.fixture
def secrets_test_file(temp_dir: Path) -> Path:
    """Create a test file with secrets."""
    test_file = temp_dir / "secrets.py"
    test_file.write_text('''
# Test file with various secrets

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

API_KEY = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

DATABASE_URL = "postgresql://user:password123@localhost/db"

# This should not be flagged (example)
# API_KEY = "your-api-key-here"
''')
    return test_file


@pytest.fixture
def requirements_file(temp_dir: Path) -> Path:
    """Create a test requirements.txt file."""
    req_file = temp_dir / "requirements.txt"
    req_file.write_text('''# Test requirements
requests==2.25.0
django==3.1.0
flask==1.0.0
pyyaml==5.3.1
''')
    return req_file


@pytest.fixture
def dockerfile(temp_dir: Path) -> Path:
    """Create a test Dockerfile."""
    dockerfile = temp_dir / "Dockerfile"
    dockerfile.write_text('''FROM python:latest
RUN apt-get update && apt-get install -y curl
RUN curl http://example.com/script.sh | bash
ENV API_KEY=secret123
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
''')
    return dockerfile


@pytest.fixture
def terraform_file(temp_dir: Path) -> Path:
    """Create a test Terraform file."""
    tf_file = temp_dir / "main.tf"
    tf_file.write_text('''
resource "aws_security_group" "bad_example" {
  name = "open-to-world"
  
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_db_instance" "bad_rds" {
  identifier = "my-db"
  publicly_accessible = true
  storage_encrypted = false
}
''')
    return tf_file


@pytest.fixture
def policy_file(temp_dir: Path) -> Path:
    """Create a test policy file."""
    policy = temp_dir / "policy.yaml"
    policy.write_text('''
version: "1.0"
name: "Test Policy"

settings:
  fail_on_severity: HIGH
  default_action: warn

rules:
  - id: block_critical
    severity: CRITICAL
    action: fail
    
  - id: block_high
    severity: HIGH
    action: fail
    
  - id: allow_test_files
    file_patterns:
      - ".*test.*"
    action: allow
    priority: 100
    
  - id: suppress_info
    severity: INFO
    action: suppress
''')
    return policy
