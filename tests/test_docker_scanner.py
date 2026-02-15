"""
Tests for Docker Scanner
"""

from pathlib import Path

import pytest

from secureflow.core.config import SecureFlowConfig
from secureflow.core.finding import Severity
from secureflow.scanners.docker import DockerScanner


class TestDockerScanner:
    """Tests for DockerScanner."""
    
    def test_scanner_name(self, config: SecureFlowConfig):
        """Test scanner has correct name."""
        scanner = DockerScanner(config)
        assert scanner.name == "docker"
    
    def test_supports_dockerfile(self, config: SecureFlowConfig):
        """Test scanner supports Dockerfiles."""
        scanner = DockerScanner(config)
        assert scanner.supports_file(Path("Dockerfile"))
        assert scanner.supports_file(Path("Dockerfile.prod"))
        assert scanner.supports_file(Path("dockerfile"))
    
    def test_does_not_support_other_files(self, config: SecureFlowConfig):
        """Test scanner doesn't support non-Docker files."""
        scanner = DockerScanner(config)
        assert not scanner.supports_file(Path("app.py"))
        assert not scanner.supports_file(Path("docker-compose.yaml"))
    
    def test_detect_latest_tag(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of :latest tag."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text("FROM python:latest\nCMD python app.py")
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
        assert any("latest" in f.title.lower() for f in findings)
    
    def test_detect_missing_tag(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of missing tag (implies :latest)."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text("FROM python\nCMD python app.py")
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
    
    def test_detect_curl_pipe_bash(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of curl | bash pattern."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM ubuntu:22.04
RUN curl https://example.com/script.sh | bash
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
        assert any("curl" in f.title.lower() or "pipe" in f.title.lower() for f in findings)
    
    def test_detect_hardcoded_env_secret(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of hardcoded secrets in ENV."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11
ENV API_KEY=supersecretkey123
ENV DATABASE_PASSWORD=mypassword
CMD python app.py
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
        assert any("secret" in f.title.lower() or "env" in f.title.lower() for f in findings)
    
    def test_detect_running_as_root(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of container running as root."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11
COPY . /app
CMD python app.py
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
        assert any("root" in f.title.lower() for f in findings)
    
    def test_no_root_warning_with_user(self, config: SecureFlowConfig, temp_dir: Path):
        """Test no root warning when USER is specified."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11-slim
RUN adduser --disabled-password appuser
USER appuser
COPY . /app
CMD python app.py
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        # Should not have root warning
        assert not any("running as root" in f.title.lower() for f in findings)
    
    def test_detect_sudo_usage(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of sudo usage."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11
RUN sudo apt-get update
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
        assert any("sudo" in f.title.lower() for f in findings)
    
    def test_detect_chmod_777(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of chmod 777."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11
COPY . /app
RUN chmod 777 /app
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
        assert any("777" in f.description or "chmod" in f.title.lower() for f in findings)
    
    def test_detect_ssh_key_copy(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of SSH key copy."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11
COPY id_rsa /root/.ssh/id_rsa
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
    
    def test_detect_missing_healthcheck(self, config: SecureFlowConfig, temp_dir: Path):
        """Test detection of missing HEALTHCHECK."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11-slim
USER nobody
COPY . /app
CMD python app.py
''')
        
        scanner = DockerScanner(config)
        findings = scanner.scan_file(dockerfile)
        
        assert any("healthcheck" in f.title.lower() for f in findings)
    
    def test_full_scan(self, config: SecureFlowConfig, dockerfile: Path):
        """Test full Docker scan."""
        config.target_path = dockerfile.parent
        scanner = DockerScanner(config)
        result = scanner.scan()
        
        assert result.success
        assert result.finding_count > 0


class TestDockerfileRules:
    """Tests for specific Dockerfile rules."""
    
    def test_parse_dockerfile_instructions(self, config: SecureFlowConfig, temp_dir: Path):
        """Test Dockerfile instruction parsing."""
        dockerfile = temp_dir / "Dockerfile"
        dockerfile.write_text('''
FROM python:3.11
# Comment
RUN apt-get update && \
    apt-get install -y curl
COPY . /app
WORKDIR /app
CMD ["python", "app.py"]
''')
        
        scanner = DockerScanner(config)
        instructions = scanner._parse_dockerfile(dockerfile)
        
        assert len(instructions) >= 4
        instruction_names = [i.instruction for i in instructions]
        assert "FROM" in instruction_names
        assert "RUN" in instruction_names
        assert "COPY" in instruction_names
        assert "CMD" in instruction_names
