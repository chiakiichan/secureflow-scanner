# 🔒 SecureFlow

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![CI](https://github.com/secureflow/secureflow/workflows/Security%20Scan/badge.svg)](https://github.com/secureflow/secureflow/actions)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-orange)](https://sarifweb.azurewebsites.net/)

**Enterprise CI/CD Pipeline Security Platform**

*Detect secrets, vulnerable dependencies, container vulnerabilities, and infrastructure misconfigurations in your codebase.*

[Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

SecureFlow is a production-grade security scanning tool designed for DevSecOps pipelines. It provides comprehensive security analysis across multiple dimensions:

| Scanner | Description | Technologies |
|---------|-------------|--------------|
| 🔑 **Secrets** | Detect hardcoded credentials, API keys, and tokens | 50+ secret patterns |
| 📦 **Dependencies** | Find vulnerable packages via OSV API | Python, Node.js, Go, Ruby, Rust |
| 🐳 **Docker** | Analyze Dockerfiles + image scanning via Trivy | Dockerfile, Container Images |
| 🏗️ **IaC** | Detect insecure infrastructure patterns | Terraform, AWS, Azure, GCP |

## ✨ Key Features

- **Policy-as-Code**: Define security policies in YAML for consistent enforcement
- **SARIF Output**: Native GitHub Security tab integration
- **CI/CD Ready**: First-class GitHub Actions support
- **Extensible**: Add custom rules and patterns
- **Fast**: Parallel scanning with intelligent caching
- **Minimal Dependencies**: Lightweight and easy to install

## 📦 Installation

### Using pip

```bash
pip install secureflow
```

### From source

```bash
git clone https://github.com/chiakiichan/secureflow-scanner.git
cd secureflow
pip install -e .
```

### Docker

```bash
docker run -v $(pwd):/scan secureflow/secureflow scan /scan
```

## 🚀 Quick Start

### Basic Scan

```bash
# Scan current directory
secureflow scan

# Scan specific path
secureflow scan ./src

# Output in JSON format
secureflow scan --format json --output results.json

# Generate SARIF for GitHub Security
secureflow scan --format sarif --output results.sarif
```

### Initialize Configuration

```bash
# Create .secureflow.yaml and policy file
secureflow init
```

### Selective Scanning

```bash
# Only scan for secrets and dependencies
secureflow scan --no-docker --no-iac

# Scan with specific severity threshold
secureflow scan --fail-on critical

# Exclude paths
secureflow scan --exclude "tests/*" --exclude "docs/*"
```

### Docker Image Scanning

```bash
# Scan a Docker image (requires Trivy)
secureflow docker-scan nginx:latest
```

## 📋 Example Output

```
═══════════════════════════════════════════════════════
  SecureFlow Security Scan Report
  Version: 1.0.0
  Target: /path/to/project
═══════════════════════════════════════════════════════

  Scanner Results:
    ✓ secrets: 3 finding(s) in 0.45s
    ✓ dependencies: 2 finding(s) in 1.23s
    ✓ docker: 5 finding(s) in 0.12s
    ✓ iac: 4 finding(s) in 0.08s

  Findings Summary:
     CRITICAL : 2
     HIGH : 5
     MEDIUM : 4
     LOW : 3

  Detailed Findings:
────────────────────────────────────────────────────────

  1.  CRITICAL  AWS Secret Access Key
      Rule: SF-SEC-002
      Location: config/settings.py:42
      AWS Secret Access Key detected. This provides full access to AWS account.
      Fix: Remove the hardcoded secret and use secure secret management.

  2.  HIGH  Vulnerable dependency: requests
      Rule: SF-DEP-GHSA-9wx4-h78v-vm56
      Location: requirements.txt:3
      Package 'requests' version 2.25.0 has known vulnerability...
      Fix: Update requests to version 2.31.0 or later

═══════════════════════════════════════════════════════
  ✖ PIPELINE FAILED - Security issues must be resolved
═══════════════════════════════════════════════════════
```

## 🔧 Configuration

### Configuration File (`.secureflow.yaml`)

```yaml
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
```

### Policy File (`.secureflow-policy.yaml`)

```yaml
version: "1.0"
name: "Production Security Policy"

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
    priority: 100  # Higher priority than block rules
    
  # Suppress info findings
  - id: suppress_info
    severity: INFO
    action: suppress
```

## 🔗 GitHub Actions Integration

### Basic Workflow

```yaml
name: Chiakii

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install SecureFlow
        run: pip install secureflow
      
      - name: Run Security Scan
        run: |
          secureflow scan . \
            --format sarif \
            --output results.sarif \
            --fail-on high \
            --ci
        continue-on-error: true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Complete Workflow

See [`.github/workflows/secureflow.yml`](.github/workflows/secureflow.yml) for a complete example with:
- Dependency review
- Container scanning
- Artifact upload
- PR comments

## 🔍 Scanners in Detail

### Secrets Scanner

Detects 50+ types of secrets including:

| Category | Examples |
|----------|----------|
| Cloud Providers | AWS, GCP, Azure credentials |
| Version Control | GitHub, GitLab tokens |
| Payment | Stripe, PayPal keys |
| Communication | Slack, Discord, Twilio tokens |
| Databases | Connection strings with credentials |
| Authentication | JWT secrets, API keys |

### Dependency Scanner

Uses the [OSV (Open Source Vulnerabilities)](https://osv.dev/) database to check:
- Python packages (requirements.txt, pyproject.toml)
- Node.js packages (package.json, package-lock.json)
- Go modules (go.mod)
- Ruby gems (Gemfile.lock)
- Rust crates (Cargo.lock)

### Docker Scanner

Analyzes Dockerfiles for:
- Using `:latest` tag
- Running as root
- Curl-pipe-bash patterns
- Hardcoded secrets in ENV/ARG
- Missing HEALTHCHECK
- Insecure file permissions

For image vulnerability scanning, requires [Trivy](https://trivy.dev/) installation.

### IaC Scanner

Detects misconfigurations in Terraform:

| Category | Examples |
|----------|----------|
| Network | Open security groups, public access |
| Storage | Public S3 buckets, unencrypted volumes |
| Database | Publicly accessible RDS, missing encryption |
| IAM | Wildcard permissions, inline policies |
| Logging | Missing CloudTrail, disabled logging |

## 📊 Report Formats

### Console
Human-readable colored output for local development.

### JSON
Machine-readable format for programmatic consumption:
```json
{
  "version": "1.0",
  "summary": {
    "total_findings": 14,
    "by_severity": {"CRITICAL": 2, "HIGH": 5}
  },
  "findings": [...]
}
```

### SARIF
[Static Analysis Results Interchange Format](https://sarifweb.azurewebsites.net/) for:
- GitHub Code Scanning
- Azure DevOps
- Visual Studio / VSCode

## 🧪 Development

### Setup

```bash
# Clone repository
git clone https://github.com/secureflow/secureflow.git
cd secureflow

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=secureflow --cov-report=html

# Run specific test file
pytest tests/test_secrets_scanner.py -v
```

### Code Quality

```bash
# Format code
black secureflow tests

# Lint code
ruff check secureflow tests

# Type checking
mypy secureflow
```

## 📁 Project Structure

```
secureflow/
├── secureflow/
│   ├── __init__.py
│   ├── cli.py              # CLI entrypoint
│   ├── core/
│   │   ├── config.py       # Configuration management
│   │   ├── finding.py      # Finding data model
│   │   └── scanner.py      # Base scanner class
│   ├── scanners/
│   │   ├── secrets.py      # Secrets detection
│   │   ├── dependencies.py # Dependency scanning
│   │   ├── docker.py       # Docker/container analysis
│   │   └── iac.py          # Infrastructure-as-Code
│   ├── policy/
│   │   ├── engine.py       # Policy evaluation engine
│   │   └── loader.py       # YAML policy loader
│   ├── reporting/
│   │   ├── console.py      # Console output
│   │   ├── json_reporter.py # JSON output
│   │   └── sarif.py        # SARIF output
│   └── integrations/
│       └── github.py       # GitHub Actions integration
├── tests/
├── docs/
├── .github/workflows/
├── pyproject.toml
└── README.md
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OSV](https://osv.dev/) for the vulnerability database
- [Trivy](https://trivy.dev/) for container scanning
- [SARIF](https://sarifweb.azurewebsites.net/) specification
- The open-source security community

---

<div align="center">

**Built with ❤️ by Chiakii Chan**

[Report Bug](https://github.com/chiakiichan/secureflow-scanner/issues) • [Request Feature](https://github.com/chiakiichan/secureflow-scanner/issues) • [Security Policy](SECURITY.md)

</div>
