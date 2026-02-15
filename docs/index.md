# SecureFlow Documentation

Welcome to the SecureFlow documentation. SecureFlow is an enterprise CI/CD pipeline security platform that helps you detect and prevent security issues in your codebase.

## Quick Links

- [Getting Started](getting-started.md)
- [Configuration](configuration.md)
- [Scanners](scanners/index.md)
- [Policy Engine](policy.md)
- [GitHub Actions Integration](github-actions.md)
- [API Reference](api/index.md)

## What is SecureFlow?

SecureFlow is a comprehensive security scanning tool designed for DevSecOps pipelines. It provides:

- **Secrets Detection**: Find hardcoded credentials, API keys, and tokens
- **Dependency Scanning**: Identify vulnerable packages using the OSV database
- **Container Security**: Analyze Dockerfiles and container images
- **Infrastructure-as-Code**: Detect misconfigurations in Terraform and other IaC tools

## Key Features

### 🔒 Multi-Scanner Architecture

SecureFlow includes four specialized scanners:

| Scanner | Purpose | Technologies |
|---------|---------|--------------|
| Secrets | Detect hardcoded credentials | 50+ patterns |
| Dependencies | Find vulnerable packages | Python, Node.js, Go, Ruby, Rust |
| Docker | Container security analysis | Dockerfile, Trivy integration |
| IaC | Infrastructure misconfigurations | Terraform (AWS, Azure, GCP) |

### 📋 Policy-as-Code

Define security policies in YAML:

```yaml
rules:
  - id: block_critical
    severity: CRITICAL
    action: fail
```

### 📊 Multiple Output Formats

- **Console**: Human-readable colored output
- **JSON**: Machine-readable format
- **SARIF**: GitHub Security tab integration

### 🔗 CI/CD Integration

First-class support for:

- GitHub Actions
- GitLab CI
- Jenkins
- Azure DevOps

## Installation

```bash
pip install secureflow
```

## Quick Start

```bash
# Initialize configuration
secureflow init

# Run a scan
secureflow scan

# Generate SARIF report
secureflow scan --format sarif --output results.sarif
```

## Getting Help

- [GitHub Issues](https://github.com/chiakiichan/secureflow-scanner/issues)
- [Discussions](https://github.com/chiakiichan/secureflow-scanner/discussions)
- [Security Policy](https://github.com/chiakiichan/secureflow-scanner/security/policy)
