# Getting Started with SecureFlow

This guide will help you get up and running with SecureFlow in minutes.

## Prerequisites

- Python 3.9 or higher
- pip package manager
- (Optional) Trivy for container image scanning

## Installation

### Using pip (recommended)

```bash
pip install secureflow
```

### From source

```bash
git clone https://github.com/chiakiichan/secureflow-scanner.git
cd secureflow
pip install -e .
```

### Verify installation

```bash
secureflow --version
```

## Your First Scan

### 1. Navigate to your project

```bash
cd /path/to/your/project
```

### 2. Run a basic scan

```bash
secureflow scan
```

This will scan the current directory for:
- Hardcoded secrets
- Vulnerable dependencies
- Dockerfile issues
- Terraform misconfigurations

### 3. Review the results

SecureFlow will display a summary of findings categorized by severity:

```
  Findings Summary:
     CRITICAL : 2
     HIGH : 5 
     MEDIUM : 4
     LOW : 3
```

## Initialize Configuration

For better control over your scans, initialize a configuration file:

```bash
secureflow init
```

This creates:
- `.secureflow.yaml` - Main configuration file
- `.secureflow-policy.yaml` - Security policy file

## Customize Your Scan

### Scan specific paths

```bash
secureflow scan ./src ./lib
```

### Select specific scanners

```bash
# Only secrets and dependencies
secureflow scan --no-docker --no-iac
```

### Set severity threshold

```bash
# Only fail on critical issues
secureflow scan --fail-on critical
```

### Exclude paths

```bash
secureflow scan --exclude "tests/*" --exclude "docs/*"
```

## Generate Reports

### JSON Report

```bash
secureflow scan --format json --output report.json
```

### SARIF Report (for GitHub)

```bash
secureflow scan --format sarif --output results.sarif
```

## Next Steps

- [Configure SecureFlow](configuration.md)
- [Set up CI/CD integration](github-actions.md)
- [Learn about scanners](scanners/index.md)
- [Define security policies](policy.md)
