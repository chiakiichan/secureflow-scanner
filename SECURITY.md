# Security Policy

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

If you discover a security vulnerability in SecureFlow, please report it responsibly by emailing:

📧 **security@secureflow.dev** (or open a private security advisory on GitHub)

### What to Include

Please provide:
1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Impact assessment** (what could an attacker do?)
4. **Your contact information** (email, name, affiliation)
5. **Suggested fix** (if you have one)

### What to Expect

- We will acknowledge receipt of your report within 48 hours
- We will investigate and provide updates every 5-7 days
- We will release a patch and publicly acknowledge the reporter (unless you prefer anonymity)
- We request a 90-day embargo period before public disclosure

## Security Best Practices

### When Using SecureFlow

1. **Run in Sandbox/CI Environment**
   - Always run SecureFlow in isolated environments
   - Use containerization (Docker) for scanning untrusted code

2. **Protect SecureFlow Configuration**
   - Store `.secureflow.yaml` securely
   - Don't commit API keys or credentials in config files
   - Use environment variables for sensitive configuration

3. **Manage Scan Results**
   - Treat scan output as sensitive information
   - Restrict access to SARIF reports and JSON exports
   - Use encrypted storage for findings archive

4. **GitHub Actions Usage**
   - Use `permissions: read` and only grant `security-events: write` for SARIF upload
   - Run scans on pull requests to catch issues before merge
   - Review and resolve critical findings before production deployment

5. **Dependency Management**
   - Regularly update SecureFlow and its dependencies
   - Monitor for security advisories about SecureFlow itself
   - Use `pip-audit` to scan SecureFlow's dependencies

### Configuration Security

```yaml
# ❌ DON'T: Hardcode credentials
scanners:
  docker:
    registry_token: "ghp_xxxxxxxxxxxxxxxxxxxx"

# ✅ DO: Use environment variables
# Then reference in config or CLI:
docker-scan --registry-token=$DOCKER_TOKEN image:tag
```

### Output Handling

```bash
# ✅ Secure handling
secureflow scan . --format sarif --output results.sarif
chmod 600 results.sarif  # Restrict read permissions
# Upload to secure location

# ❌ Avoid: Committing to public repos
git add results.json  # Don't do this!
```

## Security Features in SecureFlow

### Built-in Protections

1. **Secrets Redaction**
   - Detected secrets are redacted in output snippets
   - Original content is never logged
   - Full formatting preserved for readability

2. **Pattern Validation**
   - Entropy checks to reduce false positives
   - Contextual analysis to distinguish secrets from test values
   - Configurable sensitivity levels

3. **File Exclusion**
   - Binary files automatically skipped
   - Configurable path exclusions
   - Default ignores for common safe paths

4. **No External Reporting**
   - All scanning happens locally
   - No data sent to external services (except OSV API for dependencies)
   - No telemetry or tracking

### Data Privacy

- **Local Processing**: Scanned files never leave your system
- **OSV Integration**: Only package names/versions sent to OSV (not source code)
- **No Telemetry**: SecureFlow doesn't track usage or send analytics
- **Safe Defaults**: Policies configured to report but not block by default

## SecureFlow Security Maintenance

### Dependency Updates

- We monitor security advisories for all dependencies
- Critical issues patched within 24-48 hours
- Security patches released as minor version bumps (1.0.x)

### Supported Versions

| Version | Status | Until |
|---------|--------|-------|
| 1.x.x | Active | 2027-Q2 |
| 0.x.x | EOL | 2025-Q2 |

Only the latest minor version receives security updates.

### Disclosure Timeline

When a vulnerability is discovered:
1. **Day 1**: Acknowledgment and initial investigation
2. **Day 7**: Fix implementation
3. **Day 14**: Release patch version
4. **Day 30**: Public disclosure and CVE assignment
5. **Day 90**: Full details published

## Known Limitations

### What SecureFlow Cannot Detect

- **Logic vulnerabilities**: SecureFlow uses pattern matching, not semantic analysis
- **Memory safety issues**: Not a static analyzer like Coverity or Clang
- **Encrypted secrets**: Cannot scan content inside encrypted files
- **Obfuscated code**: Won't detect deliberately hidden malicious patterns
- **Binary vulnerabilities**: Not designed for compiled binaries

### Configuration Limitations

- Policies cannot override built-in secret patterns
- No custom entropy algorithms (uses Shannon entropy)
- Pattern regex must be valid Python regex syntax

## Compliance & Standards

### Standards Alignment

- **SARIF 2.1.0**: Full compliance for GitHub/Azure/VSCode integration
- **OWASP**: Aligned with OWASP Top 10 terminology
- **CWE**: Secret detection maps to CWE-798, CWE-259, CWE-321
- **CVE**: Dependency scanner uses official CVE data via OSV

### Recommendations for Enterprises

1. **Conduct Security Audit**
   - Review SecureFlow's source code
   - Verify pattern database completeness
   - Test custom policies

2. **Integration Testing**
   - Test with your codebase before production
   - Verify false positive/negative rates
   - Adjust severity mappings as needed

3. **Access Control**
   - Limit who can view scan results
   - Restrict SARIF report distribution
   - Audit policy modifications

4. **CI/CD Integration**
   - Use branch protection rules
   - Require manual approval for CRITICAL findings
   - Archive all scan results with timestamps

## Container Security

### Docker Image Security

```dockerfile
# SecureFlow's own Dockerfile follows best practices:
FROM python:3.11-slim

# Run as non-root user
RUN useradd -m -u 1000 scanner
USER scanner

# Minimal attack surface
RUN apt-get update && apt-get install --no-install-recommends -y \
    git \
    && rm -rf /var/lib/apt/lists/*
```

### Running Securely

```bash
# ✅ Safe: Read-only filesystem, no root, resource limits
docker run \
  --rm \
  --read-only \
  --user 1000:1000 \
  --memory 2g \
  --cpus 2 \
  -v $(pwd):/scan:ro \
  secureflow/secureflow scan /scan

# ❌ Unsafe: Running as root, full access
docker run -v $(pwd):/scan secureflow/secureflow scan /scan
```

## Bug Bounty

We currently don't have a formal bug bounty program, but we deeply appreciate security research and will:

- Publicly acknowledge researchers (with permission)
- Work collaboratively on fixes
- Provide early access to security patches
- Consider recommendations for future features

## Security Checklist for Users

Use this when deploying SecureFlow in production:

- [ ] Running SecureFlow in sandboxed environment
- [ ] API keys/credentials NOT in `.secureflow.yaml`
- [ ] Results files stored securely (encrypted or restricted access)
- [ ] GitHub Actions workflow uses minimal permissions
- [ ] Policy file reviewed and customized for organization
- [ ] Scan results reviewed before allowing CI to pass
- [ ] Log aggregation configured (if applicable)
- [ ] Team trained on interpreting SecureFlow findings
- [ ] Exclusions list reviewed and documented
- [ ] False positive patterns documented

## Getting Security Updates

### Subscribe to Notifications

1. **GitHub**: Watch releases for this repository
2. **Email**: Star the repo and configure notifications
3. **RSS**: Subscribe to GitHub releases feed

### Staying Current

```bash
# Check for updates
pip index versions secureflow

# Upgrade to latest
pip install --upgrade secureflow

# Pin to specific version in requirements
secureflow==1.2.0
```

## Questions?

- **Security Issue**: security@secureflow.dev
- **General Questions**: Check [CONTRIBUTING.md](CONTRIBUTING.md) or open a discussion
- **Feature Request**: [GitHub Issues](https://github.com/chiakiichan/secureflow-scanner/issues)

---

**Last Updated**: February 2026

For the latest security information, visit: https://github.com/chiakiichan/secureflow-scanner/security
