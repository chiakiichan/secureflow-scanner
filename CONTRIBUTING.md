# Contributing to SecureFlow

Thank you for your interest in contributing to SecureFlow Scanner! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions with other contributors and maintainers.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- pip

### Development Setup

1. **Fork the repository**
   ```bash
   # Visit: https://github.com/chiakiichan/secureflow-scanner
   # Click "Fork" button
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR-USERNAME/secureflow-scanner.git
   cd secureflow-scanner
   ```

3. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/chiakiichan/secureflow-scanner.git
   ```

4. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

5. **Install in development mode**
   ```bash
   pip install -e ".[dev]"
   ```

6. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Development Workflow

### Creating a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix-name
```

Use descriptive branch names:
- `feature/` for new features
- `fix/` for bug fixes
- `docs/` for documentation updates
- `test/` for test improvements

### Making Changes

1. Make your changes in the appropriate module
2. Write or update tests for your changes
3. Ensure code quality with linting and formatting

### Code Quality Standards

#### Formatting
```bash
black secureflow tests
```

#### Linting
```bash
ruff check secureflow tests
```

#### Type Checking
```bash
mypy secureflow
```

#### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=secureflow --cov-report=html

# Run specific test file
pytest tests/test_secrets_scanner.py -v
```

### Commit Messages

Write clear, descriptive commit messages:

```
Add support for PyPI dependency scanning

- Parse setup.py and requirements.txt files
- Query PyPI for known vulnerabilities
- Map severity levels appropriately
```

### Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then:
1. Visit https://github.com/chiakiichan/secureflow-scanner/pulls
2. Click "New Pull Request"
3. Select your branch and fill in the PR template
4. Submit

## Adding a New Scanner

To add a new security scanner:

1. **Create scanner module** in `secureflow/scanners/`
   ```python
   from secureflow.core.scanner import BaseScanner
   from secureflow.core.finding import Finding
   
   class MyScanner(BaseScanner):
       def scan(self) -> ScanResult:
           # Implementation
           pass
   ```

2. **Register in CLI** (`secureflow/cli.py`)
   - Add import and CLI option
   - Register scanner in scanner registry

3. **Create tests** in `tests/test_my_scanner.py`
   - Test pattern detection
   - Test edge cases
   - Test configuration options

4. **Update documentation**
   - Add scanner description to README.md
   - Include usage examples
   - Document any dependencies

## Adding New Secret Patterns

To add a new secret pattern:

1. Edit `secureflow/scanners/secrets.py`
2. Add pattern to the `PATTERNS` dictionary
3. Add test case in `tests/test_secrets_scanner.py`
4. Update README with new pattern

Example:
```python
{
    "name": "API Key XYZ Service",
    "pattern": r"xyz_[a-zA-Z0-9]{32}",
    "entropy_check": True,
    "entropy_threshold": 3.5,
    "severity": "HIGH"
}
```

## Testing Guidelines

- Write tests for new features
- Ensure all tests pass before submitting PR
- Aim for >80% code coverage
- Use descriptive test names
- Test both positive and negative cases

```python
def test_detects_valid_secret():
    """Test that valid secrets are detected."""
    # test code

def test_ignores_invalid_pattern():
    """Test that invalid patterns are ignored."""
    # test code
```

## Documentation

- Update docstrings for modified functions/classes
- Keep README.md current with new features
- Add comments for complex logic
- Document configuration options

### Docstring Format
```python
def scan_file(self, file_path: Path) -> List[Finding]:
    """
    Scan a file for security findings.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of findings discovered in the file
        
    Raises:
        FileNotFoundError: If file does not exist
    """
```

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code follows project style guidelines
- [ ] All tests pass (`pytest`)
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Docstrings added/updated
- [ ] No breaking changes (or documented in PR)
- [ ] Commit history is clean
- [ ] PR description is clear and detailed

## Reporting Bugs

When reporting a bug, include:

1. **Description** of the issue
2. **Steps to reproduce**
3. **Expected behavior**
4. **Actual behavior**
5. **Environment** (OS, Python version, etc.)
6. **Relevant logs or error messages**

Example:
```
Title: SecretsScanner fails to detect AWS keys in YAML files

Description:
The SecretsScanner is not detecting AWS Secret Access Keys when they are in YAML files.

Steps to Reproduce:
1. Create a file `config.yaml` with AWS_SECRET_ACCESS_KEY
2. Run `secureflow scan .`
3. No findings reported for the key

Expected:
AWS Secret Access Key should be detected

Actual:
No findings for the secret

Environment:
- OS: Ubuntu 20.04
- Python: 3.9.7
- SecureFlow: 1.0.0
```

## Feature Requests

When requesting a feature:

1. **Title** - Brief description
2. **Use case** - Why is this needed?
3. **Proposed solution** - How should it work?
4. **Alternatives** - Other approaches considered

## Getting Help

- Check [existing issues](https://github.com/chiakiichan/secureflow-scanner/issues)
- Review [documentation](docs/)
- Open a discussion for questions

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Acknowledgments

Thank you for contributing to SecureFlow! Your efforts help make the security scanning tool better for everyone.

---

Happy contributing! 🎉
