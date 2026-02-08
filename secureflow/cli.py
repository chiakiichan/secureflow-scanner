"""
SecureFlow CLI

Command-line interface for running security scans.

For now, we support only:
    secureflow scan [PATH]

More scanners and reporting will be added soon.
"""

from __future__ import annotations
from pathlib import Path

import click

from secureflow import __version__
from secureflow.scanners.secrets import SecretsScanner

@click.group()
@click.version_option(version=__version__, prog_name="SecureFlow")
def cli() -> None:
    """
    SecureFlow-Scanner - CI/CD Security Scanner Tool

    Detect secrets, vulnerable dependencies, and misconfigurations.
    """
    pass

@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--exclude",
    multiple=True,
    help="Folders or patterns to exclude (example: venv, .git)",
)
def scan(path: str, exclude:tuple) -> None:
    """
    Scan a directory for security issues.
    Example:
        secureflow scan
    """
    target = Path(path).resolve()

    click.echo("=" * 60)
    click.echo(f"🔒 SecureFlow Scanner v{__version__}")
    click.echo(f"📂 Target: {target}")
    click.echo("=" * 60)

    scanner = SecretsScanner(target, exclude=list(exclude))
    findings = scanner.scan()

    if not findings:
        click.echo("\n✅ No secrets found.")
        return
    
    click.echo(f"\n⚠️ Found {len(findings)} possible secrets:\n")

    for finding in findings:
        click.echo(finding.display())
        click.echo("-"*60)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()