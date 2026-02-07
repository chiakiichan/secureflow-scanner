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
def scan(path: str) -> None:
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

    click.echo("✅ CLI is working.")
    click.echo("Next: Implement the first scanner (SecretsScanner).")


def main() -> None:
    """Main entrypoint."""
    cli()


if __name__ == "__main__":
    main()