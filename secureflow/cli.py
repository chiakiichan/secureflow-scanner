"""
SecureFlow CLI

Command-line interface for running security scans.

Commands:
    secureflow scan [PATH]          - Run all enabled scanners
    secureflow init                 - Create default config & policy files
    secureflow docker-scan IMAGE    - Scan a Docker image via Trivy
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import click


def _safe_echo(text: str = "", **kwargs) -> None:
    """Echo text, handling Unicode issues on Windows consoles."""
    try:
        click.echo(text, **kwargs)
    except UnicodeEncodeError:
        safe = text.encode(sys.stdout.encoding or "utf-8", errors="replace").decode(
            sys.stdout.encoding or "utf-8", errors="replace"
        )
        click.echo(safe, **kwargs)

from secureflow import __version__
from secureflow.core.config import (
    CONFIG_FILENAME,
    SecureFlowConfig,
    generate_default_config,
    generate_default_policy,
)
from secureflow.core.finding import Finding, Severity
from secureflow.policy.engine import PolicyEngine
from secureflow.policy.loader import Policy
from secureflow.reporting.console import ConsoleReporter
from secureflow.reporting.json_reporter import JSONReporter
from secureflow.reporting.sarif import SARIFReporter
from secureflow.integrations.github import (
    emit_annotations,
    is_github_actions,
    write_step_summary,
)


@click.group()
@click.version_option(version=__version__, prog_name="SecureFlow")
def cli() -> None:
    """
    SecureFlow - CI/CD Security Scanner

    Detect secrets, vulnerable dependencies, container vulnerabilities,
    and infrastructure misconfigurations in your codebase.
    """
    pass


# ═══════════════════════════════════════════════════════
#  secureflow scan
# ═══════════════════════════════════════════════════════
@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--format", "-f", "output_format", type=click.Choice(["console", "json", "sarif"]),
              default=None, help="Output format (default: console).")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Write report to a file.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info"],
              case_sensitive=False), default=None,
              help="Minimum severity that causes a non-zero exit code.")
@click.option("--exclude", multiple=True, help="Paths or patterns to exclude.")
@click.option("--no-secrets", is_flag=True, help="Disable the secrets scanner.")
@click.option("--no-deps", is_flag=True, help="Disable the dependency scanner.")
@click.option("--no-docker", is_flag=True, help="Disable the Docker scanner.")
@click.option("--no-iac", is_flag=True, help="Disable the IaC scanner.")
@click.option("--ci", is_flag=True, help="Enable CI mode (GitHub Actions annotations, etc.).")
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="Path to .secureflow.yaml configuration file.")
def scan(
    path: str,
    output_format: Optional[str],
    output_file: Optional[str],
    fail_on: Optional[str],
    exclude: tuple,
    no_secrets: bool,
    no_deps: bool,
    no_docker: bool,
    no_iac: bool,
    ci: bool,
    config_path: Optional[str],
) -> None:
    """Scan a directory for security issues.

    Examples:

        secureflow scan

        secureflow scan ./src --format json --output results.json

        secureflow scan --format sarif --output results.sarif --fail-on high --ci
    """
    target = Path(path).resolve()

    # ── Load configuration ──
    cfg_path = Path(config_path) if config_path else target / CONFIG_FILENAME
    config = SecureFlowConfig.load(cfg_path)

    # CLI flags override config
    fmt = output_format or config.output.format
    out_file = output_file or config.output.file
    exclusions = list(exclude) + config.exclude_paths

    # ── Determine which scanners to run ──
    scanners_to_run: list[tuple[str, object]] = []

    if not no_secrets and config.scanners.get("secrets", _default_sc()).enabled:
        from secureflow.scanners.secrets import SecretsScanner
        scanners_to_run.append(("secrets", SecretsScanner(target, exclude=exclusions)))

    if not no_deps and config.scanners.get("dependencies", _default_sc()).enabled:
        from secureflow.scanners.dependencies import DependencyScanner
        scanners_to_run.append(("dependencies", DependencyScanner(target, exclude=exclusions)))

    if not no_docker and config.scanners.get("docker", _default_sc()).enabled:
        from secureflow.scanners.docker import DockerScanner
        scanners_to_run.append(("docker", DockerScanner(target, exclude=exclusions)))

    if not no_iac and config.scanners.get("iac", _default_sc()).enabled:
        from secureflow.scanners.iac import IaCScanner
        scanners_to_run.append(("iac", IaCScanner(target, exclude=exclusions)))

    # ── Run scanners ──
    all_findings: list[Finding] = []
    scanner_times: dict[str, tuple[int, float]] = {}

    for name, scanner in scanners_to_run:
        t0 = time.time()
        try:
            results = scanner.scan()
        except Exception as exc:
            _safe_echo(click.style(f"  [X] {name}: error - {exc}", fg="red"), err=True)
            results = []
        elapsed = time.time() - t0
        scanner_times[name] = (len(results), elapsed)
        all_findings.extend(results)

    # ── Apply policy ──
    policy_path = target / (config.policy.file or ".secureflow-policy.yaml")
    policy = Policy.load(policy_path)
    engine = PolicyEngine(policy)
    policy_result = engine.evaluate(all_findings, fail_on=fail_on)

    # Remove suppressed findings from display
    display_findings = [
        f for f in all_findings if f not in policy_result.suppressed
    ]

    # ── Report ──
    if fmt == "json":
        reporter = JSONReporter(target=str(target))
        json_str = reporter.report(display_findings, output_file=out_file)
        if not out_file:
            _safe_echo(json_str)
    elif fmt == "sarif":
        reporter = SARIFReporter(target=str(target))
        sarif_str = reporter.report(display_findings, output_file=out_file)
        if not out_file:
            _safe_echo(sarif_str)
    else:
        console = ConsoleReporter(target=str(target), ci_mode=ci)
        console.report(display_findings, scanner_times, policy_result)
        if out_file:
            # Also write JSON when console + output file
            json_reporter = JSONReporter(target=str(target))
            json_reporter.report(display_findings, output_file=out_file)

    # ── CI integrations ──
    if ci or is_github_actions():
        emit_annotations(display_findings)
        write_step_summary(display_findings, str(target), policy_result.should_fail)

    # ── Exit code ──
    if policy_result.should_fail:
        sys.exit(1)


# ═══════════════════════════════════════════════════════
#  secureflow init
# ═══════════════════════════════════════════════════════
@cli.command()
@click.option("--path", "-p", "target_path", type=click.Path(), default=".",
              help="Directory to create config files in.")
def init(target_path: str) -> None:
    """Create default .secureflow.yaml and policy file."""
    target = Path(target_path).resolve()
    target.mkdir(parents=True, exist_ok=True)

    config_file = target / ".secureflow.yaml"
    policy_file = target / ".secureflow-policy.yaml"

    if config_file.exists():
        _safe_echo(click.style(f"  [!] {config_file} already exists, skipping.", fg="yellow"))
    else:
        config_file.write_text(generate_default_config(), encoding="utf-8")
        _safe_echo(click.style(f"  [+] Created {config_file}", fg="green"))

    if policy_file.exists():
        _safe_echo(click.style(f"  [!] {policy_file} already exists, skipping.", fg="yellow"))
    else:
        policy_file.write_text(generate_default_policy(), encoding="utf-8")
        _safe_echo(click.style(f"  [+] Created {policy_file}", fg="green"))

    _safe_echo("")
    _safe_echo("  Edit these files to customize your security policy.")
    _safe_echo("  Run 'secureflow scan' to start scanning.")


# ═══════════════════════════════════════════════════════
#  secureflow docker-scan
# ═══════════════════════════════════════════════════════
@cli.command("docker-scan")
@click.argument("image")
@click.option("--format", "-f", "output_format", type=click.Choice(["console", "json", "sarif"]),
              default="console", help="Output format.")
@click.option("--output", "-o", "output_file", type=click.Path(), default=None,
              help="Write report to a file.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"],
              case_sensitive=False), default=None,
              help="Minimum severity that causes a non-zero exit code.")
def docker_scan(
    image: str,
    output_format: str,
    output_file: Optional[str],
    fail_on: Optional[str],
) -> None:
    """Scan a Docker image for vulnerabilities (requires Trivy).

    Example:

        secureflow docker-scan nginx:latest
    """
    import shutil

    if not shutil.which("trivy"):
        _safe_echo(click.style(
            "  [X] Trivy is not installed. Install it from https://trivy.dev/",
            fg="red",
        ))
        sys.exit(1)

    from secureflow.scanners.docker import DockerScanner

    _safe_echo(click.style(f"  Scanning image: {image}", fg="bright_white"))
    scanner = DockerScanner(target_path=Path("."))
    t0 = time.time()
    findings = scanner.scan_image(image)
    elapsed = time.time() - t0

    scanner_times = {"docker-image": (len(findings), elapsed)}

    # Determine failure
    should_fail = False
    if fail_on:
        threshold = Severity.from_string(fail_on)
        should_fail = any(f.severity >= threshold for f in findings)

    if output_format == "json":
        reporter = JSONReporter(target=image)
        json_str = reporter.report(findings, output_file=output_file)
        if not output_file:
            _safe_echo(json_str)
    elif output_format == "sarif":
        reporter = SARIFReporter(target=image)
        sarif_str = reporter.report(findings, output_file=output_file)
        if not output_file:
            _safe_echo(sarif_str)
    else:
        console = ConsoleReporter(target=image)
        console.report(findings, scanner_times)

    if should_fail:
        sys.exit(1)


# ── Helpers ──

def _default_sc():
    """Return a simple object with enabled=True for scanner config fallback."""
    from secureflow.core.config import ScannerConfig
    return ScannerConfig()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
