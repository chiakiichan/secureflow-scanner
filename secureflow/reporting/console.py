"""
SecureFlow Console Reporter

Generates human-readable colored console output matching the format
shown in the README example output.
"""

from __future__ import annotations

import sys
from collections import Counter
from typing import Optional

import click

from secureflow import __version__
from secureflow.core.finding import Finding, Severity
from secureflow.policy.engine import PolicyResult


def _safe_echo(text: str = "", **kwargs) -> None:
    """Echo text, handling Unicode issues on Windows consoles."""
    try:
        click.echo(text, **kwargs)
    except UnicodeEncodeError:
        safe = text.encode(sys.stdout.encoding or "utf-8", errors="replace").decode(
            sys.stdout.encoding or "utf-8", errors="replace"
        )
        click.echo(safe, **kwargs)


# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}


class ConsoleReporter:
    """Prints a rich, formatted security report to the console."""

    def __init__(self, target: str, ci_mode: bool = False) -> None:
        self.target = target
        self.ci_mode = ci_mode

    def report(
        self,
        findings: list[Finding],
        scanner_times: Optional[dict[str, tuple[int, float]]] = None,
        policy_result: Optional[PolicyResult] = None,
    ) -> None:
        """
        Print the full scan report.

        Args:
            findings: All findings from all scanners.
            scanner_times: Dict of scanner_name -> (finding_count, elapsed_seconds).
            policy_result: Policy evaluation result.
        """
        self._print_header()
        self._print_scanner_results(scanner_times or {})
        self._print_severity_summary(findings)

        if findings:
            self._print_detailed_findings(findings)

        self._print_footer(findings, policy_result)

    def _print_header(self) -> None:
        _safe_echo("")
        _safe_echo(click.style("=" * 55, fg="bright_blue"))
        _safe_echo(click.style("  SecureFlow Security Scan Report", fg="bright_white", bold=True))
        _safe_echo(click.style(f"  Version: {__version__}", fg="white"))
        _safe_echo(click.style(f"  Target: {self.target}", fg="white"))
        _safe_echo(click.style("=" * 55, fg="bright_blue"))

    def _print_scanner_results(self, scanner_times: dict[str, tuple[int, float]]) -> None:
        if not scanner_times:
            return
        _safe_echo("")
        _safe_echo(click.style("  Scanner Results:", fg="bright_white", bold=True))
        for name, (count, elapsed) in scanner_times.items():
            _safe_echo(
                click.style(f"    [+] {name}: ", fg="green")
                + click.style(f"{count} finding(s)", fg="white")
                + click.style(f" in {elapsed:.2f}s", fg="bright_black")
            )

    def _print_severity_summary(self, findings: list[Finding]) -> None:
        _safe_echo("")
        _safe_echo(click.style("  Findings Summary:", fg="bright_white", bold=True))
        counter = Counter(f.severity.value for f in findings)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = counter.get(sev, 0)
            color = SEVERITY_COLORS.get(sev, "white")
            _safe_echo(
                click.style(f"     {sev:10s}: ", fg=color) + click.style(str(count), fg="white")
            )

    def _print_detailed_findings(self, findings: list[Finding]) -> None:
        _safe_echo("")
        _safe_echo(click.style("  Detailed Findings:", fg="bright_white", bold=True))
        _safe_echo(click.style("-" * 55, fg="bright_black"))

        # Sort by severity (CRITICAL first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

        for idx, finding in enumerate(sorted_findings, start=1):
            sev = finding.severity.value
            color = SEVERITY_COLORS.get(sev, "white")

            loc = ""
            if finding.location:
                loc = f"{finding.location.file_path}:{finding.location.start_line}"

            _safe_echo("")
            _safe_echo(
                click.style(f"  {idx}. ", fg="white")
                + click.style(f" {sev} ", fg=color, bold=True)
                + click.style(f" {finding.title}", fg="bright_white")
            )
            _safe_echo(click.style(f"      Rule: {finding.rule_id}", fg="bright_black"))
            if loc:
                _safe_echo(click.style(f"      Location: {loc}", fg="bright_black"))
            _safe_echo(click.style(f"      {finding.description}", fg="white"))
            if finding.fix:
                _safe_echo(click.style(f"      Fix: {finding.fix}", fg="green"))

    def _print_footer(
        self,
        findings: list[Finding],
        policy_result: Optional[PolicyResult],
    ) -> None:
        _safe_echo("")
        _safe_echo(click.style("=" * 55, fg="bright_blue"))

        if policy_result and policy_result.should_fail:
            _safe_echo(
                click.style(
                    "  [X] PIPELINE FAILED - Security issues must be resolved",
                    fg="bright_red",
                    bold=True,
                )
            )
        elif not findings:
            _safe_echo(
                click.style("  [OK] PASSED - No security issues found", fg="green", bold=True)
            )
        else:
            _safe_echo(
                click.style(
                    "  [!] WARNINGS - Review security findings above",
                    fg="yellow",
                    bold=True,
                )
            )

        _safe_echo(click.style("=" * 55, fg="bright_blue"))
        _safe_echo("")
