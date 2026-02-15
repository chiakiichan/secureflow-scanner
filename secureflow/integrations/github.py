"""
SecureFlow GitHub Actions Integration

Provides helpers for running SecureFlow in GitHub Actions:
- GitHub Actions annotations (warnings/errors)
- Step summary output
- Environment detection
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from secureflow.core.finding import Finding, Severity


def is_github_actions() -> bool:
    """Check if currently running inside GitHub Actions."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def emit_annotations(findings: list[Finding]) -> None:
    """
    Emit GitHub Actions workflow annotations for each finding.
    Errors show as red annotations, warnings as yellow.
    """
    if not is_github_actions():
        return

    for finding in findings:
        level = "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"

        file_path = ""
        line = ""
        if finding.location:
            file_path = str(finding.location.file_path)
            line = str(finding.location.start_line)

        msg = f"{finding.title}: {finding.description}"
        if finding.fix:
            msg += f" Fix: {finding.fix}"

        # GitHub annotation format:
        # ::error file={name},line={line}::{message}
        parts = [f"::{level}"]
        annotation_params = []
        if file_path:
            annotation_params.append(f"file={file_path}")
        if line:
            annotation_params.append(f"line={line}")
        annotation_params.append(f"title={finding.rule_id} - {finding.title}")

        print(f"::{level} {','.join(annotation_params)}::{msg}")


def write_step_summary(
    findings: list[Finding],
    target: str,
    should_fail: bool = False,
) -> None:
    """
    Write a summary to the GitHub Actions step summary.
    This appears on the workflow run page.
    """
    if not is_github_actions():
        return

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    from collections import Counter

    counter = Counter(f.severity.value for f in findings)
    lines = [
        "## 🔒 SecureFlow Security Scan Results\n",
        f"**Target:** `{target}`\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = counter.get(sev, 0)
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(
            sev, ""
        )
        lines.append(f"| {emoji} {sev} | {count} |")

    lines.append("")

    if should_fail:
        lines.append("### ❌ Pipeline Status: FAILED")
        lines.append("Security issues must be resolved before merging.")
    elif findings:
        lines.append("### ⚠️ Pipeline Status: WARNINGS")
        lines.append("Review the findings above.")
    else:
        lines.append("### ✅ Pipeline Status: PASSED")
        lines.append("No security issues found.")

    lines.append("")

    # Top findings detail
    if findings:
        lines.append("<details><summary>📋 Top Findings (click to expand)</summary>\n")
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 99))
        for i, f in enumerate(sorted_findings[:20], start=1):
            loc = ""
            if f.location:
                loc = f"`{f.location.file_path}:{f.location.start_line}`"
            lines.append(f"{i}. **{f.severity.value}** - {f.title} ({f.rule_id})")
            if loc:
                lines.append(f"   - Location: {loc}")
            if f.fix:
                lines.append(f"   - Fix: {f.fix}")
        lines.append("\n</details>")

    try:
        with open(summary_file, "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def get_github_context() -> dict[str, str]:
    """Get useful GitHub Actions context variables."""
    return {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "sha": os.environ.get("GITHUB_SHA", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "actor": os.environ.get("GITHUB_ACTOR", ""),
        "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
    }
