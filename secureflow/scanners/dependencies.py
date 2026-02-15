"""
SecureFlow Dependency Scanner

Finds vulnerable packages by querying the OSV (Open Source Vulnerabilities) API.
Supports: Python (requirements.txt, pyproject.toml), Node.js (package.json,
package-lock.json), Go (go.mod), Ruby (Gemfile.lock), Rust (Cargo.lock).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, List, Optional

import requests

from secureflow.core.finding import Finding, FindingType, Location, Severity
from secureflow.core.scanner import BaseScanner

OSV_API_URL = "https://api.osv.dev/v1/query"

# Mapping of ecosystem names used by OSV
ECOSYSTEM_MAP = {
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "go.mod": "Go",
    "Gemfile.lock": "RubyGems",
    "Cargo.lock": "crates.io",
}

MANIFEST_FILES = set(ECOSYSTEM_MAP.keys())


class DependencyScanner(BaseScanner):
    """
    Scans dependency manifest files and queries the OSV database
    for known vulnerabilities.
    """

    name = "dependencies"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for file_path in self._find_manifests():
            if any(ex in str(file_path) for ex in self.exclude):
                continue

            packages = self._parse_manifest(file_path)
            ecosystem = ECOSYSTEM_MAP.get(file_path.name, "")

            for pkg_name, pkg_version, line_no in packages:
                if not pkg_version:
                    continue

                vulns = self._query_osv(pkg_name, pkg_version, ecosystem)
                for vuln in vulns:
                    severity = self._map_severity(vuln)
                    vuln_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary", "No description available.")
                    aliases = vuln.get("aliases", [])
                    fix_versions = self._get_fix_versions(vuln)

                    fix_msg = f"Update {pkg_name} to a patched version."
                    if fix_versions:
                        fix_msg = f"Update {pkg_name} to version {', '.join(fix_versions)} or later."

                    findings.append(
                        Finding(
                            rule_id=f"SF-DEP-{vuln_id}",
                            title=f"Vulnerable dependency: {pkg_name}",
                            description=(
                                f"Package '{pkg_name}' version {pkg_version} has known "
                                f"vulnerability {vuln_id}. {summary}"
                            ),
                            severity=severity,
                            finding_type=FindingType.DEPENDENCY,
                            scanner=self.name,
                            location=Location(
                                file_path=file_path,
                                start_line=line_no,
                                snippet=f"{pkg_name}=={pkg_version}",
                            ),
                            fix=fix_msg,
                            metadata={
                                "vulnerability_id": vuln_id,
                                "aliases": aliases,
                                "package": pkg_name,
                                "installed_version": pkg_version,
                                "fix_versions": fix_versions,
                                "ecosystem": ecosystem,
                            },
                            tags=["dependency", ecosystem.lower()],
                        )
                    )

        return findings

    def _find_manifests(self):
        """Find all supported dependency manifest files."""
        if self.target_path.is_file():
            if self.target_path.name in MANIFEST_FILES:
                yield self.target_path
            return

        for file_path in self.target_path.rglob("*"):
            if file_path.is_file() and file_path.name in MANIFEST_FILES:
                yield file_path

    def _parse_manifest(
        self, file_path: Path
    ) -> list[tuple[str, Optional[str], int]]:
        """Parse a manifest file and return (name, version, line_number) tuples."""
        name = file_path.name
        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            return []

        if name == "requirements.txt":
            return self._parse_requirements_txt(content)
        elif name == "pyproject.toml":
            return self._parse_pyproject_toml(content)
        elif name == "package.json":
            return self._parse_package_json(content)
        elif name == "package-lock.json":
            return self._parse_package_lock_json(content)
        elif name == "go.mod":
            return self._parse_go_mod(content)
        elif name == "Gemfile.lock":
            return self._parse_gemfile_lock(content)
        elif name == "Cargo.lock":
            return self._parse_cargo_lock(content)
        return []

    # ── Parsers ──

    @staticmethod
    def _parse_requirements_txt(content: str) -> list[tuple[str, Optional[str], int]]:
        packages = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle: package==version, package>=version, package~=version
            match = re.match(r"^([A-Za-z0-9._-]+)\s*[=~!><]+\s*([0-9][^\s;,#]*)", line)
            if match:
                packages.append((match.group(1).lower(), match.group(2), line_no))
            else:
                # Package without version pin
                match = re.match(r"^([A-Za-z0-9._-]+)", line)
                if match:
                    packages.append((match.group(1).lower(), None, line_no))
        return packages

    @staticmethod
    def _parse_pyproject_toml(content: str) -> list[tuple[str, Optional[str], int]]:
        packages = []
        in_deps = False
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("[") and "dependencies" in stripped.lower():
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps:
                # "package>=version" or "package==version" in a list
                match = re.search(r'"([A-Za-z0-9._-]+)\s*[><=~!]+\s*([0-9][^"]*)"', stripped)
                if match:
                    packages.append((match.group(1).lower(), match.group(2).strip(), line_no))
        return packages

    @staticmethod
    def _parse_package_json(content: str) -> list[tuple[str, Optional[str], int]]:
        packages = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return packages

        lines = content.splitlines()
        for dep_key in ("dependencies", "devDependencies"):
            deps = data.get(dep_key, {})
            for pkg_name, version_spec in deps.items():
                # Strip semver range chars
                version = re.sub(r"^[\^~>=<]*", "", version_spec).strip()
                # Find the line number
                line_no = 1
                for i, ln in enumerate(lines, start=1):
                    if f'"{pkg_name}"' in ln:
                        line_no = i
                        break
                packages.append((pkg_name, version or None, line_no))
        return packages

    @staticmethod
    def _parse_package_lock_json(content: str) -> list[tuple[str, Optional[str], int]]:
        packages = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return packages

        # lockfileVersion 2/3 uses "packages", v1 uses "dependencies"
        pkgs = data.get("packages", data.get("dependencies", {}))
        for key, info in pkgs.items():
            name = info.get("name") or key.split("node_modules/")[-1]
            version = info.get("version")
            if name and version and not key == "":
                packages.append((name, version, 1))
        return packages

    @staticmethod
    def _parse_go_mod(content: str) -> list[tuple[str, Optional[str], int]]:
        packages = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            # go.mod require lines: module/path v1.2.3
            match = re.match(r"^([a-zA-Z0-9._/-]+)\s+(v[0-9][^\s]*)", stripped)
            if match:
                packages.append((match.group(1), match.group(2), line_no))
        return packages

    @staticmethod
    def _parse_gemfile_lock(content: str) -> list[tuple[str, Optional[str], int]]:
        packages = []
        in_specs = False
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped == "specs:":
                in_specs = True
                continue
            if in_specs and not stripped:
                in_specs = False
                continue
            if in_specs:
                match = re.match(r"^([a-zA-Z0-9_-]+)\s+\(([^)]+)\)", stripped)
                if match:
                    packages.append((match.group(1), match.group(2), line_no))
        return packages

    @staticmethod
    def _parse_cargo_lock(content: str) -> list[tuple[str, Optional[str], int]]:
        packages = []
        current_name = None
        current_line = 0
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped == "[[package]]":
                current_name = None
                current_line = line_no
            elif stripped.startswith('name = "'):
                current_name = stripped.split('"')[1]
            elif stripped.startswith('version = "') and current_name:
                version = stripped.split('"')[1]
                packages.append((current_name, version, current_line))
                current_name = None
        return packages

    # ── OSV API ──

    @staticmethod
    def _query_osv(
        package: str, version: str, ecosystem: str
    ) -> list[dict[str, Any]]:
        """Query the OSV API for vulnerabilities."""
        try:
            payload = {
                "version": version,
                "package": {"name": package, "ecosystem": ecosystem},
            }
            resp = requests.post(OSV_API_URL, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
        except (requests.RequestException, json.JSONDecodeError):
            pass
        return []

    @staticmethod
    def _map_severity(vuln: dict[str, Any]) -> Severity:
        """Map an OSV vulnerability to a Severity level."""
        # Check database_specific or severity fields
        for sev_info in vuln.get("severity", []):
            score_str = sev_info.get("score", "")
            # CVSS v3 score string
            if "CVSS" in sev_info.get("type", ""):
                try:
                    # Extract base score from CVSS vector or score field
                    if "/" in score_str:
                        # It's a vector string, skip
                        pass
                    else:
                        score = float(score_str)
                        if score >= 9.0:
                            return Severity.CRITICAL
                        elif score >= 7.0:
                            return Severity.HIGH
                        elif score >= 4.0:
                            return Severity.MEDIUM
                        else:
                            return Severity.LOW
                except (ValueError, TypeError):
                    pass

        # Check ecosystem-specific severity
        db_specific = vuln.get("database_specific", {})
        severity_str = db_specific.get("severity", "").upper()
        if severity_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            return Severity(severity_str)

        # Default to MEDIUM if we can't determine severity
        return Severity.MEDIUM

    @staticmethod
    def _get_fix_versions(vuln: dict[str, Any]) -> list[str]:
        """Extract fix versions from OSV vulnerability data."""
        fix_versions = []
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        fix_versions.append(fixed)
        return fix_versions
