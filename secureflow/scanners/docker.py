"""
SecureFlow Docker Scanner

Analyzes Dockerfiles for security misconfigurations and best-practice violations.
Optionally scans container images via Trivy integration.

Checks:
- Using :latest tag
- Running as root
- Curl-pipe-bash patterns
- Hardcoded secrets in ENV/ARG
- Missing HEALTHCHECK
- Insecure file permissions
- ADD vs COPY usage
- Unnecessary privilege escalation
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from secureflow.core.finding import Finding, FindingType, Location, Severity
from secureflow.core.scanner import BaseScanner


class DockerScanner(BaseScanner):
    """
    Scans Dockerfiles for security issues and optionally
    runs Trivy for image vulnerability scanning.
    """

    name = "docker"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for dockerfile in self._find_dockerfiles():
            if any(ex in str(dockerfile) for ex in self.exclude):
                continue
            findings.extend(self._analyze_dockerfile(dockerfile))

        return findings

    def scan_image(self, image: str) -> List[Finding]:
        """Scan a Docker image using Trivy (if installed)."""
        return self._trivy_scan(image)

    # ── Dockerfile discovery ──

    def _find_dockerfiles(self):
        """Find all Dockerfiles in the target directory."""
        if self.target_path.is_file():
            if self._is_dockerfile(self.target_path):
                yield self.target_path
            return

        for file_path in self.target_path.rglob("*"):
            if file_path.is_file() and self._is_dockerfile(file_path):
                yield file_path

    @staticmethod
    def _is_dockerfile(path: Path) -> bool:
        name = path.name.lower()
        return (
            name == "dockerfile"
            or name.startswith("dockerfile.")
            or name.endswith(".dockerfile")
            or name == "containerfile"
        )

    # ── Dockerfile analysis ──

    def _analyze_dockerfile(self, file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            content = file_path.read_text(errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        has_user = False
        has_healthcheck = False
        from_count = 0

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            upper = line.upper()

            # ── FROM with :latest tag ──
            if upper.startswith("FROM "):
                from_count += 1
                image_ref = line.split()[1] if len(line.split()) > 1 else ""
                if image_ref and (":" not in image_ref or image_ref.endswith(":latest")):
                    if "@sha256:" not in image_ref and image_ref != "scratch":
                        findings.append(self._make_finding(
                            "SF-DOC-001",
                            "Docker image uses :latest or untagged",
                            f"Image '{image_ref}' uses the :latest tag or no tag. "
                            "This makes builds non-reproducible.",
                            Severity.MEDIUM,
                            file_path, line_no, raw_line.strip(),
                            "Pin the image to a specific version tag or SHA digest.",
                        ))

            # ── Running as root ──
            if upper.startswith("USER "):
                has_user = True
                user_val = line.split(maxsplit=1)[1].strip() if len(line.split()) > 1 else ""
                if user_val.lower() in ("root", "0"):
                    findings.append(self._make_finding(
                        "SF-DOC-002",
                        "Container runs as root",
                        "Explicitly running as root user increases attack surface.",
                        Severity.HIGH,
                        file_path, line_no, raw_line.strip(),
                        "Use a non-root user: USER nonroot:nonroot",
                    ))

            # ── Curl-pipe-bash ──
            if re.search(
                r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh)", line, re.IGNORECASE
            ):
                findings.append(self._make_finding(
                    "SF-DOC-003",
                    "Curl-pipe-bash pattern detected",
                    "Piping downloaded scripts directly to a shell is dangerous. "
                    "The script content can change between download and execution.",
                    Severity.HIGH,
                    file_path, line_no, raw_line.strip(),
                    "Download the script first, verify its checksum, then execute.",
                ))

            # ── Secrets in ENV/ARG ──
            if re.match(r"^(?:ENV|ARG)\s+", upper):
                if re.search(
                    r"(?i)(?:password|secret|token|key|api_key|apikey|credential|auth)",
                    line,
                ):
                    findings.append(self._make_finding(
                        "SF-DOC-004",
                        "Potential secret in ENV/ARG instruction",
                        "Secrets set via ENV or ARG are visible in image metadata "
                        "and layer history.",
                        Severity.CRITICAL,
                        file_path, line_no, raw_line.strip(),
                        "Use Docker BuildKit secrets or mount secrets at runtime.",
                    ))

            # ── HEALTHCHECK ──
            if upper.startswith("HEALTHCHECK "):
                has_healthcheck = True

            # ── ADD instead of COPY ──
            if upper.startswith("ADD "):
                # ADD is okay for tar extraction or URLs, but COPY is preferred otherwise
                args = line.split()[1:]
                if args and not any(
                    a.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2"))
                    or a.startswith("http")
                    for a in args
                ):
                    findings.append(self._make_finding(
                        "SF-DOC-005",
                        "ADD used instead of COPY",
                        "ADD has implicit tar extraction and remote URL capabilities "
                        "which can introduce unexpected behavior.",
                        Severity.LOW,
                        file_path, line_no, raw_line.strip(),
                        "Use COPY unless you specifically need ADD's features.",
                    ))

            # ── Insecure chmod ──
            if re.search(r"chmod\s+[0-7]*7[0-7]{0,2}\b", line):
                findings.append(self._make_finding(
                    "SF-DOC-006",
                    "Insecure file permissions",
                    "World-writable or world-executable permissions detected.",
                    Severity.MEDIUM,
                    file_path, line_no, raw_line.strip(),
                    "Use restrictive permissions (e.g., 644 for files, 755 for executables).",
                ))

            # ── Privileged operations ──
            if re.search(r"--privileged|--cap-add|--security-opt\s+apparmor=unconfined", line):
                findings.append(self._make_finding(
                    "SF-DOC-007",
                    "Privileged container configuration",
                    "Privileged mode or added capabilities reduce container isolation.",
                    Severity.HIGH,
                    file_path, line_no, raw_line.strip(),
                    "Only add specific required capabilities instead of using --privileged.",
                ))

            # ── apt-get without --no-install-recommends ──
            if re.search(r"apt-get\s+install", line) and "--no-install-recommends" not in line:
                findings.append(self._make_finding(
                    "SF-DOC-008",
                    "apt-get install without --no-install-recommends",
                    "Installing recommended packages bloats the image and increases attack surface.",
                    Severity.LOW,
                    file_path, line_no, raw_line.strip(),
                    "Add --no-install-recommends flag to apt-get install.",
                ))

            # ── EXPOSE with suspicious ports ──
            if upper.startswith("EXPOSE "):
                ports = re.findall(r"\d+", line)
                for port in ports:
                    if int(port) in (22, 23, 3389):
                        findings.append(self._make_finding(
                            "SF-DOC-009",
                            f"Suspicious port exposed: {port}",
                            f"Port {port} is commonly used for remote access "
                            f"(SSH/Telnet/RDP) and may indicate a security risk.",
                            Severity.MEDIUM,
                            file_path, line_no, raw_line.strip(),
                            "Avoid exposing remote access ports in containers.",
                        ))

        # ── Post-scan checks ──
        if from_count > 0 and not has_user:
            findings.append(self._make_finding(
                "SF-DOC-010",
                "No USER instruction found",
                "Container will run as root by default if no USER instruction is set.",
                Severity.HIGH,
                file_path, 1, "",
                "Add a USER instruction to run as a non-root user.",
            ))

        if from_count > 0 and not has_healthcheck:
            findings.append(self._make_finding(
                "SF-DOC-011",
                "Missing HEALTHCHECK instruction",
                "No HEALTHCHECK defined. Docker cannot verify the container is healthy.",
                Severity.LOW,
                file_path, 1, "",
                "Add a HEALTHCHECK instruction to monitor container health.",
            ))

        return findings

    @staticmethod
    def _make_finding(
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        file_path: Path,
        line_no: int,
        snippet: str,
        fix: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            finding_type=FindingType.DOCKER,
            scanner="docker",
            location=Location(
                file_path=file_path,
                start_line=line_no,
                snippet=snippet,
            ),
            fix=fix,
            tags=["docker"],
        )

    # ── Trivy image scanning ──

    @staticmethod
    def _trivy_scan(image: str) -> List[Finding]:
        """Run Trivy to scan a container image for vulnerabilities."""
        findings: List[Finding] = []

        trivy_path = shutil.which("trivy")
        if not trivy_path:
            return findings  # Trivy not installed, skip

        try:
            result = subprocess.run(
                [trivy_path, "image", "--format", "json", "--quiet", image],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                return findings

            data = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return findings

        for result_obj in data.get("Results", []):
            target = result_obj.get("Target", image)
            for vuln in result_obj.get("Vulnerabilities", []):
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg = vuln.get("PkgName", "unknown")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                title = vuln.get("Title", f"Vulnerability in {pkg}")
                sev_str = vuln.get("Severity", "MEDIUM").upper()

                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                }
                severity = severity_map.get(sev_str, Severity.MEDIUM)

                fix_msg = f"Update {pkg} to version {fixed}." if fixed else f"No fix available for {pkg} yet."

                findings.append(
                    Finding(
                        rule_id=f"SF-DOC-IMG-{vuln_id}",
                        title=title,
                        description=(
                            f"Package '{pkg}' version {installed} in image '{image}' "
                            f"has vulnerability {vuln_id}."
                        ),
                        severity=severity,
                        finding_type=FindingType.DOCKER,
                        scanner="docker",
                        location=Location(
                            file_path=Path(target),
                            start_line=0,
                            snippet=f"{pkg}@{installed}",
                        ),
                        fix=fix_msg,
                        metadata={
                            "vulnerability_id": vuln_id,
                            "package": pkg,
                            "installed_version": installed,
                            "fixed_version": fixed,
                            "image": image,
                        },
                        tags=["docker", "image", "trivy"],
                    )
                )

        return findings
