"""
SecureFlow Infrastructure-as-Code (IaC) Scanner

Detects misconfigurations in Terraform files covering:
- Network: Open security groups, public access
- Storage: Public S3 buckets, unencrypted volumes
- Database: Publicly accessible RDS, missing encryption
- IAM: Wildcard permissions, inline policies
- Logging: Missing CloudTrail, disabled logging
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from secureflow.core.finding import Finding, FindingType, Location, Severity
from secureflow.core.scanner import BaseScanner


class IaCScanner(BaseScanner):
    """
    Scans Terraform (.tf) and HCL files for insecure infrastructure patterns.
    """

    name = "iac"

    # Each rule: (rule_id, title, description, severity, fix, detector_func_name)
    # Detectors are methods on this class.

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for tf_file in self._find_tf_files():
            if any(ex in str(tf_file) for ex in self.exclude):
                continue
            findings.extend(self._analyze_tf(tf_file))

        return findings

    def _find_tf_files(self):
        """Find all Terraform files."""
        if self.target_path.is_file():
            if self.target_path.suffix in (".tf", ".hcl"):
                yield self.target_path
            return

        for file_path in self.target_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in (".tf", ".hcl"):
                yield file_path

    def _analyze_tf(self, file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            content = file_path.read_text(errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        # Run all detectors
        for detector in self._detectors():
            findings.extend(detector(file_path, content, lines))

        return findings

    def _detectors(self):
        return [
            self._check_open_security_group,
            self._check_public_s3_bucket,
            self._check_s3_no_encryption,
            self._check_s3_no_versioning,
            self._check_s3_no_logging,
            self._check_unencrypted_ebs,
            self._check_public_rds,
            self._check_rds_no_encryption,
            self._check_rds_no_backup,
            self._check_iam_wildcard,
            self._check_iam_inline_policy,
            self._check_missing_cloudtrail,
            self._check_cloudtrail_no_encryption,
            self._check_alb_no_https,
            self._check_ssh_open_to_world,
            self._check_public_subnet,
            self._check_default_vpc,
            self._check_hardcoded_credentials,
            self._check_missing_tags,
            self._check_unrestricted_egress,
        ]

    # ── Network ──

    def _check_open_security_group(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect security groups with 0.0.0.0/0 ingress."""
        findings = []
        # Look for cidr_blocks containing 0.0.0.0/0 in ingress blocks
        in_ingress = False
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.match(r"^\s*ingress\s*\{", stripped) or stripped == "ingress {":
                in_ingress = True
            if in_ingress and "}" in stripped:
                in_ingress = False
            if in_ingress and re.search(r'["\']0\.0\.0\.0/0["\']', line):
                findings.append(self._make(
                    "SF-IAC-001", "Security group allows unrestricted ingress",
                    "Security group ingress rule allows traffic from 0.0.0.0/0 (all IPs). "
                    "This exposes the resource to the entire internet.",
                    Severity.HIGH, file_path, line_no, stripped,
                    "Restrict ingress CIDR blocks to known IP ranges.",
                ))
        return findings

    def _check_ssh_open_to_world(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect SSH (port 22) open to 0.0.0.0/0."""
        findings = []
        in_ingress = False
        has_port_22 = False
        has_open_cidr = False
        ingress_start = 0

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.match(r"^\s*ingress\s*\{", stripped) or stripped == "ingress {":
                in_ingress = True
                has_port_22 = False
                has_open_cidr = False
                ingress_start = line_no
            if in_ingress:
                if re.search(r"(?:from_port|to_port)\s*=\s*22", stripped):
                    has_port_22 = True
                if re.search(r'["\']0\.0\.0\.0/0["\']', stripped):
                    has_open_cidr = True
                if "}" in stripped:
                    if has_port_22 and has_open_cidr:
                        findings.append(self._make(
                            "SF-IAC-002", "SSH open to the world",
                            "Port 22 (SSH) is accessible from 0.0.0.0/0. "
                            "This exposes the server to brute-force attacks.",
                            Severity.CRITICAL, file_path, ingress_start, "",
                            "Restrict SSH access to specific IP ranges or use a bastion host.",
                        ))
                    in_ingress = False
        return findings

    def _check_public_subnet(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect public subnets with map_public_ip_on_launch."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r"map_public_ip_on_launch\s*=\s*true", line, re.IGNORECASE):
                findings.append(self._make(
                    "SF-IAC-003", "Public subnet auto-assigns public IPs",
                    "Subnet is configured to auto-assign public IPs to instances.",
                    Severity.MEDIUM, file_path, line_no, line.strip(),
                    "Set map_public_ip_on_launch = false unless explicitly needed.",
                ))
        return findings

    def _check_default_vpc(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect usage of default VPC."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_default_vpc"', line):
                findings.append(self._make(
                    "SF-IAC-004", "Default VPC in use",
                    "Using the default VPC is not recommended for production workloads.",
                    Severity.MEDIUM, file_path, line_no, line.strip(),
                    "Create a custom VPC with proper network segmentation.",
                ))
        return findings

    def _check_unrestricted_egress(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect security groups with unrestricted egress."""
        findings = []
        in_egress = False
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.match(r"^\s*egress\s*\{", stripped) or stripped == "egress {":
                in_egress = True
            if in_egress and "}" in stripped:
                in_egress = False
            if in_egress and re.search(r'["\']0\.0\.0\.0/0["\']', line):
                if re.search(r"protocol\s*=\s*\"-1\"", content):
                    findings.append(self._make(
                        "SF-IAC-005", "Unrestricted egress in security group",
                        "Security group allows all outbound traffic to 0.0.0.0/0.",
                        Severity.LOW, file_path, line_no, stripped,
                        "Restrict egress rules to required destinations and ports.",
                    ))
        return findings

    # ── Storage ──

    def _check_public_s3_bucket(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect S3 buckets with public access."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'acl\s*=\s*"public-read"', line) or re.search(
                r'acl\s*=\s*"public-read-write"', line
            ):
                findings.append(self._make(
                    "SF-IAC-010", "S3 bucket has public access",
                    "S3 bucket ACL allows public access. Data may be exposed.",
                    Severity.CRITICAL, file_path, line_no, line.strip(),
                    "Set ACL to 'private' and use bucket policies for access control.",
                ))
        return findings

    def _check_s3_no_encryption(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect S3 buckets without server-side encryption."""
        findings = []
        if re.search(r'resource\s+"aws_s3_bucket"\s+', content):
            if "server_side_encryption_configuration" not in content and \
               "aws_s3_bucket_server_side_encryption_configuration" not in content:
                for line_no, line in enumerate(lines, start=1):
                    if re.search(r'resource\s+"aws_s3_bucket"\s+', line):
                        findings.append(self._make(
                            "SF-IAC-011", "S3 bucket missing encryption",
                            "S3 bucket does not have server-side encryption configured.",
                            Severity.HIGH, file_path, line_no, line.strip(),
                            "Enable server-side encryption (SSE-S3 or SSE-KMS).",
                        ))
        return findings

    def _check_s3_no_versioning(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect S3 buckets without versioning."""
        findings = []
        if re.search(r'resource\s+"aws_s3_bucket"\s+', content):
            if "versioning" not in content:
                for line_no, line in enumerate(lines, start=1):
                    if re.search(r'resource\s+"aws_s3_bucket"\s+', line):
                        findings.append(self._make(
                            "SF-IAC-012", "S3 bucket missing versioning",
                            "S3 bucket does not have versioning enabled. "
                            "Data cannot be recovered if accidentally deleted.",
                            Severity.MEDIUM, file_path, line_no, line.strip(),
                            "Enable versioning on the S3 bucket.",
                        ))
        return findings

    def _check_s3_no_logging(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect S3 buckets without access logging."""
        findings = []
        if re.search(r'resource\s+"aws_s3_bucket"\s+', content):
            if "logging" not in content and "aws_s3_bucket_logging" not in content:
                for line_no, line in enumerate(lines, start=1):
                    if re.search(r'resource\s+"aws_s3_bucket"\s+', line):
                        findings.append(self._make(
                            "SF-IAC-013", "S3 bucket missing access logging",
                            "S3 bucket does not have access logging enabled.",
                            Severity.MEDIUM, file_path, line_no, line.strip(),
                            "Enable access logging for the S3 bucket.",
                        ))
        return findings

    def _check_unencrypted_ebs(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect unencrypted EBS volumes."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_ebs_volume"', line):
                # Check if encrypted = true exists nearby
                block = self._get_resource_block(lines, line_no - 1)
                if "encrypted" not in block or re.search(
                    r"encrypted\s*=\s*false", block
                ):
                    findings.append(self._make(
                        "SF-IAC-014", "Unencrypted EBS volume",
                        "EBS volume is not encrypted. Data at rest is unprotected.",
                        Severity.HIGH, file_path, line_no, line.strip(),
                        "Set encrypted = true on the EBS volume.",
                    ))
        return findings

    # ── Database ──

    def _check_public_rds(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect publicly accessible RDS instances."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r"publicly_accessible\s*=\s*true", line, re.IGNORECASE):
                findings.append(self._make(
                    "SF-IAC-020", "RDS instance is publicly accessible",
                    "Database instance is publicly accessible from the internet.",
                    Severity.CRITICAL, file_path, line_no, line.strip(),
                    "Set publicly_accessible = false and use VPC networking.",
                ))
        return findings

    def _check_rds_no_encryption(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect RDS instances without encryption."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_db_instance"', line):
                block = self._get_resource_block(lines, line_no - 1)
                if "storage_encrypted" not in block or re.search(
                    r"storage_encrypted\s*=\s*false", block
                ):
                    findings.append(self._make(
                        "SF-IAC-021", "RDS instance missing encryption",
                        "RDS instance does not have storage encryption enabled.",
                        Severity.HIGH, file_path, line_no, line.strip(),
                        "Set storage_encrypted = true on the RDS instance.",
                    ))
        return findings

    def _check_rds_no_backup(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect RDS instances without backup retention."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_db_instance"', line):
                block = self._get_resource_block(lines, line_no - 1)
                if "backup_retention_period" not in block or re.search(
                    r"backup_retention_period\s*=\s*0", block
                ):
                    findings.append(self._make(
                        "SF-IAC-022", "RDS instance has no backup retention",
                        "RDS instance backup retention period is 0 or not configured.",
                        Severity.MEDIUM, file_path, line_no, line.strip(),
                        "Set backup_retention_period to at least 7 days.",
                    ))
        return findings

    # ── IAM ──

    def _check_iam_wildcard(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect IAM policies with wildcard (*) permissions."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            # "Action": "*" or actions = ["*"]
            if re.search(r'["\']Action["\']\s*:\s*["\']\*["\']', line) or \
               re.search(r'actions\s*=\s*\[\s*["\']\*["\']\s*\]', line):
                findings.append(self._make(
                    "SF-IAC-030", "IAM policy with wildcard permissions",
                    "IAM policy grants wildcard (*) permissions. "
                    "This violates the principle of least privilege.",
                    Severity.CRITICAL, file_path, line_no, line.strip(),
                    "Restrict actions to only those specifically required.",
                ))
            # "Resource": "*"
            if re.search(r'["\']Resource["\']\s*:\s*["\']\*["\']', line):
                findings.append(self._make(
                    "SF-IAC-031", "IAM policy with wildcard resource",
                    "IAM policy applies to all resources (*). "
                    "This grants overly broad access.",
                    Severity.HIGH, file_path, line_no, line.strip(),
                    "Scope the resource to specific ARNs.",
                ))
        return findings

    def _check_iam_inline_policy(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect inline IAM policies (prefer managed policies)."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_iam_role_policy"\s+', line):
                findings.append(self._make(
                    "SF-IAC-032", "Inline IAM policy detected",
                    "Inline IAM policies are harder to manage and audit. "
                    "Use managed policies instead.",
                    Severity.MEDIUM, file_path, line_no, line.strip(),
                    "Convert to an aws_iam_policy resource and attach via aws_iam_role_policy_attachment.",
                ))
        return findings

    # ── Logging ──

    def _check_missing_cloudtrail(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect CloudTrail without multi-region or log validation."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_cloudtrail"', line):
                block = self._get_resource_block(lines, line_no - 1)
                if "is_multi_region_trail" not in block or re.search(
                    r"is_multi_region_trail\s*=\s*false", block
                ):
                    findings.append(self._make(
                        "SF-IAC-040", "CloudTrail not multi-region",
                        "CloudTrail is not configured for multi-region logging.",
                        Severity.HIGH, file_path, line_no, line.strip(),
                        "Set is_multi_region_trail = true.",
                    ))
                if "enable_log_file_validation" not in block or re.search(
                    r"enable_log_file_validation\s*=\s*false", block
                ):
                    findings.append(self._make(
                        "SF-IAC-041", "CloudTrail log file validation disabled",
                        "CloudTrail log file validation is not enabled.",
                        Severity.MEDIUM, file_path, line_no, line.strip(),
                        "Set enable_log_file_validation = true.",
                    ))
        return findings

    def _check_cloudtrail_no_encryption(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect CloudTrail without KMS encryption."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_cloudtrail"', line):
                block = self._get_resource_block(lines, line_no - 1)
                if "kms_key_id" not in block:
                    findings.append(self._make(
                        "SF-IAC-042", "CloudTrail logs not encrypted",
                        "CloudTrail logs are not encrypted with KMS.",
                        Severity.HIGH, file_path, line_no, line.strip(),
                        "Add a kms_key_id to encrypt CloudTrail logs.",
                    ))
        return findings

    # ── Load Balancer ──

    def _check_alb_no_https(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect ALB listeners without HTTPS."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            if re.search(r'resource\s+"aws_lb_listener"', line):
                block = self._get_resource_block(lines, line_no - 1)
                if re.search(r'protocol\s*=\s*"HTTP"', block) and \
                   "redirect" not in block.lower():
                    findings.append(self._make(
                        "SF-IAC-050", "ALB listener using HTTP without redirect",
                        "Application Load Balancer listener uses HTTP without "
                        "redirecting to HTTPS.",
                        Severity.HIGH, file_path, line_no, line.strip(),
                        "Use HTTPS or add an HTTP-to-HTTPS redirect action.",
                    ))
        return findings

    # ── Hardcoded credentials ──

    def _check_hardcoded_credentials(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect hardcoded credentials in Terraform files."""
        findings = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.search(
                r'(?:access_key|secret_key|password|token)\s*=\s*"[^"$]',
                stripped, re.IGNORECASE
            ):
                # Exclude variable references ${var.xxx}
                if "${" not in stripped:
                    findings.append(self._make(
                        "SF-IAC-060", "Hardcoded credential in Terraform",
                        "Potential hardcoded credential found in Terraform configuration.",
                        Severity.CRITICAL, file_path, line_no, stripped,
                        "Use variables, environment variables, or a secrets manager.",
                    ))
        return findings

    # ── Tagging ──

    def _check_missing_tags(
        self, file_path: Path, content: str, lines: list[str]
    ) -> List[Finding]:
        """Detect resources missing tags."""
        findings = []
        taggable_resources = [
            "aws_instance", "aws_s3_bucket", "aws_db_instance",
            "aws_vpc", "aws_subnet", "aws_security_group",
            "aws_ebs_volume", "aws_lb",
        ]
        for line_no, line in enumerate(lines, start=1):
            for res in taggable_resources:
                if re.search(rf'resource\s+"{res}"\s+', line):
                    block = self._get_resource_block(lines, line_no - 1)
                    if "tags" not in block:
                        findings.append(self._make(
                            "SF-IAC-070", f"Resource missing tags: {res}",
                            f"Resource '{res}' does not have tags defined. "
                            "Tags are essential for cost allocation and governance.",
                            Severity.LOW, file_path, line_no, line.strip(),
                            "Add tags including at minimum: Name, Environment, Owner.",
                        ))
        return findings

    # ── Helpers ──

    @staticmethod
    def _get_resource_block(lines: list[str], start_idx: int) -> str:
        """Extract a resource block starting from the given index."""
        block_lines = []
        depth = 0
        started = False
        for i in range(start_idx, min(start_idx + 200, len(lines))):
            line = lines[i]
            block_lines.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
        return "\n".join(block_lines)

    @staticmethod
    def _make(
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
            finding_type=FindingType.IAC,
            scanner="iac",
            location=Location(
                file_path=file_path,
                start_line=line_no,
                snippet=snippet,
            ),
            fix=fix,
            tags=["iac", "terraform"],
        )
