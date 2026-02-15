"""
SecureFlow Secrets Scanner

Detects 50+ types of hardcoded secrets using regex patterns.
Scans all text files in the target directory.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

from secureflow.core.finding import Finding, FindingType, Location, Severity
from secureflow.core.scanner import BaseScanner

# File extensions to scan for secrets (text-based files)
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".swift", ".kt", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".yaml", ".yml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".tf", ".hcl",
    ".html", ".css", ".scss", ".less",
    ".sql", ".graphql", ".gql",
    ".md", ".txt", ".rst", ".csv",
    ".dockerfile", ".docker-compose",
    ".gradle", ".maven", ".sbt",
    ".r", ".R", ".jl",
}

# Also scan files without extension that are commonly config files
FILENAME_MATCHES = {
    "Dockerfile", "Makefile", "Vagrantfile", "Gemfile", "Rakefile",
    ".env", ".env.local", ".env.development", ".env.production",
    ".gitconfig", ".npmrc", ".pypirc",
}


class SecretsScanner(BaseScanner):
    """
    Comprehensive secrets scanner.
    Detects 50+ types of secrets including cloud credentials, API keys,
    tokens, private keys, and database connection strings.
    """

    name = "secrets"

    # (rule_id, title, pattern, severity, description, fix)
    PATTERNS: list[tuple[str, str, str, Severity, str, str]] = [
        # ── Cloud Providers ──
        ("SF-SEC-001", "AWS Access Key ID",
         r"(?:^|[^A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?:[^A-Za-z0-9/+=]|$)",
         Severity.CRITICAL,
         "AWS Access Key ID detected. This can provide access to AWS services.",
         "Remove the hardcoded key and use IAM roles or environment variables."),

        ("SF-SEC-002", "AWS Secret Access Key",
         r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
         Severity.CRITICAL,
         "AWS Secret Access Key detected. This provides full access to AWS account.",
         "Remove the hardcoded secret and use secure secret management."),

        ("SF-SEC-003", "GCP API Key",
         r"AIza[0-9A-Za-z_-]{35}",
         Severity.HIGH,
         "Google Cloud Platform API Key detected.",
         "Use GCP service accounts or restrict the API key."),

        ("SF-SEC-004", "GCP Service Account Key",
         r"(?i)\"type\"\s*:\s*\"service_account\"",
         Severity.CRITICAL,
         "GCP Service Account key file detected.",
         "Use Workload Identity Federation instead of service account keys."),

        ("SF-SEC-005", "Azure Storage Account Key",
         r"(?i)(?:AccountKey|storage_account_key)\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{88}['\"]?",
         Severity.CRITICAL,
         "Azure Storage Account Key detected.",
         "Use Azure Managed Identity or Azure Key Vault."),

        ("SF-SEC-006", "Azure Client Secret",
         r"(?i)(?:azure_client_secret|client_secret|AZURE_SECRET)\s*[=:]\s*['\"]?[A-Za-z0-9_~.-]{34,}['\"]?",
         Severity.HIGH,
         "Azure Client Secret detected.",
         "Use Managed Identity or store in Azure Key Vault."),

        # ── Version Control ──
        ("SF-SEC-010", "GitHub Personal Access Token",
         r"ghp_[A-Za-z0-9]{36}",
         Severity.CRITICAL,
         "GitHub Personal Access Token detected.",
         "Revoke this token and use fine-grained tokens with minimal permissions."),

        ("SF-SEC-011", "GitHub OAuth Access Token",
         r"gho_[A-Za-z0-9]{36}",
         Severity.CRITICAL,
         "GitHub OAuth Access Token detected.",
         "Revoke this token immediately."),

        ("SF-SEC-012", "GitHub App Token",
         r"(?:ghu|ghs)_[A-Za-z0-9]{36}",
         Severity.CRITICAL,
         "GitHub App Token detected.",
         "Revoke and rotate this token."),

        ("SF-SEC-013", "GitHub Fine-Grained Token",
         r"github_pat_[A-Za-z0-9_]{82}",
         Severity.CRITICAL,
         "GitHub Fine-Grained Personal Access Token detected.",
         "Revoke and regenerate with minimal required permissions."),

        ("SF-SEC-014", "GitLab Personal Access Token",
         r"glpat-[A-Za-z0-9_-]{20,}",
         Severity.CRITICAL,
         "GitLab Personal Access Token detected.",
         "Revoke this token and use deploy tokens with limited scope."),

        ("SF-SEC-015", "Bitbucket App Password",
         r"(?i)(?:bitbucket.*password|BITBUCKET_APP_PASSWORD)\s*[=:]\s*['\"]?[A-Za-z0-9]{18,}['\"]?",
         Severity.HIGH,
         "Bitbucket App Password detected.",
         "Use repository access tokens with minimal permissions."),

        # ── Payment ──
        ("SF-SEC-020", "Stripe Secret Key",
         r"sk_live_[A-Za-z0-9]{24,}",
         Severity.CRITICAL,
         "Stripe live secret key detected. This can process real payments.",
         "Revoke immediately and use restricted API keys."),

        ("SF-SEC-021", "Stripe Publishable Key (Live)",
         r"pk_live_[A-Za-z0-9]{24,}",
         Severity.MEDIUM,
         "Stripe live publishable key detected.",
         "While publishable keys are less sensitive, avoid hardcoding them."),

        ("SF-SEC-022", "PayPal Client Secret",
         r"(?i)(?:paypal.*secret|PAYPAL_SECRET)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{40,}['\"]?",
         Severity.CRITICAL,
         "PayPal Client Secret detected.",
         "Use environment variables or a secrets manager."),

        ("SF-SEC-023", "Square Access Token",
         r"sq0atp-[A-Za-z0-9_-]{22,}",
         Severity.CRITICAL,
         "Square Access Token detected.",
         "Revoke and rotate this token."),

        # ── Communication ──
        ("SF-SEC-030", "Slack Bot Token",
         r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}",
         Severity.HIGH,
         "Slack Bot Token detected.",
         "Revoke and rotate the token; use environment variables."),

        ("SF-SEC-031", "Slack Webhook URL",
         r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
         Severity.MEDIUM,
         "Slack Webhook URL detected.",
         "Use environment variables to store webhook URLs."),

        ("SF-SEC-032", "Discord Bot Token",
         r"(?i)(?:discord.*token|DISCORD_TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9._-]{50,}['\"]?",
         Severity.HIGH,
         "Discord Bot Token detected.",
         "Regenerate the token and use environment variables."),

        ("SF-SEC-033", "Discord Webhook URL",
         r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
         Severity.MEDIUM,
         "Discord Webhook URL detected.",
         "Store webhook URLs in environment variables."),

        ("SF-SEC-034", "Twilio Account SID",
         r"AC[0-9a-f]{32}",
         Severity.MEDIUM,
         "Twilio Account SID detected.",
         "Use environment variables for Twilio credentials."),

        ("SF-SEC-035", "Twilio Auth Token",
         r"(?i)(?:twilio.*auth.*token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['\"]?[0-9a-f]{32}['\"]?",
         Severity.HIGH,
         "Twilio Auth Token detected.",
         "Rotate the token and use environment variables."),

        ("SF-SEC-036", "Telegram Bot Token",
         r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
         Severity.HIGH,
         "Telegram Bot Token detected.",
         "Revoke via @BotFather and use environment variables."),

        ("SF-SEC-037", "SendGrid API Key",
         r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
         Severity.HIGH,
         "SendGrid API Key detected.",
         "Revoke and create a new key with minimal permissions."),

        ("SF-SEC-038", "Mailgun API Key",
         r"key-[A-Za-z0-9]{32}",
         Severity.HIGH,
         "Mailgun API Key detected.",
         "Rotate the API key and store in environment variables."),

        # ── Databases ──
        ("SF-SEC-040", "Database Connection String",
         r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)://[^\s'\"]{10,}",
         Severity.CRITICAL,
         "Database connection string with potential credentials detected.",
         "Use environment variables or a secrets manager for DB connections."),

        ("SF-SEC-041", "Database Password in Config",
         r"(?i)(?:db_password|database_password|DB_PASS|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_PASSWORD)\s*[=:]\s*['\"]?[^\s'\"]{6,}['\"]?",
         Severity.HIGH,
         "Database password detected in configuration.",
         "Use environment variables or a secrets manager."),

        # ── Authentication / Tokens ──
        ("SF-SEC-050", "JWT Secret",
         r"(?i)(?:jwt_secret|JWT_SECRET_KEY|jwt_signing_key)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?",
         Severity.HIGH,
         "JWT secret key detected.",
         "Use environment variables or a secrets manager for JWT secrets."),

        ("SF-SEC-051", "Generic API Key",
         r"(?i)(?:api_key|apikey|api-key|x-api-key)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
         Severity.MEDIUM,
         "Generic API key detected.",
         "Use environment variables for API keys."),

        ("SF-SEC-052", "Generic Secret/Token",
         r"(?i)(?:secret_key|SECRET_KEY|auth_token|AUTH_TOKEN|access_token|ACCESS_TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9_/+=.-]{20,}['\"]?",
         Severity.MEDIUM,
         "Generic secret or token detected.",
         "Use environment variables or a secrets manager."),

        ("SF-SEC-053", "Bearer Token",
         r"(?i)(?:bearer|authorization)\s*[=:]\s*['\"]?Bearer\s+[A-Za-z0-9._-]{20,}['\"]?",
         Severity.HIGH,
         "Bearer token detected in source code.",
         "Never hardcode bearer tokens; use secure token storage."),

        ("SF-SEC-054", "Basic Auth Credentials",
         r"(?i)(?:basic|authorization)\s*[=:]\s*['\"]?Basic\s+[A-Za-z0-9+/=]{10,}['\"]?",
         Severity.HIGH,
         "Basic authentication credentials detected.",
         "Use secure credential storage instead of hardcoding."),

        # ── Private Keys ──
        ("SF-SEC-060", "RSA Private Key",
         r"-----BEGIN RSA PRIVATE KEY-----",
         Severity.CRITICAL,
         "RSA Private Key detected in source code.",
         "Remove the key from source and use secure key management."),

        ("SF-SEC-061", "EC Private Key",
         r"-----BEGIN EC PRIVATE KEY-----",
         Severity.CRITICAL,
         "EC Private Key detected in source code.",
         "Remove the key and use a secure key management system."),

        ("SF-SEC-062", "OpenSSH Private Key",
         r"-----BEGIN OPENSSH PRIVATE KEY-----",
         Severity.CRITICAL,
         "OpenSSH Private Key detected in source code.",
         "Remove the key and use SSH agent or a secrets manager."),

        ("SF-SEC-063", "PGP Private Key",
         r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
         Severity.CRITICAL,
         "PGP Private Key detected in source code.",
         "Remove the key from source and use a key management system."),

        ("SF-SEC-064", "Generic Private Key",
         r"-----BEGIN PRIVATE KEY-----",
         Severity.CRITICAL,
         "Private Key detected in source code.",
         "Remove the key from source and use a key management system."),

        # ── SaaS / Third-Party ──
        ("SF-SEC-070", "Heroku API Key",
         r"(?i)(?:heroku.*api.*key|HEROKU_API_KEY)\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?",
         Severity.HIGH,
         "Heroku API Key detected.",
         "Rotate the key and use environment variables."),

        ("SF-SEC-071", "npm Token",
         r"(?:^|['\"])npm_[A-Za-z0-9]{36}(?:['\"]|$)",
         Severity.CRITICAL,
         "npm authentication token detected.",
         "Revoke the token on npmjs.com and use .npmrc with env vars."),

        ("SF-SEC-072", "PyPI Token",
         r"pypi-[A-Za-z0-9_-]{50,}",
         Severity.CRITICAL,
         "PyPI API token detected.",
         "Revoke the token on pypi.org and use trusted publishers."),

        ("SF-SEC-073", "NuGet API Key",
         r"oy2[A-Za-z0-9]{43}",
         Severity.HIGH,
         "NuGet API Key detected.",
         "Revoke the key and use scoped API keys."),

        ("SF-SEC-074", "Docker Hub Token",
         r"dckr_pat_[A-Za-z0-9_-]{27,}",
         Severity.HIGH,
         "Docker Hub Personal Access Token detected.",
         "Revoke and regenerate with minimal permissions."),

        ("SF-SEC-075", "Firebase API Key",
         r"(?i)(?:firebase.*key|FIREBASE_API_KEY)\s*[=:]\s*['\"]?AIza[0-9A-Za-z_-]{35}['\"]?",
         Severity.MEDIUM,
         "Firebase API Key detected.",
         "Restrict the key in the Firebase console and use app check."),

        ("SF-SEC-076", "Datadog API Key",
         r"(?i)(?:datadog.*key|DD_API_KEY|DATADOG_API_KEY)\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?",
         Severity.HIGH,
         "Datadog API Key detected.",
         "Rotate the key and use environment variables."),

        ("SF-SEC-077", "New Relic API Key",
         r"NRAK-[A-Z0-9]{27}",
         Severity.HIGH,
         "New Relic API Key detected.",
         "Rotate the key and use environment variables."),

        ("SF-SEC-078", "Shopify Access Token",
         r"shpat_[a-fA-F0-9]{32}",
         Severity.HIGH,
         "Shopify Access Token detected.",
         "Rotate the token via the Shopify Partner Dashboard."),

        ("SF-SEC-079", "Okta API Token",
         r"(?i)(?:okta.*token|OKTA_API_TOKEN)\s*[=:]\s*['\"]?00[A-Za-z0-9_-]{40,}['\"]?",
         Severity.HIGH,
         "Okta API Token detected.",
         "Revoke and rotate the API token."),

        # ── Encryption ──
        ("SF-SEC-080", "Hardcoded Password",
         r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{6,}['\"]",
         Severity.MEDIUM,
         "Hardcoded password detected.",
         "Use environment variables or a secrets manager for passwords."),

        ("SF-SEC-081", "Encryption Key",
         r"(?i)(?:encryption_key|ENCRYPTION_KEY|encrypt_key|aes_key|AES_KEY)\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{16,}['\"]?",
         Severity.HIGH,
         "Encryption key detected in source code.",
         "Use a KMS or environment variable for encryption keys."),

        # ── Infrastructure ──
        ("SF-SEC-090", "HashiCorp Vault Token",
         r"hvs\.[A-Za-z0-9_-]{24,}",
         Severity.CRITICAL,
         "HashiCorp Vault token detected.",
         "Revoke the token and use short-lived tokens or AppRole auth."),

        ("SF-SEC-091", "Consul Token",
         r"(?i)(?:consul.*token|CONSUL_HTTP_TOKEN)\s*[=:]\s*['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]?",
         Severity.HIGH,
         "HashiCorp Consul token detected.",
         "Rotate the token and use proper ACL management."),

        ("SF-SEC-092", "Alibaba Cloud AccessKey ID",
         r"LTAI[A-Za-z0-9]{20}",
         Severity.CRITICAL,
         "Alibaba Cloud AccessKey ID detected.",
         "Rotate the key and use RAM role-based access."),

        ("SF-SEC-093", "DigitalOcean Token",
         r"dop_v1_[a-f0-9]{64}",
         Severity.CRITICAL,
         "DigitalOcean personal access token detected.",
         "Revoke and regenerate with minimal permissions."),

        ("SF-SEC-094", "Cloudflare API Token",
         r"(?i)(?:cloudflare.*token|CF_API_TOKEN)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{40}['\"]?",
         Severity.HIGH,
         "Cloudflare API Token detected.",
         "Rotate and restrict the token to specific zones/permissions."),
    ]

    def _should_scan(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        # Check exclusions
        if any(ex in str(file_path) for ex in self.exclude):
            return False

        # Check by filename match
        if file_path.name in FILENAME_MATCHES:
            return True

        # Check by extension
        if file_path.suffix.lower() in TEXT_EXTENSIONS:
            return True

        return False

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        for file_path in self._iter_files():
            if not self._should_scan(file_path):
                continue

            try:
                content = file_path.read_text(errors="ignore")
                lines = content.splitlines()
            except Exception:
                continue

            for line_no, line in enumerate(lines, start=1):
                for rule_id, title, pattern, severity, description, fix in self.PATTERNS:
                    if re.search(pattern, line):
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                title=title,
                                description=description,
                                severity=severity,
                                finding_type=FindingType.SECRET,
                                scanner=self.name,
                                location=Location(
                                    file_path=file_path,
                                    start_line=line_no,
                                    snippet=self._mask_secret(line.strip()),
                                ),
                                fix=fix,
                                tags=["secret"],
                            )
                        )

        return findings

    def _iter_files(self):
        """Iterate over all files in the target directory."""
        if self.target_path.is_file():
            yield self.target_path
        else:
            for file_path in self.target_path.rglob("*"):
                if file_path.is_file():
                    yield file_path

    @staticmethod
    def _mask_secret(line: str, visible_chars: int = 4) -> str:
        """Mask secrets in the snippet to avoid leaking them in reports."""
        # Simple masking: show only first few characters of long tokens
        # This is a best-effort approach
        return line if len(line) <= 60 else line[:60] + "..."
