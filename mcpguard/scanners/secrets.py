from __future__ import annotations

import re
from dataclasses import dataclass

from mcpguard.config.models import MCPConfig, ServerConfig
from .base import BaseScanner, Finding, Severity


@dataclass
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    example: str


_PATTERNS: list[SecretPattern] = [
    SecretPattern("Anthropic API Key",    re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"), "sk-ant-..."),
    SecretPattern("OpenAI API Key",       re.compile(r"sk-(proj-)?[a-zA-Z0-9]{20,}"), "sk-..."),
    SecretPattern("GitHub Token (ghp)",   re.compile(r"ghp_[a-zA-Z0-9]{35,}"), "ghp_..."),
    SecretPattern("GitHub Token (ghs)",   re.compile(r"ghs_[a-zA-Z0-9]{36,}"), "ghs_..."),
    SecretPattern("GitHub PAT",           re.compile(r"github_pat_[a-zA-Z0-9_]{82,}"), "github_pat_..."),
    SecretPattern("Slack Bot Token",      re.compile(r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+"), "xoxb-..."),
    SecretPattern("Slack User Token",     re.compile(r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-zA-Z0-9]+"), "xoxp-..."),
    SecretPattern("AWS Access Key",       re.compile(r"AKIA[A-Z0-9]{16}"), "AKIA..."),
    SecretPattern("AWS Secret Key",       re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]?([a-zA-Z0-9/+]{40})['\"]?"), "..."),
    SecretPattern("Google API Key",       re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "AIza..."),
    SecretPattern("Bearer Token",         re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}"), "Bearer ..."),
    SecretPattern("Basic Auth Header",    re.compile(r"(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}"), "Basic ..."),
    SecretPattern("Connection String",    re.compile(r"[a-zA-Z][a-zA-Z0-9+\-.]+://[^:@\s]+:[^@\s]+@[^\s]+"), "proto://user:pass@host"),
    SecretPattern("Private Key Header",   re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"), "-----BEGIN PRIVATE KEY"),
    SecretPattern("Jira/Confluence Token",re.compile(r"[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}"), "UUID-style token"),
    SecretPattern("HuggingFace Token",    re.compile(r"hf_[a-zA-Z0-9]{34,}"), "hf_..."),
    SecretPattern("Stripe Key",           re.compile(r"(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}"), "sk_live_..."),
    SecretPattern("npm Token",            re.compile(r"npm_[a-zA-Z0-9]{36,}"), "npm_..."),
]

_SENSITIVE_KEY_NAMES = re.compile(
    r"(?i)(password|passwd|secret|token|api_?key|private_?key|auth|credential|access_?key|"
    r"client_?secret|db_?pass|database_?url|connection_?string)"
)


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "***" + value[-4:]


class SecretsScanner(BaseScanner):
    def scan(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []
        for server in config.servers.values():
            findings += self._scan_env(server, config)
            findings += self._scan_args(server, config)
            findings += self._scan_headers(server, config)
        return findings

    def _scan_env(self, server: ServerConfig, config: MCPConfig) -> list[Finding]:
        findings = []
        for key, value in server.env.items():
            matched_pattern = self._match_patterns(value)
            if matched_pattern:
                findings.append(self._make(
                    Severity.CRITICAL,
                    "SEC-001",
                    f"Hardcoded secret in env.{key}",
                    f"Secret matching '{matched_pattern.name}' detected in env field. "
                    f"Value: {_redact(value)}",
                    server=server,
                    field_path=f"mcpServers.{server.name}.env.{key}",
                    remediation=(
                        f"Replace the hardcoded value with an environment variable reference. "
                        f"Use ${{VAR_NAME}} syntax or remove from config and set it in your shell profile."
                    ),
                    source_file=config.source_file,
                ))
                continue

            if _SENSITIVE_KEY_NAMES.search(key) and value and not value.startswith("${"):
                findings.append(self._make(
                    Severity.HIGH,
                    "SEC-002",
                    f"Suspicious value in sensitive env key: {key}",
                    f"Key '{key}' suggests a credential but value doesn't match known patterns. "
                    f"Value: {_redact(value)}",
                    server=server,
                    field_path=f"mcpServers.{server.name}.env.{key}",
                    remediation="Verify this value is not a hardcoded credential.",
                    source_file=config.source_file,
                ))

        return findings

    def _scan_args(self, server: ServerConfig, config: MCPConfig) -> list[Finding]:
        findings = []
        for i, arg in enumerate(server.args):
            matched_pattern = self._match_patterns(arg)
            if matched_pattern:
                findings.append(self._make(
                    Severity.CRITICAL,
                    "SEC-003",
                    f"Hardcoded secret in args[{i}]",
                    f"Secret matching '{matched_pattern.name}' found in command argument. "
                    f"Value: {_redact(arg)}",
                    server=server,
                    field_path=f"mcpServers.{server.name}.args[{i}]",
                    remediation=(
                        "Connection strings and tokens in args are especially dangerous "
                        "as they appear in process listings. Move credentials to env vars."
                    ),
                    source_file=config.source_file,
                ))
        return findings

    def _scan_headers(self, server: ServerConfig, config: MCPConfig) -> list[Finding]:
        findings = []
        for key, value in server.headers.items():
            matched_pattern = self._match_patterns(value)
            if matched_pattern:
                findings.append(self._make(
                    Severity.CRITICAL,
                    "SEC-004",
                    f"Hardcoded secret in headers.{key}",
                    f"Secret matching '{matched_pattern.name}' found in HTTP header. "
                    f"Value: {_redact(value)}",
                    server=server,
                    field_path=f"mcpServers.{server.name}.headers.{key}",
                    remediation=(
                        "Use environment variable substitution for header values, "
                        "or load them from a secrets manager at runtime."
                    ),
                    source_file=config.source_file,
                ))
            elif key.lower() in ("authorization", "x-api-key", "x-auth-token") and value and "${" not in value:
                findings.append(self._make(
                    Severity.HIGH,
                    "SEC-005",
                    f"Potentially sensitive header: {key}",
                    f"Header '{key}' may contain a credential. Value: {_redact(value)}",
                    server=server,
                    field_path=f"mcpServers.{server.name}.headers.{key}",
                    remediation="Verify this header value is not a hardcoded secret.",
                    source_file=config.source_file,
                ))
        return findings

    def _match_patterns(self, value: str) -> SecretPattern | None:
        for pattern in _PATTERNS:
            if pattern.regex.search(value):
                return pattern
        return None
