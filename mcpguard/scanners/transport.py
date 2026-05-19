from __future__ import annotations

from mcpguard.config.models import MCPConfig, ServerConfig
from .base import BaseScanner, Finding, Severity


class TransportScanner(BaseScanner):
    def scan(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []
        for server in config.servers.values():
            findings += self._check(server, config)
        return findings

    def _check(self, server: ServerConfig, config: MCPConfig) -> list[Finding]:
        findings = []

        if not server.url:
            return findings

        url = server.url.strip()

        if url.startswith("http://"):
            findings.append(self._make(
                Severity.HIGH,
                "TP-001",
                f"Remote server uses HTTP (unencrypted): {server.name}",
                f"Server '{server.name}' connects to '{url}' over plain HTTP. "
                "All tool calls, arguments, and responses travel in cleartext — "
                "API keys, secrets, and code snippets are exposed to network observers.",
                server=server,
                field_path=f"mcpServers.{server.name}.url",
                remediation="Change the URL scheme from http:// to https://. "
                            "If the server is local (localhost/127.0.0.1), this is lower risk.",
                source_file=config.source_file,
            ))

        if url.startswith("http://") and not any(
            local in url for local in ("localhost", "127.0.0.1", "::1")
        ):
            findings.append(self._make(
                Severity.CRITICAL,
                "TP-002",
                f"Non-local remote server over HTTP: {server.name}",
                f"'{url}' is a non-local HTTP endpoint. Credentials and tool output "
                "are fully exposed on the network path.",
                server=server,
                field_path=f"mcpServers.{server.name}.url",
                remediation="Enforce HTTPS on the remote server. Never connect to "
                            "non-local services over plain HTTP.",
                source_file=config.source_file,
            ))

        return findings
