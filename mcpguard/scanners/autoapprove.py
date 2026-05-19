from __future__ import annotations

from mcpguard.config.models import MCPConfig, ServerConfig
from .base import BaseScanner, Finding, Severity

_DESTRUCTIVE_TOOLS = {
    "write_file", "delete_file", "move_file", "create_file",
    "push_files", "create_or_update_file", "create_repository",
    "delete_repository", "create_pull_request", "merge_pull_request",
    "run_command", "execute_command", "bash", "shell",
    "send_email", "send_message",
    "create_issue", "close_issue",
    "delete_branch", "force_push",
    "drop_table", "delete_record", "truncate",
}


class AutoApproveScanner(BaseScanner):
    def scan(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []
        for server in config.servers.values():
            findings += self._check(server, config)
        return findings

    def _check(self, server: ServerConfig, config: MCPConfig) -> list[Finding]:
        findings = []
        aa = server.auto_approve

        if not aa:
            return findings

        wildcard = aa == ["*"] or "*" in aa

        if wildcard:
            findings.append(self._make(
                Severity.CRITICAL,
                "AA-001",
                "autoApprove wildcard — all tools run without user confirmation",
                f"Server '{server.name}' has autoApprove: [\"*\"]. Every tool call from this "
                "server executes silently. Combined with tool poisoning, this allows full "
                "exfiltration without any UI prompt.",
                server=server,
                field_path=f"mcpServers.{server.name}.autoApprove",
                remediation=(
                    "Remove autoApprove entirely or restrict to a minimal list of "
                    "truly read-only, low-risk tools (e.g. [\"list_directory\"])."
                ),
                source_file=config.source_file,
            ))
            return findings

        dangerous_approved = [t for t in aa if t.lower() in _DESTRUCTIVE_TOOLS]
        if dangerous_approved:
            findings.append(self._make(
                Severity.HIGH,
                "AA-002",
                "Destructive tools in autoApprove",
                f"Server '{server.name}' auto-approves destructive tools: "
                f"{', '.join(dangerous_approved)}. These execute without user confirmation.",
                server=server,
                field_path=f"mcpServers.{server.name}.autoApprove",
                remediation=(
                    "Remove destructive tools from autoApprove. Only non-destructive "
                    "read operations should bypass the approval dialog."
                ),
                source_file=config.source_file,
            ))

        if len(aa) > 10:
            findings.append(self._make(
                Severity.MEDIUM,
                "AA-003",
                "Large autoApprove list — broad silent execution surface",
                f"Server '{server.name}' auto-approves {len(aa)} tools. "
                "Broad auto-approval increases the blast radius of tool poisoning attacks.",
                server=server,
                field_path=f"mcpServers.{server.name}.autoApprove",
                remediation="Reduce autoApprove to only the minimum required tools.",
                source_file=config.source_file,
            ))

        return findings
