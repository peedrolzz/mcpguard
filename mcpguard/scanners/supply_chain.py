from __future__ import annotations

import re
from difflib import SequenceMatcher

from mcpguard.config.models import MCPConfig, ServerConfig
from .base import BaseScanner, Finding, Severity

_VERSION_RE = re.compile(r"@\d+\.\d+")

_KNOWN_PACKAGES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-aws-kb-retrieval",
    "@anthropic-ai/claude-code",
    "mcp-server-git",
    "mcp-remote",
    "mcp",
    "@cursor/mcp",
]

_PACKAGE_RE = re.compile(r"^(@[a-z0-9\-]+/[a-z0-9\-]+|[a-z0-9\-]+)(@[^\s]+)?$")

_NPX_COMMANDS = {"npx", "bunx", "pnpx", "yarn dlx"}
_PYTHON_COMMANDS = {"uvx", "pipx"}


def _extract_package(args: list[str]) -> str | None:
    clean = [a for a in args if a not in ("-y", "--yes", "--no", "-p", "-q", "--quiet")]
    for arg in clean:
        if _PACKAGE_RE.match(arg):
            return arg
    return None


def _strip_version(package: str) -> str:
    at_idx = package.rfind("@", 1)
    if at_idx == -1:
        return package
    return package[:at_idx]


def _is_pinned(package: str) -> bool:
    at_idx = package.rfind("@", 1)
    if at_idx == -1:
        return False
    version_part = package[at_idx + 1:]
    return bool(_VERSION_RE.match("@" + version_part))


def _typosquat_score(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


class SupplyChainScanner(BaseScanner):
    def scan(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []
        for server in config.servers.values():
            findings += self._check(server, config)
        return findings

    def _check(self, server: ServerConfig, config: MCPConfig) -> list[Finding]:
        findings = []

        if not server.command:
            return findings

        cmd = server.command.split("/")[-1]

        if cmd not in _NPX_COMMANDS and cmd not in _PYTHON_COMMANDS:
            return findings

        package = _extract_package(server.args)
        if not package:
            return findings

        if not _is_pinned(package):
            findings.append(self._make(
                Severity.HIGH,
                "SC-001",
                f"Unpinned package: {package}",
                f"Server '{server.name}' uses '{package}' without a pinned version. "
                f"'{cmd} -y {package}' pulls the latest version on every agent startup. "
                "A compromised update is silently accepted.",
                server=server,
                field_path=f"mcpServers.{server.name}.args",
                remediation=(
                    f"Pin the exact version: replace '{package}' with "
                    f"'{_strip_version(package)}@<exact-version>'. "
                    "Check the current version on npmjs.com and commit the lock."
                ),
                source_file=config.source_file,
            ))

        bare = _strip_version(package)
        # Only flag typosquats for packages NOT already in the known-good list
        if bare not in _KNOWN_PACKAGES:
          squats = self._find_typosquats(bare)
        else:
          squats = []
        if squats:
            findings.append(self._make(
                Severity.HIGH,
                "SC-002",
                f"Possible typosquat: {bare}",
                f"Package '{bare}' closely resembles known legitimate packages: "
                f"{', '.join(squats)}. Edit distance ≤ 2.",
                server=server,
                field_path=f"mcpServers.{server.name}.args",
                remediation=(
                    "Verify the package name on npmjs.com. Check the publisher, "
                    "download count, and creation date before trusting."
                ),
                source_file=config.source_file,
            ))

        if "-y" not in server.args and "--yes" not in server.args and cmd == "npx":
            findings.append(self._make(
                Severity.LOW,
                "SC-003",
                f"npx without -y flag — may prompt on first run",
                f"Server '{server.name}' runs npx without -y. This may hang silently "
                "waiting for user confirmation in non-interactive mode.",
                server=server,
                field_path=f"mcpServers.{server.name}.args",
                remediation="Add '-y' to args if the server must start unattended.",
                source_file=config.source_file,
            ))

        return findings

    def _find_typosquats(self, package: str) -> list[str]:
        matches = []
        for known in _KNOWN_PACKAGES:
            if known == package:
                continue
            score = _typosquat_score(package, known)
            if score >= 0.85 and package != known:
                matches.append(known)
        return matches
