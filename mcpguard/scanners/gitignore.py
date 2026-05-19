from __future__ import annotations

from pathlib import Path

from mcpguard.config.models import MCPConfig
from .base import BaseScanner, Finding, Severity

_CONFIG_FILENAMES = {
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp_config.json",
}


def _is_gitignored(config_path: Path) -> bool:
    filename = config_path.name
    search_dir = config_path.parent
    for parent in [search_dir, *search_dir.parents]:
        gitignore = parent / ".gitignore"
        if gitignore.exists():
            for line in gitignore.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if line == filename or line == f"/{filename}" or line == f"**/{filename}":
                    return True
                if line == "*.json" and filename.endswith(".json"):
                    return True
        git_dir = parent / ".git"
        if git_dir.exists():
            break
    return False


def _is_inside_git_repo(path: Path) -> bool:
    for parent in [path, *path.parents]:
        if (parent / ".git").exists():
            return True
    return False


class GitIgnoreScanner(BaseScanner):
    def scan(self, config: MCPConfig) -> list[Finding]:
        findings = []
        if not config.source_file:
            return findings

        path = config.source_file

        if not _is_inside_git_repo(path.parent):
            return findings

        if path.name not in _CONFIG_FILENAMES:
            return findings

        if not _is_gitignored(path):
            findings.append(self._make(
                Severity.MEDIUM,
                "GI-001",
                f"{path.name} is not in .gitignore",
                f"'{path}' is inside a git repository but not listed in any .gitignore. "
                "Committing this file could expose hardcoded secrets to version control history.",
                field_path=str(path),
                remediation=(
                    f"Add '{path.name}' to your .gitignore file. "
                    "If secrets were already committed, rotate them immediately and "
                    "use 'git filter-repo' to purge the history."
                ),
                source_file=path,
            ))

        return findings
