from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from rich.console import Console

from mcpguard.config.models import MCPConfig
from mcpguard.scanners.supply_chain import _strip_version
from mcpguard.scanners.gitignore import _is_inside_git_repo, _is_gitignored

console = Console()


@dataclass
class Fix:
    description: str
    rule_id: str
    apply: Callable[[dict], None]


def _find_gitignore(config_path: Path) -> Path | None:
    for parent in [config_path.parent, *config_path.parent.parents]:
        gi = parent / ".gitignore"
        if gi.exists():
            return gi
        if (parent / ".git").exists():
            return parent / ".gitignore"
    return None


def _add_to_gitignore(config_path: Path) -> bool:
    gi_path = _find_gitignore(config_path)
    if gi_path is None:
        return False
    existing = gi_path.read_text(encoding="utf-8") if gi_path.exists() else ""
    # Check line-by-line to avoid substring false matches
    existing_entries = {
        line.strip() for line in existing.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    target = config_path.name
    if target in existing_entries or f"/{target}" in existing_entries:
        return False
    separator = "\n" if existing and not existing.endswith("\n") else ""
    gi_path.write_text(existing + separator + target + "\n", encoding="utf-8")
    return True


def _pin_package_in_args(args: list, package: str, version: str) -> list:
    bare = _strip_version(package)
    return [f"{bare}@{version}" if a == package else a for a in args]


def collect_fixes(config: MCPConfig, fetch_npm: bool = True) -> list[Fix]:
    fixes: list[Fix] = []
    raw = json.loads(config.source_file.read_text(encoding="utf-8")) if config.source_file else {}

    # GI-001: gitignore
    if config.source_file and _is_inside_git_repo(config.source_file.parent):
        if not _is_gitignored(config.source_file):
            path = config.source_file

            def _fix_gitignore(raw: dict, p: Path = path) -> None:
                _add_to_gitignore(p)

            fixes.append(Fix(
                description=f"Add '{config.source_file.name}' to .gitignore",
                rule_id="GI-001",
                apply=_fix_gitignore,
            ))

    # AA-001: autoApprove wildcard
    for name, server_data in raw.get("mcpServers", {}).items():
        aa = server_data.get("autoApprove", [])
        if aa == ["*"] or "*" in aa:
            def _fix_aa(raw: dict, sname: str = name) -> None:
                raw["mcpServers"][sname]["autoApprove"] = []

            fixes.append(Fix(
                description=f"Remove autoApprove wildcard from server '{name}'",
                rule_id="AA-001",
                apply=_fix_aa,
            ))

    # SC-001: unpinned packages
    from mcpguard.scanners.supply_chain import (
        _extract_package, _is_pinned, _NPX_COMMANDS, _PYTHON_COMMANDS
    )

    for name, server_data in raw.get("mcpServers", {}).items():
        cmd = (server_data.get("command") or "").split("/")[-1]
        if cmd not in _NPX_COMMANDS and cmd not in _PYTHON_COMMANDS:
            continue
        args = server_data.get("args", [])
        package = _extract_package(args)
        if not package or _is_pinned(package):
            continue

        if fetch_npm:
            from mcpguard.utils.npm import fetch_latest_version
            bare = _strip_version(package)
            version = fetch_latest_version(bare)
        else:
            version = None

        if version:
            def _fix_pin(raw: dict, sname: str = name, pkg: str = package, ver: str = version) -> None:
                raw["mcpServers"][sname]["args"] = _pin_package_in_args(
                    raw["mcpServers"][sname]["args"], pkg, ver
                )

            fixes.append(Fix(
                description=f"Pin '{_strip_version(package)}' to @{version} in server '{name}'",
                rule_id="SC-001",
                apply=_fix_pin,
            ))
        else:
            console.print(
                f"  [dim]Could not fetch version for '{_strip_version(package)}' — pin manually.[/dim]"
            )

    return fixes


def apply_fixes(config: MCPConfig, fixes: list[Fix], dry_run: bool = False) -> int:
    if not config.source_file:
        console.print("[red]No source file — cannot apply fixes.[/red]")
        return 0

    raw = json.loads(config.source_file.read_text(encoding="utf-8"))
    applied = 0

    for fix in fixes:
        if "pin manually" in fix.description:
            console.print(f"  [yellow]SKIP[/yellow]  {fix.description}")
            continue

        console.print(f"  [green]{'DRY ' if dry_run else ''}FIX[/green]  [{fix.rule_id}] {fix.description}")
        if not dry_run:
            fix.apply(raw)
            applied += 1

    if not dry_run and applied > 0:
        config.source_file.write_text(
            json.dumps(raw, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        console.print(f"\n[bold green]{applied} fix(es) applied[/bold green] → {config.source_file}")

    return applied
