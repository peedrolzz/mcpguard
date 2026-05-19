from __future__ import annotations

import json
import sys
from pathlib import Path

from .models import MCPConfig


_CANDIDATES: list[Path] = []


def _build_candidates() -> list[Path]:
    home = Path.home()
    paths = [
        Path.cwd() / ".mcp.json",
        Path.cwd() / ".cursor" / "mcp.json",
        Path.cwd() / ".vscode" / "mcp.json",
    ]

    if sys.platform == "darwin":
        paths += [
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ]
    elif sys.platform == "win32":
        appdata = Path.home() / "AppData" / "Roaming"
        paths += [appdata / "Claude" / "claude_desktop_config.json"]
    else:
        paths += [
            home / ".config" / "claude" / "claude_desktop_config.json",
        ]

    paths += [
        home / ".claude.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
    ]
    return paths


def discover_configs(search_path: Path | None = None) -> list[Path]:
    found: list[Path] = []
    candidates = _build_candidates()

    if search_path is not None:
        extra = [
            search_path / ".mcp.json",
            search_path / ".cursor" / "mcp.json",
            search_path / ".vscode" / "mcp.json",
        ]
        candidates = extra + candidates

    seen: set[Path] = set()
    for p in candidates:
        resolved = p.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if p.exists():
            found.append(p)

    return found


class ConfigLoadError(Exception):
    pass


def load_config(path: Path) -> MCPConfig:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigLoadError(f"Cannot read {path}: {e}") from e

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigLoadError(f"Invalid JSON in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigLoadError(f"{path} does not contain a JSON object at the top level")

    raw["source_file"] = path

    try:
        return MCPConfig.model_validate(raw)
    except Exception as e:
        raise ConfigLoadError(f"Schema validation failed for {path}: {e}") from e


def load_all(search_path: Path | None = None) -> list[MCPConfig]:
    configs = []
    for p in discover_configs(search_path):
        try:
            configs.append(load_config(p))
        except ConfigLoadError:
            pass
    return configs
