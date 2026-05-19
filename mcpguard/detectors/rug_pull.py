from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone


_STATE_DIR = Path.home() / ".mcpguard" / "state"
_STATE_FILE = _STATE_DIR / "tool_hashes.json"


def _load_state() -> dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_state(state: dict) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def hash_tool(tool: dict) -> str:
    canonical = json.dumps(
        {k: tool[k] for k in sorted(tool.keys()) if k != "name"},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def hash_toolset(server_name: str, tools: list[dict]) -> str:
    tool_hashes = sorted(hash_tool(t) for t in tools)
    combined = json.dumps({"server": server_name, "tools": tool_hashes})
    return hashlib.sha256(combined.encode()).hexdigest()


def check_and_update(server_name: str, tools: list[dict]) -> list[str]:
    """Returns list of changed tool names since last scan. Updates stored hashes."""
    state = _load_state()
    changed: list[str] = []

    server_state = state.get(server_name, {})
    new_hashes: dict[str, str] = {}

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        current_hash = hash_tool(tool)
        new_hashes[name] = current_hash

        if name in server_state:
            stored = server_state[name]
            if (stored.get("hash") if isinstance(stored, dict) else stored) != current_hash:
                changed.append(name)

    state[server_name] = {
        name: {"hash": h, "seen": datetime.now(timezone.utc).isoformat()}
        for name, h in new_hashes.items()
    }
    _save_state(state)

    return changed


def get_stored_hashes(server_name: str) -> dict[str, str]:
    state = _load_state()
    server_state = state.get(server_name, {})
    return {name: data["hash"] for name, data in server_state.items()}
