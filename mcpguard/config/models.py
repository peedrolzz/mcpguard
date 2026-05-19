from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator


class ServerConfig(BaseModel):
    name: str = ""
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    auto_approve: list[str] = Field(default_factory=list, alias="autoApprove")
    disabled: bool = False
    disabled_tools: list[str] = Field(default_factory=list, alias="disabledTools")
    cwd: str | None = None
    timeout: int | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    type: str | None = None

    model_config = {"populate_by_name": True}

    @property
    def is_remote(self) -> bool:
        return self.url is not None

    @property
    def is_local(self) -> bool:
        return self.command is not None


class MCPConfig(BaseModel):
    servers: dict[str, ServerConfig] = Field(default_factory=dict)
    source_file: Path | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            servers = data.get("mcpServers") or data.get("servers") or {}
            named: dict[str, Any] = {}
            for name, cfg in servers.items():
                if isinstance(cfg, dict):
                    cfg = dict(cfg)
                    cfg["name"] = name
                named[name] = cfg
            return {"servers": named, "source_file": data.get("source_file")}
        return data
