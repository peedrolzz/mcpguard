from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path

from mcpguard.config.models import MCPConfig, ServerConfig


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    def __lt__(self, other: "Severity") -> bool:
        return self.order < other.order


@dataclass
class Finding:
    severity: Severity
    rule_id: str
    title: str
    detail: str
    server_name: str = ""
    field_path: str = ""
    remediation: str = ""
    source_file: Path | None = None

    def as_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "detail": self.detail,
            "server_name": self.server_name,
            "field_path": self.field_path,
            "remediation": self.remediation,
            "source_file": str(self.source_file) if self.source_file else None,
        }


class BaseScanner(ABC):
    @abstractmethod
    def scan(self, config: MCPConfig) -> list[Finding]:
        ...

    def _make(
        self,
        severity: Severity,
        rule_id: str,
        title: str,
        detail: str,
        server: ServerConfig | None = None,
        field_path: str = "",
        remediation: str = "",
        source_file: Path | None = None,
    ) -> Finding:
        return Finding(
            severity=severity,
            rule_id=rule_id,
            title=title,
            detail=detail,
            server_name=server.name if server else "",
            field_path=field_path,
            remediation=remediation,
            source_file=source_file,
        )
