from __future__ import annotations

import asyncio
import subprocess
import json
import sys
from pathlib import Path

from mcpguard.config.models import MCPConfig, ServerConfig
from mcpguard.detectors.unicode_scan import scan_text as unicode_scan, summarize as unicode_summarize
from mcpguard.detectors.patterns import scan_description, scan_param_name
from .base import BaseScanner, Finding, Severity


def _fetch_tool_schemas(server: ServerConfig, timeout: int = 10) -> tuple[list[dict] | None, str | None]:
    """Returns (tools, error_message). tools is None on failure."""
    if server.command is None:
        return None, "server has no command (remote-only server)"
    try:
        result = subprocess.run(
            [sys.executable, "-m", "mcpguard._mcp_probe",
             server.command, json.dumps(server.args), json.dumps(server.env)],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            return None, f"probe exited with code {result.returncode}" + (f": {stderr}" if stderr else "")
        tools = json.loads(result.stdout)
        return tools, None
    except subprocess.TimeoutExpired:
        return None, f"server did not respond within {timeout}s"
    except json.JSONDecodeError as e:
        return None, f"invalid JSON from probe: {e}"
    except Exception as e:
        return None, str(e)


class ToolPoisonScanner(BaseScanner):
    def __init__(self, connect: bool = False) -> None:
        self.connect = connect

    def scan(self, config: MCPConfig) -> list[Finding]:
        findings: list[Finding] = []
        for server in config.servers.values():
            if self.connect:
                tools, err = _fetch_tool_schemas(server)
                if tools is not None:
                    findings += self._analyze_tools(tools, server, config)
                else:
                    findings += [self._make(
                        Severity.INFO,
                        "TP-INFO",
                        f"Could not connect to server '{server.name}' for tool audit",
                        f"Reason: {err}. Static config checks still apply.",
                        server=server,
                        source_file=config.source_file,
                    )]
        return findings

    def _analyze_tools(
        self, tools: list[dict], server: ServerConfig, config: MCPConfig
    ) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            name = tool.get("name", "<unnamed>")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})

            unicode_hits = unicode_scan(description)
            if unicode_hits:
                findings.append(self._make(
                    Severity.CRITICAL,
                    "POI-001",
                    f"Invisible Unicode in tool '{name}' description",
                    f"Tool '{name}' on server '{server.name}' contains invisible Unicode: "
                    + unicode_summarize(unicode_hits),
                    server=server,
                    field_path=f"tool:{name}.description",
                    remediation=(
                        "Do not use this server. The invisible characters may encode "
                        "hidden instructions executed by the LLM without user visibility."
                    ),
                    source_file=config.source_file,
                ))

            pattern_hits = scan_description(description)
            for hit in pattern_hits:
                severity = (
                    Severity.CRITICAL
                    if hit.pattern_name == "injection_keyword"
                    else Severity.HIGH
                )
                findings.append(self._make(
                    severity,
                    "POI-002",
                    f"Suspicious pattern in tool '{name}': {hit.pattern_name}",
                    f"Matched '{hit.matched_text}' — context: ...{hit.context}...",
                    server=server,
                    field_path=f"tool:{name}.description",
                    remediation="Treat this server as potentially malicious. Do not approve its tools.",
                    source_file=config.source_file,
                ))

            properties = input_schema.get("properties", {})
            for param_name in properties:
                param_desc = properties[param_name].get("description", "")

                param_hit = scan_param_name(param_name)
                if param_hit:
                    findings.append(self._make(
                        Severity.HIGH,
                        "POI-003",
                        f"Suspicious parameter name in tool '{name}': {param_name}",
                        f"Parameter name '{param_name}' suggests credential extraction.",
                        server=server,
                        field_path=f"tool:{name}.inputSchema.properties.{param_name}",
                        remediation="Parameter names should not encode instructions or reference file paths.",
                        source_file=config.source_file,
                    ))

                if param_desc:
                    for hit in scan_description(param_desc):
                        findings.append(self._make(
                            Severity.HIGH,
                            "POI-004",
                            f"Suspicious pattern in parameter '{param_name}' description",
                            f"Tool '{name}', param '{param_name}': matched '{hit.matched_text}'",
                            server=server,
                            field_path=f"tool:{name}.inputSchema.properties.{param_name}.description",
                            remediation="Parameter descriptions should not contain instructions.",
                            source_file=config.source_file,
                        ))

        return findings
