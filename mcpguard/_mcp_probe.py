"""
Subprocess entrypoint: spawns an MCP server via stdio, calls tools/list,
prints the result as JSON to stdout, and exits.

Usage (called internally by tool_poison.py):
    python -m mcpguard._mcp_probe <command> <args_json> <env_json>
"""
from __future__ import annotations

import asyncio
import json
import os
import sys


async def _probe(command: str, args: list[str], env: dict[str, str]) -> list[dict]:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        return []

    merged_env = {**os.environ, **env}
    params = StdioServerParameters(command=command, args=args, env=merged_env)

    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=8)
                result = await asyncio.wait_for(session.list_tools(), timeout=8)
                return [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "inputSchema": t.inputSchema or {},
                    }
                    for t in result.tools
                ]
    except Exception:
        return []


def main() -> None:
    if len(sys.argv) < 4:
        print("[]")
        sys.exit(0)

    command = sys.argv[1]
    try:
        args = json.loads(sys.argv[2])
        env = json.loads(sys.argv[3])
    except (json.JSONDecodeError, IndexError):
        print("[]")
        sys.exit(1)

    tools = asyncio.run(_probe(command, args, env))
    print(json.dumps(tools))


if __name__ == "__main__":
    main()
