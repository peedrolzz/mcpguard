# mcpguard

Security scanner for MCP (Model Context Protocol) agent configurations.

Audits `.mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, and other AI agent config files for hardcoded secrets, dangerous permissions, supply chain risks, and tool poisoning attacks.

```
$ mcpguard scan .mcp.json

╭─ CRIT ─────────────────────────────────────────────────╮
│ Hardcoded secret in env.GITHUB_TOKEN                   │
│ SEC-001  |  github                                     │
│ Secret matching 'GitHub Token (ghp)' detected.         │
│ Fix: Use ${GITHUB_TOKEN} instead.                      │
╰────────────────────────────────────────────────────────╯

  CRITICAL   2
  HIGH       3
  TOTAL      5

FAIL — Critical findings require immediate action.
```

---

## Why

MCP configs are a new and actively exploited attack surface:

- **24,008 secrets** found in public MCP config files on GitHub (GitGuardian, 2026)
- **CVE-2025-6514** (CVSS 9.6) — command injection via `mcp-remote`
- **CVE-2025-68145** — RCE in Anthropic's own git MCP server
- **postmark-mcp v1.0.16** — malicious npm update silently BCC'd all emails sent through the server
- Tool poisoning via invisible Unicode (U+E0000–U+E007F) in tool descriptions

Existing tools (`mcp-scan`) send your tool schemas to external servers and miss static config issues. `mcpguard` runs fully offline.

---

## Install

```bash
git clone https://github.com/peedrolzz/mcpguard
cd mcpguard
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Usage

### `scan` — static config audit

```bash
# Auto-discover and scan all MCP configs on the system
mcpguard scan

# Scan a specific file
mcpguard scan .mcp.json

# Scan a directory
mcpguard scan ~/projects/myapp

# Scan all system-wide configs (Claude Desktop, Windsurf, etc.)
mcpguard scan --all

# Connect to each server and audit live tool schemas (tool poisoning detection)
mcpguard scan --connect .mcp.json

# JSON output for CI/CD pipelines
mcpguard scan --json .mcp.json

# HTML report saved to file
mcpguard scan --format html -o report.html .mcp.json

# Exit codes: 0=clean, 1=HIGH findings, 2=CRITICAL findings
mcpguard scan --fail-on critical .mcp.json
```

### `fix` — auto-remediate simple issues

```bash
# Preview what would be fixed (dry-run)
mcpguard fix --dry-run .mcp.json

# Apply fixes in-place
mcpguard fix .mcp.json
```

Fixes applied automatically:
- Adds config file to `.gitignore` if missing
- Pins unpinned `npx` package versions (fetches current version from npm registry)
- Replaces `autoApprove: ["*"]` with an empty list

### `watch` — real-time schema monitor

```bash
mcpguard watch .mcp.json
```

Polls tool schemas and alerts when a hash changes between runs (rug pull detection).

### `discover` — list all config files found

```bash
mcpguard discover
mcpguard discover ~/projects
```

### `explain` — rule reference

```bash
mcpguard explain SEC-001
mcpguard explain AA-001
mcpguard explain POI-001
```

---

## Rules

| Rule    | Severity | Description |
|---------|----------|-------------|
| SEC-001 | CRITICAL | Hardcoded secret in `env` field |
| SEC-003 | CRITICAL | Hardcoded secret in `args` (connection string) |
| SEC-004 | CRITICAL | Hardcoded secret in `headers` |
| SEC-002 | HIGH     | Suspicious value in sensitive env key |
| SEC-005 | HIGH     | Sensitive header with non-env-var value |
| AA-001  | CRITICAL | `autoApprove: ["*"]` — full silent execution |
| AA-002  | HIGH     | Destructive tools in `autoApprove` |
| AA-003  | MEDIUM   | Large `autoApprove` list (>10 tools) |
| SC-001  | HIGH     | Unpinned `npx` package version |
| SC-002  | HIGH     | Package name resembles known package (typosquat) |
| SC-003  | LOW      | `npx` without `-y` flag |
| TP-001  | HIGH     | Remote server using HTTP |
| TP-002  | CRITICAL | Non-local server using plain HTTP |
| GI-001  | MEDIUM   | Config file not in `.gitignore` |
| POI-001 | CRITICAL | Invisible Unicode characters in tool description |
| POI-002 | CRITICAL | Injection keywords in tool description |
| POI-003 | HIGH     | Suspicious parameter name (credential extraction pattern) |
| POI-004 | HIGH     | Injection pattern in parameter description |

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Audit MCP config
  run: |
    pip install mcpguard
    mcpguard scan --json .mcp.json | tee mcpguard-report.json
    mcpguard scan --fail-on high .mcp.json
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: mcpguard
        name: Audit MCP configs
        entry: mcpguard scan --fail-on critical
        language: python
        files: '(\.mcp\.json|claude_desktop_config\.json|mcp_config\.json)$'
```

---

## Supported config files

| Client | Config path |
|--------|-------------|
| Claude Code | `.mcp.json` (project), `~/.claude.json` (user) |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Linux) | `~/.config/claude/claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` |
| VS Code Copilot | `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

---

## Architecture

```
mcpguard/
├── config/
│   ├── models.py       # Pydantic models (MCPConfig, ServerConfig)
│   └── loader.py       # Multi-platform config discovery
├── scanners/
│   ├── base.py         # Finding, Severity, BaseScanner
│   ├── secrets.py      # Hardcoded credential detection (18 patterns)
│   ├── autoapprove.py  # autoApprove misconfiguration
│   ├── supply_chain.py # Unpinned packages + typosquatting
│   ├── transport.py    # HTTP vs HTTPS enforcement
│   ├── gitignore.py    # Version control exposure check
│   └── tool_poison.py  # Live tool schema analysis
├── detectors/
│   ├── unicode_scan.py # Invisible character detection (8 Unicode ranges)
│   ├── patterns.py     # Injection keyword + file path patterns
│   └── rug_pull.py     # SHA-256 schema hash tracking
└── report/
    └── formatter.py    # Rich terminal + JSON + HTML output
```

---

## License

MIT
