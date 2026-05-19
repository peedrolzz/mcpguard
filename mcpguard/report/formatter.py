from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.rule import Rule

from mcpguard.scanners.base import Finding, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "bold cyan",
    Severity.LOW:      "dim white",
    Severity.INFO:     "dim",
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "[bold red]CRIT[/bold red]",
    Severity.HIGH:     "[bold yellow]HIGH[/bold yellow]",
    Severity.MEDIUM:   "[bold cyan]MED [/bold cyan]",
    Severity.LOW:      "[dim white]LOW [/dim white]",
    Severity.INFO:     "[dim]INFO[/dim]",
}

console = Console(highlight=False)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[f.severity.value] += 1
    return dict(counts)


def print_findings(findings: list[Finding], source_file: Path | None = None) -> None:
    if not findings:
        console.print("\n[bold green]No findings.[/bold green] Config looks clean.\n")
        return

    sorted_findings = sorted(findings, key=lambda f: f.severity.order)

    if source_file:
        console.print(Rule(f"[bold]{source_file}[/bold]", style="blue"))

    for f in sorted_findings:
        icon = _SEVERITY_ICON[f.severity]
        style = _SEVERITY_STYLE[f.severity]

        header = Text()
        header.append(f"  {f.rule_id}  ", style="bold dim")
        header.append(f.title, style=style)

        location_parts = []
        if f.server_name:
            location_parts.append(f"server: {f.server_name}")
        if f.field_path:
            location_parts.append(f"field: {f.field_path}")
        location = "  " + " | ".join(location_parts) if location_parts else ""

        body = f"\n[dim]{f.detail}[/dim]"
        if f.remediation:
            body += f"\n[bold green]Fix:[/bold green] {f.remediation}"

        panel_content = str(header) + location + body
        console.print(
            Panel(
                f"[{_SEVERITY_STYLE[f.severity]}]{f.title}[/{_SEVERITY_STYLE[f.severity]}]\n"
                f"[dim]{f.rule_id}{'  |  ' + f.server_name if f.server_name else ''}[/dim]\n\n"
                f"{f.detail}\n\n"
                + (f"[bold green]Fix:[/bold green] {f.remediation}" if f.remediation else ""),
                border_style=_SEVERITY_STYLE[f.severity].replace("bold ", ""),
                title=icon,
                title_align="left",
                padding=(0, 1),
            )
        )

    _print_summary(findings)


def _print_summary(findings: list[Finding]) -> None:
    counts = _severity_counts(findings)
    total = len(findings)

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for sev in order:
        count = counts.get(sev.value, 0)
        if count:
            table.add_row(
                Text(sev.value, style=_SEVERITY_STYLE[sev]),
                str(count),
            )

    table.add_row("TOTAL", str(total), style="bold")
    console.print(Rule("Summary", style="dim"))
    console.print(table)

    has_critical = counts.get("CRITICAL", 0) > 0
    has_high = counts.get("HIGH", 0) > 0
    if has_critical:
        console.print("[bold red]FAIL[/bold red] — Critical findings require immediate action.\n")
    elif has_high:
        console.print("[bold yellow]WARN[/bold yellow] — High-severity findings detected.\n")
    else:
        console.print("[bold green]PASS[/bold green] — No critical or high findings.\n")


def print_json(findings: list[Finding], to_string: bool = False) -> str | None:
    data = [f.as_dict() for f in findings]
    serialized = json.dumps(data, indent=2)
    if to_string:
        return serialized
    console.print_json(serialized)
    return None


_SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#d97706",
    "MEDIUM":   "#0891b2",
    "LOW":      "#6b7280",
    "INFO":     "#9ca3af",
}

_SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fffbeb",
    "MEDIUM":   "#ecfeff",
    "LOW":      "#f9fafb",
    "INFO":     "#f9fafb",
}


def print_html(findings: list[Finding]) -> str:
    import html as _html
    from datetime import datetime

    def h(s: str) -> str:
        return _html.escape(s)

    counts = _severity_counts(findings)
    total = len(findings)
    sorted_findings = sorted(findings, key=lambda f: f.severity.order)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def badge(sev: str) -> str:
        color = _SEVERITY_COLOR.get(sev, "#6b7280")
        return (
            f'<span style="background:{color};color:white;padding:2px 8px;'
            f'border-radius:4px;font-size:0.75rem;font-weight:bold">{h(sev)}</span>'
        )

    rows = ""
    for f in sorted_findings:
        color = _SEVERITY_COLOR.get(f.severity.value, "#6b7280")
        bg = _SEVERITY_BG.get(f.severity.value, "#f9fafb")
        server_cell = (
            f"<code style='color:#6b7280;font-size:0.8rem'>|  {h(f.server_name)}</code>"
            if f.server_name else ""
        )
        fix_cell = (
            f"<div style='color:#059669;font-size:0.85rem'><strong>Fix:</strong> {h(f.remediation)}</div>"
            if f.remediation else ""
        )
        path_cell = (
            f"<div style='color:#9ca3af;font-size:0.75rem;margin-top:4px'>{h(f.field_path)}</div>"
            if f.field_path else ""
        )
        rows += f"""
        <div class="finding" style="border-left:4px solid {color};background:{bg};
             padding:12px 16px;margin-bottom:12px;border-radius:0 6px 6px 0">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
            {badge(f.severity.value)}
            <code style="color:#6b7280;font-size:0.8rem">{h(f.rule_id)}</code>
            {server_cell}
          </div>
          <div style="font-weight:600;color:#111827;margin-bottom:4px">{h(f.title)}</div>
          <div style="color:#374151;font-size:0.9rem;margin-bottom:{"8px" if f.remediation else "0"}">{h(f.detail)}</div>
          {fix_cell}
          {path_cell}
        </div>"""

    summary_rows = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = counts.get(sev, 0)
        if cnt:
            color = _SEVERITY_COLOR[sev]
            summary_rows += (
                f'<tr><td style="padding:4px 12px">{badge(sev)}</td>'
                f'<td style="padding:4px 12px;font-weight:bold;color:{color}">{cnt}</td></tr>'
            )

    overall = "FAIL" if counts.get("CRITICAL", 0) else ("WARN" if counts.get("HIGH", 0) else "PASS")
    overall_color = "#dc2626" if overall == "FAIL" else ("#d97706" if overall == "WARN" else "#059669")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>mcpguard report — {now}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 860px; margin: 40px auto;
           padding: 0 20px; color: #111827; background: #fff; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 4px; }}
    .meta {{ color: #6b7280; font-size: 0.85rem; margin-bottom: 32px; }}
    .summary {{ display: flex; align-items: center; gap: 24px; margin-bottom: 32px;
                padding: 16px; background: #f9fafb; border-radius: 8px; }}
    .overall {{ font-size: 1.4rem; font-weight: bold; color: {overall_color}; }}
    table {{ border-collapse: collapse; }}
    td {{ vertical-align: middle; }}
    h2 {{ font-size: 1rem; text-transform: uppercase; letter-spacing: .05em;
          color: #6b7280; margin: 24px 0 12px; }}
  </style>
</head>
<body>
  <h1>mcpguard security report</h1>
  <div class="meta">Generated {now} &nbsp;·&nbsp; {total} finding(s)</div>

  <div class="summary">
    <div class="overall">{overall}</div>
    <table>
      {summary_rows}
      <tr><td style="padding:4px 12px"><strong>TOTAL</strong></td>
          <td style="padding:4px 12px;font-weight:bold">{total}</td></tr>
    </table>
  </div>

  <h2>Findings</h2>
  {"<p style='color:#059669'>No findings.</p>" if not sorted_findings else rows}
</body>
</html>"""


def exit_code(findings: list[Finding]) -> int:
    counts = _severity_counts(findings)
    if counts.get("CRITICAL", 0):
        return 2
    if counts.get("HIGH", 0):
        return 1
    return 0
