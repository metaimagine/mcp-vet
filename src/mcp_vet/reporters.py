from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import Finding, ScanReport


def print_terminal(report: ScanReport) -> None:
    console = Console()
    table = Table(title="mcp-vet findings")
    table.add_column("Severity")
    table.add_column("Server")
    table.add_column("Finding")
    table.add_column("Remediation")
    for finding in report.findings:
        table.add_row(
            finding.severity.value,
            finding.server or "-",
            f"{finding.id}: {finding.title}",
            finding.remediation,
        )
    if report.findings:
        console.print(table)
    else:
        console.print("[green]No findings detected.[/green]")


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# mcp-vet Report",
        "",
        "| Severity | Server | Finding | Evidence | Remediation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in report.findings:
        lines.append(
            f"| {finding.severity.value} | {finding.server or '-'} | {finding.id}: {finding.title} | "
            f"{_escape(finding.evidence)} | {_escape(finding.remediation)} |"
        )
    if not report.findings:
        lines.append("| info | - | no findings | - | No action required. |")
    return "\n".join(lines) + "\n"


def render_json(report: ScanReport) -> str:
    return json.dumps(_safe_report_dump(report), indent=2, sort_keys=True)


def render_sarif(report: ScanReport) -> str:
    rules = [_finding_to_rule(finding) for finding in report.findings]
    results = [_finding_to_result(finding) for finding in report.findings]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-vet",
                        "informationUri": "https://github.com/metaimagine/mcp-vet",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _finding_to_rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "help": {"text": finding.remediation},
    }


def _finding_to_result(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": finding.id,
        "level": _sarif_level(finding.severity.value),
        "message": {"text": f"{finding.title}: {finding.evidence}"},
        "locations": [],
    }


def _sarif_level(severity: str) -> str:
    return {"high": "error", "medium": "warning", "low": "note", "info": "none"}[severity]


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _safe_report_dump(report: ScanReport) -> dict[str, object]:
    payload = report.model_dump(mode="json")
    for config in payload.get("configs", []):
        if isinstance(config, dict):
            config["raw"] = _redact_env_blocks(config.get("raw"))
            for server in config.get("servers", []):
                if isinstance(server, dict):
                    server["env"] = {key: "<redacted>" for key in server.get("env", {})}
                    server["raw"] = _redact_env_blocks(server.get("raw"))
    return payload


def _redact_env_blocks(value: object) -> object:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if key == "env" and isinstance(item, dict):
                redacted[key] = {env_key: "<redacted>" for env_key in item}
            else:
                redacted[key] = _redact_env_blocks(item)
        return redacted
    if isinstance(value, list):
        return [_redact_env_blocks(item) for item in value]
    return value
