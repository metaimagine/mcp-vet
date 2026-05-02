from __future__ import annotations

from pathlib import Path

import typer

from .config_discovery import discover_configs, load_config
from .reporters import print_terminal, render_json, render_markdown, render_sarif
from .scanner import scan_configs


app = typer.Typer(
    help="Local MCP security and configuration doctor for AI agents.",
    no_args_is_help=True,
)


@app.command()
def scan(
    config: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        exists=True,
        readable=True,
        help="Path to a specific MCP client config JSON file.",
    ),
) -> None:
    """Scan MCP configs and print a terminal report."""

    configs = _load_requested_configs(config)
    scan_report = scan_configs(configs)
    print_terminal(scan_report)


@app.command()
def report(
    config: Path = typer.Option(
        ...,
        "--config",
        "-c",
        exists=True,
        readable=True,
        help="Path to an MCP client config JSON file.",
    ),
    output_format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report format: markdown, json, or sarif.",
    ),
) -> None:
    """Render a machine-readable or shareable report."""

    scan_report = scan_configs([load_config(config)])
    if output_format == "markdown":
        typer.echo(render_markdown(scan_report))
    elif output_format == "json":
        typer.echo(render_json(scan_report))
    elif output_format == "sarif":
        typer.echo(render_sarif(scan_report))
    else:
        raise typer.BadParameter("format must be markdown, json, or sarif")


@app.command()
def explain(finding_id: str) -> None:
    """Explain a finding and show remediation guidance."""

    explanations = {
        "command.shell-wrapper": "Shell wrappers can hide arbitrary command chains. Use a direct executable with fixed arguments.",
        "command.unpinned-package": "Unpinned remote packages can change between runs. Pin versions or use a reviewed local checkout.",
        "secret.env-value": "Secrets in MCP configs are easy to commit or share. Move them to your shell environment or secret manager.",
        "prompt-injection.description": "Tool metadata is visible to agents. Remove text that tries to override the agent's instructions.",
        "metadata.missing-command": "Every MCP server needs a command field that launches the server.",
        "metadata.command-not-found": "The configured executable is not on PATH. Install it or use an absolute path.",
    }
    typer.echo(explanations.get(finding_id, f"No built-in explanation for {finding_id}."))


def _load_requested_configs(config: Path | None):
    paths = [config] if config else discover_configs()
    if not paths:
        raise typer.BadParameter("No MCP configs found. Pass --config PATH to scan a specific file.")
    return [load_config(path) for path in paths]
