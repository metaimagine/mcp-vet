from __future__ import annotations

from pathlib import Path

import typer


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

    typer.echo(f"scan requested for {config or 'auto-discovered configs'}")


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

    typer.echo(f"report requested for {config} as {output_format}")


@app.command()
def explain(finding_id: str) -> None:
    """Explain a finding and show remediation guidance."""

    typer.echo(f"explain requested for {finding_id}")
