from __future__ import annotations

from collections.abc import Iterable
from shutil import which

from mcp_vet.models import Finding, MCPServer, Severity


def check_metadata(server: MCPServer) -> Iterable[Finding]:
    if not server.command:
        yield Finding(
            id="metadata.missing-command",
            title="Server has no command",
            severity=Severity.HIGH,
            server=server.name,
            evidence="command is missing",
            remediation="Add a command field that points to the MCP server executable.",
            confidence=1.0,
        )
        return

    command = server.command
    if "/" not in command and "\\" not in command and which(command) is None:
        yield Finding(
            id="metadata.command-not-found",
            title="Server command is not on PATH",
            severity=Severity.MEDIUM,
            server=server.name,
            evidence=command,
            remediation="Install the executable or use an absolute path to the server command.",
            confidence=0.85,
        )
