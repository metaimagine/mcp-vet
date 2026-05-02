from __future__ import annotations

from collections.abc import Iterable

from mcp_vet.models import Finding, MCPServer, Severity


SHELL_COMMANDS = {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"}
SHELL_FLAGS = {"-c", "/c", "-command"}


def check_command(server: MCPServer) -> Iterable[Finding]:
    command = (server.command or "").lower()
    args = [arg.lower() for arg in server.args]
    if command in SHELL_COMMANDS and any(arg in SHELL_FLAGS for arg in args):
        yield Finding(
            id="command.shell-wrapper",
            title="Server launches through a shell wrapper",
            severity=Severity.HIGH,
            server=server.name,
            evidence=f"{server.command} {' '.join(server.args)}",
            remediation="Replace shell wrappers with a direct executable and fixed arguments.",
            confidence=0.95,
        )
    if command in {"npx", "uvx"} and not any(_looks_pinned(arg) for arg in server.args):
        yield Finding(
            id="command.unpinned-package",
            title="Server appears to run an unpinned package",
            severity=Severity.MEDIUM,
            server=server.name,
            evidence=f"{server.command} {' '.join(server.args)}",
            remediation="Pin the server package version or use a reviewed local checkout.",
            confidence=0.75,
        )


def _looks_pinned(arg: str) -> bool:
    return "@" in arg and not arg.startswith("@")
