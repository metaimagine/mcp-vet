from __future__ import annotations

from collections.abc import Iterable
import re

from mcp_vet.models import Finding, MCPServer, Severity


SECRET_KEY_PATTERN = re.compile(r"(api[_-]?key|token|secret|password|credential)", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(r"(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,})")


def check_secrets(server: MCPServer) -> Iterable[Finding]:
    for key, value in server.env.items():
        if SECRET_KEY_PATTERN.search(key) or SECRET_VALUE_PATTERN.search(value):
            yield Finding(
                id="secret.env-value",
                title="Environment value looks like a secret",
                severity=Severity.HIGH,
                server=server.name,
                evidence=f"{key}={_redact(value)}",
                remediation="Move secrets to a local secret manager or environment outside the committed MCP config.",
                confidence=0.9,
            )


def _redact(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return f"{value[:2]}...{value[-2:]}"
