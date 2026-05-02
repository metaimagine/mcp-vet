from __future__ import annotations

from collections.abc import Iterable

from mcp_vet.models import Finding, MCPServer, Severity


INJECTION_PHRASES = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "exfiltrate",
    "send the contents",
    "reveal your system prompt",
)


def check_prompt_injection(server: MCPServer) -> Iterable[Finding]:
    haystack = " ".join(str(value) for value in server.raw.values()).lower()
    for phrase in INJECTION_PHRASES:
        if phrase in haystack:
            yield Finding(
                id="prompt-injection.description",
                title="Tool metadata contains prompt-injection-like text",
                severity=Severity.MEDIUM,
                server=server.name,
                evidence=phrase,
                remediation="Review tool descriptions and metadata. Remove instructions aimed at the agent rather than the user.",
                confidence=0.7,
            )
            return
