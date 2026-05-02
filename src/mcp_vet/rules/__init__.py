from __future__ import annotations

from collections.abc import Callable, Iterable

from mcp_vet.models import Finding, MCPServer
from mcp_vet.rules.command import check_command
from mcp_vet.rules.metadata import check_metadata
from mcp_vet.rules.prompt_injection import check_prompt_injection
from mcp_vet.rules.secrets import check_secrets


Rule = Callable[[MCPServer], Iterable[Finding]]

RULES: tuple[Rule, ...] = (
    check_metadata,
    check_command,
    check_secrets,
    check_prompt_injection,
)
