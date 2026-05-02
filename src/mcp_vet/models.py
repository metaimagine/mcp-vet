from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class MCPServer(BaseModel):
    name: str
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class MCPConfig(BaseModel):
    path: Path
    servers: list[MCPServer] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    server: str | None = None
    evidence: str
    remediation: str
    confidence: float = 1.0


class ScanReport(BaseModel):
    configs: list[MCPConfig] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
