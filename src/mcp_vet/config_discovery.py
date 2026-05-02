from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import MCPConfig, MCPServer


DEFAULT_CONFIG_CANDIDATES = [
    Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
    Path.home() / ".config/Claude/claude_desktop_config.json",
    Path.home() / ".cursor/mcp.json",
]


def discover_configs() -> list[Path]:
    return [path for path in DEFAULT_CONFIG_CANDIDATES if path.exists()]


def load_config(path: Path) -> MCPConfig:
    raw = _load_json(path)
    server_map = raw.get("mcpServers", {})
    servers = [
        MCPServer(
            name=name,
            command=server.get("command"),
            args=[str(arg) for arg in server.get("args", [])],
            env={str(key): str(value) for key, value in server.get("env", {}).items()},
            raw=server,
        )
        for name, server in server_map.items()
        if isinstance(server, dict)
    ]
    return MCPConfig(path=path, servers=servers, raw=raw)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data
