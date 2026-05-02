import json
from pathlib import Path

from mcp_vet.config_discovery import load_config


def test_load_config_extracts_mcp_servers(tmp_path: Path):
    config_path = tmp_path / "claude_desktop_config.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                        "env": {"SAFE_MODE": "1"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    loaded = load_config(config_path)

    assert loaded.path == config_path
    assert len(loaded.servers) == 1
    assert loaded.servers[0].name == "filesystem"
    assert loaded.servers[0].command == "npx"
    assert loaded.servers[0].args[-1] == "/tmp"


def test_load_config_handles_empty_server_map(tmp_path: Path):
    config_path = tmp_path / "empty.json"
    config_path.write_text('{"mcpServers": {}}', encoding="utf-8")

    loaded = load_config(config_path)

    assert loaded.servers == []
