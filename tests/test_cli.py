from typer.testing import CliRunner

from mcp_vet.cli import app


runner = CliRunner()


def test_cli_help_lists_scan_and_explain_commands():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "explain" in result.stdout
    assert "report" in result.stdout
