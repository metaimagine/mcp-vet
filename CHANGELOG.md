# Changelog

## v0.1.0 - 2026-05-02

Initial public release of `mcp-vet`.

### Added

- Local MCP config scanning for Claude Desktop, Cursor, Codex, Gemini CLI, and custom config paths.
- Detection for shell-wrapper launches, likely secret values, prompt-injection-like metadata, unpinned `npx` or `uvx` packages, and missing commands.
- Terminal, Markdown, JSON, and SARIF reporting.
- Redaction of likely secret values in findings and JSON output.
- Example risky and safe MCP configs for demos and tests.
- GitHub Actions CI.

### Scope

This release is a local static scanner. It does not sandbox MCP servers, inspect remote package contents, or guarantee that a server is safe.
