# Contributing

Thanks for improving `mcp-vet`. The project is intentionally small: fast local checks, clear findings, and no network calls in the default scan path.

## Useful Contributions

- New deterministic rules for risky MCP config patterns.
- False-positive reductions with small fixtures.
- Additional MCP client config discovery paths.
- Better SARIF, Markdown, or terminal reporting.
- Documentation examples that help developers fix real MCP setup risks.

## Local Setup

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -v
```

## Pull Request Checklist

- Add or update tests for behavior changes.
- Keep secret values redacted in all output formats.
- Avoid network calls in the default scanner.
- Keep findings actionable: include severity, evidence, confidence, and remediation.
- Update `CHANGELOG.md` for user-visible changes.
