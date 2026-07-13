# Cursor integration

Use both layers:

1. Start Cursor's agent CLI through `reposeal run -- cursor-agent` when available.
2. Register the RepoSeal MCP server from [`../mcp/config.example.json`](../mcp/config.example.json) so the agent can call `verify_dependency` before acquisition.

GUI subprocesses that do not inherit the wrapper PATH are outside the local shim guarantee; use the VS Code-compatible extension for visible verification commands and enterprise endpoint controls for mandatory GUI coverage.

