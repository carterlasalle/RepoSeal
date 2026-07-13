# Codex integration

Launch Codex behind inherited command mediation:

```bash
reposeal run -- codex
```

For voluntary structured verification, register `reposeal mcp` as a stdio MCP server using [`../mcp/config.example.json`](../mcp/config.example.json). RepoSeal deliberately does not claim a native Codex pre-execution hook that Codex does not expose; the PATH firewall is the enforcement layer.

