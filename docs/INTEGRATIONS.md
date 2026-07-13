# Integration Matrix

| Surface | Enforcement path | Structured verification | Failure behavior |
| --- | --- | --- | --- |
| Claude Code | `reposeal run -- claude` plus PreToolUse hook | MCP | hook/wrapper deny |
| Codex | `reposeal run -- codex` | MCP | wrapper denies |
| OpenCode | wrapper plus plugin `tool.execute.before` | SDK/MCP | plugin throws and wrapper denies |
| Cursor CLI | wrapper | MCP | wrapper denies |
| Cursor/VS Code GUI | extension commands; enterprise process controls for mandatory coverage | extension/MCP | UI warns; unavailable errors |
| Gemini CLI | `reposeal run -- gemini` | MCP | wrapper denies |
| Terminal | `reposeal guard` or shell alias/wrapper | CLI JSON | exit 2/10 |
| GitHub Actions | composite action | scan/lock CLI | job fails on critical findings |
| Python/TypeScript | local static binary | stable JSON | operational exception, decisions returned |

No integration reimplements policy. A vendor-specific layer converts its event into an exact command/reference, calls RepoSeal, and maps `verified`, `review`, or `blocked` into the native UI. Hooks must treat missing binary, timeout, or invalid JSON as denial in enforce mode.

