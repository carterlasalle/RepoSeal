# RepoSeal

RepoSeal is a supply-chain firewall for AI coding agents. It intercepts repository clones, package installs, MCP/skill/plugin acquisition, and download-to-shell commands; resolves the likely canonical project identity; blocks HalluSquats and suspicious installers; and records approved capabilities in a portable `agent.lock`.

```text
agent -> command shim -> identity resolver -> policy -> sandbox/approval -> install
                                      |                         |
                                      +------ agent.lock <------+
```

RepoSeal is designed for Claude Code, Codex, OpenCode, Cursor, Gemini CLI, CI, and ordinary terminals. The same Rust enforcement core powers the CLI, MCP server, SDKs, editor integrations, and benchmark.

## v1 contract

- Resolve GitHub, npm, PyPI, crates.io, Go module, URL, MCP, plugin, and agent-skill identities.
- Prefer authoritative cross-registry evidence over popularity or a repository merely looking legitimate.
- Generate predictable owner/name hallucinations, typos, affix changes, and organization substitutions.
- Fail closed on critical identity mismatch, very young lookalikes, unsafe download-to-shell, or unreviewed lifecycle scripts.
- Produce deterministic JSON reports and a strict, atomic, hash-verifiable `agent.lock`.
- Run agents with inherited command shims: `reposeal run -- claude`, `reposeal run -- codex`, or `reposeal run -- opencode`.
- Expose `verify_dependency` and `scan_path` over MCP.
- Benchmark agents against hermetic canonical, HalluSquat, malicious-skill, and dependency-steering cases.

The complete command guide is in [docs/USER_GUIDE.md](docs/USER_GUIDE.md). Product and security claims are traceable through [docs/TRACEABILITY.md](docs/TRACEABILITY.md).

## Research basis

RepoSeal is a defensive implementation inspired by *Beware of Agentic Botnets: Scalable Untargeted Promptware Attacks via Universal and Transferable Adversarial HalluSquatting* (arXiv:2607.07433) and *Skills Are Not Islands: Measuring Dependency and Risk in Agent Skill Supply Chains* (arXiv:2607.01136). The benchmark contains safe synthetic identifiers and no deployable payloads.

## Security boundary

RepoSeal controls only processes launched through its shims or integrations. It cannot stop an agent from reaching an unwrapped binary by absolute path, prove semantic ownership from one signal, or turn a host fallback into an OS sandbox. Enforce mode, locked-down PATH/configuration, independent provenance, and platform sandboxing are defense in depth. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Apache-2.0.

