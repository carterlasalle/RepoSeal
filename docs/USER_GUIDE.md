# RepoSeal User Guide

## Install

Build from a reviewed checkout:

```bash
cargo build --locked --release -p reposeal
cargo install --locked --path crates/reposeal-cli
reposeal doctor
```

Tagged releases provide checksummed Linux x86_64 and macOS arm64/x86_64 binaries plus SBOM and GitHub artifact attestation. Verify those artifacts before installation.

## Start with policy

```bash
reposeal init
reposeal verify github:astral-sh/uv
reposeal verify npm:@modelcontextprotocol/sdk
reposeal verify pypi:ruff
reposeal verify skill:example/security-review
```

Exit 0 means verified, 2 means review, 10 means blocked, and 3 means an operational failure. JSON output contains the same decision:

```bash
reposeal verify github:astral-sh/uv --json > report.json
```

Provider failure, rate limiting, malformed metadata, or missing canonical evidence never becomes verified. Use an exact reviewed lock entry for controlled offline operation.

## Protect an agent

```bash
reposeal run -- claude
reposeal run -- codex
reposeal run -- opencode
reposeal run -- gemini
```

The agent inherits RepoSeal shims for Git/GitHub CLI, npm/npx/yarn/pnpm/bun, pip/uv/Poetry, Cargo, Go, curl, and wget. A denied acquisition returns before the real executable starts. Ordinary commands such as `git status` pass through unchanged.

Use the native hook/plugin plus the wrapper when an agent supports hooks. The wrapper is the general enforcement layer; MCP is a voluntary structured interface. Absolute executable paths and processes outside this wrapped tree remain outside the local shim guarantee.

## Lock reviewed capabilities

```bash
reposeal lock add github:astral-sh/uv --commit 38b94d4
reposeal lock verify agent.lock
reposeal verify github:astral-sh/uv --offline
```

Review decisions require `--approve`; blocked decisions cannot be locked. Every entry binds identity, exact version/commit, integrity facts, permissions, dependencies, instruction hash, provenance, approvals, and review time. Unknown fields, noncanonical IDs, missing dependencies, reordering, and any entry-field modification fail verification.

For a skill, compute and retain the normalized instruction hash through the provenance SDK/API, list transitive dependencies, and record shell/network/filesystem/environment capabilities. A lock is a reviewed trust record, not a malware-clean certificate.

## Scan and isolate installation

```bash
reposeal scan path/to/staged-source
reposeal scan . --ignore-file .reposealignore
reposeal sandbox plan --workspace /tmp/reposeal-stage -- npm install
reposeal sandbox inspect --workspace /tmp/reposeal-stage -- npm install
```

Static scanning detects download-to-shell, credential paths, Docker socket access, startup persistence, encoded execution, broad environment enumeration, lifecycle scripts, subprocesses, and instruction override content. Dynamic inspection executes only if Bubblewrap or macOS Seatbelt was successfully selected. When no strong backend exists, RepoSeal says unavailable and refuses to call the execution sandboxed.

Path exclusions are operator-controlled and rooted. RepoSeal never auto-discovers an ignore file from the tree being scanned, because an untrusted package could otherwise exempt its own payload. Pass `--ignore-file` explicitly for reviewed research fixtures or generated content; entries are exact rooted paths or directory prefixes ending in `/` or `/**`, with no negation or rule-level suppression.

## Capability manifests and provenance

Maintainers publish `reposeal.manifest.json` using the schema under `spec/`:

```bash
reposeal manifest check reposeal.manifest.json
```

The manifest declares canonical identities, domains, dependencies, and permissions. Attestation authorization additionally requires a cryptographically verified external result whose issuer, subject, manifest digest, and commit exactly match local trust policy. RepoSeal never treats a merely well-formed bundle as a verified signature.

## MCP

Run `reposeal mcp` over stdio and register [`integrations/mcp/config.example.json`](../integrations/mcp/config.example.json). Tools:

- `verify_dependency`: returns the stable verification report.
- `scan_path`: statically scans local staged content.

Frames larger than one MiB, malformed JSON-RPC, unknown methods, and invalid arguments fail closed.

## Hooks and SDKs

- Claude Code: `integrations/claude-code/`
- Codex, Cursor, Gemini CLI: `integrations/`
- OpenCode: `packages/opencode-plugin/`
- VS Code/Cursor-compatible editor command UI: `packages/vscode-extension/`
- TypeScript: `@reposeal/sdk`
- Python: `reposeal`
- GitHub Actions: `packages/github-action/action.yml`

SDKs invoke the Rust binary without a shell and accept policy decision exits as structured reports. Operational failures remain exceptions so callers cannot confuse “RepoSeal unavailable” with “verified.”

## Benchmark

```bash
reposeal benchmark --agent "Claude Code 2026.07"
reposeal benchmark --agent codex --json
```

The default v1 run is hermetic: 100 canonical, 100 HalluSquat, and 50 malicious-install cases. The agent name is a label for the protected configuration; it is not an unprotected model evaluation. Share the corpus ID/hash and limitations with any score.

## Audit and incident handling

Every verification appends metadata to `.reposeal/audit.jsonl` without arguments, tokens, or environment values:

```bash
reposeal audit verify .reposeal/audit.jsonl
```

If a suspicious install was attempted, stop the agent, preserve the policy/lock/audit/report and exact command, confirm the child did not execute, rotate any credential that an unisolated installer may have accessed, and report RepoSeal bypasses privately through `SECURITY.md`.
