# RepoSeal v1 Specification

## Acquisition mediation

- FR-001 MUST recognize `git clone`, `gh repo clone`, npm/yarn/pnpm/bun add/install, pip/uv/poetry add/install, Cargo add/install, Go install/get, direct executable downloads, MCP additions, and skill/plugin installations.
- FR-002 MUST preserve exact arguments and environment for allowed commands and MUST NOT invoke a denied command.
- FR-003 MUST resolve the real executable without recursing through the RepoSeal shim directory.
- FR-004 MUST identify unsupported or ambiguous acquisition syntax and apply configured fail-closed policy.
- FR-005 `run` MUST prepend ephemeral shims to PATH and propagate a session identifier, lock path, policy path, and audit path.

## Identity resolution

- SR-001 MUST normalize resource identifiers without Unicode-confusable or URL-userinfo ambiguity.
- SR-002 MUST distinguish requested, resolved, canonical, and locked identity.
- SR-003 MUST collect attributable evidence for registry ownership, repository metadata, official source links, age/history, forks, releases, domains, and provenance.
- SR-004 MUST never treat a single popularity, README, or name-similarity signal as proof of identity.
- SR-005 MUST generate bounded predictable HalluSquat candidates and compare both owner and project.
- SR-006 MUST surface conflicting authoritative evidence as ambiguity rather than averaging it into “safe.”
- SR-007 network failure, rate limit, malformed metadata, or unsupported registry MUST be explicit evidence, never silent success.

## Policy and decision

- SR-010 Decisions are `verified`, `review`, or `blocked`; `blocked` takes precedence over every allow score.
- SR-011 Critical conditions include canonical mismatch, explicitly denied owner/domain, lock substitution, unsafe `curl|sh`, and critical install behavior.
- SR-012 High-risk lifecycle scripts and young lookalikes require block or explicit approval according to policy.
- SR-013 Every result MUST contain stable signal codes, severity, message, evidence source, and remediation.
- SR-014 Policy MUST be strict, versioned, deterministic, and default deny for unresolved acquisition in enforce mode.

## Lockfile and provenance

- SR-020 `agent.lock` MUST be strict YAML schema 1 with canonical component IDs and unique entries.
- SR-021 Entries MUST include exact identity/version/commit, source mapping, integrity, provenance, permissions, dependencies, instruction hash when relevant, approval history, and review time.
- SR-022 Lock integrity MUST bind all security fields using canonical JSON and SHA-256.
- SR-023 Writes MUST use create/flush/sync/rename and reject symlink lock paths.
- SR-024 Verification MUST report missing, additional, or changed components without running installers.

## Sandbox and scanning

- SR-030 Static scanning MUST cover lifecycle scripts, download-to-shell, encoded commands, credential paths, startup persistence, Docker socket, broad environment reads, and suspicious endpoints.
- SR-031 Execution inspection MUST use an available OS isolation backend and clearly identify when no strong backend exists.
- SR-032 Sandbox reports MUST include attempted filesystem, network, environment, process, and persistence behavior without storing secret values.
- SR-033 RepoSeal MUST NOT call an unisolated execution a sandbox.

## Integrations and benchmark

- FR-030 MCP MUST expose `verify_dependency` and `scan_path` with bounded JSON-RPC messages.
- FR-031 SDKs MUST return the same JSON report schema produced by the CLI.
- FR-032 Hooks and plugins MUST fail closed when RepoSeal is unavailable in enforce mode.
- FR-033 GitHub Action MUST validate policy, lockfile, manifests, skills, MCP configs, and changed acquisition files.
- FR-040 Benchmark results MUST state corpus version, agent label/version, protected/unprotected mode, counts, false-positive rate, elapsed time, and limitations.
- FR-041 Corpus payloads MUST be inert and safe for public CI.

