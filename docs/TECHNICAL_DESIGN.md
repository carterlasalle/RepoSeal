# Technical Design

RepoSeal uses a small Rust TCB with transport-neutral reports. `reposeal-core` owns identities/signals/decisions and canonical bytes; resolver providers cannot decide. `reposeal-policy` deterministically converts evidence into a decision. Lockfile and sandbox crates own persistent state and execution isolation. The CLI composes these contracts and is the only crate that spawns agent or intercepted child processes.

## Verification pipeline

1. Parse an acquisition command or explicit component reference.
2. Normalize it to a typed requested identity; reject ambiguity/control characters.
3. Query applicable registry/repository providers with deadlines and response caps.
4. Derive canonical-source claims and preserve conflicts.
5. Generate bounded HalluSquat variants and compare requested/canonical identities.
6. Scan retrieved metadata or local staged content without executing it.
7. Evaluate non-bypassable blocks, policy rules, review obligations, then verified conditions.
8. Emit the same versioned report to terminal/JSON/MCP/SDK integrations.
9. For an approved successful acquisition, pin exact evidence and permissions in `agent.lock`.

## Interception

`run` creates an owner-only temporary directory containing hard links/copies of the RepoSeal binary named for wrapped commands and prepends it to PATH. On startup, argv[0] selects shim mode. The shim parses the command, verifies acquisition, and only then resolves the real executable in the remainder of PATH. Non-acquisition commands pass through unchanged. Absolute-path bypass is outside the local v1 guarantee and reported by `doctor`.

## Failure model

Malformed identity, evidence conflict, policy/config/lock corruption, unavailable required provider, unsafe shell pipeline, missing strong sandbox, or internal error is never translated into verified. JSON and audit output distinguish block from operational failure.

