# Test Strategy

- T-01 unit/golden tests: parsing, canonicalization, hashing, candidate generation, scoring, policy, lockfile.
- T-02 property tests: bounded identifiers, edit transformations, order stability, round trips.
- T-03 provider contract tests: recorded GitHub/npm/PyPI/crates/Go metadata, conflicts, rate limits, malformed/oversized responses.
- T-04 command grammar tests: every supported manager plus aliases, flags, workspaces, URLs, ambiguity, and bypass attempts.
- T-05 process integration: denied child count is zero; allowed argv/env/cwd/exit code are preserved.
- T-06 adversarial corpus: HalluSquats, cloned README, lifecycle scripts, malicious skills, MCP configs, dependency steering, encoded instructions.
- T-07 filesystem/fault tests: symlinks, permission failure, crash before rename, corrupted lock/cache/audit.
- T-08 MCP/SDK/integration contracts: identical report schema and fail-closed unavailable behavior.
- T-09 sandbox tests: backend selection, strong/weak labeling, inert behavior observations, time/resource bounds.
- T-10 performance: cached verification, scanner throughput, candidate limits, benchmark overhead.
- T-11 release: fmt, clippy, test, rustdoc, dependency/license/secret checks, docs/schema validation, target builds, checksums, SBOM, attestations.

The public corpus contains no active reverse shell, credential theft, persistence, or destructive command. Expected limitations are labeled and cannot be counted as blocks.

