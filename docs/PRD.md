# RepoSeal Product Requirements

**Release:** 1.0.0

## Problem

Coding agents can hallucinate plausible repositories, packages, and skill identifiers, then fetch attacker-controlled lookalikes with terminal privileges. Conventional scanners inspect content after identity selection; RepoSeal must decide whether the selected artifact is the intended canonical project before execution.

## Users and outcomes

| User | Outcome |
| --- | --- |
| Developer | Run an agent normally while unsafe acquisition is blocked with an actionable explanation |
| Maintainer | Publish canonical identities, domains, packages, and capability requirements |
| Security team | Enforce policy, private registries, approvals, inventories, and audit-ready lockfiles |
| Researcher/vendor | Run a reproducible benchmark and contribute non-weaponized attack cases |

## Product goals

- PG-01 mediate acquisition commands without modifying the agent.
- PG-02 determine canonical identity using multiple independent evidence classes.
- PG-03 detect predictable hallucination and lookalike patterns before execution.
- PG-04 freeze reviewed identity, integrity, dependencies, provenance, and permissions in `agent.lock`.
- PG-05 inspect install behavior without granting the installer normal host authority.
- PG-06 expose one enforcement model through native integrations and SDKs.
- PG-07 make agent acquisition safety measurable and shareable.

## v1 success gates

1. Every supported acquisition grammar has positive, bypass, and ambiguity fixtures.
2. A block results in zero child-process execution.
3. Lock writes are atomic and subsequent verification detects source, hash, or instruction drift.
4. Hermetic critical HalluSquat and malicious-install cases never execute.
5. JSON output is stable enough for SDKs and editor/CI consumers.
6. Linux and macOS builds, unit/integration/adversarial tests, documentation, and dependency policy pass in CI.
7. Release artifacts include checksums, SBOMs, and provenance attestations.

## Non-goals

RepoSeal v1 is not a malware classifier, vulnerability scanner, hosted reputation oracle, perfect owner-verification authority, or kernel security boundary. It does not claim that popularity proves identity. Live network evidence can be unavailable or manipulated; policy controls the fail-closed response.

