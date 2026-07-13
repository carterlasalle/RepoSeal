# Implementation Plan

| Milestone | Outcome | Release evidence |
| --- | --- | --- |
| M0 | specifications, workspace, CI and test harness | docs/schema checks |
| M1 | canonical component identities and deterministic reports | golden/property tests |
| M2 | HalluSquat generation and risk signal engine | adversarial candidate corpus |
| M3 | live GitHub/npm/PyPI/crates/Go resolver and cache | provider fixtures/live opt-in tests |
| M4 | strict policy and fail-closed decision engine | decision tables/mutation cases |
| M5 | atomic `agent.lock`, manifests, integrity and approval history | drift/race/filesystem tests |
| M6 | static installer/skill/MCP scanning and sandbox backends | inert behavior corpus |
| M7 | CLI shims, agent runner, MCP and audit | zero-execution denial integration tests |
| M8 | benchmark and shareable reports/badges | hermetic benchmark snapshots |
| M9 | Python/TypeScript SDKs and all native integrations | contract/smoke tests |
| M10 | packaging, cross-platform release, SBOM, attestations, operations docs | final CI/release report |

Each security behavior lands as test/corpus contract, implementation, then integration/docs. No milestone may weaken unresolved-identity default denial to improve demo pass rate.

