# ADR-0003: Deterministic universal agent lockfile

- Status: Accepted
- Date: 2026-07-12

`agent.lock` is strict YAML for review but every component integrity value is computed over canonical JSON security fields. Components have typed IDs, exact source/integrity/provenance/permissions/dependencies/instruction hashes, and approval history. Unknown fields fail. Writes are atomic, durable where supported, and reject symlink targets.

