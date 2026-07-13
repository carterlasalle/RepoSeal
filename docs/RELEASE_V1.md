# RepoSeal 1.0 Release Evidence

RepoSeal 1.0 implements milestones M0–M10: specifications, typed identities, predictable HalluSquat generation, live registry/repository providers, evidence-preserving policy, atomic lockfile, capability manifests/attestations, static and dynamic installation controls, PATH shims, MCP, audit, benchmark, SDKs, editor/agent integrations, CI, SBOM, and release attestation.

Release evidence commands:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check advisories bans licenses sources
corepack yarn install --immutable
corepack yarn check
uv sync --project packages/python-sdk --locked
uv run --project packages/python-sdk python -m unittest discover -s packages/python-sdk/tests
python3 scripts/check_repo.py
cargo run -p reposeal -- benchmark --agent release-gate --json
```

The public benchmark is not an external security assessment. Live canonical-source accuracy needs ongoing curated evaluation and independent review. v1 does not claim an OS kernel boundary when no supported strong sandbox is available.

