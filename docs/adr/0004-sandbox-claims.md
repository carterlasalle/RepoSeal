# ADR-0004: Sandbox claims match isolation

- Status: Accepted
- Date: 2026-07-12

Static analysis is always available. Dynamic execution is called sandboxed only when RepoSeal successfully activates a strong OS backend: Bubblewrap on Linux, Seatbelt on macOS, or a separately configured container/VM backend. A timeout or environment scrub alone is not a sandbox. Policy may require a strong backend and fail closed.

