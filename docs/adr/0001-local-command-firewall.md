# ADR-0001: Local inherited command firewall

- Status: Accepted
- Date: 2026-07-12

RepoSeal launches an agent with an ephemeral shim directory first in PATH. Shims mediate acquisition commands and delegate non-acquisition commands to the exact real executable without a shell. This works across agents without depending on optional voluntary tool calls. Absolute paths and processes outside the wrapped tree remain explicit limitations.

