# Threat Model

## Assets

Developer source, credentials, agent configuration, shell startup files, signing identities, package integrity, canonical project identity, lockfiles, and the trust decision itself.

## Trust boundaries

Untrusted inputs include agent output, command arguments, repository/package/skill content, README instructions, registry metadata, DNS/HTTP responses, MCP configuration, local project files, and benchmark submissions. The RepoSeal binary, reviewed policy, lockfile trust root, OS isolation backend, and configured enterprise roots form the v1 TCB.

## Threats and controls

| Threat | Primary controls | Residual risk |
| --- | --- | --- |
| Predictable HalluSquat | canonical cross-evidence, candidate generator, age/owner mismatch, default deny | novel hallucination outside candidate set |
| Typosquat/confusable | strict parsing, Unicode/control rejection, edit distance, owner/project comparison | visually similar ASCII with legitimate history |
| Registry/repository takeover | lock pin, ownership/source cross-check, age/history/provenance | legitimate maintainer compromise |
| README/source clone | similarity signal plus lineage/age/owner evidence | independently rewritten clone |
| Malicious lifecycle script | static scan, strong sandbox backend, approval | kernel/virtualization escape |
| Documentation payload | scan fenced commands/instructions and dependency steering | semantic obfuscation |
| Shim bypass | session checks, doctor, enterprise PATH policy | absolute executable path or separate process |
| TOCTOU | commit/version/tree/instruction hashes, post-fetch verification | mutable external service before pinning |
| Lock substitution | canonical digest, atomic no-symlink writes, review history | attacker controlling user account and trust roots |
| Evidence poisoning | attributable/conflict-preserving evidence; no single-signal proof | correlated compromise of authorities |
| DoS/rate limit | bounded timeouts/cache and explicit unavailable result | fail-closed work interruption |

RepoSeal does not make an allowed dependency harmless. AgentGate should constrain runtime capability and LeakLens should detect disclosure; these are complementary boundaries.

