# Technical Requirements

| ID | Requirement | Evidence |
| --- | --- | --- |
| TR-001 | Rust 1.97 stable, unsafe forbidden, strict Clippy/rustdoc | CI |
| TR-002 | Bounded identifiers 2 KiB, reports 10 MiB, MCP frames 1 MiB | limit tests |
| TR-003 | Registry HTTP uses HTTPS, finite deadlines, response caps, explicit user agent | provider tests |
| TR-004 | Canonical serialization sorts object keys, preserves arrays, rejects non-finite numbers | golden tests |
| TR-005 | Resolver caches metadata with source/expiry and never upgrades stale evidence to verified | cache tests |
| TR-006 | Edit distance and candidate generation are bounded by count and identifier length | property tests |
| TR-007 | Policy unknown fields and duplicate IDs fail compilation | invalid fixtures |
| TR-008 | Command parser never invokes a shell to execute ordinary package/repository commands | integration tests |
| TR-009 | Shell syntax is parsed only to identify unsafe pipelines and is blocked by default | grammar corpus |
| TR-010 | Lock and audit paths reject symlinks and unsafe replacement | filesystem tests |
| TR-011 | Sensitive environment values and tokens never appear in reports/logs | snapshots |
| TR-012 | Scanner traversal is bounded, ignores VCS/build directories, and refuses special files | scan tests |
| TR-013 | MCP validates JSON-RPC shape, IDs, methods, and frame size | conformance tests |
| TR-014 | SDK schemas and examples are tested against CLI JSON | contract tests |
| TR-015 | Median cached verification under 10 ms; live overhead documented separately | benchmark |
| TR-016 | Supported targets: Linux x86_64, macOS arm64/x86_64 | release CI |

