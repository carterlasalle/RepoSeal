# Repository Identity Attestation v1

A maintainer may publish `.well-known/reposeal.json` or `reposeal.manifest.json` containing the capability manifest and a Sigstore bundle or detached signature. The attested subject is the canonical JSON hash of the manifest, repository owner/name, and exact commit. RepoSeal treats a verified attestation as strong evidence but still preserves registry or domain conflicts. Keyless identity policies bind issuer and subject; raw public-key policies bind an explicit reviewed key fingerprint.

