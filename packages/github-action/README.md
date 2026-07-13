# RepoSeal GitHub Action

The composite action installs an exact RepoSeal release, verifies `agent.lock`, validates policy, scans the checkout, and fails on critical findings.

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v7
  - uses: carterlasalle/RepoSeal/packages/github-action@v1
    with:
      version: "1.0.0"
      policy: .reposeal/policy.yaml
      lockfile: agent.lock
```

Pin the action to a full commit SHA in higher-assurance environments. The installer itself uses the requested exact `vX.Y.Z` Git tag and Cargo's committed lockfile.
