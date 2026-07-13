# `@reposeal/sdk`

Typed TypeScript access to RepoSeal's stable verification and scanning reports. The SDK invokes an installed `reposeal` binary with `execFile`; it never builds a shell command.

```ts
import { RepoSeal } from "@reposeal/sdk";

const client = new RepoSeal({ policy: ".reposeal/policy.yaml" });
const report = await client.verify("npm:@modelcontextprotocol/sdk");
if (report.decision !== "verified") {
  throw new Error(`dependency denied: ${report.report_hash}`);
}
```

Review and blocked decisions are returned as typed reports. Timeouts, missing binaries, malformed JSON, and other operational failures reject the promise so availability failure cannot be mistaken for approval.
