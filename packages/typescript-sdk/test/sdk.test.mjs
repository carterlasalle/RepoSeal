import assert from "node:assert/strict";
import test from "node:test";
import { RepoSeal } from "../dist/index.js";

test("SDK keeps explicit configuration", () => {
  const client = new RepoSeal({ binary: "/tmp/reposeal", lockfile: "custom.lock", policy: "policy.yaml" });
  assert.equal(client.binary, "/tmp/reposeal");
  assert.equal(client.lockfile, "custom.lock");
  assert.equal(client.policy, "policy.yaml");
});

