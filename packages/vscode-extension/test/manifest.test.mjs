import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("extension contributes both security commands", async () => {
  const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const commands = manifest.contributes.commands.map((item) => item.command);
  assert.deepEqual(commands, ["reposeal.verifyDependency", "reposeal.scanWorkspace"]);
});

