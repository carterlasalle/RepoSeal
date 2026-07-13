import assert from "node:assert/strict";
import test from "node:test";
import { isShellTool } from "../dist/index.js";

test("only execution tools enter the acquisition guard", () => {
  assert.equal(isShellTool("bash"), true);
  assert.equal(isShellTool("terminal"), true);
  assert.equal(isShellTool("read"), false);
});

