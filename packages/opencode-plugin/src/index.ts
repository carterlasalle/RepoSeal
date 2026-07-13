import { execFile } from "node:child_process";

interface ToolInput { tool: string; args?: { command?: string } }
interface GuardResult { decision: "verified" | "review" | "blocked"; signals?: Array<{ message: string }> }

/** OpenCode-compatible plugin factory; all decisions remain in the RepoSeal Rust binary. */
export default async function RepoSealPlugin(): Promise<Record<string, unknown>> {
  return {
    "tool.execute.before": async (input: ToolInput): Promise<void> => {
      if (!isShellTool(input.tool) || !input.args?.command) return;
      const result = await guard(input.args.command);
      if (result.decision !== "verified") {
        const reason = result.signals?.map((item) => item.message).join("; ") ?? "dependency acquisition was not verified";
        throw new Error(`RepoSeal ${result.decision}: ${reason}`);
      }
    },
  };
}

export function isShellTool(name: string): boolean {
  return ["bash", "shell", "terminal", "execute"].includes(name.toLowerCase());
}

function guard(command: string): Promise<GuardResult> {
  return new Promise((resolve, reject) => {
    const child = execFile("reposeal", ["guard", "--command", command, "--json"], {
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
      shell: false,
    }, (error, stdout, stderr) => {
      const code = typeof error?.code === "number" ? error.code : 0;
      if (error && ![2, 10].includes(code)) {
        reject(new Error(`RepoSeal unavailable; failing closed: ${stderr || error.message}`));
        return;
      }
      try { resolve(JSON.parse(stdout) as GuardResult); }
      catch (parseError) { reject(new Error(`RepoSeal returned invalid JSON: ${String(parseError)}`)); }
    });
    child.stdin?.end();
  });
}

