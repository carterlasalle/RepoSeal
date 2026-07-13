import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as vscode from "vscode";

const execFileAsync = promisify(execFile);

interface RepoSealReport {
  decision: "verified" | "review" | "blocked";
  risk: string;
  request: { ecosystem: string; name: string; version: string | null };
  canonical: { ecosystem: string; name: string; version: string | null } | null;
  signals: Array<{ severity: string; code: string; message: string; remediation: string }>;
  report_hash: string;
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("RepoSeal", { log: true });
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
  status.text = "$(shield) RepoSeal";
  status.tooltip = "RepoSeal supply-chain firewall";
  status.command = "reposeal.verifyDependency";
  status.show();

  context.subscriptions.push(
    output,
    status,
    vscode.commands.registerCommand("reposeal.verifyDependency", async () => {
      const reference = await vscode.window.showInputBox({
        title: "Verify dependency identity",
        prompt: "github:owner/project, npm:package, pypi:package, skill:owner/name, mcp:owner/name",
        validateInput: (value) => (value.includes(":") ? undefined : "Use a typed RepoSeal reference"),
      });
      if (!reference) return;
      status.text = "$(loading~spin) RepoSeal resolving";
      try {
        const report = await runRepoSeal(["verify", reference, "--json"]);
        renderReport(output, report);
        status.text = report.decision === "verified" ? "$(verified) RepoSeal verified" : "$(shield-x) RepoSeal blocked";
        const message = `${reference}: ${report.decision.toUpperCase()} (${report.risk})`;
        if (report.decision === "verified") await vscode.window.showInformationMessage(message);
        else await vscode.window.showWarningMessage(message, "Show Evidence").then((choice) => choice && output.show());
      } catch (error) {
        status.text = "$(error) RepoSeal unavailable";
        await vscode.window.showErrorMessage(`RepoSeal failed closed: ${String(error)}`);
      }
    }),
    vscode.commands.registerCommand("reposeal.scanWorkspace", async () => {
      const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!root) throw new Error("Open a workspace before scanning");
      const result = await runRaw(["scan", root, "--json"]);
      output.clear();
      output.appendLine(result);
      output.show();
    }),
  );
}

export function deactivate(): void {}

async function runRepoSeal(args: string[]): Promise<RepoSealReport> {
  return JSON.parse(await runRaw(args)) as RepoSealReport;
}

async function runRaw(args: string[]): Promise<string> {
  const config = vscode.workspace.getConfiguration("reposeal");
  const binary = config.get<string>("binary", "reposeal");
  const policy = config.get<string>("policy", "");
  const lockfile = config.get<string>("lockfile", "agent.lock");
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const complete = [...args];
  if (args[0] === "verify") complete.push("--lock", lockfile);
  if (args[0] === "verify" && policy) complete.push("--policy", policy);
  try {
    const { stdout } = await execFileAsync(binary, complete, {
      cwd: root,
      timeout: 30_000,
      maxBuffer: 10 * 1024 * 1024,
      shell: false,
    });
    return stdout;
  } catch (error) {
    const candidate = error as { stdout?: string; code?: number };
    if ([2, 10].includes(candidate.code ?? -1) && candidate.stdout) return candidate.stdout;
    throw error;
  }
}

function renderReport(output: vscode.LogOutputChannel, report: RepoSealReport): void {
  output.clear();
  output.info(`Decision: ${report.decision.toUpperCase()}  Risk: ${report.risk}`);
  output.info(`Requested: ${report.request.ecosystem}:${report.request.name}`);
  output.info(`Canonical: ${report.canonical ? `${report.canonical.ecosystem}:${report.canonical.name}` : "unresolved"}`);
  for (const signal of report.signals) {
    output.warn(`${signal.severity.toUpperCase()} ${signal.code}: ${signal.message}`);
    output.info(`  Remediation: ${signal.remediation}`);
  }
  output.info(`Evidence: ${report.report_hash}`);
}

