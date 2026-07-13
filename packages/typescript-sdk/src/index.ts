import { spawn } from "node:child_process";

export type Decision = "verified" | "review" | "blocked";
export type Risk = "low" | "medium" | "high" | "critical";

export interface ComponentRef {
  ecosystem: "github" | "npm" | "pypi" | "cargo" | "go" | "skill" | "mcp" | "plugin" | "url";
  name: string;
  version: string | null;
}

export interface Signal {
  code: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  message: string;
  evidence_source: string | null;
  remediation: string;
}

export interface Evidence {
  kind: string;
  source: string;
  claim: string;
  strength: string;
  observed_at: string;
  expires_at: string | null;
  metadata: Record<string, string>;
}

export interface VerificationReport {
  schema_version: 1;
  request_id: string;
  request: ComponentRef;
  canonical: ComponentRef | null;
  decision: Decision;
  risk: Risk;
  signals: Signal[];
  evidence: Evidence[];
  evaluated_at: string;
  report_hash: `sha256:${string}`;
}

export interface ScanFinding {
  code: string;
  severity: Signal["severity"];
  path: string;
  line: number | null;
  message: string;
  excerpt: string;
}

export interface ScanReport {
  files_scanned: number;
  bytes_scanned: number;
  findings: ScanFinding[];
  truncated: boolean;
}

export interface RepoSealOptions {
  binary?: string;
  policy?: string;
  lockfile?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export class RepoSealError extends Error {
  constructor(
    message: string,
    readonly exitCode: number,
    readonly stderr: string,
  ) {
    super(message);
    this.name = "RepoSealError";
  }
}

/** Thin, deterministic wrapper over the audited RepoSeal CLI JSON contract. */
export class RepoSeal {
  readonly binary: string;
  readonly policy?: string;
  readonly lockfile: string;
  readonly cwd?: string;
  readonly env: NodeJS.ProcessEnv;

  constructor(options: RepoSealOptions = {}) {
    this.binary = options.binary ?? "reposeal";
    this.policy = options.policy;
    this.lockfile = options.lockfile ?? "agent.lock";
    this.cwd = options.cwd;
    this.env = { ...process.env, ...options.env };
  }

  async verify(reference: string, options: { offline?: boolean } = {}): Promise<VerificationReport> {
    const args = ["verify", reference, "--json", "--lock", this.lockfile];
    if (options.offline) args.push("--offline");
    if (this.policy) args.push("--policy", this.policy);
    return this.runJson<VerificationReport>(args, new Set([0, 2, 10]));
  }

  async scan(path = "."): Promise<ScanReport> {
    return this.runJson<ScanReport>(["scan", path, "--json"], new Set([0, 10]));
  }

  async guard(command: string): Promise<VerificationReport | { decision: "verified"; acquisition: false }> {
    const args = ["guard", "--command", command, "--json", "--lock", this.lockfile];
    if (this.policy) args.push("--policy", this.policy);
    return this.runJson(args, new Set([0, 2, 10]));
  }

  private runJson<T>(args: string[], accepted: Set<number>): Promise<T> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.binary, args, {
        cwd: this.cwd,
        env: this.env,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
        stdout += chunk;
        if (stdout.length > 10 * 1024 * 1024) child.kill();
      });
      child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
        stderr += chunk;
      });
      child.on("error", reject);
      child.on("close", (code) => {
        const exitCode = code ?? 3;
        if (!accepted.has(exitCode)) {
          reject(new RepoSealError(`RepoSeal exited ${exitCode}`, exitCode, stderr));
          return;
        }
        try {
          resolve(JSON.parse(stdout) as T);
        } catch (error) {
          reject(new RepoSealError(`Invalid RepoSeal JSON: ${String(error)}`, exitCode, stderr));
        }
      });
    });
  }
}

