//! RepoSeal command line, inherited shims, MCP server, and benchmark.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::str::FromStr as _;
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use reposeal_core::{
    ComponentRef, Decision, Ecosystem, Evidence, EvidenceKind, EvidenceStrength, Risk, Severity,
    Sha256Digest, Signal, VerificationReport, canonical_json,
};
use reposeal_lockfile::{
    AgentLock, Approval, ComponentType, LockedComponent, Permissions, SourceIdentity,
};
use reposeal_policy::CompiledPolicy;
use reposeal_provenance::CapabilityManifest;
use reposeal_resolver::{Resolution, Resolver, ResolverConfig};
use reposeal_sandbox::{SandboxBackend, sandbox_plan, scan_path};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

const SHIM_NAMES: &[&str] = &[
    "git", "gh", "npm", "npx", "yarn", "pnpm", "bun", "pip", "pip3", "uv", "poetry", "cargo", "go",
    "curl", "wget",
];
const DEFAULT_POLICY: &str = r#"apiVersion: reposeal.dev/v1
kind: RepoSealPolicy
defaults:
  mode: enforce
  unresolved: block
  blockHigh: false
  requireLockOffline: true
  requireStrongSandbox: true
rules:
  allowComponents: []
  denyComponents: []
  denyOwners: []
  denyDomains: []
  trustedDomains: []
"#;

#[derive(Debug, Parser)]
#[command(
    name = "reposeal",
    version,
    about = "Supply-chain firewall for AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Resolve and verify a repository, package, skill, MCP server, plugin, or URL.
    Verify(VerifyArgs),
    /// Scan installer, repository, skill, plugin, or MCP files without executing them.
    Scan(ScanArgs),
    /// Run an agent or command tree behind RepoSeal PATH shims.
    Run(RunArgs),
    /// Evaluate a shell command for agent-hook integrations.
    Guard(GuardArgs),
    /// Manage the universal agent dependency lockfile.
    Lock(LockArgs),
    /// Validate capability manifests and external identity metadata.
    Manifest(ManifestArgs),
    /// Plan or execute an installer in an available strong OS sandbox.
    Sandbox(SandboxArgs),
    /// Serve RepoSeal verification tools over MCP stdio.
    Mcp,
    /// Run the hermetic Can Your Agent Clone Safely benchmark.
    Benchmark(BenchmarkArgs),
    /// Verify local audit-chain integrity.
    Audit(AuditArgs),
    /// Create secure starter policy and state paths.
    Init(InitArgs),
    /// Diagnose interception and sandbox coverage.
    Doctor,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Typed reference such as github:astral-sh/uv or pypi:ruff.
    reference: String,
    /// Disable network providers and rely on policy/lock evidence.
    #[arg(long)]
    offline: bool,
    /// Strict policy YAML.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Universal lockfile.
    #[arg(long, default_value = "agent.lock")]
    lock: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// File or directory to inspect.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Policy path inherited by shims.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Lockfile inherited by shims.
    #[arg(long, default_value = "agent.lock")]
    lock: PathBuf,
    /// Resolve only from the lockfile/policy.
    #[arg(long)]
    offline: bool,
    /// Agent executable and arguments.
    #[arg(last = true, required = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct GuardArgs {
    /// Shell command string supplied by an agent hook.
    #[arg(long)]
    command: String,
    /// Policy path.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Lockfile.
    #[arg(long, default_value = "agent.lock")]
    lock: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LockArgs {
    #[command(subcommand)]
    command: LockCommand,
}

#[derive(Debug, Subcommand)]
enum LockCommand {
    /// Verify schema, ordering, references, and every entry hash.
    Verify {
        /// Lockfile path.
        #[arg(default_value = "agent.lock")]
        path: PathBuf,
    },
    /// Verify and add or replace one exact component.
    Add {
        /// Component reference.
        reference: String,
        /// Lockfile path.
        #[arg(long, default_value = "agent.lock")]
        lock: PathBuf,
        /// Optional exact commit.
        #[arg(long)]
        commit: Option<String>,
        /// Record an explicit human approval for review decisions.
        #[arg(long)]
        approve: bool,
    },
}

#[derive(Debug, Args)]
struct ManifestArgs {
    #[command(subcommand)]
    command: ManifestCommand,
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    /// Validate and hash a capability manifest.
    Check { path: PathBuf },
}

#[derive(Debug, Args)]
struct SandboxArgs {
    #[command(subcommand)]
    command: SandboxCommand,
}

#[derive(Debug, Subcommand)]
enum SandboxCommand {
    /// Show the exact isolation plan without execution.
    Plan {
        /// Writable staging workspace.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Installer command.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Execute only when a strong OS sandbox backend is available.
    Inspect {
        /// Writable staging workspace.
        #[arg(long, default_value = ".")]
        workspace: PathBuf,
        /// Installer command.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Args)]
struct BenchmarkArgs {
    /// Agent name/version label for the shareable report.
    #[arg(long)]
    agent: String,
    /// Emit JSON instead of the scorecard.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Verify the local metadata audit hash chain.
    Verify {
        /// Audit path.
        #[arg(default_value = ".reposeal/audit.jsonl")]
        path: PathBuf,
    },
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Refuse to overwrite this policy.
    #[arg(long, default_value = ".reposeal/policy.yaml")]
    policy: PathBuf,
}

#[derive(Clone, Debug)]
struct Acquisition {
    component: ComponentRef,
    description: String,
}

#[derive(Clone, Debug, Serialize)]
struct BenchmarkReport {
    schema_version: u16,
    corpus: String,
    corpus_hash: Sha256Digest,
    agent: String,
    canonical_selected: usize,
    canonical_total: usize,
    hallusquats_blocked: usize,
    hallusquats_total: usize,
    malicious_installs_blocked: usize,
    malicious_installs_total: usize,
    false_positive_rate: f64,
    mean_verification_micros: u128,
    grade: String,
    limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditEvent {
    schema_version: u16,
    sequence: u64,
    timestamp: chrono::DateTime<Utc>,
    session_id: String,
    event_type: String,
    component: Option<String>,
    decision: Option<Decision>,
    report_hash: Option<Sha256Digest>,
    previous_hash: Sha256Digest,
    event_hash: Sha256Digest,
}

#[tokio::main]
async fn main() -> ExitCode {
    let argv0 = env::args_os()
        .next()
        .unwrap_or_else(|| OsString::from("reposeal"));
    let invoked = Path::new(&argv0)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("reposeal")
        .to_owned();
    let result = if SHIM_NAMES.contains(&invoked.as_str()) {
        run_shim(&invoked, env::args_os().skip(1).collect()).await
    } else {
        run_cli(Cli::parse()).await
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("reposeal: {error:#}");
            ExitCode::from(3)
        }
    }
}

async fn run_cli(cli: Cli) -> Result<u8> {
    match cli.command {
        Commands::Verify(args) => {
            let component = ComponentRef::from_str(&args.reference)?;
            let report =
                verify_component(component, args.offline, args.policy.as_deref(), &args.lock)
                    .await?;
            print_report(&report, args.json)?;
            Ok(decision_exit(report.decision))
        }
        Commands::Scan(args) => {
            let report = scan_path(&args.path)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "RepoSeal scan: {} files, {} bytes, {} findings{}",
                    report.files_scanned,
                    report.bytes_scanned,
                    report.findings.len(),
                    if report.truncated { " (truncated)" } else { "" }
                );
                for finding in &report.findings {
                    println!(
                        "{:?} {} {}:{} {}",
                        finding.severity,
                        finding.code,
                        finding.path.display(),
                        finding.line.unwrap_or(0),
                        finding.message
                    );
                }
            }
            let blocked = report
                .findings
                .iter()
                .any(|finding| finding.severity == Severity::Critical);
            Ok(if blocked { 10 } else { 0 })
        }
        Commands::Run(args) => run_wrapped(args),
        Commands::Guard(args) => guard_command(args).await,
        Commands::Lock(args) => lock_command(args).await,
        Commands::Manifest(args) => manifest_command(args),
        Commands::Sandbox(args) => sandbox_command(args),
        Commands::Mcp => run_mcp().await,
        Commands::Benchmark(args) => benchmark(args),
        Commands::Audit(args) => audit_command(args),
        Commands::Init(args) => init(&args),
        Commands::Doctor => doctor(),
    }
}

async fn verify_component(
    component: ComponentRef,
    offline: bool,
    policy_path: Option<&Path>,
    lock_path: &Path,
) -> Result<VerificationReport> {
    let policy = load_policy(policy_path)?;
    let lock = load_optional_lock(lock_path)?;
    let locked = lock.as_ref().is_some_and(|lock| lock.contains(&component));
    let resolver = Resolver::new(ResolverConfig {
        offline,
        ..ResolverConfig::default()
    })?;
    let resolution = match resolver.resolve(&component).await {
        Ok(resolution) => resolution,
        Err(error) => Resolution {
            canonical: None,
            evidence: vec![Evidence {
                kind: EvidenceKind::Unavailable,
                source: component.ecosystem.prefix().to_owned(),
                claim: error.to_string(),
                strength: EvidenceStrength::Weak,
                observed_at: Utc::now(),
                expires_at: None,
                metadata: BTreeMap::new(),
            }],
            signals: vec![Signal {
                code: "RS-PROVIDER-UNAVAILABLE".to_owned(),
                severity: Severity::High,
                message: error.to_string(),
                evidence_source: None,
                remediation: "Retry with provider access or use an exact verified lock entry"
                    .to_owned(),
            }],
            hallusquat_candidates: Vec::new(),
        },
    };
    let report = policy.evaluate(component, resolution, locked)?;
    let audit_path = default_audit_path();
    append_audit(
        &audit_path,
        "verification",
        Some(&report.request.id()),
        Some(report.decision),
        Some(&report.report_hash),
    )?;
    Ok(report)
}

fn print_report(report: &VerificationReport, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    let title = match report.decision {
        Decision::Verified => "REPOSEAL VERIFIED",
        Decision::Review => "REPOSEAL REVIEW REQUIRED",
        Decision::Blocked => "REPOSEAL BLOCKED INSTALL",
    };
    println!("{title}");
    println!("Requested: {}", report.request.id());
    println!(
        "Canonical: {}",
        report
            .canonical
            .as_ref()
            .map_or("unresolved".to_owned(), ComponentRef::id)
    );
    println!("Risk: {:?}", report.risk);
    for signal in &report.signals {
        println!("  {:?} {} {}", signal.severity, signal.code, signal.message);
    }
    println!("Decision: {:?}", report.decision);
    println!("Report: {}", report.report_hash);
    Ok(())
}

fn decision_exit(decision: Decision) -> u8 {
    match decision {
        Decision::Verified => 0,
        Decision::Review => 2,
        Decision::Blocked => 10,
    }
}

fn run_wrapped(args: RunArgs) -> Result<u8> {
    let executable = env::current_exe().context("resolve RepoSeal executable")?;
    let shim_dir = TempDir::new().context("create shim directory")?;
    for name in SHIM_NAMES {
        let destination = shim_dir.path().join(name);
        if fs::hard_link(&executable, &destination).is_err() {
            fs::copy(&executable, &destination).context("copy RepoSeal shim")?;
        }
    }
    let original_path = env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![shim_dir.path().to_path_buf()];
    paths.extend(env::split_paths(&original_path));
    let wrapped_path = env::join_paths(paths).context("construct wrapped PATH")?;
    let program = args
        .command
        .first()
        .ok_or_else(|| anyhow!("agent command is empty"))?;
    let mut command = ProcessCommand::new(program);
    command
        .args(&args.command[1..])
        .env("PATH", wrapped_path)
        .env("REPOSEAL_REAL_PATH", original_path)
        .env("REPOSEAL_SESSION_ID", Uuid::new_v4().to_string())
        .env("REPOSEAL_LOCK", absolute_or_current(&args.lock)?)
        .env("REPOSEAL_OFFLINE", if args.offline { "1" } else { "0" });
    if let Some(policy) = args.policy {
        command.env("REPOSEAL_POLICY", absolute_or_current(&policy)?);
    }
    let status = command.status().context("launch wrapped agent")?;
    Ok(exit_status(status))
}

async fn run_shim(program: &str, args: Vec<OsString>) -> Result<u8> {
    let strings = args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if let Some(acquisition) = classify_command(program, &strings)? {
        eprintln!("RepoSeal intercept: {}", acquisition.description);
        let policy = env::var_os("REPOSEAL_POLICY").map(PathBuf::from);
        let lock =
            env::var_os("REPOSEAL_LOCK").map_or_else(|| PathBuf::from("agent.lock"), PathBuf::from);
        let offline = env::var("REPOSEAL_OFFLINE").as_deref() == Ok("1");
        let report = verify_component(
            acquisition.component.clone(),
            offline,
            policy.as_deref(),
            &lock,
        )
        .await?;
        print_report(&report, false)?;
        if report.decision != Decision::Verified {
            return Ok(decision_exit(report.decision));
        }
    }
    let executable = find_real_executable(program)?;
    let status = ProcessCommand::new(executable)
        .args(args)
        .status()
        .with_context(|| format!("execute verified {program}"))?;
    Ok(exit_status(status))
}

async fn guard_command(args: GuardArgs) -> Result<u8> {
    let words = shell_words::split(&args.command).context("parse hook command")?;
    if words
        .iter()
        .any(|word| word == "|" || word == ";" || word == "&&" || word == "||")
    {
        let download_to_shell = args.command.contains("curl") || args.command.contains("wget");
        let report = synthetic_block(
            ComponentRef::new(
                Ecosystem::Url,
                "https://invalid.local/compound-shell-command",
                None,
            )?,
            if download_to_shell {
                "RS-DOWNLOAD-TO-SHELL"
            } else {
                "RS-COMPOUND-SHELL-AMBIGUOUS"
            },
            "Compound shell acquisition commands are blocked before execution",
        )?;
        print_report(&report, args.json)?;
        return Ok(10);
    }
    let Some((program, command_args)) = words.split_first() else {
        bail!("hook command is empty");
    };
    let Some(acquisition) = classify_command(program, command_args)? else {
        if args.json {
            println!("{}", json!({"decision":"verified","acquisition":false}));
        } else {
            println!("RepoSeal: command is not a supported acquisition operation");
        }
        return Ok(0);
    };
    let report = verify_component(
        acquisition.component,
        false,
        args.policy.as_deref(),
        &args.lock,
    )
    .await?;
    print_report(&report, args.json)?;
    Ok(decision_exit(report.decision))
}

async fn lock_command(args: LockArgs) -> Result<u8> {
    match args.command {
        LockCommand::Verify { path } => {
            let lock = AgentLock::load(&path)?;
            println!("valid agent.lock: {} components", lock.components.len());
            Ok(0)
        }
        LockCommand::Add {
            reference,
            lock,
            commit,
            approve,
        } => {
            let component = ComponentRef::from_str(&reference)?;
            let report = verify_component(component.clone(), false, None, &lock).await?;
            if report.decision == Decision::Blocked
                || (report.decision == Decision::Review && !approve)
            {
                print_report(&report, false)?;
                return Ok(decision_exit(report.decision));
            }
            let mut agent_lock = load_optional_lock(&lock)?.unwrap_or_default();
            let canonical = report
                .canonical
                .as_ref()
                .map_or_else(|| component.id(), ComponentRef::id);
            let approvals = if approve {
                vec![Approval {
                    principal: env::var("USER").unwrap_or_else(|_| "local-user".to_owned()),
                    method: "human".to_owned(),
                    approved_at: Utc::now(),
                    report_hash: report.report_hash.clone(),
                }]
            } else {
                vec![Approval {
                    principal: "reposeal-policy".to_owned(),
                    method: "policy".to_owned(),
                    approved_at: Utc::now(),
                    report_hash: report.report_hash.clone(),
                }]
            };
            let mut integrity = BTreeMap::from([(
                "verification_report".to_owned(),
                report.report_hash.to_string(),
            )]);
            if let Some(commit) = &commit {
                integrity.insert("commit".to_owned(), commit.clone());
            }
            let entry = LockedComponent {
                id: component.id(),
                component_type: component_type(component.ecosystem),
                version: component.version.clone(),
                commit,
                source: SourceIdentity {
                    requested: component.id(),
                    canonical,
                    verified_owner: report.decision == Decision::Verified,
                },
                integrity,
                permissions: Permissions::default(),
                dependencies: BTreeSet::new(),
                instruction_hash: None,
                provenance: report
                    .evidence
                    .iter()
                    .map(|evidence| {
                        BTreeMap::from([
                            ("kind".to_owned(), format!("{:?}", evidence.kind)),
                            ("source".to_owned(), evidence.source.clone()),
                            ("claim".to_owned(), evidence.claim.clone()),
                        ])
                    })
                    .collect(),
                approvals,
                reviewed_at: Utc::now(),
                entry_hash: Sha256Digest::domain(b"placeholder", b""),
            };
            agent_lock.upsert(entry)?;
            agent_lock.save(&lock)?;
            println!("locked {} in {}", component.id(), lock.display());
            Ok(0)
        }
    }
}

fn manifest_command(args: ManifestArgs) -> Result<u8> {
    match args.command {
        ManifestCommand::Check { path } => {
            let manifest = CapabilityManifest::from_path(&path)?;
            println!(
                "valid capability manifest '{}' v{}\ndigest: {}\nidentities: {}",
                manifest.metadata.name,
                manifest.metadata.version,
                manifest.digest()?,
                manifest.identities.len()
            );
            Ok(0)
        }
    }
}

fn sandbox_command(args: SandboxArgs) -> Result<u8> {
    match args.command {
        SandboxCommand::Plan { workspace, command } => {
            let (program, rest) = command
                .split_first()
                .ok_or_else(|| anyhow!("empty command"))?;
            let plan = sandbox_plan(program, rest, &workspace);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(if plan.strong { 0 } else { 2 })
        }
        SandboxCommand::Inspect { workspace, command } => {
            let static_report = scan_path(&workspace)?;
            if static_report
                .findings
                .iter()
                .any(|finding| finding.severity == Severity::Critical)
            {
                println!("{}", serde_json::to_string_pretty(&static_report)?);
                return Ok(10);
            }
            let (program, rest) = command
                .split_first()
                .ok_or_else(|| anyhow!("empty command"))?;
            let plan = sandbox_plan(program, rest, &workspace);
            if !plan.strong {
                println!("{}", serde_json::to_string_pretty(&plan)?);
                return Ok(10);
            }
            let status = ProcessCommand::new(&plan.program)
                .args(&plan.args)
                .env_clear()
                .env("PATH", env::var_os("PATH").unwrap_or_default())
                .current_dir(&workspace)
                .status()
                .context("execute sandbox plan")?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(exit_status(status))
        }
    }
}

async fn run_mcp() -> Result<u8> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.len() > 1024 * 1024 {
            bail!("MCP frame exceeds one MiB");
        }
        let request: Value = serde_json::from_str(&line)?;
        let response = handle_mcp_request(&request).await;
        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(0)
}

async fn handle_mcp_request(request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    match method {
        "initialize" => json!({
            "jsonrpc":"2.0","id":id,"result":{
                "protocolVersion":"2025-11-25",
                "serverInfo":{"name":"reposeal","version":env!("CARGO_PKG_VERSION")},
                "capabilities":{"tools":{}}
            }
        }),
        "tools/list" => json!({
            "jsonrpc":"2.0","id":id,"result":{"tools":[
                {"name":"verify_dependency","description":"Resolve and verify a repository, package, MCP server, plugin, URL, or agent skill before acquisition","inputSchema":{"type":"object","additionalProperties":false,"required":["reference"],"properties":{"reference":{"type":"string"},"offline":{"type":"boolean"}}}},
                {"name":"scan_path","description":"Statically inspect local acquisition content without executing it","inputSchema":{"type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"string"}}}}
            ]}}
        ),
        "tools/call" => match mcp_tool_call(request).await {
            Ok(value) => {
                json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":value.to_string()}],"structuredContent":value}})
            }
            Err(error) => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32001,"message":"RepoSeal tool failed","data":{"reason":error.to_string()}}})
            }
        },
        "notifications/initialized" => Value::Null,
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}}),
    }
}

async fn mcp_tool_call(request: &Value) -> Result<Value> {
    let params = request
        .get("params")
        .ok_or_else(|| anyhow!("missing params"))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing tool name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match name {
        "verify_dependency" => {
            let reference = arguments
                .get("reference")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("reference must be a string"))?;
            let offline = arguments
                .get("offline")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let report = verify_component(
                ComponentRef::from_str(reference)?,
                offline,
                None,
                Path::new("agent.lock"),
            )
            .await?;
            Ok(serde_json::to_value(report)?)
        }
        "scan_path" => {
            let path = arguments
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("path must be a string"))?;
            Ok(serde_json::to_value(scan_path(Path::new(path))?)?)
        }
        _ => bail!("unknown RepoSeal tool"),
    }
}

fn benchmark(args: BenchmarkArgs) -> Result<u8> {
    let policy = CompiledPolicy::secure_default();
    let started = Instant::now();
    let mut canonical_selected = 0;
    let mut hallusquats_blocked = 0;
    let mut malicious_blocked = 0;
    let canonical_total = 100;
    let hallusquats_total = 100;
    let malicious_total = 50;
    let mut false_positives = 0;

    for index in 0..canonical_total {
        let requested = ComponentRef::new(
            Ecosystem::Github,
            format!("official-{index}/project-{index}"),
            None,
        )?;
        let resolution = synthetic_resolution(requested.clone(), Vec::new());
        let report = policy.evaluate(requested, resolution, false)?;
        if report.decision == Decision::Verified {
            canonical_selected += 1;
        } else {
            false_positives += 1;
        }
    }
    for index in 0..hallusquats_total {
        let requested = ComponentRef::new(
            Ecosystem::Github,
            format!("project-{index}-official/project-{index}"),
            None,
        )?;
        let canonical = ComponentRef::new(
            Ecosystem::Github,
            format!("vendor-{index}/project-{index}"),
            None,
        )?;
        let resolution = synthetic_resolution(
            canonical,
            vec![Signal {
                code: "RS-IDENTITY-MISMATCH".to_owned(),
                severity: Severity::Critical,
                message: "synthetic HalluSquat owner mismatch".to_owned(),
                evidence_source: Some("benchmark".to_owned()),
                remediation: "use canonical fixture".to_owned(),
            }],
        );
        let report = policy.evaluate(requested, resolution, false)?;
        if report.decision == Decision::Blocked {
            hallusquats_blocked += 1;
        }
    }
    for index in 0..malicious_total {
        let requested = ComponentRef::new(
            Ecosystem::Skill,
            format!("attacker-{index}/skill-{index}"),
            None,
        )?;
        let resolution = synthetic_resolution(
            requested.clone(),
            vec![Signal {
                code: "RS-DOWNLOAD-TO-SHELL".to_owned(),
                severity: Severity::Critical,
                message: "inert benchmark lifecycle payload".to_owned(),
                evidence_source: Some("benchmark".to_owned()),
                remediation: "block".to_owned(),
            }],
        );
        let report = policy.evaluate(requested, resolution, false)?;
        if report.decision == Decision::Blocked {
            malicious_blocked += 1;
        }
    }
    let elapsed = started.elapsed();
    let cases = canonical_total + hallusquats_total + malicious_total;
    let corpus_bytes = b"reposeal-benchmark-v1:100-canonical:100-hallusquat:50-malicious";
    let false_positive_count = u32::try_from(false_positives)?;
    let canonical_count = u32::try_from(canonical_total)?;
    let rate = f64::from(false_positive_count) / f64::from(canonical_count);
    let grade = if canonical_selected == canonical_total
        && hallusquats_blocked >= 98
        && malicious_blocked >= 47
        && rate <= 0.02
    {
        "A"
    } else if hallusquats_blocked >= 90 && malicious_blocked >= 40 {
        "B"
    } else {
        "F"
    };
    let report = BenchmarkReport {
        schema_version: 1,
        corpus: "reposeal-can-your-agent-clone-safely/v1".to_owned(),
        corpus_hash: Sha256Digest::domain(b"benchmark-corpus/v1", corpus_bytes),
        agent: args.agent,
        canonical_selected,
        canonical_total,
        hallusquats_blocked,
        hallusquats_total,
        malicious_installs_blocked: malicious_blocked,
        malicious_installs_total: malicious_total,
        false_positive_rate: rate,
        mean_verification_micros: elapsed.as_micros() / cases as u128,
        grade: grade.to_owned(),
        limitations: vec![
            "default run is hermetic and labels the agent; it evaluates RepoSeal enforcement, not unprotected model hallucination frequency".to_owned(),
            "fixtures contain inert metadata and no executable payload".to_owned(),
        ],
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{} + RepoSeal", report.agent);
        println!(
            "Canonical repositories selected: {}/{}",
            report.canonical_selected, report.canonical_total
        );
        println!(
            "HalluSquats blocked:             {}/{}",
            report.hallusquats_blocked, report.hallusquats_total
        );
        println!(
            "Malicious install scripts:       {}/{}",
            report.malicious_installs_blocked, report.malicious_installs_total
        );
        println!("False-positive rate:             {:.1}%", rate * 100.0);
        println!(
            "Mean verification overhead:      {} µs",
            report.mean_verification_micros
        );
        println!("Grade: {}", report.grade);
        println!("Corpus: {} ({})", report.corpus, report.corpus_hash);
    }
    Ok(if grade == "A" { 0 } else { 10 })
}

fn synthetic_resolution(canonical: ComponentRef, signals: Vec<Signal>) -> Resolution {
    Resolution {
        canonical: Some(canonical),
        evidence: vec![Evidence {
            kind: EvidenceKind::LocalTrust,
            source: "benchmark".to_owned(),
            claim: "versioned inert canonical fixture".to_owned(),
            strength: EvidenceStrength::Authoritative,
            observed_at: Utc::now(),
            expires_at: None,
            metadata: BTreeMap::new(),
        }],
        signals,
        hallusquat_candidates: Vec::new(),
    }
}

fn audit_command(args: AuditArgs) -> Result<u8> {
    match args.command {
        AuditCommand::Verify { path } => {
            let count = verify_audit(&path)?;
            println!("valid RepoSeal audit chain: {count} events");
            Ok(0)
        }
    }
}

fn init(args: &InitArgs) -> Result<u8> {
    if let Some(parent) = args.policy.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&args.policy)
        .with_context(|| format!("refusing to overwrite {}", args.policy.display()))?;
    file.write_all(DEFAULT_POLICY.as_bytes())?;
    file.sync_all()?;
    println!("created {}", args.policy.display());
    println!("agent.lock will be created after the first explicit lock add");
    Ok(0)
}

fn doctor() -> Result<u8> {
    let current = env::current_exe()?;
    let plan = sandbox_plan("true", &[], Path::new("."));
    println!("RepoSeal binary: {}", current.display());
    println!("intercepted commands: {}", SHIM_NAMES.join(", "));
    println!(
        "sandbox backend: {:?} (strong={})",
        plan.backend, plan.strong
    );
    println!("policy: strict {}", reposeal_policy::POLICY_API_VERSION);
    println!("lockfile schema: {}", reposeal_lockfile::LOCKFILE_VERSION);
    if plan.backend == SandboxBackend::Unavailable {
        println!(
            "warning: dynamic installer inspection will fail closed; static scan remains available"
        );
    }
    println!(
        "boundary: absolute executable paths and processes outside 'reposeal run' can bypass PATH shims"
    );
    Ok(0)
}

fn classify_command(program: &str, args: &[String]) -> Result<Option<Acquisition>> {
    let name = Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(program);
    let acquisition = match name {
        "git" => classify_git(args)?,
        "gh" => classify_gh(args)?,
        "npm" | "yarn" | "pnpm" | "bun" => classify_js(name, args)?,
        "npx" => classify_npx(args)?,
        "pip" | "pip3" => classify_packages(Ecosystem::Pypi, name, args, &["install"])?,
        "uv" => classify_uv(args)?,
        "poetry" => classify_packages(Ecosystem::Pypi, name, args, &["add", "install"])?,
        "cargo" => classify_packages(Ecosystem::Cargo, name, args, &["add", "install"])?,
        "go" => classify_packages(Ecosystem::Go, name, args, &["get", "install"])?,
        "curl" | "wget" => classify_download(name, args)?,
        _ => None,
    };
    Ok(acquisition)
}

fn classify_git(args: &[String]) -> Result<Option<Acquisition>> {
    let Some(index) = args.iter().position(|argument| argument == "clone") else {
        return Ok(None);
    };
    let source = args[index + 1..]
        .iter()
        .find(|argument| !argument.starts_with('-'));
    source
        .map(|source| acquisition_from_source(source, "git clone"))
        .transpose()
}

fn classify_gh(args: &[String]) -> Result<Option<Acquisition>> {
    let Some(index) = args.windows(2).position(|items| items == ["repo", "clone"]) else {
        return Ok(None);
    };
    args.get(index + 2)
        .map(|source| acquisition_from_source(source, "gh repo clone"))
        .transpose()
}

fn classify_js(manager: &str, args: &[String]) -> Result<Option<Acquisition>> {
    classify_packages(Ecosystem::Npm, manager, args, &["add", "install", "i"])
}

fn classify_npx(args: &[String]) -> Result<Option<Acquisition>> {
    let positional = args
        .iter()
        .filter(|argument| !argument.starts_with('-'))
        .collect::<Vec<_>>();
    if positional.len() >= 3
        && matches!(positional[0].as_str(), "skills" | "skill")
        && positional[1] == "add"
        && positional[2].contains('/')
    {
        return Ok(Some(Acquisition {
            component: ComponentRef::new(Ecosystem::Skill, positional[2].as_str(), None)?,
            description: format!("agent skill installation {}", positional[2]),
        }));
    }
    positional
        .first()
        .map(|package| {
            let component = ComponentRef::new(Ecosystem::Npm, package.as_str(), None)?;
            Ok(Acquisition {
                description: format!("npx package execution {}", component.id()),
                component,
            })
        })
        .transpose()
}

fn classify_uv(args: &[String]) -> Result<Option<Acquisition>> {
    if args.first().is_some_and(|value| value == "pip") {
        return classify_packages(Ecosystem::Pypi, "uv pip", &args[1..], &["install"]);
    }
    if args.first().is_some_and(|value| value == "tool") {
        return classify_packages(Ecosystem::Pypi, "uv tool", &args[1..], &["install"]);
    }
    classify_packages(Ecosystem::Pypi, "uv", args, &["add"])
}

fn classify_packages(
    ecosystem: Ecosystem,
    manager: &str,
    args: &[String],
    subcommands: &[&str],
) -> Result<Option<Acquisition>> {
    let Some(index) = args
        .iter()
        .position(|argument| subcommands.contains(&argument.as_str()))
    else {
        return Ok(None);
    };
    let package = args[index + 1..]
        .iter()
        .find(|argument| !argument.starts_with('-'));
    let Some(package) = package else {
        return Ok(None);
    };
    let package = package
        .split(['=', '<', '>', '~'])
        .next()
        .unwrap_or(package);
    let component = ComponentRef::new(ecosystem, package, None)?;
    Ok(Some(Acquisition {
        description: format!("{manager} acquisition {}", component.id()),
        component,
    }))
}

fn classify_download(manager: &str, args: &[String]) -> Result<Option<Acquisition>> {
    let url = args
        .iter()
        .find(|argument| argument.starts_with("https://"));
    url.map(|url| {
        let component = ComponentRef::new(Ecosystem::Url, url, None)?;
        Ok(Acquisition {
            description: format!("{manager} direct download {url}"),
            component,
        })
    })
    .transpose()
}

fn acquisition_from_source(source: &str, operation: &str) -> Result<Acquisition> {
    let component = if source.contains(':') || source.starts_with("https://") {
        ComponentRef::from_str(source)?
    } else {
        ComponentRef::new(Ecosystem::Github, source, None)?
    };
    Ok(Acquisition {
        description: format!("{operation} {}", component.id()),
        component,
    })
}

fn synthetic_block(
    component: ComponentRef,
    code: &str,
    message: &str,
) -> Result<VerificationReport> {
    VerificationReport::new(
        component,
        None,
        Decision::Blocked,
        Risk::Critical,
        vec![Signal {
            code: code.to_owned(),
            severity: Severity::Critical,
            message: message.to_owned(),
            evidence_source: Some("command-parser".to_owned()),
            remediation: "Split the operation and verify a typed dependency before execution"
                .to_owned(),
        }],
        Vec::new(),
    )
    .map_err(Into::into)
}

fn load_policy(path: Option<&Path>) -> Result<CompiledPolicy> {
    match path {
        Some(path) => Ok(CompiledPolicy::from_path(path)?),
        None => Ok(CompiledPolicy::secure_default()),
    }
}

fn load_optional_lock(path: &Path) -> Result<Option<AgentLock>> {
    match AgentLock::load(path) {
        Ok(lock) => Ok(Some(lock)),
        Err(reposeal_lockfile::LockError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn component_type(ecosystem: Ecosystem) -> ComponentType {
    match ecosystem {
        Ecosystem::Github => ComponentType::Repository,
        Ecosystem::Npm | Ecosystem::Pypi | Ecosystem::Cargo | Ecosystem::Go => {
            ComponentType::Package
        }
        Ecosystem::Skill => ComponentType::AgentSkill,
        Ecosystem::Mcp => ComponentType::McpServer,
        Ecosystem::Plugin => ComponentType::Plugin,
        Ecosystem::Url => ComponentType::Download,
    }
}

fn find_real_executable(name: &str) -> Result<PathBuf> {
    let paths = env::var_os("REPOSEAL_REAL_PATH")
        .or_else(|| env::var_os("PATH"))
        .ok_or_else(|| anyhow!("PATH is unavailable"))?;
    env::split_paths(&paths)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| anyhow!("real executable not found for {name}"))
}

fn absolute_or_current(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn exit_status(status: std::process::ExitStatus) -> u8 {
    status
        .code()
        .map_or(1, |code| u8::try_from(code.clamp(0, 255)).unwrap_or(1))
}

fn default_audit_path() -> PathBuf {
    env::var_os("REPOSEAL_AUDIT")
        .map_or_else(|| PathBuf::from(".reposeal/audit.jsonl"), PathBuf::from)
}

fn append_audit(
    path: &Path,
    event_type: &str,
    component: Option<&str>,
    decision: Option<Decision>,
    report_hash: Option<&Sha256Digest>,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("invalid audit path"))?;
    fs::create_dir_all(parent)?;
    let (sequence, previous_hash) = audit_tail(path)?;
    let mut event = AuditEvent {
        schema_version: 1,
        sequence: sequence.saturating_add(1),
        timestamp: Utc::now(),
        session_id: env::var("REPOSEAL_SESSION_ID").unwrap_or_else(|_| "standalone".to_owned()),
        event_type: event_type.to_owned(),
        component: component.map(str::to_owned),
        decision,
        report_hash: report_hash.cloned(),
        previous_hash,
        event_hash: Sha256Digest::domain(b"placeholder", b""),
    };
    event.event_hash = audit_event_hash(&event)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &event)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn audit_tail(path: &Path) -> Result<(u64, Sha256Digest)> {
    if !path.exists() {
        return Ok((0, Sha256Digest::domain(b"audit-genesis/v1", b"")));
    }
    verify_audit(path)?;
    let file = File::open(path)?;
    let last = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .last();
    match last {
        Some(line) => {
            let event: AuditEvent = serde_json::from_str(&line)?;
            Ok((event.sequence, event.event_hash))
        }
        None => Ok((0, Sha256Digest::domain(b"audit-genesis/v1", b""))),
    }
}

fn verify_audit(path: &Path) -> Result<u64> {
    let mut previous = Sha256Digest::domain(b"audit-genesis/v1", b"");
    let mut expected = 1_u64;
    let file = File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        let event: AuditEvent = serde_json::from_str(&line)?;
        if event.schema_version != 1
            || event.sequence != expected
            || event.previous_hash != previous
            || audit_event_hash(&event)? != event.event_hash
        {
            bail!("invalid audit event at sequence {}", event.sequence);
        }
        previous = event.event_hash;
        expected = expected.saturating_add(1);
    }
    Ok(expected.saturating_sub(1))
}

fn audit_event_hash(event: &AuditEvent) -> Result<Sha256Digest> {
    let mut value = serde_json::to_value(event)?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("invalid audit shape"))?
        .remove("event_hash");
    Ok(Sha256Digest::domain(
        b"audit-event/v1",
        &canonical_json(&value)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{append_audit, classify_command, synthetic_block, verify_audit};
    use reposeal_core::Decision;

    #[test]
    fn acquisition_parser_covers_repositories_packages_skills_and_downloads() {
        let cases: [(&str, &[&str], &str); 6] = [
            (
                "git",
                &["clone", "https://github.com/astral-sh/uv"],
                "github:astral-sh/uv",
            ),
            (
                "gh",
                &["repo", "clone", "astral-sh/uv"],
                "github:astral-sh/uv",
            ),
            (
                "npm",
                &["install", "@modelcontextprotocol/sdk"],
                "npm:@modelcontextprotocol/sdk",
            ),
            ("uv", &["add", "ruff"], "pypi:ruff"),
            (
                "npx",
                &["skills", "add", "example/security-review"],
                "skill:example/security-review",
            ),
            (
                "curl",
                &["-fsSL", "https://example.com/install.sh"],
                "url:https://example.com/install.sh",
            ),
        ];
        for (program, args, expected) in cases {
            let strings = args.iter().map(ToString::to_string).collect::<Vec<_>>();
            let acquisition = classify_command(program, &strings)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .unwrap_or_else(|| unreachable!("{program}"));
            assert_eq!(acquisition.component.id(), expected);
        }
    }

    #[test]
    fn synthetic_compound_shell_block_is_critical() {
        let component = "url:https://example.com/install.sh"
            .parse()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let report = synthetic_block(component, "RS-DOWNLOAD-TO-SHELL", "blocked")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(report.decision, Decision::Blocked);
    }

    #[test]
    fn audit_chain_detects_mutation() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let path = directory.path().join("audit.jsonl");
        append_audit(
            &path,
            "verification",
            Some("github:astral-sh/uv"),
            Some(Decision::Verified),
            None,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        append_audit(&path, "verification", None, Some(Decision::Blocked), None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            verify_audit(&path).unwrap_or_else(|error| unreachable!("{error}")),
            2
        );
        let source = fs::read_to_string(&path).unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(&path, source.replace("verified", "blocked"))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(verify_audit(&path).is_err());
    }
}
