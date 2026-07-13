//! Canonical component resolution and predictable HalluSquatting signals.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use reposeal_core::{
    ComponentRef, Ecosystem, Evidence, EvidenceKind, EvidenceStrength, Severity, Signal,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strsim::normalized_levenshtein;
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;

const MAX_PROVIDER_BYTES: usize = 2 * 1024 * 1024;
const MAX_HALLUSQUAT_CANDIDATES: usize = 256;

/// Resolver runtime configuration.
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// Do not use network providers.
    pub offline: bool,
    /// Provider request deadline.
    pub timeout: Duration,
    /// Optional GitHub API bearer token.
    pub github_token: Option<String>,
    /// HTTP user agent.
    pub user_agent: String,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            offline: false,
            timeout: Duration::from_secs(8),
            github_token: std::env::var("GITHUB_TOKEN").ok(),
            user_agent: format!("RepoSeal/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

/// Provider-neutral resolver output before policy evaluation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    /// Likely authoritative identity, when sufficiently established.
    pub canonical: Option<ComponentRef>,
    /// Attributable provider facts.
    pub evidence: Vec<Evidence>,
    /// Deterministic security signals.
    pub signals: Vec<Signal>,
    /// Bounded predictable hallucination candidates.
    pub hallusquat_candidates: Vec<String>,
}

#[derive(Clone)]
struct CacheEntry {
    expires_at: DateTime<Utc>,
    value: Value,
}

/// Live and offline canonical-source resolver.
pub struct Resolver {
    config: ResolverConfig,
    client: Client,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl Resolver {
    /// Constructs a bounded HTTPS resolver.
    pub fn new(config: ResolverConfig) -> Result<Self, ResolveError> {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .build()
            .map_err(ResolveError::Http)?;
        Ok(Self {
            config,
            client,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Resolves one component without applying allow policy.
    pub async fn resolve(&self, requested: &ComponentRef) -> Result<Resolution, ResolveError> {
        let candidates = hallusquat_candidates(requested);
        if self.config.offline {
            return Ok(Resolution {
                canonical: None,
                evidence: vec![unavailable_evidence(
                    "offline",
                    "network providers disabled by configuration",
                )],
                signals: vec![signal(
                    "RS-EVIDENCE-OFFLINE",
                    Severity::Medium,
                    "Canonical identity could not be established in offline mode",
                    "Use a matching agent.lock entry or perform one reviewed online resolution",
                )],
                hallusquat_candidates: candidates,
            });
        }

        let mut resolution = match requested.ecosystem {
            Ecosystem::Github => self.resolve_github(requested).await?,
            Ecosystem::Npm => self.resolve_npm(requested).await?,
            Ecosystem::Pypi => self.resolve_pypi(requested).await?,
            Ecosystem::Cargo => self.resolve_cargo(requested).await?,
            Ecosystem::Go => self.resolve_go(requested).await?,
            Ecosystem::Skill | Ecosystem::Mcp | Ecosystem::Plugin => {
                self.resolve_github_namespace(requested).await?
            }
            Ecosystem::Url => Self::resolve_url(requested),
        };
        resolution.hallusquat_candidates = candidates;
        apply_identity_comparison(requested, &mut resolution);
        Ok(resolution)
    }

    async fn resolve_github(&self, requested: &ComponentRef) -> Result<Resolution, ResolveError> {
        let (owner, project) = requested
            .owner_project()
            .ok_or(ResolveError::InvalidIdentity)?;
        let url = format!("https://api.github.com/repos/{owner}/{project}");
        let repository = match self.get_json(&url).await {
            Ok(value) => value,
            Err(ResolveError::NotFound) => {
                return Ok(Resolution {
                    canonical: None,
                    evidence: vec![unavailable_evidence(&url, "repository does not exist")],
                    signals: vec![signal(
                        "RS-REPOSITORY-NOT-FOUND",
                        Severity::Critical,
                        "Requested GitHub repository does not exist",
                        "Find the project through authoritative documentation before cloning",
                    )],
                    hallusquat_candidates: Vec::new(),
                });
            }
            Err(error) => return Err(error),
        };
        let profile = GithubProfile::from_value(&repository)?;
        let mut evidence = vec![profile.evidence(&url)];
        let mut signals = profile.signals();
        let mut canonical = Some(ComponentRef::new(
            Ecosystem::Github,
            &profile.full_name,
            requested.version.clone(),
        )?);

        if let Some(candidate) = self.search_canonical_github(project, &profile).await? {
            let candidate_url = format!("https://api.github.com/repos/{}", candidate.full_name);
            evidence.push(candidate.evidence(&candidate_url));
            signals.push(Signal {
                code: "RS-CANONICAL-OWNER-MISMATCH".to_owned(),
                severity: Severity::Critical,
                message: format!(
                    "Requested {} but repository history strongly identifies {} as canonical",
                    profile.full_name, candidate.full_name
                ),
                evidence_source: Some(candidate_url),
                remediation:
                    "Use the older established repository referenced by project authorities"
                        .to_owned(),
            });
            canonical = Some(ComponentRef::new(
                Ecosystem::Github,
                &candidate.full_name,
                requested.version.clone(),
            )?);
        }
        Ok(Resolution {
            canonical,
            evidence,
            signals,
            hallusquat_candidates: Vec::new(),
        })
    }

    async fn resolve_github_namespace(
        &self,
        requested: &ComponentRef,
    ) -> Result<Resolution, ResolveError> {
        let github = ComponentRef::new(
            Ecosystem::Github,
            requested.name.clone(),
            requested.version.clone(),
        )?;
        let mut resolution = self.resolve_github(&github).await?;
        resolution.canonical = resolution.canonical.map(|item| ComponentRef {
            ecosystem: requested.ecosystem,
            name: item.name,
            version: item.version,
        });
        Ok(resolution)
    }

    async fn resolve_npm(&self, requested: &ComponentRef) -> Result<Resolution, ResolveError> {
        let encoded = requested.name.replace('/', "%2F");
        let url = format!("https://registry.npmjs.org/{encoded}");
        let value = self.get_json(&url).await?;
        let repository = value
            .pointer("/repository/url")
            .or_else(|| value.pointer("/repository"))
            .and_then(Value::as_str)
            .and_then(github_identity_from_repository_url);
        let latest = value
            .pointer("/dist-tags/latest")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let created = value
            .pointer("/time/created")
            .and_then(Value::as_str)
            .and_then(parse_time);
        let maintainers = value
            .get("maintainers")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let mut metadata = BTreeMap::from([
            ("package".to_owned(), requested.name.clone()),
            ("maintainers".to_owned(), maintainers.to_string()),
        ]);
        if let Some(latest) = &latest {
            metadata.insert("latest".to_owned(), latest.clone());
        }
        if let Some(repository) = &repository {
            metadata.insert("repository".to_owned(), repository.id());
        }
        let mut signals = Vec::new();
        if let Some(version) = requested.version.as_deref().or(latest.as_deref())
            && has_lifecycle_scripts(&value, version)
        {
            signals.push(signal(
                "RS-INSTALL-LIFECYCLE-SCRIPT",
                Severity::High,
                "npm package declares install-time lifecycle scripts",
                "Inspect or sandbox the exact package tarball before installation",
            ));
        }
        if created.is_some_and(|time| Utc::now() - time < TimeDelta::days(1)) {
            signals.push(signal(
                "RS-ARTIFACT-VERY-YOUNG",
                Severity::Critical,
                "npm package was created less than 24 hours ago",
                "Require authoritative project documentation and explicit review",
            ));
        }
        Ok(Resolution {
            canonical: Some(requested.clone()),
            evidence: vec![Evidence {
                kind: EvidenceKind::Registry,
                source: url,
                claim: repository.map_or_else(
                    || "npm package exists; no GitHub source was declared".to_owned(),
                    |repository| format!("npm declares source {}", repository.id()),
                ),
                strength: if metadata.contains_key("repository") {
                    EvidenceStrength::Strong
                } else {
                    EvidenceStrength::Supporting
                },
                observed_at: Utc::now(),
                expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                metadata,
            }],
            signals,
            hallusquat_candidates: Vec::new(),
        })
    }

    async fn resolve_pypi(&self, requested: &ComponentRef) -> Result<Resolution, ResolveError> {
        let url = format!("https://pypi.org/pypi/{}/json", requested.name);
        let value = self.get_json(&url).await?;
        let source = project_url(&value, &["Source", "Source Code", "Repository", "Homepage"])
            .and_then(github_identity_from_repository_url);
        let version = value.pointer("/info/version").and_then(Value::as_str);
        let mut metadata = BTreeMap::new();
        if let Some(version) = version {
            metadata.insert("latest".to_owned(), version.to_owned());
        }
        if let Some(source) = &source {
            metadata.insert("repository".to_owned(), source.id());
        }
        Ok(Resolution {
            canonical: Some(requested.clone()),
            evidence: vec![Evidence {
                kind: EvidenceKind::Registry,
                source: url,
                claim: source.map_or_else(
                    || "PyPI project exists; no GitHub source was declared".to_owned(),
                    |item| format!("PyPI declares source {}", item.id()),
                ),
                strength: if metadata.contains_key("repository") {
                    EvidenceStrength::Strong
                } else {
                    EvidenceStrength::Supporting
                },
                observed_at: Utc::now(),
                expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                metadata,
            }],
            signals: Vec::new(),
            hallusquat_candidates: Vec::new(),
        })
    }

    async fn resolve_cargo(&self, requested: &ComponentRef) -> Result<Resolution, ResolveError> {
        let url = format!("https://crates.io/api/v1/crates/{}", requested.name);
        let value = self.get_json(&url).await?;
        let repository = value
            .pointer("/crate/repository")
            .and_then(Value::as_str)
            .and_then(github_identity_from_repository_url);
        let newest = value
            .pointer("/crate/newest_version")
            .and_then(Value::as_str);
        let downloads = value
            .pointer("/crate/downloads")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let mut metadata = BTreeMap::from([("downloads".to_owned(), downloads.to_string())]);
        if let Some(newest) = newest {
            metadata.insert("latest".to_owned(), newest.to_owned());
        }
        if let Some(repository) = &repository {
            metadata.insert("repository".to_owned(), repository.id());
        }
        Ok(Resolution {
            canonical: Some(requested.clone()),
            evidence: vec![Evidence {
                kind: EvidenceKind::Registry,
                source: url,
                claim: repository.map_or_else(
                    || "crates.io package exists; no GitHub source was declared".to_owned(),
                    |item| format!("crates.io declares source {}", item.id()),
                ),
                strength: if metadata.contains_key("repository") {
                    EvidenceStrength::Strong
                } else {
                    EvidenceStrength::Supporting
                },
                observed_at: Utc::now(),
                expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                metadata,
            }],
            signals: Vec::new(),
            hallusquat_candidates: Vec::new(),
        })
    }

    async fn resolve_go(&self, requested: &ComponentRef) -> Result<Resolution, ResolveError> {
        let url = format!("https://proxy.golang.org/{}/@v/list", requested.name);
        let body = self.get_text(&url).await?;
        let versions = body.lines().filter(|line| !line.trim().is_empty()).count();
        Ok(Resolution {
            canonical: Some(requested.clone()),
            evidence: vec![Evidence {
                kind: EvidenceKind::Registry,
                source: url,
                claim: "Go module proxy contains the requested module".to_owned(),
                strength: EvidenceStrength::Supporting,
                observed_at: Utc::now(),
                expires_at: Some(Utc::now() + TimeDelta::hours(1)),
                metadata: BTreeMap::from([("versions".to_owned(), versions.to_string())]),
            }],
            signals: Vec::new(),
            hallusquat_candidates: Vec::new(),
        })
    }

    fn resolve_url(requested: &ComponentRef) -> Resolution {
        let host = Url::parse(&requested.name)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        Resolution {
            canonical: None,
            evidence: vec![Evidence {
                kind: EvidenceKind::Domain,
                source: requested.name.clone(),
                claim: format!("Direct HTTPS download is hosted by {host}"),
                strength: EvidenceStrength::Weak,
                observed_at: Utc::now(),
                expires_at: None,
                metadata: BTreeMap::from([("host".to_owned(), host)]),
            }],
            signals: vec![signal(
                "RS-DIRECT-DOWNLOAD-UNRESOLVED",
                Severity::High,
                "A direct download has no independently established project identity",
                "Pin an integrity hash and authoritative domain in policy or agent.lock",
            )],
            hallusquat_candidates: Vec::new(),
        }
    }

    async fn search_canonical_github(
        &self,
        project: &str,
        requested: &GithubProfile,
    ) -> Result<Option<GithubProfile>, ResolveError> {
        let mut url = Url::parse("https://api.github.com/search/repositories")
            .map_err(|_| ResolveError::InvalidProviderUrl)?;
        url.query_pairs_mut()
            .append_pair("q", &format!("{project} in:name"))
            .append_pair("sort", "stars")
            .append_pair("order", "desc")
            .append_pair("per_page", "10");
        let value = self.get_json(url.as_str()).await?;
        let items = value
            .get("items")
            .and_then(Value::as_array)
            .ok_or(ResolveError::MalformedProvider)?;
        for item in items {
            let candidate = GithubProfile::from_value(item)?;
            if candidate
                .full_name
                .eq_ignore_ascii_case(&requested.full_name)
            {
                continue;
            }
            let candidate_project = candidate
                .full_name
                .split_once('/')
                .map_or("", |(_, name)| name);
            let established = candidate.stars >= requested.stars.saturating_mul(20).max(1_000)
                && candidate.created_at + TimeDelta::days(90) < requested.created_at;
            if candidate_project.eq_ignore_ascii_case(project) && established {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    async fn get_json(&self, url: &str) -> Result<Value, ResolveError> {
        if let Some(value) = self.cached(url).await {
            return Ok(value);
        }
        let text = self.get_text(url).await?;
        let value: Value = serde_json::from_str(&text).map_err(ResolveError::Json)?;
        self.cache.lock().await.insert(
            url.to_owned(),
            CacheEntry {
                expires_at: Utc::now() + TimeDelta::minutes(15),
                value: value.clone(),
            },
        );
        Ok(value)
    }

    async fn get_text(&self, url: &str) -> Result<String, ResolveError> {
        let mut request = self.client.get(url).header("Accept", "application/json");
        if url.starts_with("https://api.github.com/")
            && let Some(token) = &self.config.github_token
        {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(ResolveError::Http)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(ResolveError::NotFound);
        }
        if response.status() == StatusCode::TOO_MANY_REQUESTS
            || response.status() == StatusCode::FORBIDDEN
        {
            return Err(ResolveError::RateLimited);
        }
        let response = response.error_for_status().map_err(ResolveError::Http)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_BYTES as u64)
        {
            return Err(ResolveError::ResponseTooLarge);
        }
        let bytes = response.bytes().await.map_err(ResolveError::Http)?;
        if bytes.len() > MAX_PROVIDER_BYTES {
            return Err(ResolveError::ResponseTooLarge);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| ResolveError::MalformedProvider)
    }

    async fn cached(&self, key: &str) -> Option<Value> {
        self.cache
            .lock()
            .await
            .get(key)
            .filter(|entry| entry.expires_at > Utc::now())
            .map(|entry| entry.value.clone())
    }
}

/// Generates bounded transferable owner/project hallucination candidates.
#[must_use]
pub fn hallusquat_candidates(component: &ComponentRef) -> Vec<String> {
    let Some((owner, project)) = component.owner_project() else {
        return package_candidates(&component.name);
    };
    let mut output = BTreeSet::new();
    let owners = [
        owner.to_owned(),
        project.to_owned(),
        format!("{project}-ai"),
        format!("{project}hq"),
        format!("{project}-official"),
    ];
    let projects = project_variants(project);
    for candidate_owner in owners {
        for candidate_project in &projects {
            let value = format!("{candidate_owner}/{candidate_project}");
            if value != component.name {
                output.insert(value);
            }
            if output.len() >= MAX_HALLUSQUAT_CANDIDATES {
                break;
            }
        }
    }
    output.into_iter().take(MAX_HALLUSQUAT_CANDIDATES).collect()
}

fn package_candidates(name: &str) -> Vec<String> {
    project_variants(name)
        .into_iter()
        .filter(|candidate| candidate != name)
        .take(MAX_HALLUSQUAT_CANDIDATES)
        .collect()
}

fn project_variants(project: &str) -> Vec<String> {
    let mut output = BTreeSet::from([
        project.to_owned(),
        project.replace('-', ""),
        project.replace('_', "-"),
        format!("{project}-ai"),
        format!("{project}-official"),
        format!("{project}-cli"),
        format!("{project}s"),
    ]);
    let characters = project.char_indices().collect::<Vec<_>>();
    for (position, &(index, _)) in characters.iter().enumerate().take(32) {
        let next = characters
            .get(position + 1)
            .map_or(project.len(), |(next, _)| *next);
        let mut deletion = project.to_owned();
        deletion.replace_range(index..next, "");
        if !deletion.is_empty() {
            output.insert(deletion);
        }
        if let Some(&(second_index, second_char)) = characters.get(position + 1) {
            let second_end = characters
                .get(position + 2)
                .map_or(project.len(), |(next, _)| *next);
            let first_char = project[index..next].to_owned();
            let mut transposed = project.to_owned();
            transposed.replace_range(index..second_end, &format!("{second_char}{first_char}"));
            output.insert(transposed);
            let _ = second_index;
        }
    }
    output.into_iter().collect()
}

#[derive(Clone, Debug)]
struct GithubProfile {
    full_name: String,
    created_at: DateTime<Utc>,
    pushed_at: Option<DateTime<Utc>>,
    stars: u64,
    forks: u64,
    archived: bool,
    fork: bool,
    default_branch: String,
}

impl GithubProfile {
    fn from_value(value: &Value) -> Result<Self, ResolveError> {
        Ok(Self {
            full_name: string_field(value, "full_name")?.to_ascii_lowercase(),
            created_at: parse_time(string_field(value, "created_at")?)
                .ok_or(ResolveError::MalformedProvider)?,
            pushed_at: value
                .get("pushed_at")
                .and_then(Value::as_str)
                .and_then(parse_time),
            stars: value
                .get("stargazers_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            forks: value
                .get("forks_count")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            archived: value
                .get("archived")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            fork: value.get("fork").and_then(Value::as_bool).unwrap_or(false),
            default_branch: value
                .get("default_branch")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        })
    }

    fn evidence(&self, source: &str) -> Evidence {
        Evidence {
            kind: EvidenceKind::Repository,
            source: source.to_owned(),
            claim: format!(
                "GitHub identifies {} with {} stars, {} forks, created {}",
                self.full_name,
                self.stars,
                self.forks,
                self.created_at.to_rfc3339()
            ),
            strength: EvidenceStrength::Supporting,
            observed_at: Utc::now(),
            expires_at: Some(Utc::now() + TimeDelta::minutes(15)),
            metadata: BTreeMap::from([
                ("full_name".to_owned(), self.full_name.clone()),
                ("created_at".to_owned(), self.created_at.to_rfc3339()),
                ("stars".to_owned(), self.stars.to_string()),
                ("forks".to_owned(), self.forks.to_string()),
                ("fork".to_owned(), self.fork.to_string()),
                ("archived".to_owned(), self.archived.to_string()),
                ("default_branch".to_owned(), self.default_branch.clone()),
                (
                    "pushed_at".to_owned(),
                    self.pushed_at
                        .map_or_else(String::new, |time| time.to_rfc3339()),
                ),
            ]),
        }
    }

    fn signals(&self) -> Vec<Signal> {
        let age = Utc::now() - self.created_at;
        let mut signals = Vec::new();
        if age < TimeDelta::days(1) {
            signals.push(signal(
                "RS-REPOSITORY-VERY-YOUNG",
                Severity::Critical,
                "Repository was created less than 24 hours ago",
                "Verify the project through authoritative documentation and maintainer channels",
            ));
        } else if age < TimeDelta::days(30) {
            signals.push(signal(
                "RS-REPOSITORY-YOUNG",
                Severity::High,
                "Repository was created less than 30 days ago",
                "Require explicit review and independent canonical-source evidence",
            ));
        }
        if self.fork {
            signals.push(signal(
                "RS-REPOSITORY-FORK",
                Severity::Medium,
                "Requested repository is a fork",
                "Confirm that the fork—not its upstream—is explicitly intended",
            ));
        }
        if self.archived {
            signals.push(signal(
                "RS-REPOSITORY-ARCHIVED",
                Severity::Medium,
                "Requested repository is archived",
                "Confirm the maintained successor from official project documentation",
            ));
        }
        signals
    }
}

fn apply_identity_comparison(requested: &ComponentRef, resolution: &mut Resolution) {
    let Some(canonical) = &resolution.canonical else {
        return;
    };
    if requested.ecosystem == canonical.ecosystem && requested.name != canonical.name {
        resolution.signals.push(signal(
            "RS-IDENTITY-MISMATCH",
            Severity::Critical,
            &format!(
                "Requested {} but authoritative evidence points to {}",
                requested.id(),
                canonical.id()
            ),
            "Use the canonical identity or add a narrowly reviewed policy exception",
        ));
    }
    let similarity = normalized_levenshtein(&requested.name, &canonical.name);
    if requested.name != canonical.name && similarity >= 0.82 {
        resolution.signals.push(signal(
            "RS-HALLUSQUAT-NAME-SIMILARITY",
            Severity::High,
            &format!(
                "Requested identity is {:.0}% similar to canonical",
                similarity * 100.0
            ),
            "Use the exact canonical owner and project/package spelling",
        ));
    }
}

fn has_lifecycle_scripts(value: &Value, version: &str) -> bool {
    value
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|version| version.get("scripts"))
        .and_then(Value::as_object)
        .is_some_and(|scripts| {
            ["preinstall", "install", "postinstall", "prepare"]
                .iter()
                .any(|key| scripts.contains_key(*key))
        })
}

fn github_identity_from_repository_url(input: &str) -> Option<ComponentRef> {
    let normalized = input
        .trim()
        .trim_start_matches("git+")
        .trim_start_matches("git://")
        .trim_start_matches("ssh://git@github.com/")
        .trim_start_matches("git@github.com:");
    let normalized = if normalized.starts_with("github.com/") {
        format!("https://{normalized}")
    } else {
        normalized.to_owned()
    };
    normalized.parse().ok()
}

fn project_url<'a>(value: &'a Value, names: &[&str]) -> Option<&'a str> {
    let urls = value.pointer("/info/project_urls")?.as_object()?;
    names
        .iter()
        .find_map(|name| urls.get(*name).and_then(Value::as_str))
        .or_else(|| value.pointer("/info/home_page").and_then(Value::as_str))
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|time| time.with_timezone(&Utc))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ResolveError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ResolveError::MalformedProvider)
}

fn unavailable_evidence(source: &str, claim: &str) -> Evidence {
    Evidence {
        kind: EvidenceKind::Unavailable,
        source: source.to_owned(),
        claim: claim.to_owned(),
        strength: EvidenceStrength::Weak,
        observed_at: Utc::now(),
        expires_at: None,
        metadata: BTreeMap::new(),
    }
}

fn signal(code: &str, severity: Severity, message: &str, remediation: &str) -> Signal {
    Signal {
        code: code.to_owned(),
        severity,
        message: message.to_owned(),
        evidence_source: None,
        remediation: remediation.to_owned(),
    }
}

/// Provider, network, or identity-resolution errors.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// HTTP setup or request failed.
    #[error("provider HTTP request failed: {0}")]
    Http(reqwest::Error),
    /// JSON response was malformed.
    #[error("provider JSON failed: {0}")]
    Json(serde_json::Error),
    /// Component identity was not valid for this provider.
    #[error("invalid provider component identity")]
    InvalidIdentity,
    /// Provider URL construction failed.
    #[error("invalid provider URL")]
    InvalidProviderUrl,
    /// Provider returned missing required fields.
    #[error("provider returned malformed metadata")]
    MalformedProvider,
    /// Provider reported no artifact.
    #[error("component was not found")]
    NotFound,
    /// Provider rate limited the request.
    #[error("provider rate limited resolution")]
    RateLimited,
    /// Response exceeded the configured security bound.
    #[error("provider response exceeded size limit")]
    ResponseTooLarge,
    /// Core identity validation failed.
    #[error(transparent)]
    Core(#[from] reposeal_core::CoreError),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use chrono::{TimeDelta, Utc};
    use reposeal_core::{ComponentRef, Ecosystem, Severity};
    use serde_json::json;

    use super::{GithubProfile, hallusquat_candidates, has_lifecycle_scripts};

    #[test]
    fn candidate_generation_is_bounded_deterministic_and_transferable() {
        let requested = ComponentRef::new(Ecosystem::Github, "astral-sh/uv", None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let first = hallusquat_candidates(&requested);
        let second = hallusquat_candidates(&requested);
        assert_eq!(first, second);
        assert!(first.len() <= 256);
        assert!(first.contains(&"uv/uv".to_owned()));
        assert!(first.contains(&"uv-ai/uv".to_owned()));
        assert!(first.contains(&"uv-official/uv".to_owned()));
        assert!(!first.contains(&requested.name));
    }

    #[test]
    fn lifecycle_scripts_are_version_specific() {
        let metadata =
            json!({"versions":{"1.0.0":{"scripts":{"postinstall":"node setup.js"}},"1.0.1":{}}});
        assert!(has_lifecycle_scripts(&metadata, "1.0.0"));
        assert!(!has_lifecycle_scripts(&metadata, "1.0.1"));
    }

    #[test]
    fn github_profile_flags_new_repository_without_popularity_override() {
        let profile = GithubProfile::from_value(&json!({
            "full_name":"attacker/cool-project",
            "created_at":(Utc::now()-TimeDelta::hours(2)).to_rfc3339(),
            "pushed_at":Utc::now().to_rfc3339(),
            "stargazers_count":50000,
            "forks_count":1,
            "archived":false,
            "fork":false,
            "default_branch":"main"
        }))
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(profile.signals().iter().any(|signal| {
            signal.code == "RS-REPOSITORY-VERY-YOUNG" && signal.severity == Severity::Critical
        }));
    }

    #[test]
    fn repository_url_normalizes_to_github_identity() {
        let parsed = ComponentRef::from_str("https://github.com/astral-sh/uv.git")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(parsed.id(), "github:astral-sh/uv");
    }
}
