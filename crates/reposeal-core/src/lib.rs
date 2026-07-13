//! RepoSeal security-domain types and deterministic report encoding.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Maximum accepted external component-reference length.
pub const MAX_REFERENCE_BYTES: usize = 2_048;

/// A lowercase SHA-256 value with an explicit algorithm prefix.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Hashes a domain-separated byte sequence.
    #[must_use]
    pub fn domain(domain: &[u8], payload: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"reposeal\0");
        hash.update((domain.len() as u64).to_be_bytes());
        hash.update(domain);
        hash.update((payload.len() as u64).to_be_bytes());
        hash.update(payload);
        Self(format!("sha256:{}", hex::encode(hash.finalize())))
    }

    /// Parses a prefixed 32-byte digest.
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        let Some(hex_value) = value.strip_prefix("sha256:") else {
            return Err(CoreError::InvalidDigest);
        };
        let bytes = hex::decode(hex_value).map_err(|_| CoreError::InvalidDigest)?;
        if bytes.len() != 32 || hex_value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(CoreError::InvalidDigest);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the stable textual representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Supported acquisition ecosystems.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    /// GitHub repository identity.
    Github,
    /// npm-compatible registry.
    Npm,
    /// Python Package Index.
    Pypi,
    /// crates.io.
    Cargo,
    /// Go module proxy/VCS identity.
    Go,
    /// Agent skill identifier.
    Skill,
    /// MCP server identifier.
    Mcp,
    /// Coding-agent plugin identifier.
    Plugin,
    /// Direct URL download.
    Url,
}

impl Ecosystem {
    /// Stable prefix used in component IDs.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::Skill => "skill",
            Self::Mcp => "mcp",
            Self::Plugin => "plugin",
            Self::Url => "url",
        }
    }
}

/// Normalized component requested by an agent or user.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRef {
    /// Registry or namespace.
    pub ecosystem: Ecosystem,
    /// Canonical normalized name within the ecosystem.
    pub name: String,
    /// Optional exact requested version, tag, or commit.
    pub version: Option<String>,
}

impl ComponentRef {
    /// Constructs and validates a typed identity.
    pub fn new(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: Option<String>,
    ) -> Result<Self, CoreError> {
        let name = normalize_name(ecosystem, &name.into())?;
        if version.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 256
                || value.chars().any(char::is_control)
                || value.contains(char::is_whitespace)
        }) {
            return Err(CoreError::InvalidVersion);
        }
        Ok(Self {
            ecosystem,
            name,
            version,
        })
    }

    /// Stable lockfile component ID.
    #[must_use]
    pub fn id(&self) -> String {
        match &self.version {
            Some(version) => format!("{}:{}@{version}", self.ecosystem.prefix(), self.name),
            None => format!("{}:{}", self.ecosystem.prefix(), self.name),
        }
    }

    /// Returns owner and project for owner/name namespaces.
    #[must_use]
    pub fn owner_project(&self) -> Option<(&str, &str)> {
        let (owner, project) = self.name.split_once('/')?;
        Some((owner, project))
    }
}

impl fmt::Display for ComponentRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id().fmt(formatter)
    }
}

impl FromStr for ComponentRef {
    type Err = CoreError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_component(input)
    }
}

/// Attributable evidence category.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Package-registry source or owner metadata.
    Registry,
    /// Repository metadata/history.
    Repository,
    /// Official project documentation reference.
    Documentation,
    /// Domain relationship.
    Domain,
    /// Release/tag signature.
    Signature,
    /// SLSA/Sigstore-style provenance.
    Provenance,
    /// Fork or rename lineage.
    Lineage,
    /// Content/instruction similarity.
    Similarity,
    /// Local lock or policy fact.
    LocalTrust,
    /// Provider unavailable, malformed, or rate limited.
    Unavailable,
}

/// Strength of an evidence claim, not an aggregate risk score.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    /// Informational and not identity-establishing alone.
    Weak,
    /// Independently useful but not authoritative alone.
    Supporting,
    /// Direct statement by a relevant authority.
    Strong,
    /// Cryptographically or locally pinned trust root.
    Authoritative,
}

/// One source-attributed identity or security fact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Stable evidence category.
    pub kind: EvidenceKind,
    /// URL, registry, manifest, policy, or lock source.
    pub source: String,
    /// Human-readable bounded claim.
    pub claim: String,
    /// Identity weight of this fact.
    pub strength: EvidenceStrength,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
    /// Optional cache expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Non-sensitive structured facts.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Ordered signal severity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Context only.
    Info,
    /// Low-confidence or low-impact issue.
    Low,
    /// Review-worthy issue.
    Medium,
    /// Unsafe without explicit review.
    High,
    /// Non-bypassable invariant violation.
    Critical,
}

/// Stable machine-readable finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    /// Stable code such as `RS-IDENTITY-MISMATCH`.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Safe explanation.
    pub message: String,
    /// Optional evidence-source reference.
    pub evidence_source: Option<String>,
    /// Safe next action.
    pub remediation: String,
}

/// Final enforcement decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Identity and policy checks are sufficiently established.
    Verified,
    /// Explicit human or enterprise review is required.
    Review,
    /// Acquisition must not execute.
    Blocked,
}

/// Coarse risk label for display and policy thresholds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// No material unresolved signal.
    Low,
    /// Review is prudent.
    Medium,
    /// Unsafe without explicit approval.
    High,
    /// Invariant violation.
    Critical,
}

/// Stable verification report consumed by every integration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    /// Schema version.
    pub schema_version: u16,
    /// Correlation identifier.
    pub request_id: Uuid,
    /// Exact normalized request.
    pub request: ComponentRef,
    /// Likely authoritative component, when established.
    pub canonical: Option<ComponentRef>,
    /// Final policy result.
    pub decision: Decision,
    /// Display risk.
    pub risk: Risk,
    /// Ordered findings.
    pub signals: Vec<Signal>,
    /// Ordered attributable evidence.
    pub evidence: Vec<Evidence>,
    /// Time of decision.
    pub evaluated_at: DateTime<Utc>,
    /// Canonical hash of all preceding report fields.
    pub report_hash: Sha256Digest,
}

impl VerificationReport {
    /// Creates a report and binds all fields into `report_hash`.
    pub fn new(
        request: ComponentRef,
        canonical: Option<ComponentRef>,
        decision: Decision,
        risk: Risk,
        mut signals: Vec<Signal>,
        mut evidence: Vec<Evidence>,
    ) -> Result<Self, CoreError> {
        signals.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.message.cmp(&right.message))
        });
        evidence.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.claim.cmp(&right.claim))
        });
        let mut report = Self {
            schema_version: 1,
            request_id: Uuid::new_v4(),
            request,
            canonical,
            decision,
            risk,
            signals,
            evidence,
            evaluated_at: Utc::now(),
            report_hash: Sha256Digest::domain(b"report-placeholder/v1", b""),
        };
        report.report_hash = report.compute_hash()?;
        Ok(report)
    }

    /// Recomputes the canonical report hash.
    pub fn compute_hash(&self) -> Result<Sha256Digest, CoreError> {
        let mut value = serde_json::to_value(self).map_err(CoreError::Json)?;
        let object = value.as_object_mut().ok_or(CoreError::CanonicalType)?;
        object.remove("report_hash");
        let bytes = canonical_json(&value)?;
        Ok(Sha256Digest::domain(b"verification-report/v1", &bytes))
    }

    /// Verifies report integrity.
    pub fn verify_hash(&self) -> Result<(), CoreError> {
        if self.compute_hash()? != self.report_hash {
            return Err(CoreError::HashMismatch);
        }
        Ok(())
    }
}

/// Core parsing, serialization, and integrity errors.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Reference was empty, too long, or contained controls.
    #[error("invalid component reference")]
    InvalidReference,
    /// Ecosystem prefix was not supported.
    #[error("unsupported component ecosystem")]
    UnsupportedEcosystem,
    /// Component name was invalid for its ecosystem.
    #[error("invalid component name")]
    InvalidName,
    /// Requested version was malformed.
    #[error("invalid component version")]
    InvalidVersion,
    /// URL was malformed or used an unsafe scheme/shape.
    #[error("invalid component URL")]
    InvalidUrl,
    /// Digest was not a lowercase prefixed SHA-256.
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    /// JSON serialization failed.
    #[error("JSON serialization failed: {0}")]
    Json(serde_json::Error),
    /// Canonical JSON only accepts JSON values.
    #[error("canonical JSON value had an unsupported shape")]
    CanonicalType,
    /// Bound hash did not match recomputed security fields.
    #[error("integrity hash mismatch")]
    HashMismatch,
}

/// Serializes JSON with recursively sorted object members and no whitespace.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CoreError> {
    let normalized = sort_value(value);
    serde_json::to_vec(&normalized).map_err(CoreError::Json)
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, value)| (key.clone(), sort_value(value)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(sort_value).collect()),
        scalar => scalar.clone(),
    }
}

fn parse_component(input: &str) -> Result<ComponentRef, CoreError> {
    let input = input.trim();
    if input.is_empty() || input.len() > MAX_REFERENCE_BYTES || input.chars().any(char::is_control)
    {
        return Err(CoreError::InvalidReference);
    }
    if input.starts_with("https://github.com/") || input.starts_with("http://github.com/") {
        return parse_github_url(input);
    }
    if let Some(rest) = input.strip_prefix("git@github.com:") {
        return ComponentRef::new(Ecosystem::Github, trim_git_suffix(rest), None);
    }
    let (prefix, rest) = input
        .split_once(':')
        .ok_or(CoreError::UnsupportedEcosystem)?;
    let ecosystem = match prefix.to_ascii_lowercase().as_str() {
        "github" | "gh" => Ecosystem::Github,
        "npm" => Ecosystem::Npm,
        "pypi" | "pip" | "python" => Ecosystem::Pypi,
        "cargo" | "crate" | "crates" => Ecosystem::Cargo,
        "go" => Ecosystem::Go,
        "skill" => Ecosystem::Skill,
        "mcp" => Ecosystem::Mcp,
        "plugin" => Ecosystem::Plugin,
        "url" => Ecosystem::Url,
        _ => return Err(CoreError::UnsupportedEcosystem),
    };
    if ecosystem == Ecosystem::Url {
        validate_download_url(rest)?;
        return ComponentRef::new(ecosystem, rest, None);
    }
    let (name, version) = split_version(ecosystem, rest);
    ComponentRef::new(ecosystem, name, version.map(str::to_owned))
}

fn parse_github_url(input: &str) -> Result<ComponentRef, CoreError> {
    let url = Url::parse(input).map_err(|_| CoreError::InvalidUrl)?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CoreError::InvalidUrl);
    }
    let segments = url
        .path_segments()
        .ok_or(CoreError::InvalidUrl)?
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() != 2 {
        return Err(CoreError::InvalidUrl);
    }
    ComponentRef::new(
        Ecosystem::Github,
        format!("{}/{}", segments[0], trim_git_suffix(segments[1])),
        None,
    )
}

fn validate_download_url(input: &str) -> Result<(), CoreError> {
    let url = Url::parse(input).map_err(|_| CoreError::InvalidUrl)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(CoreError::InvalidUrl);
    }
    Ok(())
}

fn split_version(ecosystem: Ecosystem, value: &str) -> (&str, Option<&str>) {
    if ecosystem == Ecosystem::Npm && value.starts_with('@') {
        return value
            .rfind('@')
            .filter(|index| *index > 0)
            .map_or((value, None), |index| {
                (&value[..index], Some(&value[index + 1..]))
            });
    }
    value
        .rsplit_once('@')
        .map_or((value, None), |(name, version)| (name, Some(version)))
}

fn trim_git_suffix(value: &str) -> &str {
    value.strip_suffix(".git").unwrap_or(value)
}

fn normalize_name(ecosystem: Ecosystem, input: &str) -> Result<String, CoreError> {
    let input = input.trim().trim_matches('/');
    if input.is_empty() || input.len() > MAX_REFERENCE_BYTES || input.contains("..") {
        return Err(CoreError::InvalidName);
    }
    match ecosystem {
        Ecosystem::Github | Ecosystem::Skill | Ecosystem::Mcp | Ecosystem::Plugin => {
            let segments = input.split('/').collect::<Vec<_>>();
            if segments.len() != 2 || segments.iter().any(|segment| !safe_slug(segment)) {
                return Err(CoreError::InvalidName);
            }
            Ok(format!(
                "{}/{}",
                segments[0].to_ascii_lowercase(),
                segments[1].to_ascii_lowercase()
            ))
        }
        Ecosystem::Npm => {
            let valid = input.bytes().all(|byte| {
                byte.is_ascii_alphabetic()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'@' | b'/' | b'.' | b'_' | b'-')
            });
            if !valid || input.contains(char::is_whitespace) {
                return Err(CoreError::InvalidName);
            }
            Ok(input.to_ascii_lowercase())
        }
        Ecosystem::Pypi => {
            if !input
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(CoreError::InvalidName);
            }
            Ok(input
                .to_ascii_lowercase()
                .replace(['.', '_'], "-")
                .split('-')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("-"))
        }
        Ecosystem::Cargo => {
            if !input
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(CoreError::InvalidName);
            }
            Ok(input.to_ascii_lowercase())
        }
        Ecosystem::Go => {
            if input.split('/').count() < 2
                || !input.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/')
                })
            {
                return Err(CoreError::InvalidName);
            }
            Ok(input.to_ascii_lowercase())
        }
        Ecosystem::Url => {
            validate_download_url(input)?;
            Ok(input.to_owned())
        }
    }
}

fn safe_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use serde_json::json;

    use super::{ComponentRef, Ecosystem, Sha256Digest, canonical_json};

    #[test]
    fn parses_and_normalizes_supported_identities() {
        let cases = [
            ("https://github.com/Astral-SH/uv.git", "github:astral-sh/uv"),
            ("git@github.com:astral-sh/uv.git", "github:astral-sh/uv"),
            (
                "npm:@ModelContextProtocol/sdk@1.2.3",
                "npm:@modelcontextprotocol/sdk@1.2.3",
            ),
            ("pypi:Foo_Bar@2.0", "pypi:foo-bar@2.0"),
            ("cargo:serde@1.0.0", "cargo:serde@1.0.0"),
            (
                "go:golang.org/x/tools@v0.1.0",
                "go:golang.org/x/tools@v0.1.0",
            ),
            (
                "skill:Example/Security-Review",
                "skill:example/security-review",
            ),
        ];
        for (input, expected) in cases {
            let parsed = ComponentRef::from_str(input)
                .unwrap_or_else(|error| unreachable!("{input}: {error}"));
            assert_eq!(parsed.id(), expected);
        }
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_references() {
        for input in [
            "http://github.com/owner/project",
            "https://user@github.com/owner/project",
            "github:owner/project/extra",
            "github:owner/../project",
            "url:http://example.com/install.sh",
            "npm:Package With Spaces",
        ] {
            assert!(ComponentRef::from_str(input).is_err(), "{input}");
        }
    }

    #[test]
    fn canonical_json_sorts_recursively() {
        let left = canonical_json(&json!({"z":1,"a":{"y":2,"b":3}}))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let right = canonical_json(&json!({"a":{"b":3,"y":2},"z":1}))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(left, right);
        assert_eq!(Sha256Digest::domain(b"test", &left).as_str().len(), 71);
    }

    #[test]
    fn github_owner_project_is_explicit() {
        let component = ComponentRef::new(Ecosystem::Github, "owner/project", None)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(component.owner_project(), Some(("owner", "project")));
    }
}
