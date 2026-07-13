//! Strict policy compiler and deterministic RepoSeal decision engine.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use reposeal_core::{
    ComponentRef, Decision, EvidenceStrength, Risk, Severity, Signal, VerificationReport,
};
use reposeal_resolver::Resolution;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable policy API.
pub const POLICY_API_VERSION: &str = "reposeal.dev/v1";

/// Enforcement mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block decisions prevent child execution.
    Enforce,
    /// Blocks are reported but the calling integration may observe only.
    Audit,
}

/// Behavior when canonical identity cannot be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnresolvedAction {
    /// Do not execute.
    Block,
    /// Require explicit review.
    Review,
}

/// Default decision behavior.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Defaults {
    /// Enforcement versus observation.
    pub mode: Mode,
    /// Missing canonical evidence behavior.
    pub unresolved: UnresolvedAction,
    /// Escalate any high signal from review to block.
    #[serde(default)]
    pub block_high: bool,
    /// Require a matching lock entry when offline.
    #[serde(default = "default_true")]
    pub require_lock_offline: bool,
    /// Require strong OS sandbox for dynamic install inspection.
    #[serde(default = "default_true")]
    pub require_strong_sandbox: bool,
}

/// Explicit policy lists. Exact values only; glob ambiguity is intentionally excluded from v1.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rules {
    /// Exact canonical component IDs that may resolve from lock/policy evidence.
    #[serde(default)]
    pub allow_components: BTreeSet<String>,
    /// Exact component IDs denied regardless of provider evidence.
    #[serde(default)]
    pub deny_components: BTreeSet<String>,
    /// Lowercase GitHub/skill/MCP/plugin owners denied.
    #[serde(default)]
    pub deny_owners: BTreeSet<String>,
    /// Lowercase direct-download domains denied.
    #[serde(default)]
    pub deny_domains: BTreeSet<String>,
    /// Trusted direct-download domains; integrity is still required separately.
    #[serde(default)]
    pub trusted_domains: BTreeSet<String>,
}

/// Strict top-level RepoSeal policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDocument {
    /// Must be `reposeal.dev/v1`.
    pub api_version: String,
    /// Must be `RepoSealPolicy`.
    pub kind: String,
    /// Default decisions.
    pub defaults: Defaults,
    /// Exact allow/deny roots.
    #[serde(default)]
    pub rules: Rules,
}

/// Validated immutable policy.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    document: PolicyDocument,
}

impl CompiledPolicy {
    /// Loads and validates YAML policy.
    pub fn from_path(path: &Path) -> Result<Self, PolicyError> {
        let source = fs::read_to_string(path).map_err(PolicyError::Io)?;
        Self::from_yaml(&source)
    }

    /// Parses and validates strict YAML policy.
    pub fn from_yaml(source: &str) -> Result<Self, PolicyError> {
        let document: PolicyDocument =
            serde_yaml_ng::from_str(source).map_err(PolicyError::Yaml)?;
        validate(&document)?;
        Ok(Self { document })
    }

    /// Secure default for local enforcement.
    #[must_use]
    pub fn secure_default() -> Self {
        Self {
            document: PolicyDocument {
                api_version: POLICY_API_VERSION.to_owned(),
                kind: "RepoSealPolicy".to_owned(),
                defaults: Defaults {
                    mode: Mode::Enforce,
                    unresolved: UnresolvedAction::Block,
                    block_high: false,
                    require_lock_offline: true,
                    require_strong_sandbox: true,
                },
                rules: Rules::default(),
            },
        }
    }

    /// Returns the authoring document.
    #[must_use]
    pub const fn document(&self) -> &PolicyDocument {
        &self.document
    }

    /// Converts resolver evidence into the final non-bypassable decision.
    pub fn evaluate(
        &self,
        requested: ComponentRef,
        mut resolution: Resolution,
        locked: bool,
    ) -> Result<VerificationReport, PolicyError> {
        apply_explicit_denies(&self.document.rules, &requested, &mut resolution.signals);
        let allowlisted = self
            .document
            .rules
            .allow_components
            .contains(&requested.id());
        let maximum = resolution
            .signals
            .iter()
            .map(|signal| signal.severity)
            .max()
            .unwrap_or(Severity::Info);
        let unresolved = resolution.canonical.is_none() && !locked && !allowlisted;
        let conflict = resolution.signals.iter().any(|signal| {
            matches!(
                signal.code.as_str(),
                "RS-IDENTITY-MISMATCH" | "RS-CANONICAL-OWNER-MISMATCH" | "RS-REPOSITORY-NOT-FOUND"
            )
        });
        let decision = if conflict || maximum == Severity::Critical {
            Decision::Blocked
        } else if unresolved {
            match self.document.defaults.unresolved {
                UnresolvedAction::Block => Decision::Blocked,
                UnresolvedAction::Review => Decision::Review,
            }
        } else if maximum == Severity::High {
            if self.document.defaults.block_high {
                Decision::Blocked
            } else {
                Decision::Review
            }
        } else if maximum == Severity::Medium {
            Decision::Review
        } else if identity_evidence_sufficient(&resolution, locked, allowlisted) {
            Decision::Verified
        } else {
            Decision::Review
        };
        if unresolved {
            resolution.signals.push(Signal {
                code: "RS-CANONICAL-UNRESOLVED".to_owned(),
                severity: if self.document.defaults.unresolved == UnresolvedAction::Block {
                    Severity::High
                } else {
                    Severity::Medium
                },
                message: "Canonical project identity was not established".to_owned(),
                evidence_source: None,
                remediation:
                    "Use authoritative project documentation, policy, or a reviewed lock entry"
                        .to_owned(),
            });
        }
        let final_maximum = resolution
            .signals
            .iter()
            .map(|signal| signal.severity)
            .max()
            .unwrap_or(Severity::Info);
        let risk = match final_maximum {
            Severity::Critical => Risk::Critical,
            Severity::High => Risk::High,
            Severity::Medium => Risk::Medium,
            Severity::Info | Severity::Low => {
                if decision == Decision::Verified {
                    Risk::Low
                } else {
                    Risk::Medium
                }
            }
        };
        VerificationReport::new(
            requested,
            resolution.canonical,
            decision,
            risk,
            resolution.signals,
            resolution.evidence,
        )
        .map_err(PolicyError::Core)
    }
}

fn validate(document: &PolicyDocument) -> Result<(), PolicyError> {
    if document.api_version != POLICY_API_VERSION {
        return Err(PolicyError::Validation(format!(
            "apiVersion must be {POLICY_API_VERSION}"
        )));
    }
    if document.kind != "RepoSealPolicy" {
        return Err(PolicyError::Validation(
            "kind must be RepoSealPolicy".to_owned(),
        ));
    }
    for collection in [
        &document.rules.allow_components,
        &document.rules.deny_components,
        &document.rules.deny_owners,
        &document.rules.deny_domains,
        &document.rules.trusted_domains,
    ] {
        if collection.iter().any(|value| {
            value.is_empty()
                || value.len() > 2_048
                || value.chars().any(char::is_control)
                || value != &value.to_ascii_lowercase()
        }) {
            return Err(PolicyError::Validation(
                "rule values must be bounded lowercase values without controls".to_owned(),
            ));
        }
    }
    if document
        .rules
        .allow_components
        .intersection(&document.rules.deny_components)
        .next()
        .is_some()
    {
        return Err(PolicyError::Validation(
            "the same component cannot be both allowed and denied".to_owned(),
        ));
    }
    Ok(())
}

fn apply_explicit_denies(rules: &Rules, requested: &ComponentRef, signals: &mut Vec<Signal>) {
    if rules.deny_components.contains(&requested.id()) {
        signals.push(critical_deny(
            "RS-POLICY-COMPONENT-DENIED",
            "Component is explicitly denied by policy",
        ));
    }
    if requested
        .owner_project()
        .is_some_and(|(owner, _)| rules.deny_owners.contains(owner))
    {
        signals.push(critical_deny(
            "RS-POLICY-OWNER-DENIED",
            "Component owner is explicitly denied by policy",
        ));
    }
    if requested.ecosystem == reposeal_core::Ecosystem::Url
        && url::Url::parse(&requested.name)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_some_and(|host| rules.deny_domains.contains(&host))
    {
        signals.push(critical_deny(
            "RS-POLICY-DOMAIN-DENIED",
            "Download domain is explicitly denied by policy",
        ));
    }
}

fn critical_deny(code: &str, message: &str) -> Signal {
    Signal {
        code: code.to_owned(),
        severity: Severity::Critical,
        message: message.to_owned(),
        evidence_source: Some("policy".to_owned()),
        remediation: "Remove the request or change policy through reviewed administration"
            .to_owned(),
    }
}

fn identity_evidence_sufficient(resolution: &Resolution, locked: bool, allowlisted: bool) -> bool {
    locked
        || allowlisted
        || resolution.evidence.iter().any(|evidence| {
            matches!(
                evidence.strength,
                EvidenceStrength::Supporting
                    | EvidenceStrength::Strong
                    | EvidenceStrength::Authoritative
            ) && !matches!(evidence.kind, reposeal_core::EvidenceKind::Unavailable)
        })
}

const fn default_true() -> bool {
    true
}

/// Policy loading and evaluation errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy file could not be read.
    #[error("policy I/O failed: {0}")]
    Io(std::io::Error),
    /// YAML was malformed or contained unknown fields.
    #[error("invalid policy YAML: {0}")]
    Yaml(serde_yaml_ng::Error),
    /// Semantic policy validation failed.
    #[error("invalid policy: {0}")]
    Validation(String),
    /// Report construction failed.
    #[error("report construction failed: {0}")]
    Core(reposeal_core::CoreError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use reposeal_core::{
        ComponentRef, Decision, Ecosystem, Evidence, EvidenceKind, EvidenceStrength, Severity,
        Signal,
    };
    use reposeal_resolver::Resolution;

    use super::CompiledPolicy;

    fn requested() -> ComponentRef {
        ComponentRef::new(Ecosystem::Github, "astral-sh/uv", None)
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn strong_resolution() -> Resolution {
        Resolution {
            canonical: Some(requested()),
            evidence: vec![Evidence {
                kind: EvidenceKind::Repository,
                source: "fixture".to_owned(),
                claim: "established repository".to_owned(),
                strength: EvidenceStrength::Strong,
                observed_at: Utc::now(),
                expires_at: None,
                metadata: BTreeMap::new(),
            }],
            signals: Vec::new(),
            hallusquat_candidates: Vec::new(),
        }
    }

    #[test]
    fn strong_matching_identity_is_verified() {
        let report = CompiledPolicy::secure_default()
            .evaluate(requested(), strong_resolution(), false)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(report.decision, Decision::Verified);
        assert!(report.verify_hash().is_ok());
    }

    #[test]
    fn critical_signal_cannot_be_allowlisted_away() {
        let mut resolution = strong_resolution();
        resolution.signals.push(Signal {
            code: "RS-IDENTITY-MISMATCH".to_owned(),
            severity: Severity::Critical,
            message: "wrong owner".to_owned(),
            evidence_source: None,
            remediation: "use canonical".to_owned(),
        });
        let report = CompiledPolicy::secure_default()
            .evaluate(requested(), resolution, true)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(report.decision, Decision::Blocked);
    }

    #[test]
    fn unresolved_defaults_to_block() {
        let report = CompiledPolicy::secure_default()
            .evaluate(requested(), Resolution::default(), false)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(report.decision, Decision::Blocked);
    }

    #[test]
    fn unknown_policy_fields_and_allow_deny_conflict_fail() {
        let unknown = r#"
apiVersion: reposeal.dev/v1
kind: RepoSealPolicy
defaults: { mode: enforce, unresolved: block }
surprise: true
"#;
        assert!(CompiledPolicy::from_yaml(unknown).is_err());
        let conflict = r#"
apiVersion: reposeal.dev/v1
kind: RepoSealPolicy
defaults: { mode: enforce, unresolved: block }
rules:
  allowComponents: [github:owner/project]
  denyComponents: [github:owner/project]
"#;
        assert!(CompiledPolicy::from_yaml(conflict).is_err());
    }
}
