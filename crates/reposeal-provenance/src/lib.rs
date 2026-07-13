//! Typed capability manifests and externally verified identity provenance.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use reposeal_core::{ComponentRef, Sha256Digest, canonical_json};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable capability-manifest API.
pub const MANIFEST_API_VERSION: &str = "reposeal.dev/v1";

/// Capability identity/version metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestMetadata {
    /// Human-readable project name.
    pub name: String,
    /// Maintainer-controlled manifest version.
    pub version: String,
}

/// Declared capability permissions.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityPermissions {
    /// Filesystem scopes.
    #[serde(default)]
    pub filesystem: BTreeSet<String>,
    /// Network hosts.
    #[serde(default)]
    pub network: BTreeSet<String>,
    /// Environment variable names read.
    #[serde(default)]
    pub environment_read: BTreeSet<String>,
    /// Shell execution required.
    #[serde(default)]
    pub shell: bool,
}

/// Maintainer-published canonical capability manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityManifest {
    /// Must be `reposeal.dev/v1`.
    pub api_version: String,
    /// Must be `CapabilityManifest`.
    pub kind: String,
    /// Project metadata.
    pub metadata: ManifestMetadata,
    /// Canonical repository/package/skill/MCP/plugin identities.
    pub identities: BTreeSet<String>,
    /// Official domains.
    #[serde(default)]
    pub domains: BTreeSet<String>,
    /// Typed component dependencies.
    #[serde(default)]
    pub dependencies: BTreeSet<String>,
    /// Required install/runtime permissions.
    pub permissions: CapabilityPermissions,
    /// Non-secret provenance descriptors.
    #[serde(default)]
    pub provenance: Vec<BTreeMap<String, String>>,
}

impl CapabilityManifest {
    /// Reads and validates a bounded JSON manifest.
    pub fn from_path(path: &Path) -> Result<Self, ProvenanceError> {
        let bytes = fs::read(path).map_err(ProvenanceError::Io)?;
        if bytes.len() > 1024 * 1024 {
            return Err(ProvenanceError::TooLarge);
        }
        Self::from_json(&bytes)
    }

    /// Parses and validates strict JSON.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProvenanceError> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(ProvenanceError::Json)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates identity/domain/dependency fields.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        if self.api_version != MANIFEST_API_VERSION || self.kind != "CapabilityManifest" {
            return Err(ProvenanceError::InvalidSchema);
        }
        if self.metadata.name.is_empty()
            || self.metadata.name.len() > 128
            || self.metadata.version.is_empty()
            || self.metadata.version.len() > 128
            || self.identities.is_empty()
        {
            return Err(ProvenanceError::InvalidMetadata);
        }
        for identity in &self.identities {
            let parsed: ComponentRef = identity
                .parse()
                .map_err(|_| ProvenanceError::InvalidIdentity(identity.clone()))?;
            if parsed.id() != *identity {
                return Err(ProvenanceError::InvalidIdentity(identity.clone()));
            }
        }
        for dependency in &self.dependencies {
            let parsed: ComponentRef = dependency
                .parse()
                .map_err(|_| ProvenanceError::InvalidIdentity(dependency.clone()))?;
            if parsed.id() != *dependency {
                return Err(ProvenanceError::InvalidIdentity(dependency.clone()));
            }
        }
        for domain in &self.domains {
            if domain.is_empty()
                || domain.len() > 253
                || domain != &domain.to_ascii_lowercase()
                || domain
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
            {
                return Err(ProvenanceError::InvalidDomain(domain.clone()));
            }
        }
        Ok(())
    }

    /// Canonical manifest digest used in attestations and lockfiles.
    pub fn digest(&self) -> Result<Sha256Digest, ProvenanceError> {
        let value = serde_json::to_value(self).map_err(ProvenanceError::Json)?;
        let bytes = canonical_json(&value).map_err(ProvenanceError::Core)?;
        Ok(Sha256Digest::domain(b"capability-manifest/v1", &bytes))
    }

    /// Returns whether a request is one of the exact maintainer-declared identities.
    #[must_use]
    pub fn declares(&self, component: &ComponentRef) -> bool {
        self.identities.contains(&component.id())
    }
}

/// Result produced by an external signature verifier such as Cosign.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalVerification {
    /// Whether the cryptographic signature and transparency proof were verified.
    pub signature_verified: bool,
    /// OIDC issuer or key fingerprint.
    pub issuer: String,
    /// OIDC subject or key identity.
    pub subject: String,
    /// Manifest digest bound by the verified attestation.
    pub manifest_digest: Sha256Digest,
    /// Exact repository commit bound by the attestation.
    pub commit: String,
    /// Optional transparency log index.
    pub log_index: Option<u64>,
}

/// Reviewed issuer/subject constraint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationPolicy {
    /// Exact allowed issuers.
    pub issuers: BTreeSet<String>,
    /// Exact allowed subjects.
    pub subjects: BTreeSet<String>,
}

impl AttestationPolicy {
    /// Validates externally verified results against local trust roots and exact artifacts.
    pub fn authorize(
        &self,
        verification: &ExternalVerification,
        manifest: &CapabilityManifest,
        commit: &str,
    ) -> Result<(), ProvenanceError> {
        if !verification.signature_verified {
            return Err(ProvenanceError::SignatureNotVerified);
        }
        if !self.issuers.contains(&verification.issuer)
            || !self.subjects.contains(&verification.subject)
        {
            return Err(ProvenanceError::UntrustedIdentity);
        }
        if verification.manifest_digest != manifest.digest()? || verification.commit != commit {
            return Err(ProvenanceError::AttestationBinding);
        }
        Ok(())
    }
}

/// Extracts a stable hash of skill/plugin instructions from normalized UTF-8 bytes.
pub fn instruction_hash(bytes: &[u8]) -> Result<Sha256Digest, ProvenanceError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProvenanceError::InvalidUtf8)?;
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    Ok(Sha256Digest::domain(
        b"agent-instructions/v1",
        normalized.as_bytes(),
    ))
}

/// Provenance manifest or attestation error.
#[derive(Debug, Error)]
pub enum ProvenanceError {
    /// Manifest I/O failed.
    #[error("provenance I/O failed: {0}")]
    Io(std::io::Error),
    /// Manifest JSON failed or had unknown fields.
    #[error("invalid capability manifest JSON: {0}")]
    Json(serde_json::Error),
    /// Manifest exceeded one MiB.
    #[error("capability manifest exceeds one MiB")]
    TooLarge,
    /// Top-level API/kind was invalid.
    #[error("invalid capability manifest schema")]
    InvalidSchema,
    /// Metadata was empty or excessive.
    #[error("invalid capability manifest metadata")]
    InvalidMetadata,
    /// Typed identity was invalid.
    #[error("invalid capability identity {0}")]
    InvalidIdentity(String),
    /// Domain was malformed.
    #[error("invalid capability domain {0}")]
    InvalidDomain(String),
    /// Canonicalization failed.
    #[error("capability canonicalization failed: {0}")]
    Core(reposeal_core::CoreError),
    /// Instructions were not UTF-8.
    #[error("instructions must be UTF-8")]
    InvalidUtf8,
    /// External verifier did not establish signature validity.
    #[error("attestation signature was not cryptographically verified")]
    SignatureNotVerified,
    /// Verified issuer/subject was not trusted by policy.
    #[error("attestation identity is not trusted")]
    UntrustedIdentity,
    /// Attestation did not bind the exact manifest/commit.
    #[error("attestation does not bind the exact manifest and commit")]
    AttestationBinding,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{AttestationPolicy, CapabilityManifest, ExternalVerification, instruction_hash};

    const MANIFEST: &str = r#"{
      "apiVersion":"reposeal.dev/v1",
      "kind":"CapabilityManifest",
      "metadata":{"name":"uv","version":"1"},
      "identities":["github:astral-sh/uv","pypi:uv"],
      "domains":["astral.sh"],
      "dependencies":[],
      "permissions":{"filesystem":["project","cache"],"network":["pypi.org"]},
      "provenance":[]
    }"#;

    #[test]
    fn strict_manifest_hash_and_identity_are_deterministic() {
        let manifest = CapabilityManifest::from_json(MANIFEST.as_bytes())
            .unwrap_or_else(|error| unreachable!("{error}"));
        let first = manifest
            .digest()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let second = manifest
            .digest()
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(first, second);
        let component = "github:astral-sh/uv"
            .parse()
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(manifest.declares(&component));
    }

    #[test]
    fn external_verification_must_bind_trusted_identity_manifest_and_commit() {
        let manifest = CapabilityManifest::from_json(MANIFEST.as_bytes())
            .unwrap_or_else(|error| unreachable!("{error}"));
        let policy = AttestationPolicy {
            issuers: BTreeSet::from(["https://token.actions.githubusercontent.com".to_owned()]),
            subjects: BTreeSet::from(["repo:astral-sh/uv:ref:refs/heads/main".to_owned()]),
        };
        let result = ExternalVerification {
            signature_verified: true,
            issuer: "https://token.actions.githubusercontent.com".to_owned(),
            subject: "repo:astral-sh/uv:ref:refs/heads/main".to_owned(),
            manifest_digest: manifest
                .digest()
                .unwrap_or_else(|error| unreachable!("{error}")),
            commit: "38b94d4".to_owned(),
            log_index: Some(42),
        };
        assert!(policy.authorize(&result, &manifest, "38b94d4").is_ok());
        assert!(policy.authorize(&result, &manifest, "different").is_err());
    }

    #[test]
    fn instruction_hash_normalizes_line_endings_but_not_content() {
        let windows = instruction_hash(b"# Skill\r\nRun safe tool\r\n")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let unix = instruction_hash(b"# Skill\nRun safe tool\n")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(windows, unix);
        let safe =
            instruction_hash(b"Run safe tool").unwrap_or_else(|error| unreachable!("{error}"));
        let unsafe_hash =
            instruction_hash(b"Run unsafe tool").unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(safe, unsafe_hash);
    }
}
