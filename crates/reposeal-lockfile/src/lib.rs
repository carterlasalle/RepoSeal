//! Strict `agent.lock` model, integrity verification, and atomic persistence.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use reposeal_core::{ComponentRef, Sha256Digest, canonical_json};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Stable lockfile schema.
pub const LOCKFILE_VERSION: u16 = 1;

/// Component artifact class.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentType {
    /// VCS repository.
    Repository,
    /// Registry package.
    Package,
    /// Agent skill.
    AgentSkill,
    /// MCP server.
    McpServer,
    /// Agent/editor plugin.
    Plugin,
    /// Direct download.
    Download,
}

/// Requested-to-canonical identity mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Exact requested identity.
    pub requested: String,
    /// Reviewed canonical identity.
    pub canonical: String,
    /// Whether relevant owner evidence was established.
    pub verified_owner: bool,
}

/// Bounded permissions observed or approved for a component.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    /// Filesystem scopes, never secret values.
    #[serde(default)]
    pub filesystem: BTreeSet<String>,
    /// Network hosts.
    #[serde(default)]
    pub network: BTreeSet<String>,
    /// Environment variable names read.
    #[serde(default)]
    pub environment_read: BTreeSet<String>,
    /// Whether shell execution is required.
    #[serde(default)]
    pub shell: bool,
}

/// Human or policy approval record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// Approver identity or policy principal.
    pub principal: String,
    /// `human`, `policy`, or `enterprise`.
    pub method: String,
    /// UTC approval time.
    pub approved_at: DateTime<Utc>,
    /// Hash of the reviewed verification report.
    pub report_hash: Sha256Digest,
}

/// One exact locked capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedComponent {
    /// Stable typed component ID.
    pub id: String,
    /// Artifact class.
    #[serde(rename = "type")]
    pub component_type: ComponentType,
    /// Registry/package version.
    pub version: Option<String>,
    /// Exact VCS commit.
    pub commit: Option<String>,
    /// Requested and canonical identities.
    pub source: SourceIdentity,
    /// Tree/tarball/signature/provenance integrity facts.
    #[serde(default)]
    pub integrity: BTreeMap<String, String>,
    /// Bounded capabilities.
    #[serde(default)]
    pub permissions: Permissions,
    /// Typed dependency IDs.
    #[serde(default)]
    pub dependencies: BTreeSet<String>,
    /// Hash of natural-language instructions for skills/plugins.
    pub instruction_hash: Option<Sha256Digest>,
    /// Non-secret provenance claims.
    #[serde(default)]
    pub provenance: Vec<BTreeMap<String, String>>,
    /// Approval history.
    #[serde(default)]
    pub approvals: Vec<Approval>,
    /// Last complete review time.
    pub reviewed_at: DateTime<Utc>,
    /// Canonical hash of all preceding fields.
    pub entry_hash: Sha256Digest,
}

impl LockedComponent {
    /// Recomputes the entry hash over all other fields.
    pub fn compute_hash(&self) -> Result<Sha256Digest, LockError> {
        let mut value = serde_json::to_value(self).map_err(LockError::Json)?;
        value
            .as_object_mut()
            .ok_or(LockError::InvalidShape)?
            .remove("entry_hash");
        let bytes = canonical_json(&value).map_err(LockError::Core)?;
        Ok(Sha256Digest::domain(b"agent-lock-entry/v1", &bytes))
    }

    /// Updates the bound entry hash after an intentional change.
    pub fn seal(&mut self) -> Result<(), LockError> {
        self.entry_hash = self.compute_hash()?;
        Ok(())
    }

    /// Checks the bound entry hash and identity consistency.
    pub fn verify(&self) -> Result<(), LockError> {
        if self.compute_hash()? != self.entry_hash {
            return Err(LockError::EntryHashMismatch(self.id.clone()));
        }
        let parsed: ComponentRef = self
            .id
            .parse()
            .map_err(|_| LockError::InvalidComponentId(self.id.clone()))?;
        if parsed.id() != self.id {
            return Err(LockError::InvalidComponentId(self.id.clone()));
        }
        Ok(())
    }
}

/// Strict universal agent dependency lockfile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLock {
    /// Must be one.
    pub version: u16,
    /// Unique sorted capabilities.
    #[serde(default)]
    pub components: Vec<LockedComponent>,
}

impl Default for AgentLock {
    fn default() -> Self {
        Self {
            version: LOCKFILE_VERSION,
            components: Vec::new(),
        }
    }
}

impl AgentLock {
    /// Reads and completely verifies a lockfile.
    pub fn load(path: &Path) -> Result<Self, LockError> {
        reject_symlink(path)?;
        let bytes = fs::read(path).map_err(LockError::Io)?;
        if bytes.len() > 10 * 1024 * 1024 {
            return Err(LockError::TooLarge);
        }
        let lock: Self = serde_yaml_ng::from_slice(&bytes).map_err(LockError::Yaml)?;
        lock.verify()?;
        Ok(lock)
    }

    /// Verifies schema, uniqueness, order, references, and entry integrity.
    pub fn verify(&self) -> Result<(), LockError> {
        if self.version != LOCKFILE_VERSION {
            return Err(LockError::UnsupportedVersion(self.version));
        }
        let mut prior: Option<&str> = None;
        let mut ids = BTreeSet::new();
        for component in &self.components {
            component.verify()?;
            if !ids.insert(component.id.as_str()) {
                return Err(LockError::DuplicateComponent(component.id.clone()));
            }
            if prior.is_some_and(|value| value >= component.id.as_str()) {
                return Err(LockError::NotSorted);
            }
            prior = Some(&component.id);
        }
        for component in &self.components {
            for dependency in &component.dependencies {
                if !ids.contains(dependency.as_str()) {
                    return Err(LockError::MissingDependency {
                        component: component.id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns a matching component ID.
    #[must_use]
    pub fn contains(&self, component: &ComponentRef) -> bool {
        self.components.iter().any(|item| item.id == component.id())
    }

    /// Adds or replaces one sealed component and restores deterministic order.
    pub fn upsert(&mut self, mut component: LockedComponent) -> Result<(), LockError> {
        component.seal()?;
        self.components.retain(|item| item.id != component.id);
        self.components.push(component);
        self.components
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.verify()
    }

    /// Atomically writes a verified lockfile with owner-only permissions on Unix.
    pub fn save(&self, path: &Path) -> Result<(), LockError> {
        self.verify()?;
        reject_symlink(path)?;
        let parent = path.parent().ok_or(LockError::InvalidPath)?;
        fs::create_dir_all(parent).map_err(LockError::Io)?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(LockError::Io)?;
        set_owner_only(temporary.as_file())?;
        let bytes = serde_yaml_ng::to_string(self).map_err(LockError::Yaml)?;
        temporary
            .write_all(bytes.as_bytes())
            .map_err(LockError::Io)?;
        temporary.flush().map_err(LockError::Io)?;
        temporary.as_file().sync_all().map_err(LockError::Io)?;
        temporary
            .persist(path)
            .map_err(|error| LockError::Io(error.error))?;
        sync_parent(parent)?;
        Ok(())
    }
}

/// Lockfile storage or integrity error.
#[derive(Debug, Error)]
pub enum LockError {
    /// Filesystem operation failed.
    #[error("lockfile I/O failed: {0}")]
    Io(std::io::Error),
    /// Strict YAML failed.
    #[error("invalid agent.lock YAML: {0}")]
    Yaml(serde_yaml_ng::Error),
    /// JSON conversion failed.
    #[error("lockfile JSON failed: {0}")]
    Json(serde_json::Error),
    /// Core canonicalization failed.
    #[error("lockfile canonicalization failed: {0}")]
    Core(reposeal_core::CoreError),
    /// Lock exceeded 10 MiB.
    #[error("agent.lock exceeds the 10 MiB limit")]
    TooLarge,
    /// Schema version is unsupported.
    #[error("unsupported agent.lock version {0}")]
    UnsupportedVersion(u16),
    /// Duplicate component ID.
    #[error("duplicate locked component {0}")]
    DuplicateComponent(String),
    /// Components were not strictly sorted.
    #[error("locked components are not strictly sorted")]
    NotSorted,
    /// Referenced dependency was absent.
    #[error("component {component} references missing dependency {dependency}")]
    MissingDependency {
        /// Parent component.
        component: String,
        /// Missing dependency.
        dependency: String,
    },
    /// Entry security hash changed.
    #[error("integrity hash mismatch for {0}")]
    EntryHashMismatch(String),
    /// ID was malformed or not canonically normalized.
    #[error("invalid locked component ID {0}")]
    InvalidComponentId(String),
    /// Lock path was missing a safe parent.
    #[error("invalid agent.lock path")]
    InvalidPath,
    /// Lock target is a symlink.
    #[error("refusing symlink agent.lock path")]
    SymlinkPath,
    /// Internal serialized shape was invalid.
    #[error("invalid lockfile serialization shape")]
    InvalidShape,
}

fn reject_symlink(path: &Path) -> Result<(), LockError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(LockError::SymlinkPath),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LockError::Io(error)),
    }
}

#[cfg(unix)]
fn set_owner_only(file: &File) -> Result<(), LockError> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(LockError::Io)
}

#[cfg(not(unix))]
fn set_owner_only(_file: &File) -> Result<(), LockError> {
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), LockError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(LockError::Io)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use chrono::Utc;
    use reposeal_core::Sha256Digest;
    use tempfile::tempdir;

    use super::{AgentLock, ComponentType, LockedComponent, Permissions, SourceIdentity};

    fn component() -> LockedComponent {
        LockedComponent {
            id: "github:astral-sh/uv".to_owned(),
            component_type: ComponentType::Repository,
            version: None,
            commit: Some("38b94d4".to_owned()),
            source: SourceIdentity {
                requested: "github:astral-sh/uv".to_owned(),
                canonical: "github:astral-sh/uv".to_owned(),
                verified_owner: true,
            },
            integrity: BTreeMap::from([(
                "tree_sha256".to_owned(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
            )]),
            permissions: Permissions {
                filesystem: BTreeSet::from(["project".to_owned(), "cache".to_owned()]),
                network: BTreeSet::from(["github.com".to_owned()]),
                environment_read: BTreeSet::from(["PATH".to_owned()]),
                shell: false,
            },
            dependencies: BTreeSet::new(),
            instruction_hash: None,
            provenance: Vec::new(),
            approvals: Vec::new(),
            reviewed_at: Utc::now(),
            entry_hash: Sha256Digest::domain(b"placeholder", b""),
        }
    }

    #[test]
    fn atomic_round_trip_and_tamper_detection() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let path = directory.path().join("agent.lock");
        let mut lock = AgentLock::default();
        lock.upsert(component())
            .unwrap_or_else(|error| unreachable!("{error}"));
        lock.save(&path)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let loaded = AgentLock::load(&path).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(loaded, lock);
        let source = fs::read_to_string(&path).unwrap_or_else(|error| unreachable!("{error}"));
        fs::write(&path, source.replace("38b94d4", "attacker"))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(AgentLock::load(&path).is_err());
    }

    #[test]
    fn unknown_fields_fail_strict_loading() {
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let path = directory.path().join("agent.lock");
        fs::write(&path, "version: 1\ncomponents: []\nsurprise: true\n")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(AgentLock::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_target() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
        let real = directory.path().join("real.lock");
        fs::write(&real, "unchanged").unwrap_or_else(|error| unreachable!("{error}"));
        let link = directory.path().join("agent.lock");
        symlink(&real, &link).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(AgentLock::default().save(&link).is_err());
        assert_eq!(
            fs::read_to_string(real).unwrap_or_else(|error| unreachable!("{error}")),
            "unchanged"
        );
    }
}
