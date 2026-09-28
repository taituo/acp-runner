//! Credential store abstraction.
//!
//! The store holds the *material* of enrolled credential profiles (whitelisted files only).
//! The journal holds non-secret profile records and leases. Implementations:
//!
//! * `K8sSecretStore` (crate `acp-runner-k8s`): one Secret per profile in the controller
//!   namespace (never mounted into agent pods directly; per-attempt Secrets are created from
//!   it for the leased profile only).
//! * [`FileCredentialStore`]: a directory (development and tests).
//!
//! A Vault/external-secrets implementation only needs to implement [`CredentialStore`].

use acp_runner_core::credentials::{CredentialBundle, CredentialMetadata, Provider, validate_bundle};
use acp_runner_journal::{Journal, ProfileUpsert};
use async_trait::async_trait;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct StoredProfile {
    pub name: String,
    pub provider: Provider,
    pub max_concurrent_leases: i32,
    pub metadata: CredentialMetadata,
    /// V2 usage policy (namespaces × classes), deny by default.
    pub allowed_namespaces: Vec<String>,
    pub allowed_classes: Vec<String>,
    pub store_ref: String,
}



#[derive(Debug, thiserror::Error)]
pub enum CredStoreError {
    #[error("credential profile {0:?} not found")]
    NotFound(String),
    #[error("credential store error: {0}")]
    Store(String),
    #[error("invalid credential bundle: {0}")]
    Invalid(String),
    #[error("concurrent modification of profile {0:?}")]
    Conflict(String),
}

#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn list(&self) -> Result<Vec<StoredProfile>, CredStoreError>;
    async fn load(&self, profile: &str) -> Result<(StoredProfile, CredentialBundle), CredStoreError>;
    /// Create or replace a profile (enrollment). The bundle must already be validated.
    async fn save(&self, profile: &StoredProfile, bundle: &CredentialBundle) -> Result<(), CredStoreError>;
    /// Replace one whitelisted file of an existing profile (validated write-back).
    ///
    /// `expected_fingerprint` is the material fingerprint the caller saw when
    /// it authorized the write (the locked enrollment record). If the store's
    /// current bytes fingerprint differently — e.g. an admin re-enrolled
    /// concurrently — the write is refused with [`CredStoreError::Conflict`]
    /// instead of clobbering the newer enrollment.
    async fn update_file(
        &self,
        profile: &str,
        key: &str,
        bytes: &[u8],
        metadata: &CredentialMetadata,
        expected_fingerprint: &str,
    ) -> Result<(), CredStoreError>;
    async fn delete(&self, profile: &str) -> Result<(), CredStoreError>;

    /// Admin assignment for the V2 trust boundary: replace the profile's
    /// usage policy. Default implementation loads, patches, and saves (both
    /// bundled stores persist policy, so this is atomic enough for admin use).
    async fn set_policy(
        &self,
        profile: &str,
        namespaces: Vec<String>,
        classes: Vec<String>,
    ) -> Result<(), CredStoreError> {
        let (mut sp, bundle) = self.load(profile).await?;
        sp.allowed_namespaces = namespaces;
        sp.allowed_classes = classes;
        self.save(&sp, &bundle).await
    }
    }

/// Mirror the store's profiles into `credential_profiles` (non-secret records only).
///
/// Concurrency: only the profile *names* come from the initial listing. Each
/// profile row is then locked (`FOR UPDATE`) and its store data re-loaded
/// fresh *after* the lock is held, so a racing write-back commit can never be
/// overwritten by a stale pre-lock snapshot. A profile deleted from the store
/// between listing and locking is skipped.
pub async fn sync_profiles(store: &dyn CredentialStore, journal: &Journal) -> anyhow::Result<usize> {
    let names: Vec<String> = store.list().await?.into_iter().map(|p| p.name).collect();
    let mut synced = 0;
    for name in &names {
        let guard = journal.begin_profile_sync(name).await?;
        let loaded = match store.load(name).await {
            Ok(loaded) => loaded,
            Err(e) => {
                tracing::debug!(profile = %name, error = %e, "profile vanished during sync; skipping");
                continue;
            }
        };
        let (sp, _bundle) = loaded;
        let max = if sp.provider.spec().exclusive_lease { 1 } else { sp.max_concurrent_leases.max(1) };
        guard
            .commit(&ProfileUpsert {
                name: sp.name.clone(),
                provider: sp.provider.as_str().to_string(),
                store: sp.store_ref.clone(),
                max_concurrent_leases: max,
                metadata: serde_json::to_value(&sp.metadata)?,
                material_fingerprint: sp.metadata.material_fingerprint.clone(),
                allowed_namespaces: sp.allowed_namespaces.clone(),
                allowed_classes: sp.allowed_classes.clone(),
            })
            .await?;
        synced += 1;
    }
    Ok(synced)
}

/// Directory layout: `<root>/<profile>/profile.json` + one file per whitelisted key.
pub struct FileCredentialStore {
    pub root: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileFile {
    provider: Provider,
    max_concurrent_leases: i32,
    metadata: CredentialMetadata,
    /// V2 usage policy; missing (pre-V2 files) means deny.
    #[serde(default)]
    allowed_namespaces: Vec<String>,
    #[serde(default)]
    allowed_classes: Vec<String>,
}

fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 50
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

pub fn check_profile_name(name: &str) -> Result<(), CredStoreError> {
    if valid_profile_name(name) {
        Ok(())
    } else {
        Err(CredStoreError::Invalid(format!(
            "profile name {name:?} must be a DNS label (lowercase letters, digits, '-', max 50)"
        )))
    }
}

#[async_trait]
impl CredentialStore for FileCredentialStore {
    async fn list(&self) -> Result<Vec<StoredProfile>, CredStoreError> {
        let mut out = vec![];
        let Ok(rd) = std::fs::read_dir(&self.root) else { return Ok(out) };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Ok(bytes) = std::fs::read(e.path().join("profile.json"))
                && let Ok(pf) = serde_json::from_slice::<ProfileFile>(&bytes)
            {
                out.push(StoredProfile {
                    store_ref: format!("file:{}", e.path().display()),
                    name,
                    provider: pf.provider,
                    max_concurrent_leases: pf.max_concurrent_leases,
                    metadata: pf.metadata,
                    allowed_namespaces: pf.allowed_namespaces,
                    allowed_classes: pf.allowed_classes,
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn load(&self, profile: &str) -> Result<(StoredProfile, CredentialBundle), CredStoreError> {
        check_profile_name(profile)?;
        let dir = self.root.join(profile);
        let pf: ProfileFile = serde_json::from_slice(
            &std::fs::read(dir.join("profile.json")).map_err(|_| CredStoreError::NotFound(profile.to_string()))?,
        )
        .map_err(|e| CredStoreError::Store(e.to_string()))?;
        let mut bundle = CredentialBundle::new();
        if pf.provider.dynamic_keys() {
            // V9 files provider: bundle keys are per-profile filenames —
            // enumerate everything except the profile record itself.
            for e in std::fs::read_dir(&dir).map_err(|e| CredStoreError::Store(e.to_string()))?.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name == "profile.json" {
                    continue;
                }
                let b =
                    std::fs::read(e.path()).map_err(|e| CredStoreError::Store(format!("{name}: {e}")))?;
                bundle.insert(name, b);
            }
        } else {
            for key in pf.provider.spec().keys() {
                let b = std::fs::read(dir.join(key)).map_err(|e| CredStoreError::Store(format!("{key}: {e}")))?;
                bundle.insert(key.to_string(), b);
            }
        }
        let sp = StoredProfile {
            name: profile.to_string(),
            provider: pf.provider,
            max_concurrent_leases: pf.max_concurrent_leases,
            metadata: pf.metadata,
            allowed_namespaces: pf.allowed_namespaces,
            allowed_classes: pf.allowed_classes,
            store_ref: format!("file:{}", dir.display()),
        };
        Ok((sp, bundle))
    }

    async fn save(&self, profile: &StoredProfile, bundle: &CredentialBundle) -> Result<(), CredStoreError> {
        check_profile_name(&profile.name)?;
        validate_bundle(profile.provider, bundle).map_err(|e| CredStoreError::Invalid(e.to_string()))?;
        let dir = self.root.join(&profile.name);
        let io = |e: std::io::Error| CredStoreError::Store(e.to_string());
        std::fs::create_dir_all(&dir).map_err(io)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        for (k, v) in bundle {
            let p = dir.join(k);
            std::fs::write(&p, v).map_err(io)?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
        let pf = ProfileFile {
            provider: profile.provider,
            max_concurrent_leases: profile.max_concurrent_leases,
            metadata: profile.metadata.clone(),
            allowed_namespaces: profile.allowed_namespaces.clone(),
            allowed_classes: profile.allowed_classes.clone(),
        };
        std::fs::write(
            dir.join("profile.json"),
            serde_json::to_vec_pretty(&pf).map_err(|e| CredStoreError::Store(e.to_string()))?,
        )
        .map_err(io)
    }

    async fn update_file(
        &self,
        profile: &str,
        key: &str,
        bytes: &[u8],
        metadata: &CredentialMetadata,
        expected_fingerprint: &str,
    ) -> Result<(), CredStoreError> {
        use acp_runner_core::credentials::fingerprint;
        let (mut sp, mut bundle) = self.load(profile).await?;
        let current = bundle.get(key).ok_or_else(|| CredStoreError::Invalid(format!("key {key:?} not in profile")))?;
        // Coordinated local compare: refuse to overwrite files changed since
        // the caller authorized. (Cross-process races additionally serialize
        // on the DB profile row lock held by the write-back guard.)
        if fingerprint(current) != expected_fingerprint {
            return Err(CredStoreError::Conflict(format!(
                "profile {profile:?} changed since write-back was authorized"
            )));
        }
        bundle.insert(key.to_string(), bytes.to_vec());
        sp.metadata = metadata.clone();
        self.save(&sp, &bundle).await
    }

    async fn delete(&self, profile: &str) -> Result<(), CredStoreError> {
        check_profile_name(profile)?;
        std::fs::remove_dir_all(self.root.join(profile)).map_err(|e| CredStoreError::Store(e.to_string()))
    }
}
