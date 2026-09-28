//! Kubernetes-Secret-backed credential store.
//!
//! One Secret per profile in the controller namespace (`acp-runner-system` by default):
//!
//! ```text
//! name:        acp-cred-<profile>
//! labels:      acp-runner.dev/credential-profile=<profile>, acp-runner.dev/provider=<codex|claude>
//! annotations: acp-runner.dev/metadata=<non-secret CredentialMetadata JSON>
//!              acp-runner.dev/max-concurrent-leases=<n>
//!              acp-runner.dev/allowed-namespaces=<comma-separated namespaces, V2 grant>
//!              acp-runner.dev/allowed-classes=<comma-separated runner classes, V2 grant>
//! data:        only the provider-whitelisted keys (codex: auth.json, claude: oauth-token)
//! ```
//!
//! Missing grant annotations mean deny (V2 deny by default).
//!
//! Agent pods never mount these Secrets; the controller copies the leased profile into a
//! per-attempt Secret. Kubernetes Secrets are only base64-encoded unless the cluster has
//! encryption at rest configured — see README "Credential storage".

use acp_runner_core::credentials::{CredentialBundle, CredentialMetadata, Provider};
use acp_runner_engine::creds::{CredStoreError, CredentialStore, StoredProfile, check_profile_name};
use async_trait::async_trait;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Client;
use kube::api::{Api, DeleteParams, ListParams, PostParams};
use std::collections::BTreeMap;

pub const PROFILE_LABEL: &str = "acp-runner.dev/credential-profile";
pub const PROVIDER_LABEL: &str = "acp-runner.dev/provider";
pub const METADATA_ANNOTATION: &str = "acp-runner.dev/metadata";
pub const MAX_LEASES_ANNOTATION: &str = "acp-runner.dev/max-concurrent-leases";
/// V2 usage grants (comma-separated; absent means deny).
pub const ALLOWED_NAMESPACES_ANNOTATION: &str = "acp-runner.dev/allowed-namespaces";
pub const ALLOWED_CLASSES_ANNOTATION: &str = "acp-runner.dev/allowed-classes";

fn parse_grant_list(value: Option<&String>) -> Vec<String> {
    value
        .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

fn render_grant_list(items: &[String]) -> String {
    items.join(",")
}

pub fn secret_name(profile: &str) -> String {
    format!("acp-cred-{profile}")
}

pub struct K8sSecretStore {
    pub client: Client,
    pub namespace: String,
}

impl K8sSecretStore {
    fn api(&self) -> Api<Secret> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn to_profile(&self, s: &Secret) -> Option<StoredProfile> {
        let labels = s.metadata.labels.as_ref()?;
        let name = labels.get(PROFILE_LABEL)?.clone();
        let provider: Provider = labels.get(PROVIDER_LABEL)?.parse().ok()?;
        let ann = s.metadata.annotations.clone().unwrap_or_default();
        let metadata: CredentialMetadata =
            ann.get(METADATA_ANNOTATION).and_then(|m| serde_json::from_str(m).ok()).unwrap_or_default();
        let max = ann.get(MAX_LEASES_ANNOTATION).and_then(|m| m.parse().ok()).unwrap_or(1);
        Some(StoredProfile {
            store_ref: format!("k8s-secret:{}/{}", self.namespace, s.metadata.name.clone().unwrap_or_default()),
            name,
            provider,
            max_concurrent_leases: max,
            metadata,
            allowed_namespaces: parse_grant_list(ann.get(ALLOWED_NAMESPACES_ANNOTATION)),
            allowed_classes: parse_grant_list(ann.get(ALLOWED_CLASSES_ANNOTATION)),
        })
    }

    fn build(&self, p: &StoredProfile, bundle: &CredentialBundle, resource_version: Option<String>) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some(secret_name(&p.name)),
                namespace: Some(self.namespace.clone()),
                resource_version,
                labels: Some(BTreeMap::from([
                    (PROFILE_LABEL.to_string(), p.name.clone()),
                    (PROVIDER_LABEL.to_string(), p.provider.as_str().to_string()),
                    ("app.kubernetes.io/managed-by".to_string(), "acp-runner".to_string()),
                ])),
                annotations: Some(BTreeMap::from([
                    (METADATA_ANNOTATION.to_string(), serde_json::to_string(&p.metadata).unwrap_or_default()),
                    (MAX_LEASES_ANNOTATION.to_string(), p.max_concurrent_leases.to_string()),
                    (ALLOWED_NAMESPACES_ANNOTATION.to_string(), render_grant_list(&p.allowed_namespaces)),
                    (ALLOWED_CLASSES_ANNOTATION.to_string(), render_grant_list(&p.allowed_classes)),
                ])),
                ..Default::default()
            },
            type_: Some("Opaque".into()),
            data: Some(bundle.iter().map(|(k, v)| (k.clone(), ByteString(v.clone()))).collect()),
            ..Default::default()
        }
    }
}

fn store_err(e: kube::Error) -> CredStoreError {
    CredStoreError::Store(e.to_string())
}

#[async_trait]
impl CredentialStore for K8sSecretStore {
    async fn list(&self) -> Result<Vec<StoredProfile>, CredStoreError> {
        let list = self.api().list(&ListParams::default().labels(PROFILE_LABEL)).await.map_err(store_err)?;
        let mut v: Vec<StoredProfile> = list.items.iter().filter_map(|s| self.to_profile(s)).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    async fn load(&self, profile: &str) -> Result<(StoredProfile, CredentialBundle), CredStoreError> {
        check_profile_name(profile)?;
        let s = self
            .api()
            .get_opt(&secret_name(profile))
            .await
            .map_err(store_err)?
            .ok_or_else(|| CredStoreError::NotFound(profile.to_string()))?;
        let p = self.to_profile(&s).ok_or_else(|| CredStoreError::Invalid("secret lacks acp-runner labels".into()))?;
        let data = s.data.unwrap_or_default();
        let mut bundle = CredentialBundle::new();
        if p.provider.dynamic_keys() {
            // V9 files provider: the Secret data map IS the bundle (written
            // by save(); no other keys are stored there).
            for (k, v) in &data {
                bundle.insert(k.clone(), v.0.clone());
            }
        } else {
            for key in p.provider.spec().keys() {
                let v = data.get(key).ok_or_else(|| CredStoreError::Invalid(format!("secret lacks key {key}")))?;
                bundle.insert(key.to_string(), v.0.clone());
            }
        }
        Ok((p, bundle))
    }

    async fn save(&self, profile: &StoredProfile, bundle: &CredentialBundle) -> Result<(), CredStoreError> {
        check_profile_name(&profile.name)?;
        acp_runner_core::credentials::validate_bundle(profile.provider, bundle)
            .map_err(|e| CredStoreError::Invalid(e.to_string()))?;
        let api = self.api();
        match api.get_opt(&secret_name(&profile.name)).await.map_err(store_err)? {
            Some(existing) => {
                let s = self.build(profile, bundle, existing.metadata.resource_version.clone());
                api.replace(&secret_name(&profile.name), &PostParams::default(), &s).await.map_err(store_err)?;
            }
            None => {
                api.create(&PostParams::default(), &self.build(profile, bundle, None)).await.map_err(store_err)?;
            }
        }
        Ok(())
    }

    async fn update_file(
        &self,
        profile: &str,
        key: &str,
        bytes: &[u8],
        metadata: &CredentialMetadata,
        expected_fingerprint: &str,
    ) -> Result<(), CredStoreError> {
        let api = self.api();
        let s = api
            .get_opt(&secret_name(profile))
            .await
            .map_err(store_err)?
            .ok_or_else(|| CredStoreError::NotFound(profile.to_string()))?;
        let mut p =
            self.to_profile(&s).ok_or_else(|| CredStoreError::Invalid("secret lacks acp-runner labels".into()))?;
        let mut bundle: CredentialBundle =
            s.data.clone().unwrap_or_default().into_iter().map(|(k, v)| (k, v.0)).collect();
        let current = bundle.get(key).ok_or_else(|| CredStoreError::Invalid(format!("key {key:?} not in profile")))?;
        // Store-side compare against the authorized baseline: a concurrent
        // admin save that landed after the GET is still caught below by the
        // resourceVersion replace (Conflict); this check catches everything
        // that changed before the GET.
        if acp_runner_core::credentials::fingerprint(current) != expected_fingerprint {
            return Err(CredStoreError::Conflict(format!(
                "profile {profile:?} changed since write-back was authorized"
            )));
        }
        bundle.insert(key.to_string(), bytes.to_vec());
        p.metadata = metadata.clone();
        let updated = self.build(&p, &bundle, s.metadata.resource_version.clone());
        match api.replace(&secret_name(profile), &PostParams::default(), &updated).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(st)) if st.is_conflict() => Err(CredStoreError::Conflict(profile.to_string())),
            Err(e) => Err(store_err(e)),
        }
    }

    async fn delete(&self, profile: &str) -> Result<(), CredStoreError> {
        check_profile_name(profile)?;
        match self.api().delete(&secret_name(profile), &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(st)) if st.is_not_found() => Ok(()),
            Err(e) => Err(store_err(e)),
        }
    }
}
