//! Authenticated encryption before local/S3 evidence storage. No plaintext files.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use object_store::{
    aws::{AmazonS3Builder, AmazonS3ConfigKey},
    local::LocalFileSystem,
    path::Path as ObjectPath,
    ClientOptions, ObjectStore, ObjectStoreExt,
};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PLAINTEXT_BYTES: usize = 20 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"APLEV001";
const MAX_KEY_ID_BYTES: usize = 64;
const MAX_READ_KEYS: usize = 15;
const MAX_READ_KEYS_JSON_BYTES: usize = 4096;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
pub const MAX_ENCRYPTED_BYTES: usize =
    MAX_PLAINTEXT_BYTES + MAGIC.len() + 1 + MAX_KEY_ID_BYTES + NONCE_BYTES + TAG_BYTES;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const DELETE_BATCH_SIZE: usize = 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportScope {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub export_id: Uuid,
    pub generation: i64,
}

impl ExportScope {
    pub fn object_path(self) -> Result<String, EvidenceError> {
        if self.tenant_id.is_nil()
            || self.environment_id.is_nil()
            || self.export_id.is_nil()
            || self.generation <= 0
        {
            return Err(EvidenceError::InvalidScope);
        }
        Ok(format!(
            "evidence/v1/{}/{}/{}/{}.aead",
            self.tenant_id, self.environment_id, self.export_id, self.generation
        ))
    }

    fn aad(self, key_id: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(128);
        aad.extend_from_slice(MAGIC);
        aad.extend_from_slice(self.tenant_id.as_bytes());
        aad.extend_from_slice(self.environment_id.as_bytes());
        aad.extend_from_slice(self.export_id.as_bytes());
        aad.extend_from_slice(&self.generation.to_be_bytes());
        aad.push(key_id.len() as u8);
        aad.extend_from_slice(key_id.as_bytes());
        aad
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvidenceError {
    #[error("invalid evidence storage configuration")]
    InvalidConfiguration,
    #[error("invalid evidence export scope")]
    InvalidScope,
    #[error("evidence exceeds the size limit")]
    TooLarge,
    #[error("evidence object is unavailable")]
    Storage,
    #[error("evidence object was not found")]
    NotFound,
    #[error("evidence storage operation timed out")]
    Timeout,
    #[error("evidence object could not be authenticated")]
    Authentication,
    #[error("secure randomness is unavailable")]
    Randomness,
}

#[derive(Clone)]
pub struct EvidenceStore {
    store: Arc<dyn ObjectStore>,
    cipher: Arc<Aes256Gcm>,
    read_ciphers: Arc<BTreeMap<String, Arc<Aes256Gcm>>>,
    key_id: Arc<str>,
}

impl EvidenceStore {
    /// Keys are copied into the cipher; the caller must also protect its copy.
    pub fn from_store(
        store: Arc<dyn ObjectStore>,
        key_id: &str,
        mut key: [u8; 32],
    ) -> Result<Self, EvidenceError> {
        let cipher = Aes256Gcm::new_from_slice(&key);
        key.zeroize();
        let cipher = cipher.map_err(|_| EvidenceError::InvalidConfiguration)?;
        if key_id.is_empty()
            || key_id.len() > MAX_KEY_ID_BYTES
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(EvidenceError::InvalidConfiguration);
        }
        Ok(Self {
            store,
            cipher: Arc::new(cipher),
            read_ciphers: Arc::new(BTreeMap::new()),
            key_id: Arc::from(key_id),
        })
    }

    /// Adds one retired decryption-only key. The active write key is unchanged.
    pub fn with_read_key(mut self, key_id: &str, mut key: [u8; 32]) -> Result<Self, EvidenceError> {
        let cipher = Aes256Gcm::new_from_slice(&key);
        key.zeroize();
        if key_id.is_empty()
            || key_id.len() > MAX_KEY_ID_BYTES
            || !key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || key_id == self.key_id.as_ref()
            || self.read_ciphers.contains_key(key_id)
            || self.read_ciphers.len() >= MAX_READ_KEYS
        {
            return Err(EvidenceError::InvalidConfiguration);
        }
        Arc::make_mut(&mut self.read_ciphers).insert(
            key_id.to_owned(),
            Arc::new(cipher.map_err(|_| EvidenceError::InvalidConfiguration)?),
        );
        Ok(self)
    }

    pub fn local(root: &Path, key_id: &str, key: [u8; 32]) -> Result<Self, EvidenceError> {
        let key = Zeroizing::new(key);
        if !root.is_absolute() || !root.is_dir() {
            return Err(EvidenceError::InvalidConfiguration);
        }
        let store = LocalFileSystem::new_with_prefix(root)
            .map_err(|_| EvidenceError::InvalidConfiguration)?;
        Self::from_store(Arc::new(store), key_id, *key)
    }

    /// AWS S3 only. Credentials come from explicit AWS credential environment
    /// fields, IRSA, ECS, EKS pod identity, or IMDSv2; no custom data/STS endpoint.
    pub fn s3(
        bucket: &str,
        region: &str,
        key_id: &str,
        key: [u8; 32],
    ) -> Result<Self, EvidenceError> {
        let key = Zeroizing::new(key);
        if !(3..=63).contains(&bucket.len())
            || !bucket
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !bucket.as_bytes()[0].is_ascii_alphanumeric()
            || !bucket.as_bytes()[bucket.len() - 1].is_ascii_alphanumeric()
            || !(3..=32).contains(&region.len())
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(EvidenceError::InvalidConfiguration);
        }
        let options = ClientOptions::new()
            .with_allow_http(false)
            .with_timeout(OPERATION_TIMEOUT)
            .with_connect_timeout(Duration::from_secs(5));
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_region(region)
            .with_client_options(options);
        // Avoid from_env: it also consumes endpoint, skip-signing, and TLS settings.
        for (name, config) in [
            ("AWS_ACCESS_KEY_ID", AmazonS3ConfigKey::AccessKeyId),
            ("AWS_SECRET_ACCESS_KEY", AmazonS3ConfigKey::SecretAccessKey),
            ("AWS_SESSION_TOKEN", AmazonS3ConfigKey::Token),
            (
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                AmazonS3ConfigKey::ContainerAuthorizationTokenFile,
            ),
        ] {
            if let Some(value) = env(name)? {
                builder = builder.with_config(config, value);
            }
        }
        if let Some(uri) = env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")? {
            if !uri.starts_with('/')
                || uri.starts_with("//")
                || uri.contains(['\r', '\n', '?', '#', '\\'])
            {
                return Err(EvidenceError::InvalidConfiguration);
            }
            builder = builder.with_config(AmazonS3ConfigKey::ContainerCredentialsRelativeUri, uri);
        }
        if let Some(uri) = env("AWS_CONTAINER_CREDENTIALS_FULL_URI")? {
            // EKS pod identity's standard link-local endpoint, never arbitrary URLs.
            if !uri.starts_with("http://169.254.170.23/")
                || uri.contains(['\r', '\n', '?', '#', '\\', '@'])
            {
                return Err(EvidenceError::InvalidConfiguration);
            }
            builder = builder.with_config(AmazonS3ConfigKey::ContainerCredentialsFullUri, uri);
        }
        let store = builder
            .build()
            .map_err(|_| EvidenceError::InvalidConfiguration)?;
        Self::from_store(Arc::new(store), key_id, *key)
    }

    pub fn from_env() -> Result<Option<Self>, EvidenceError> {
        Self::from_lookup(env)
    }

    /// Deletes at most 1000 objects from this exact export's generation prefix.
    /// True means the bounded listing was exhausted; repeat false results.
    pub async fn delete_export(
        &self,
        tenant_id: Uuid,
        environment_id: Uuid,
        export_id: Uuid,
    ) -> Result<bool, EvidenceError> {
        let scope = ExportScope {
            tenant_id,
            environment_id,
            export_id,
            generation: 1,
        };
        let object = scope.object_path()?;
        let prefix = object
            .rsplit_once('/')
            .ok_or(EvidenceError::InvalidScope)?
            .0;
        let boundary = format!("{prefix}/");
        let location = ObjectPath::from(prefix);
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            // Buffer paths before deleting so paginated listings are not mutated
            // mid-page. One lookahead entry bounds both memory and deletion count.
            let mut listed = self.store.list(Some(&location));
            let mut paths = Vec::with_capacity(DELETE_BATCH_SIZE + 1);
            while paths.len() <= DELETE_BATCH_SIZE {
                let Some(object) = listed.next().await else {
                    break;
                };
                let object = object.map_err(storage_error)?;
                if !object.location.as_ref().starts_with(&boundary) {
                    return Err(EvidenceError::Storage);
                }
                paths.push(object.location);
            }
            let exhausted = paths.len() <= DELETE_BATCH_SIZE;
            for path in paths.into_iter().take(DELETE_BATCH_SIZE) {
                match self.store.delete(&path).await {
                    Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                    Err(error) => return Err(storage_error(error)),
                }
            }
            Ok(exhausted)
        })
        .await
        .map_err(|_| EvidenceError::Timeout)?
    }

    fn from_lookup(
        lookup: impl Fn(&str) -> Result<Option<String>, EvidenceError>,
    ) -> Result<Option<Self>, EvidenceError> {
        let backend = lookup("APL_EVIDENCE_BACKEND")?;
        let key_id = lookup("APL_EVIDENCE_KEY_ID")?;
        let key = lookup("APL_EVIDENCE_KEY")?.map(Zeroizing::new);
        let root = lookup("APL_EVIDENCE_LOCAL_DIR")?;
        let bucket = lookup("APL_EVIDENCE_BUCKET")?;
        let region = lookup("APL_EVIDENCE_REGION")?;
        let read_keys = lookup("APL_EVIDENCE_READ_KEYS")?.map(Zeroizing::new);
        let Some(backend) = backend else {
            if key_id.is_some()
                || key.is_some()
                || root.is_some()
                || bucket.is_some()
                || region.is_some()
                || read_keys.is_some()
            {
                return Err(EvidenceError::InvalidConfiguration);
            }
            return Ok(None);
        };
        let key_id = key_id.ok_or(EvidenceError::InvalidConfiguration)?;
        let key = key.ok_or(EvidenceError::InvalidConfiguration)?;
        let key = decode_key(&key)?;
        // Validate the complete keyring before constructing any storage backend.
        let retired = read_keys
            .as_deref()
            .map(|json| read_keyring(json, &key_id))
            .transpose()?;
        let mut store = match backend.as_str() {
            "local" if bucket.is_none() && region.is_none() => {
                if lookup("APL_LOCAL_DEV")?.as_deref() != Some("true") {
                    return Err(EvidenceError::InvalidConfiguration);
                }
                Self::local(
                    Path::new(&root.ok_or(EvidenceError::InvalidConfiguration)?),
                    &key_id,
                    *key,
                )
            }
            "s3" if root.is_none() => Self::s3(
                &bucket.ok_or(EvidenceError::InvalidConfiguration)?,
                &region.ok_or(EvidenceError::InvalidConfiguration)?,
                &key_id,
                *key,
            ),
            _ => Err(EvidenceError::InvalidConfiguration),
        }?;
        for (key_id, key) in retired.unwrap_or_default() {
            store = store.with_read_key(&key_id, *key)?;
        }
        Ok(Some(store))
    }

    pub async fn put(&self, scope: ExportScope, plaintext: &[u8]) -> Result<(), EvidenceError> {
        let path = scope.object_path()?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(EvidenceError::TooLarge);
        }
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        aes_gcm::aead::rand_core::RngCore::try_fill_bytes(
            &mut aes_gcm::aead::OsRng,
            &mut nonce_bytes,
        )
        .map_err(|_| EvidenceError::Randomness)?;
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &scope.aad(&self.key_id),
                },
            )
            .map_err(|_| EvidenceError::Authentication)?;
        let mut object = Vec::with_capacity(
            MAGIC.len() + 1 + self.key_id.len() + NONCE_BYTES + ciphertext.len(),
        );
        object.extend_from_slice(MAGIC);
        object.push(self.key_id.len() as u8);
        object.extend_from_slice(self.key_id.as_bytes());
        object.extend_from_slice(&nonce_bytes);
        object.extend_from_slice(&ciphertext);
        tokio::time::timeout(
            OPERATION_TIMEOUT,
            self.store.put(&ObjectPath::from(path), object.into()),
        )
        .await
        .map_err(|_| EvidenceError::Timeout)?
        .map_err(storage_error)?;
        Ok(())
    }

    pub async fn get(&self, scope: ExportScope) -> Result<Vec<u8>, EvidenceError> {
        let path = ObjectPath::from(scope.object_path()?);
        let object = tokio::time::timeout(OPERATION_TIMEOUT, async {
            let response = self.store.get(&path).await.map_err(storage_error)?;
            if response.meta.size > MAX_ENCRYPTED_BYTES as u64 {
                return Err(EvidenceError::TooLarge);
            }
            let mut stream = response.into_stream();
            let mut object = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(storage_error)?;
                if chunk.len() > MAX_ENCRYPTED_BYTES - object.len() {
                    return Err(EvidenceError::TooLarge);
                }
                object.extend_from_slice(&chunk);
            }
            Ok(object)
        })
        .await
        .map_err(|_| EvidenceError::Timeout)??;
        let invalid = EvidenceError::Authentication;
        if object.len() < MAGIC.len() + 1 + NONCE_BYTES + TAG_BYTES
            || &object[..MAGIC.len()] != MAGIC
        {
            return Err(invalid);
        }
        let id_len = usize::from(object[MAGIC.len()]);
        let nonce_start = MAGIC.len() + 1 + id_len;
        if id_len == 0
            || id_len > MAX_KEY_ID_BYTES
            || object.len() < nonce_start + NONCE_BYTES + TAG_BYTES
        {
            return Err(invalid);
        }
        let key_id =
            std::str::from_utf8(&object[MAGIC.len() + 1..nonce_start]).map_err(|_| invalid)?;
        let cipher = if key_id == self.key_id.as_ref() {
            &self.cipher
        } else {
            self.read_ciphers.get(key_id).ok_or(invalid)?
        };
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&object[nonce_start..nonce_start + NONCE_BYTES]),
                Payload {
                    msg: &object[nonce_start + NONCE_BYTES..],
                    aad: &scope.aad(key_id),
                },
            )
            .map_err(|_| invalid)?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(EvidenceError::TooLarge);
        }
        Ok(plaintext)
    }
}

fn valid_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= MAX_KEY_ID_BYTES
        && key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn decode_key(encoded: &str) -> Result<Zeroizing<[u8; 32]>, EvidenceError> {
    if encoded.len() != 44 {
        return Err(EvidenceError::InvalidConfiguration);
    }
    // The decode buffer is sized to base64's maximum estimate, then the exact
    // 32-byte output length is checked. Partial output is zeroized on errors.
    let mut decoded = Zeroizing::new([0_u8; 33]);
    let length = STANDARD
        .decode_slice(encoded, decoded.as_mut())
        .map_err(|_| EvidenceError::InvalidConfiguration)?;
    if length != 32 {
        return Err(EvidenceError::InvalidConfiguration);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&decoded[..32]);
    Ok(key)
}

type ReadKeyring = BTreeMap<String, Zeroizing<[u8; 32]>>;

fn read_keyring(json: &str, active_key_id: &str) -> Result<ReadKeyring, EvidenceError> {
    use serde::de::{DeserializeSeed, Error, MapAccess, Visitor};

    if json.len() > MAX_READ_KEYS_JSON_BYTES {
        return Err(EvidenceError::InvalidConfiguration);
    }
    struct KeyringSeed<'a>(&'a str);
    impl<'de> DeserializeSeed<'de> for KeyringSeed<'_> {
        type Value = ReadKeyring;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_map(self)
        }
    }
    impl<'de> Visitor<'de> for KeyringSeed<'_> {
        type Value = ReadKeyring;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded evidence read-key map")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut entries: M) -> Result<Self::Value, M::Error> {
            let mut keys = BTreeMap::new();
            while let Some(id) = entries.next_key::<String>()? {
                if keys.len() >= MAX_READ_KEYS
                    || !valid_key_id(&id)
                    || id == self.0
                    || keys.contains_key(&id)
                {
                    return Err(M::Error::custom("invalid evidence read-key configuration"));
                }
                let encoded = entries.next_value::<EncodedReadKey>()?;
                let key = decode_key(&encoded.0)
                    .map_err(|_| M::Error::custom("invalid evidence read-key configuration"))?;
                keys.insert(id, key);
            }
            Ok(keys)
        }
    }
    struct EncodedReadKey(Zeroizing<String>);
    impl<'de> serde::Deserialize<'de> for EncodedReadKey {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            <String as serde::Deserialize>::deserialize(deserializer)
                .map(|value| Self(Zeroizing::new(value)))
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let result = KeyringSeed(active_key_id)
        .deserialize(&mut deserializer)
        .map_err(|_| EvidenceError::InvalidConfiguration)?;
    deserializer
        .end()
        .map_err(|_| EvidenceError::InvalidConfiguration)?;
    Ok(result)
}

fn env(name: &str) -> Result<Option<String>, EvidenceError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(EvidenceError::InvalidConfiguration),
    }
}

fn storage_error(error: object_store::Error) -> EvidenceError {
    match error {
        object_store::Error::NotFound { .. } => EvidenceError::NotFound,
        _ => EvidenceError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn config(values: &[(&str, &str)]) -> Result<Option<EvidenceStore>, EvidenceError> {
        let values: BTreeMap<_, _> = values.iter().copied().collect();
        EvidenceStore::from_lookup(|key| Ok(values.get(key).map(|value| (*value).to_owned())))
    }

    #[test]
    fn env_configuration_is_explicit_and_stray_values_fail_closed() {
        assert!(config(&[]).unwrap().is_none());
        for name in [
            "APL_EVIDENCE_KEY",
            "APL_EVIDENCE_KEY_ID",
            "APL_EVIDENCE_BUCKET",
            "APL_EVIDENCE_REGION",
            "APL_EVIDENCE_LOCAL_DIR",
            "APL_EVIDENCE_READ_KEYS",
        ] {
            assert!(config(&[(name, "stray")]).is_err());
        }
        let directory = tempfile::tempdir().unwrap();
        let key = STANDARD.encode([7; 32]);
        let valid = [
            ("APL_EVIDENCE_BACKEND", "local"),
            ("APL_LOCAL_DEV", "true"),
            ("APL_EVIDENCE_LOCAL_DIR", directory.path().to_str().unwrap()),
            ("APL_EVIDENCE_KEY_ID", "key-v1"),
            ("APL_EVIDENCE_KEY", &key),
        ];
        assert!(config(&valid).unwrap().is_some());
        for (name, value) in [
            ("APL_LOCAL_DEV", "false"),
            ("APL_EVIDENCE_KEY", "not-base64"),
            ("APL_EVIDENCE_KEY", "YWJj"),
            ("APL_EVIDENCE_KEY_ID", "../key"),
            ("APL_EVIDENCE_LOCAL_DIR", "relative"),
            ("APL_EVIDENCE_BACKEND", "unknown"),
        ] {
            let mut invalid = valid;
            let index = invalid.iter().position(|(key, _)| *key == name).unwrap();
            invalid[index] = (name, value);
            assert!(config(&invalid).is_err(), "{name}");
        }
    }

    #[test]
    fn s3_builder_accepts_only_aws_bucket_and_region_configuration() {
        // Construction is lazy: no credentials are fetched and no cloud calls occur.
        assert!(EvidenceStore::s3("apl-evidence-test", "us-east-1", "v1", [7; 32]).is_ok());
        assert!(EvidenceStore::s3("https://attacker.example", "us-east-1", "v1", [7; 32]).is_err());
        assert!(EvidenceStore::s3("apl-evidence-test", "http://127.0.0.1", "v1", [7; 32]).is_err());
    }

    #[tokio::test]
    async fn startup_keyring_reads_retired_artifacts_and_keeps_active_writes_separate() {
        let directory = tempfile::tempdir().unwrap();
        let scope = ExportScope {
            tenant_id: Uuid::from_u128(1),
            environment_id: Uuid::from_u128(2),
            export_id: Uuid::from_u128(3),
            generation: 1,
        };
        let old = EvidenceStore::local(directory.path(), "retired-v1", [7; 32]).unwrap();
        old.put(scope, b"old artifact").await.unwrap();
        let active = STANDARD.encode([9; 32]);
        let retired = serde_json::json!({"retired-v1":STANDARD.encode([7;32])}).to_string();
        let rotated = config(&[
            ("APL_EVIDENCE_BACKEND", "local"),
            ("APL_LOCAL_DEV", "true"),
            ("APL_EVIDENCE_LOCAL_DIR", directory.path().to_str().unwrap()),
            ("APL_EVIDENCE_KEY_ID", "active-v2"),
            ("APL_EVIDENCE_KEY", &active),
            ("APL_EVIDENCE_READ_KEYS", &retired),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(rotated.get(scope).await.unwrap(), b"old artifact");
        let new_scope = ExportScope {
            generation: 2,
            ..scope
        };
        rotated.put(new_scope, b"new artifact").await.unwrap();
        assert_eq!(rotated.get(new_scope).await.unwrap(), b"new artifact");
        assert_eq!(old.get(new_scope).await, Err(EvidenceError::Authentication));
    }

    #[test]
    fn startup_keyring_rejects_bad_shapes_duplicates_ids_and_encoded_secrets() {
        let encoded = STANDARD.encode([7; 32]);
        for json in [
            "".to_owned(),
            "[]".into(),
            "null".into(),
            "true".into(),
            r#"{"old":null}"#.into(),
            r#"{"old":123}"#.into(),
            format!(r#"{{"active":"{encoded}"}}"#),
            format!(r#"{{"old":"{encoded}","old":"{encoded}"}}"#),
            format!(r#"{{"old":"{encoded}","ol\u0064":"{encoded}"}}"#),
            format!(r#"{{"../old":"{encoded}"}}"#),
            format!(r#"{{"{}":"{encoded}"}}"#, "x".repeat(MAX_KEY_ID_BYTES + 1)),
            format!(r#"{{"":"{encoded}"}}"#),
            r#"{"old":"not-base64"}"#.into(),
            format!(r#"{{"old":"{}"}}"#, STANDARD.encode([7; 31])),
            format!(r#"{{"old":"{}"}}"#, STANDARD.encode([7; 33])),
            "{} trailing".into(),
        ] {
            assert!(read_keyring(&json, "active").is_err());
        }
    }

    #[test]
    fn startup_keyring_enforces_raw_json_and_entry_count_boundaries() {
        let maximum: BTreeMap<_, _> = (0..MAX_READ_KEYS)
            .map(|index| (format!("old-{index}"), STANDARD.encode([index as u8; 32])))
            .collect();
        let raw = serde_json::to_string(&maximum).unwrap();
        assert_eq!(read_keyring(&raw, "active").unwrap().len(), MAX_READ_KEYS);
        let mut excess = maximum;
        excess.insert("too-many".into(), STANDARD.encode([99; 32]));
        assert!(read_keyring(&serde_json::to_string(&excess).unwrap(), "active").is_err());
        let padded = format!("{{}}{}", " ".repeat(MAX_READ_KEYS_JSON_BYTES - 2));
        assert_eq!(padded.len(), MAX_READ_KEYS_JSON_BYTES);
        assert!(read_keyring(&padded, "active").unwrap().is_empty());
        assert!(read_keyring(&(padded + " "), "active").is_err());
    }
}
