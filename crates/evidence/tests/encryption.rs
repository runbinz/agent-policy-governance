use apl_evidence::{
    EvidenceError, EvidenceStore, ExportScope, MAX_ENCRYPTED_BYTES, MAX_PLAINTEXT_BYTES,
};
use object_store::{
    memory::InMemory,
    path::Path,
    throttle::{ThrottleConfig, ThrottledStore},
    ObjectStore, ObjectStoreExt,
};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

fn scope() -> ExportScope {
    ExportScope {
        tenant_id: Uuid::from_u128(1),
        environment_id: Uuid::from_u128(2),
        export_id: Uuid::from_u128(3),
        generation: 1,
    }
}

fn encrypted(store: Arc<dyn ObjectStore>) -> EvidenceStore {
    EvidenceStore::from_store(store, "key-v1", [7; 32]).unwrap()
}

#[tokio::test]
async fn random_nonce_each_write_and_generation_fences_object_names() {
    let raw = Arc::new(InMemory::new());
    let store = encrypted(raw.clone());
    let one = scope();
    let two = ExportScope {
        generation: 2,
        ..one
    };
    let path = Path::from(one.object_path().unwrap());
    store.put(one, b"redacted export").await.unwrap();
    let first = raw.get(&path).await.unwrap().bytes().await.unwrap();
    store.put(one, b"redacted export").await.unwrap();
    let second = raw.get(&path).await.unwrap().bytes().await.unwrap();
    assert_ne!(first, second);
    assert!(!second
        .windows(b"redacted export".len())
        .any(|part| part == b"redacted export"));
    store.put(two, b"newer export").await.unwrap();
    assert_eq!(store.get(one).await.unwrap(), b"redacted export");
    assert_eq!(store.get(two).await.unwrap(), b"newer export");
}

#[tokio::test]
async fn wrong_key_unknown_key_and_tampering_fail_authentication() {
    let raw = Arc::new(InMemory::new());
    let store = encrypted(raw.clone());
    let path = Path::from(scope().object_path().unwrap());
    store.put(scope(), b"evidence").await.unwrap();
    let bytes = raw.get(&path).await.unwrap().bytes().await.unwrap();
    let wrong_key = EvidenceStore::from_store(raw.clone(), "key-v1", [8; 32]).unwrap();
    let wrong_id = EvidenceStore::from_store(raw.clone(), "key-v2", [7; 32]).unwrap();
    assert_eq!(
        wrong_key.get(scope()).await,
        Err(EvidenceError::Authentication)
    );
    assert_eq!(
        wrong_id.get(scope()).await,
        Err(EvidenceError::Authentication)
    );
    for index in [0, 8, 9, bytes.len() - 1] {
        let mut altered = bytes.to_vec();
        altered[index] ^= 1;
        raw.put(&path, altered.into()).await.unwrap();
        assert_eq!(store.get(scope()).await, Err(EvidenceError::Authentication));
    }
    for length in [0, 1, 8, 9, bytes.len() - 1] {
        raw.put(&path, bytes.slice(..length).into()).await.unwrap();
        assert_eq!(store.get(scope()).await, Err(EvidenceError::Authentication));
    }
}

#[tokio::test]
async fn aad_prevents_scope_and_generation_substitution() {
    let raw = Arc::new(InMemory::new());
    let store = encrypted(raw.clone());
    let original = scope();
    store.put(original, b"scoped").await.unwrap();
    let bytes = raw
        .get(&Path::from(original.object_path().unwrap()))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    for target in [
        ExportScope {
            tenant_id: Uuid::from_u128(4),
            ..original
        },
        ExportScope {
            environment_id: Uuid::from_u128(4),
            ..original
        },
        ExportScope {
            export_id: Uuid::from_u128(4),
            ..original
        },
        ExportScope {
            generation: 2,
            ..original
        },
    ] {
        raw.put(
            &Path::from(target.object_path().unwrap()),
            bytes.clone().into(),
        )
        .await
        .unwrap();
        assert_eq!(store.get(target).await, Err(EvidenceError::Authentication));
    }
}

#[tokio::test]
async fn local_storage_contains_only_ciphertext_and_round_trips() {
    let directory = tempfile::tempdir().unwrap();
    let store = EvidenceStore::local(directory.path(), "key-v1", [7; 32]).unwrap();
    let plaintext = b"this text must never be written as plaintext";
    store.put(scope(), plaintext).await.unwrap();
    let file = directory.path().join(scope().object_path().unwrap());
    let disk = std::fs::read(file).unwrap();
    assert!(!disk.windows(plaintext.len()).any(|part| part == plaintext));
    assert_eq!(store.get(scope()).await.unwrap(), plaintext);
}

#[tokio::test]
async fn enforces_size_scope_and_missing_object_boundaries() {
    let raw = Arc::new(InMemory::new());
    let store = encrypted(raw.clone());
    assert_eq!(store.get(scope()).await, Err(EvidenceError::NotFound));
    let invalid = ExportScope {
        generation: 0,
        ..scope()
    };
    assert_eq!(
        store.put(invalid, b"").await,
        Err(EvidenceError::InvalidScope)
    );
    assert_eq!(store.get(invalid).await, Err(EvidenceError::InvalidScope));
    assert_eq!(
        store.put(scope(), &vec![0; MAX_PLAINTEXT_BYTES + 1]).await,
        Err(EvidenceError::TooLarge)
    );
    raw.put(
        &Path::from(scope().object_path().unwrap()),
        vec![0; MAX_ENCRYPTED_BYTES + 1].into(),
    )
    .await
    .unwrap();
    assert_eq!(store.get(scope()).await, Err(EvidenceError::TooLarge));
    let largest = vec![11; MAX_PLAINTEXT_BYTES];
    store.put(scope(), &largest).await.unwrap();
    assert_eq!(store.get(scope()).await.unwrap(), largest);
}

#[tokio::test(start_paused = true)]
async fn storage_operations_time_out_without_blocking_the_runtime() {
    let raw = Arc::new(ThrottledStore::new(
        InMemory::new(),
        ThrottleConfig {
            wait_put_per_call: Duration::from_secs(60),
            wait_get_per_call: Duration::from_secs(60),
            ..Default::default()
        },
    ));
    let store = encrypted(raw);
    assert_eq!(
        store.put(scope(), b"small").await,
        Err(EvidenceError::Timeout)
    );
    assert_eq!(store.get(scope()).await, Err(EvidenceError::Timeout));
}

#[tokio::test]
async fn retained_read_keys_preserve_existing_artifacts_without_affecting_new_writes() {
    let raw = Arc::new(InMemory::new());
    let old = encrypted(raw.clone());
    old.put(scope(), b"old export").await.unwrap();
    let rotated = EvidenceStore::from_store(raw, "key-v2", [9; 32])
        .unwrap()
        .with_read_key("key-v1", [7; 32])
        .unwrap();
    assert_eq!(rotated.get(scope()).await.unwrap(), b"old export");
    let newer = ExportScope {
        generation: 2,
        ..scope()
    };
    rotated.put(newer, b"new export").await.unwrap();
    assert_eq!(rotated.get(newer).await.unwrap(), b"new export");
    assert_eq!(old.get(newer).await, Err(EvidenceError::Authentication));
}
