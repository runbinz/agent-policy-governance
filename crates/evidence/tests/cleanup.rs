use apl_evidence::{EvidenceError, EvidenceStore, ExportScope};
use futures_util::TryStreamExt;
use object_store::{
    local::LocalFileSystem,
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

async fn verify_isolation(raw: Arc<dyn ObjectStore>) {
    let writer = EvidenceStore::from_store(raw.clone(), "old-key", [7; 32]).unwrap();
    // Cleanup does not need any matching artifact decryption key.
    let cleaner = EvidenceStore::from_store(raw.clone(), "new-key", [9; 32]).unwrap();
    let target = scope();
    let other_scopes = [
        ExportScope {
            tenant_id: Uuid::from_u128(4),
            ..target
        },
        ExportScope {
            environment_id: Uuid::from_u128(4),
            ..target
        },
        ExportScope {
            export_id: Uuid::from_u128(4),
            ..target
        },
    ];
    for generation in 1..=3 {
        writer
            .put(
                ExportScope {
                    generation,
                    ..target
                },
                b"target",
            )
            .await
            .unwrap();
    }
    for other in other_scopes {
        writer.put(other, b"unrelated").await.unwrap();
    }
    // A backend prefix must respect path components, even with a textual sibling.
    let target_path = target.object_path().unwrap();
    let prefix = target_path.rsplit_once('/').unwrap().0;
    let sibling = Path::from(format!("{prefix}-sibling/1.aead"));
    raw.put(&sibling, b"untouched".to_vec().into())
        .await
        .unwrap();

    assert!(cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await
        .unwrap());
    assert!(cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await
        .unwrap());
    for generation in 1..=3 {
        assert_eq!(
            writer
                .get(ExportScope {
                    generation,
                    ..target
                })
                .await,
            Err(EvidenceError::NotFound)
        );
    }
    for other in other_scopes {
        assert_eq!(writer.get(other).await.unwrap(), b"unrelated");
    }
    assert_eq!(
        raw.get(&sibling)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        b"untouched"
    );
}

#[tokio::test]
async fn memory_cleanup_is_exact_and_independent_of_encryption_keys() {
    verify_isolation(Arc::new(InMemory::new())).await;
}

#[tokio::test]
async fn local_cleanup_is_exact_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    verify_isolation(Arc::new(
        LocalFileSystem::new_with_prefix(directory.path()).unwrap(),
    ))
    .await;
}

#[tokio::test]
async fn batches_are_bounded_and_retries_remove_every_generation() {
    let raw = Arc::new(InMemory::new());
    let cleaner = EvidenceStore::from_store(raw.clone(), "key", [7; 32]).unwrap();
    let target = scope();
    for generation in 1..=1001 {
        let path = Path::from(
            ExportScope {
                generation,
                ..target
            }
            .object_path()
            .unwrap(),
        );
        // Invalid/legacy ciphertext must also be removable without decryption.
        raw.put(&path, b"old ciphertext".to_vec().into())
            .await
            .unwrap();
    }
    assert!(!cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await
        .unwrap());
    let remaining: Vec<_> = raw.list(None).try_collect().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await
        .unwrap());
    assert!(cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await
        .unwrap());

    // Exactly 1000 objects is exhausted, rather than requiring an empty retry.
    for generation in 1..=1000 {
        raw.put(
            &Path::from(
                ExportScope {
                    generation,
                    ..target
                }
                .object_path()
                .unwrap(),
            ),
            vec![0].into(),
        )
        .await
        .unwrap();
    }
    assert!(cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await
        .unwrap());
}

#[tokio::test(start_paused = true)]
async fn timeout_bounds_listing_and_partial_deletions_remain_retryable() {
    let raw = Arc::new(ThrottledStore::new(
        InMemory::new(),
        ThrottleConfig {
            wait_list_per_call: Duration::from_secs(60),
            ..Default::default()
        },
    ));
    let cleaner = EvidenceStore::from_store(raw.clone(), "key", [7; 32]).unwrap();
    let target = scope();
    for generation in 1..=2 {
        raw.put(
            &Path::from(
                ExportScope {
                    generation,
                    ..target
                }
                .object_path()
                .unwrap(),
            ),
            vec![0].into(),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        cleaner
            .delete_export(target.tenant_id, target.environment_id, target.export_id)
            .await,
        Err(EvidenceError::Timeout)
    );
    raw.config_mut(|config| {
        config.wait_list_per_call = Duration::ZERO;
        config.wait_delete_per_call = Duration::from_secs(20);
    });
    assert_eq!(
        cleaner
            .delete_export(target.tenant_id, target.environment_id, target.export_id)
            .await,
        Err(EvidenceError::Timeout)
    );
    raw.config_mut(|config| config.wait_delete_per_call = Duration::ZERO);
    let remaining: Vec<_> = raw.list(None).try_collect().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await
        .unwrap());
}

#[tokio::test]
async fn invalid_scope_and_backing_store_errors_are_generic() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    std::fs::create_dir(&root).unwrap();
    let cleaner = EvidenceStore::local(&root, "key", [7; 32]).unwrap();
    let target = scope();
    assert_eq!(
        cleaner
            .delete_export(Uuid::nil(), target.environment_id, target.export_id)
            .await,
        Err(EvidenceError::InvalidScope)
    );
    std::fs::remove_dir(&root).unwrap();
    std::fs::write(&root, b"file instead of storage directory").unwrap();
    let result = cleaner
        .delete_export(target.tenant_id, target.environment_id, target.export_id)
        .await;
    assert_eq!(result, Err(EvidenceError::Storage));
    assert_eq!(
        EvidenceError::Storage.to_string(),
        "evidence object is unavailable"
    );
}
