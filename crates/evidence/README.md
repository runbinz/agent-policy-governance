# Encrypted evidence artifacts

`EvidenceStore` encrypts evidence in memory before passing it to a local
filesystem or AWS S3 object store. The binary v1 envelope contains the explicit
key ID, a fresh OS-random 96-bit nonce, AES-256-GCM ciphertext, and its
authentication tag. Authenticated data binds the format, key ID, tenant,
environment, export, and generation. Paths use the same scope plus generation;
a stale export worker cannot overwrite another generation's object.

Plaintext is capped at 20 MiB. Reads reject excessive metadata sizes and enforce
the same bound while streaming; storage operations time out after 30 seconds.
Failures expose no backing object details or secret material. The store has no
Debug implementation. Caller-owned encryption keys and returned plaintext
still need appropriate handling. The library zeroizes its temporary key buffers.

## Configuration

With no `APL_EVIDENCE_BACKEND`, exports are disabled; stray evidence settings
are rejected. Both backends require `APL_EVIDENCE_KEY_ID` and
`APL_EVIDENCE_KEY` (standard padded base64 encoding of exactly 32 random bytes):

- `local`: requires `APL_LOCAL_DEV=true` and
  `APL_EVIDENCE_LOCAL_DIR`, an existing absolute directory. Restrict directory
  permissions. The application writes only ciphertext there.
- `s3`: requires `APL_EVIDENCE_BUCKET` and `APL_EVIDENCE_REGION`. Bucket
  names use the supported lowercase alphanumeric/hyphen subset. Object storage
  uses standard HTTPS AWS endpoints and AWS credential environment variables,
  IRSA, ECS relative credentials, standard EKS pod credentials, or IMDSv2.
  Arbitrary storage/STS endpoints and unsigned access are not configurable.
  Apply a least-privilege bucket policy, public-access blocking, retention and
  cleanup rules, and restrict credentials to the evidence prefix.

S3 construction is lazy. Tests build configuration without contacting AWS;
actual IAM, encryption-key provisioning, bucket policy and cloud operation
remain deployment acceptance checks.

## Key rotation

The active write/read key is configured by `APL_EVIDENCE_KEY_ID` and
`APL_EVIDENCE_KEY`. Optional `APL_EVIDENCE_READ_KEYS` is a JSON object mapping
retired immutable key IDs to standard padded base64-encoded 32-byte keys.
For example, its shape is `{"previous-key-id":"<base64 key>"}`; provision
actual values through your secrets system.

The keyring accepts at most 15 unique retired IDs and at most 4096 bytes of
raw JSON. Empty objects are allowed. Duplicate IDs (including JSON-escaped
aliases), the active ID, malformed values, and stray keyring configuration
when the backend is disabled all cause startup to fail without exposing key
material in errors.

For rotation, provision the new active key and retain the old key under its
original ID in both API and worker read keyrings. New writes use only the
active key; reads select a configured key by the authenticated envelope ID.
Keep every retired key until its artifacts and backups expire. Changing a
key's bytes while retaining its old ID makes old artifacts unreadable.

The programmatic `with_read_key` constructor applies the same retired-key
limits. This library does not rotate keys automatically or replace a managed secrets
system.

## Expired export cleanup

`delete_export(tenant_id, environment_id, export_id)` removes objects only
under that exact UUID export prefix, including every generation and objects
that cannot be decrypted with the current keys. The caller must first verify
retention eligibility and scoped authority in the database. Each call examines
at most 1001 entries, deletes at most 1000 objects, and has a 30-second I/O
timeout. A `false` result requires another call; `true` means that bounded
listing was exhausted. Missing objects are harmless. Retry partial failures
and timeouts idempotently.

A completed sweep cannot prevent a suspended stale worker from later writing
an orphan object. The database orchestrator must periodically re-sweep expired
exports, even after a previous sweep returned true, and must never restore
download access for those exports. Apply S3 lifecycle expiration as an
independent cleanup defense. Bucket versioning, replicas and backups may retain
older object versions; their retention must be configured separately.

Storage uses Apache Arrow's
[object_store](https://github.com/apache/arrow-rs-object-store/tree/0.12.4),
pinned to 0.12.4 for compatibility with Rust 1.90, and RustCrypto's
[AES-GCM](https://docs.rs/aes-gcm/0.10.3/aes_gcm/).
