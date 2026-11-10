# Dependency advisory verification

Run python3 scripts/verify-dependencies.py with cargo-audit 0.22.2 installed and console dependencies installed. CARGO_AUDIT can select a separately installed executable/arguments. CI installs the pinned scanner from crates.io, audits the committed lockfile with the current RustSec database, and runs npm audit including development dependencies. Network/parse/tool failures fail the gate.

The gate resolves the enabled normal/build/dev Rust dependency graph for the current target. Active vulnerability or warning findings fail. New findings fail even when inactive. Two explicitly reviewed exceptions are permitted only while their affected package/version is absent from that graph:

- RUSTSEC-2023-0071, RSA: SQLx 0.8 optional MySQL backend.
- RUSTSEC-2026-0459, libsqlite3-sys: SQLx 0.8 optional SQLite backend.

PostgreSQL is the supported backend. Enabling either optional backend makes the matching advisory fatal. This is an explicit inactive-lockfile exception, not a claim those packages are patched. Revisit when SQLx can resolve patched optional dependencies. Test each supported target/feature configuration; this check does not establish safety for arbitrary future features.

The November 9, 2026 remediation updates Tokio, rustls, certificate verification/root dependencies and object_store/quick-xml. Object_store 0.14.2 uses reqwest 0.13 and native certificate verification, changing TLS trust behavior. Local encrypted storage/failure/cleanup tests and compilation do not replace acceptance against the intended external S3 endpoint and trust configuration.

Advisory matching establishes affected versions, not exploitability or a complete security review. Secret scanning, application threat tests and deployment hardening remain separate release work. Local audit evidence is in ignored .local/dependency-review; shared status records completed checks.
