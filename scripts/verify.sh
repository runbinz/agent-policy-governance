#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Use only a disposable database: integration tests create schema, roles, and fixtures.
: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to a dedicated disposable PostgreSQL database}"
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
# Run serially: these tests share migration ownership and worker queues.
cargo test --locked --workspace -- --ignored --test-threads=1
git diff --check
