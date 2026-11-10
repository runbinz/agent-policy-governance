//! Shared one-use login transactions and opaque browser sessions.
use crate::{Result, Store, StoreError};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

// Deliberately no Debug: CSRF hashes and identity are private authentication data.
pub struct BrowserSession {
    pub issuer: String,
    pub subject: String,
    pub expires_at_unix: i64,
    pub csrf_hash: Vec<u8>,
}

fn hash(value: &[u8]) -> Result<()> {
    if value.len() != 32 {
        return Err(StoreError::Invalid(
            "invalid browser credential hash".into(),
        ));
    }
    Ok(())
}

impl Store {
    async fn browser_transaction(&self) -> Result<Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    pub async fn start_browser_login(&self, state_hash: &[u8], binding_hash: &[u8]) -> Result<()> {
        hash(state_hash)?;
        hash(binding_hash)?;
        let mut tx = self.browser_transaction().await?;
        sqlx::query("SELECT start_browser_login($1,$2)")
            .bind(state_hash)
            .bind(binding_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn consume_browser_login(
        &self,
        state_hash: &[u8],
        binding_hash: &[u8],
    ) -> Result<bool> {
        hash(state_hash)?;
        hash(binding_hash)?;
        let mut tx = self.browser_transaction().await?;
        let consumed = sqlx::query_scalar("SELECT consume_browser_login($1,$2)")
            .bind(state_hash)
            .bind(binding_hash)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(consumed)
    }

    pub async fn create_browser_session(
        &self,
        session_hash: &[u8],
        csrf_hash: &[u8],
        issuer: &str,
        subject: &str,
    ) -> Result<()> {
        hash(session_hash)?;
        hash(csrf_hash)?;
        let mut tx = self.browser_transaction().await?;
        sqlx::query("SELECT create_browser_session($1,$2,$3,$4,$5)")
            .bind(session_hash)
            .bind(csrf_hash)
            .bind(Uuid::new_v4())
            .bind(issuer)
            .bind(subject)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn read_browser_session(
        &self,
        session_hash: &[u8],
    ) -> Result<Option<BrowserSession>> {
        hash(session_hash)?;
        let mut tx = self.browser_transaction().await?;
        let session = sqlx::query("SELECT * FROM read_browser_session($1)")
            .bind(session_hash)
            .fetch_optional(&mut *tx)
            .await?
            .map(|row| BrowserSession {
                issuer: row.get("issuer"),
                subject: row.get("subject"),
                expires_at_unix: row.get("expires_at_unix"),
                csrf_hash: row.get("csrf_hash"),
            });
        tx.commit().await?;
        Ok(session)
    }

    pub async fn revoke_browser_session(
        &self,
        session_hash: &[u8],
        csrf_hash: &[u8],
    ) -> Result<bool> {
        hash(session_hash)?;
        hash(csrf_hash)?;
        let mut tx = self.browser_transaction().await?;
        let revoked = sqlx::query_scalar("SELECT revoke_browser_session($1,$2)")
            .bind(session_hash)
            .bind(csrf_hash)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(revoked)
    }
}
