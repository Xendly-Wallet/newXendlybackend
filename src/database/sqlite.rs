use crate::errors::{AppError, Result};
use crate::models::user::User;
use crate::models::kyc::KycSubmission;
use sqlx::{SqlitePool, Row};
use uuid::Uuid;
use std::path::Path;
use chrono::{DateTime, Utc};
use serde_json;
use hmac::Mac;
use base32;
use once_cell::sync::OnceCell;
use std::sync::Arc;

#[allow(dead_code)] // For future global DB singleton usage
pub static GLOBAL_DB: OnceCell<Arc<SqliteDatabase>> = OnceCell::new();

#[derive(Debug)]
pub struct SqliteDatabase {
    pool: SqlitePool,
}

impl SqliteDatabase {
    pub async fn new(database_path: &str) -> Result<Self> {
        // Ensure the directory exists
        if let Some(parent) = Path::new(database_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::DatabaseError(format!("Failed to create database directory: {}", e)))?;
        }

        //Create the database file if it doesn't exist
        if !Path::new(database_path).exists() {
            std::fs::File::create(database_path)
                .map_err(|e| AppError::DatabaseError(format!("Failed to create database file: {}", e)))?;
            println!("📁 Created new database file: {}", database_path);
        }
        let database_url = format!("sqlite:{}", database_path);
               
        let pool = SqlitePool::connect(&database_url)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to connect to database: {}", e)))?;

        let db = Self { pool };
               
        // Create tables if they don't exist
        db.create_tables().await?;
               
        println!("✅ Connected to SQLite database: {}", database_path);
        Ok(db)
    }

    async fn create_tables(&self) -> Result<()> {
        let query = r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE,
                stellar_public_key TEXT,
                phone_number TEXT,
                is_phone_verified BOOLEAN DEFAULT FALSE,
                phone_verification_code TEXT,
                phone_verified_at TEXT,
                totp_secret TEXT,
                totp_enabled BOOLEAN DEFAULT FALSE,
                backup_codes TEXT,
                is_deleted BOOLEAN DEFAULT FALSE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                token_id TEXT UNIQUE NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS stellar_wallets (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                public_key TEXT UNIQUE NOT NULL,
                encrypted_secret_key TEXT NOT NULL,
                wallet_name TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                balance_xlm TEXT DEFAULT '0',
                sequence_number INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_sync_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS wallet_transactions (
                id TEXT PRIMARY KEY,
                wallet_id TEXT NOT NULL,
                transaction_hash TEXT UNIQUE NOT NULL,
                transaction_type TEXT NOT NULL, -- 'send', 'receive', 'payment'
                amount TEXT NOT NULL,
                asset_code TEXT DEFAULT 'XLM',
                asset_issuer TEXT,
                from_address TEXT,
                to_address TEXT,
                memo TEXT,
                fee TEXT,
                status TEXT DEFAULT 'pending', -- 'pending', 'success', 'failed'
                created_at TEXT NOT NULL,
                confirmed_at TEXT,
                FOREIGN KEY (wallet_id) REFERENCES stellar_wallets (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS exchange_transactions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                from_currency TEXT NOT NULL,
                to_currency TEXT NOT NULL,
                from_amount REAL NOT NULL,
                to_amount REAL NOT NULL,
                exchange_rate REAL NOT NULL,
                fee_amount REAL NOT NULL,
                stellar_tx_hash TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS asset_balances (
                id TEXT PRIMARY KEY,
                wallet_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                asset_code TEXT NOT NULL,
                asset_issuer TEXT,
                balance TEXT NOT NULL,
                last_updated TEXT NOT NULL,
                FOREIGN KEY (wallet_id) REFERENCES stellar_wallets(id),
                UNIQUE(wallet_id, asset_code, asset_issuer)
            );

            CREATE TABLE IF NOT EXISTS notification_preferences (
                user_id TEXT PRIMARY KEY,
                email_enabled BOOLEAN DEFAULT TRUE,
                sms_enabled BOOLEAN DEFAULT FALSE,
                push_enabled BOOLEAN DEFAULT FALSE,
                in_app_enabled BOOLEAN DEFAULT TRUE,
                incoming_payment_alerts BOOLEAN DEFAULT TRUE,
                outgoing_payment_alerts BOOLEAN DEFAULT TRUE,
                payment_failure_alerts BOOLEAN DEFAULT TRUE,
                balance_change_alerts BOOLEAN DEFAULT TRUE,
                low_balance_threshold REAL,
                security_alerts BOOLEAN DEFAULT TRUE,
                exchange_alerts BOOLEAN DEFAULT TRUE,
                system_alerts BOOLEAN DEFAULT TRUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT NOT NULL,
                channels TEXT NOT NULL,
                metadata TEXT,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TEXT NOT NULL,
                sent_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS email_templates (
                id TEXT PRIMARY KEY,
                template_name TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                html_body TEXT NOT NULL,
                text_body TEXT NOT NULL,
                variables TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kyc_submissions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                full_name TEXT NOT NULL,
                id_type TEXT NOT NULL,
                id_number TEXT NOT NULL,
                id_photo_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'not_submitted',
                submitted_at TEXT,
                reviewed_at TEXT,
                rejection_reason TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON user_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_token_id ON user_tokens(token_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_active ON user_tokens(is_active);
            CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON stellar_wallets(user_id);
            CREATE INDEX IF NOT EXISTS idx_wallets_public_key ON stellar_wallets(public_key);
            CREATE INDEX IF NOT EXISTS idx_wallets_active ON stellar_wallets(is_active);
            CREATE INDEX IF NOT EXISTS idx_transactions_wallet_id ON wallet_transactions(wallet_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_hash ON wallet_transactions(transaction_hash);
            CREATE INDEX IF NOT EXISTS idx_transactions_type ON wallet_transactions(transaction_type);
            CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
            CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(notification_type);
            CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);
            CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read);
        "#;

        sqlx::query(query)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create tables: {}", e)))?;

        println!("📋 Database tables created/verified");
        Ok(())
    }

    pub async fn create_user(&self, user: &User) -> Result<()> {
        let query = r#"
            INSERT INTO users (id, email, username, password_hash, is_verified, stellar_public_key, phone_number, is_phone_verified, phone_verification_code, phone_verified_at, totp_secret, totp_enabled, backup_codes, is_deleted, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        "#;

        sqlx::query(query)
            .bind(user.id.to_string())
            .bind(&user.email)
            .bind(&user.username)
            .bind(&user.password_hash)
            .bind(user.is_verified)
            .bind(&user.stellar_public_key)
            .bind(&user.phone_number)
            .bind(user.is_phone_verified)
            .bind(&user.phone_verification_code)
            .bind(user.phone_verified_at)
            .bind(&user.totp_secret)
            .bind(user.totp_enabled)
            .bind(&user.backup_codes)
            .bind(user.is_deleted)
            .bind(user.created_at.to_rfc3339())
            .bind(user.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                if e.to_string().contains("UNIQUE constraint failed") {
                    if e.to_string().contains("email") {
                        AppError::ValidationError("Email already exists".to_string())
                    } else if e.to_string().contains("username") {
                        AppError::ValidationError("Username already exists".to_string())
                    } else {
                        AppError::ValidationError("User already exists".to_string())
                    }
                } else {
                    AppError::DatabaseError(format!("Failed to create user: {}", e))
                }
            })?;

        println!("💾 User '{}' saved to database", user.username);
        Ok(())
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let query = "SELECT * FROM users WHERE email = ?1";
        let row = sqlx::query(query)
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch user by email: {}", e)))?;

        if let Some(row) = row {
            Ok(Some(User {
                id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid user ID: {}", e)))?,
                email: row.get("email"),
                username: row.get("username"),
                password_hash: row.get("password_hash"),
                is_verified: row.get("is_verified"),
                stellar_public_key: row.get("stellar_public_key"),
                phone_number: row.get("phone_number"),
                is_phone_verified: row.get("is_phone_verified"),
                phone_verification_code: row.get("phone_verification_code"),
                phone_verified_at: row.get::<Option<String>, _>("phone_verified_at").and_then(|s| s.parse().ok()),
                totp_secret: row.get("totp_secret"),
                totp_enabled: row.get("totp_enabled"),
                backup_codes: row.get("backup_codes"),
                is_deleted: row.get("is_deleted"),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid updated_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let query = "SELECT * FROM users WHERE username = ?1";
        let row = sqlx::query(query)
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch user by username: {}", e)))?;

        if let Some(row) = row {
            Ok(Some(User {
                id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid user ID: {}", e)))?,
                email: row.get("email"),
                username: row.get("username"),
                password_hash: row.get("password_hash"),
                is_verified: row.get("is_verified"),
                stellar_public_key: row.get("stellar_public_key"),
                phone_number: row.get("phone_number"),
                is_phone_verified: row.get("is_phone_verified"),
                phone_verification_code: row.get("phone_verification_code"),
                phone_verified_at: row.get::<Option<String>, _>("phone_verified_at").and_then(|s| s.parse().ok()),
                totp_secret: row.get("totp_secret"),
                totp_enabled: row.get("totp_enabled"),
                backup_codes: row.get("backup_codes"),
                is_deleted: row.get("is_deleted"),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid updated_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
            }))
        } else {
            Ok(None)
        }
    }

    #[allow(dead_code)]
    pub async fn get_user_count(&self) -> Result<i64> {
        let query = "SELECT COUNT(*) as count FROM users";
               
        let row = sqlx::query(query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to get user count: {}", e)))?;

        Ok(row.get("count"))
    }
    // JWT Token methods
    pub async fn store_user_token(&self, user_id: &Uuid, token_id: &str, token_hash: &str, expires_at: DateTime<Utc>) -> Result<()> {
        // First, deactivate any existing active tokens for this user
        let deactivate_query = "UPDATE user_tokens SET is_active = FALSE WHERE user_id = ?1 AND is_active = TRUE";
        sqlx::query(deactivate_query)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to deactivate existing tokens: {}", e)))?;

        // Insert new token
        let insert_query = r#"
            INSERT INTO user_tokens (user_id, token_id, token_hash, created_at, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
        "#;

        sqlx::query(insert_query)
            .bind(user_id.to_string())
            .bind(token_id)
            .bind(token_hash)
            .bind(Utc::now().to_rfc3339())
            .bind(expires_at.to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to store token: {}", e)))?;

        println!("🔐 JWT token stored for user: {}", user_id);
        Ok(())
    }

    pub async fn is_token_valid(&self, token_id: &str) -> Result<bool> {
        let query = r#"
            SELECT COUNT(*) as count FROM user_tokens 
            WHERE token_id = ?1 AND is_active = TRUE AND expires_at > ?2
        "#;

        let row = sqlx::query(query)
            .bind(token_id)
            .bind(Utc::now().to_rfc3339())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to validate token: {}", e)))?;

        let count: i64 = row.get("count");
        Ok(count > 0)
    }

    pub async fn revoke_token(&self, token_id: &str) -> Result<()> {
        let query = "UPDATE user_tokens SET is_active = FALSE WHERE token_id = ?1";
        
        let result = sqlx::query(query)
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to revoke token: {}", e)))?;

        if result.rows_affected() > 0 {
            println!("🚪 Token revoked successfully");
        } else {
            return Err(AppError::AuthenticationError("Token not found".to_string()));
        }

        Ok(())
    }

    pub async fn cleanup_expired_tokens(&self) -> Result<()> {
        let query = "DELETE FROM user_tokens WHERE expires_at < ?1";
        
        let result = sqlx::query(query)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to cleanup expired tokens: {}", e)))?;

        if result.rows_affected() > 0 {
            println!("🧹 Cleaned up {} expired tokens", result.rows_affected());
        }

        Ok(())
    }

    pub async fn get_user_active_tokens_count(&self, user_id: &Uuid) -> Result<i64> {
        let query = r#"
            SELECT COUNT(*) as count FROM user_tokens 
            WHERE user_id = ?1 AND is_active = TRUE AND expires_at > ?2
        "#;

        let row = sqlx::query(query)
            .bind(user_id.to_string())
            .bind(Utc::now().to_rfc3339())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to get active tokens count: {}", e)))?;

        Ok(row.get("count"))
    }

    pub async fn revoke_all_user_tokens(&self, user_id: &Uuid) -> Result<()> {
        let query = "UPDATE user_tokens SET is_active = FALSE WHERE user_id = ?1 AND is_active = TRUE";
        
        let result = sqlx::query(query)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to revoke all user tokens: {}", e)))?;

        println!("🚪 Revoked {} active tokens for user", result.rows_affected());
        Ok(())
    }

    // Stellar wallet database methods
    pub async fn create_stellar_wallet(&self, wallet: &crate::models::stellar_wallet::StellarWallet) -> Result<()> {
        let query = r#"
            INSERT INTO stellar_wallets (
                id, user_id, public_key, encrypted_secret_key, wallet_name, 
                is_active, balance_xlm, sequence_number, created_at, updated_at, last_sync_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#;

        sqlx::query(query)
            .bind(wallet.id.to_string())
            .bind(wallet.user_id.to_string())
            .bind(&wallet.public_key)
            .bind(&wallet.encrypted_secret_key)
            .bind(&wallet.wallet_name)
            .bind(wallet.is_active)
            .bind(&wallet.balance_xlm)
            .bind(wallet.sequence_number)
            .bind(wallet.created_at.to_rfc3339())
            .bind(wallet.updated_at.to_rfc3339())
            .bind(wallet.last_sync_at.map(|dt| dt.to_rfc3339()))
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create stellar wallet: {}", e)))?;

        println!("🌟 Stellar wallet created in database: {}", wallet.public_key);
        Ok(())
    }

    pub async fn get_user_wallets(&self, user_id: &uuid::Uuid) -> Result<Vec<crate::models::stellar_wallet::StellarWallet>> {
        let query = r#"
            SELECT id, user_id, public_key, encrypted_secret_key, wallet_name, 
                   is_active, balance_xlm, sequence_number, created_at, updated_at, last_sync_at
            FROM stellar_wallets 
            WHERE user_id = ?1 AND is_active = TRUE
            ORDER BY created_at DESC
        "#;

        let rows = sqlx::query(query)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch user wallets: {}", e)))?;

        let mut wallets = Vec::new();
        for row in rows {
            let wallet = crate::models::stellar_wallet::StellarWallet {
                id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid wallet ID: {}", e)))?,
                user_id: uuid::Uuid::parse_str(&row.get::<String, _>("user_id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid user ID: {}", e)))?,
                public_key: row.get("public_key"),
                encrypted_secret_key: row.get("encrypted_secret_key"),
                wallet_name: row.get("wallet_name"),
                is_active: row.get("is_active"),
                balance_xlm: row.get("balance_xlm"),
                sequence_number: row.get("sequence_number"),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid updated_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                last_sync_at: row.get::<Option<String>, _>("last_sync_at")
                    .map(|s| chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&chrono::Utc)))
                    .transpose()
                    .map_err(|e| AppError::DatabaseError(format!("Invalid last_sync_at date: {}", e)))?,
            };
            wallets.push(wallet);
        }

        Ok(wallets)
    }
    #[allow(dead_code)]
    pub async fn get_wallet_by_public_key(&self, public_key: &str) -> Result<Option<crate::models::stellar_wallet::StellarWallet>> {
        let query = r#"
            SELECT id, user_id, public_key, encrypted_secret_key, wallet_name, 
                   is_active, balance_xlm, sequence_number, created_at, updated_at, last_sync_at
            FROM stellar_wallets 
            WHERE public_key = ?1 AND is_active = TRUE
        "#;

        let row = sqlx::query(query)
            .bind(public_key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch wallet: {}", e)))?;

        if let Some(row) = row {
            let wallet = crate::models::stellar_wallet::StellarWallet {
                id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid wallet ID: {}", e)))?,
                user_id: uuid::Uuid::parse_str(&row.get::<String, _>("user_id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid user ID: {}", e)))?,
                public_key: row.get("public_key"),
                encrypted_secret_key: row.get("encrypted_secret_key"),
                wallet_name: row.get("wallet_name"),
                is_active: row.get("is_active"),
                balance_xlm: row.get("balance_xlm"),
                sequence_number: row.get("sequence_number"),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid updated_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                last_sync_at: row.get::<Option<String>, _>("last_sync_at")
                    .map(|s| chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&chrono::Utc)))
                    .transpose()
                    .map_err(|e| AppError::DatabaseError(format!("Invalid last_sync_at date: {}", e)))?,
            };
            Ok(Some(wallet))
        } else {
            Ok(None)
        }
    }

    pub async fn update_wallet_balance(&self, wallet_id: &uuid::Uuid, balance: &str, sequence_number: Option<i64>) -> Result<()> {
        let query = r#"
            UPDATE stellar_wallets 
            SET balance_xlm = ?1, sequence_number = ?2, last_sync_at = ?3, updated_at = ?4
            WHERE id = ?5
        "#;

        let now = chrono::Utc::now();
        sqlx::query(query)
            .bind(balance)
            .bind(sequence_number)
            .bind(now.to_rfc3339())
            .bind(now.to_rfc3339())
            .bind(wallet_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update wallet balance: {}", e)))?;

        Ok(())
    }
    #[allow(dead_code)]
    pub async fn deactivate_wallet(&self, wallet_id: &uuid::Uuid) -> Result<()> {
        let query = "UPDATE stellar_wallets SET is_active = FALSE, updated_at = ?1 WHERE id = ?2";
        
        sqlx::query(query)
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(wallet_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to deactivate wallet: {}", e)))?;

        println!("🗑️ Wallet deactivated: {}", wallet_id);
        Ok(())
    }
    #[allow(dead_code)]
    pub async fn get_user_wallets_count(&self, user_id: &uuid::Uuid) -> Result<i64> {
        let query = "SELECT COUNT(*) as count FROM stellar_wallets WHERE user_id = ?1 AND is_active = TRUE";
        
        let row = sqlx::query(query)
            .bind(user_id.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count user wallets: {}", e)))?;

        Ok(row.get("count"))
    }
    pub async fn update_wallet_encryption(&self, wallet_id: &Uuid, new_encrypted_secret: &str) -> Result<()> {
        let query = "UPDATE stellar_wallets SET encrypted_secret_key = ?1, updated_at = ?2 WHERE id = ?3";
        
        sqlx::query(query)
            .bind(new_encrypted_secret)
            .bind(Utc::now())
            .bind(wallet_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update wallet encryption: {}", e)))?;

        Ok(())
    }

    pub async fn store_wallet_transaction(&self, transaction: &crate::models::stellar_wallet::WalletTransaction) -> Result<()> {
        let query = r#"
            INSERT INTO wallet_transactions (
                id, wallet_id, transaction_hash, transaction_type, amount,
                asset_code, asset_issuer, from_address, to_address,
                memo, fee, status, created_at, confirmed_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#;

        sqlx::query(query)
            .bind(transaction.id.to_string())
            .bind(transaction.wallet_id.to_string())
            .bind(&transaction.transaction_hash)
            .bind(&transaction.transaction_type)
            .bind(&transaction.amount)
            .bind(&transaction.asset_code)
            .bind(&transaction.asset_issuer)
            .bind(&transaction.from_address)
            .bind(&transaction.to_address)
            .bind(&transaction.memo)
            .bind(&transaction.fee)
            .bind(&transaction.status)
            .bind(transaction.created_at.to_rfc3339())
            .bind(transaction.confirmed_at.map(|dt| dt.to_rfc3339()))
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to store transaction: {}", e)))?;

        println!("💾 Transaction stored in database: {}", transaction.transaction_hash);
        Ok(())
    }

    // Add method to get wallet transactions
    pub async fn get_wallet_transactions(&self, wallet_id: &Uuid) -> Result<Vec<crate::models::stellar_wallet::WalletTransaction>> {
        let query = r#"
            SELECT * FROM wallet_transactions 
            WHERE wallet_id = ?1 
            ORDER BY created_at DESC
        "#;

        let rows = sqlx::query(query)
            .bind(wallet_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch transactions: {}", e)))?;

        let mut transactions = Vec::new();
        for row in rows {
            let transaction = crate::models::stellar_wallet::WalletTransaction {
                id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid transaction ID: {}", e)))?,
                wallet_id: uuid::Uuid::parse_str(&row.get::<String, _>("wallet_id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid wallet ID: {}", e)))?,
                transaction_hash: row.get("transaction_hash"),
                transaction_type: row.get("transaction_type"),
                amount: row.get("amount"),
                asset_code: row.get("asset_code"),
                asset_issuer: row.get("asset_issuer"),
                from_address: row.get("from_address"),
                to_address: row.get("to_address"),
                memo: row.get("memo"),
                fee: row.get("fee"),
                status: row.get("status"),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                confirmed_at: row.get::<Option<String>, _>("confirmed_at")
                    .map(|s| chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&chrono::Utc)))
                    .transpose()
                    .map_err(|e| AppError::DatabaseError(format!("Invalid confirmed_at date: {}", e)))?,
            };
            transactions.push(transaction);
        }

        Ok(transactions)
    }

    pub async fn get_wallet_by_id(&self, wallet_id: &uuid::Uuid) -> Result<crate::models::stellar_wallet::StellarWallet> {
        let query = r#"
            SELECT id, user_id, public_key, encrypted_secret_key, wallet_name, 
                   is_active, balance_xlm, sequence_number, created_at, updated_at, last_sync_at
            FROM stellar_wallets 
            WHERE id = ?1 AND is_active = TRUE
        "#;

        let row = sqlx::query(query)
            .bind(wallet_id.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch wallet: {}", e)))?;

        let wallet = crate::models::stellar_wallet::StellarWallet {
            id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                .map_err(|e| AppError::DatabaseError(format!("Invalid wallet ID: {}", e)))?,
            user_id: uuid::Uuid::parse_str(&row.get::<String, _>("user_id"))
                .map_err(|e| AppError::DatabaseError(format!("Invalid user ID: {}", e)))?,
            public_key: row.get("public_key"),
            encrypted_secret_key: row.get("encrypted_secret_key"),
            wallet_name: row.get("wallet_name"),
            is_active: row.get("is_active"),
            balance_xlm: row.get("balance_xlm"),
            sequence_number: row.get("sequence_number"),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                .map_err(|e| AppError::DatabaseError(format!("Invalid updated_at date: {}", e)))?
                .with_timezone(&chrono::Utc),
            last_sync_at: row.get::<Option<String>, _>("last_sync_at")
                .map(|s| chrono::DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&chrono::Utc)))
                .transpose()
                .map_err(|e| AppError::DatabaseError(format!("Invalid last_sync_at date: {}", e)))?,
        };

        Ok(wallet)
    }

    // Add method to store or update asset balance
    pub async fn update_asset_balance(&self, balance: &crate::models::stellar_wallet::AssetBalance) -> Result<()> {
        let query = r#"
        INSERT INTO asset_balances (id, wallet_id, asset_type, asset_code, asset_issuer, balance, last_updated)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT (wallet_id, asset_code, asset_issuer)
        DO UPDATE SET
            balance = excluded.balance,
            last_updated = excluded.last_updated
        "#;

        sqlx::query(query)
            .bind(balance.id.to_string())
            .bind(balance.wallet_id.to_string())
            .bind(&balance.asset_type)
            .bind(&balance.asset_code)
            .bind(&balance.asset_issuer)
            .bind(&balance.balance)
            .bind(balance.last_updated.to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update asset balance: {}", e)))?;

        Ok(())
    }

    // Add method to get asset balances for a wallet
    pub async fn get_wallet_asset_balances(&self, wallet_id: &Uuid) -> Result<Vec<crate::models::stellar_wallet::AssetBalance>> {
        let query = r#"
        SELECT id, wallet_id, asset_type, asset_code, asset_issuer, balance, last_updated
        FROM asset_balances
        WHERE wallet_id = ?1
        "#;

        let rows = sqlx::query(query)
            .bind(wallet_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch asset balances: {}", e)))?;

        let mut balances = Vec::new();
        for row in rows {
            let balance = crate::models::stellar_wallet::AssetBalance {
                id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid balance ID: {}", e)))?,
                wallet_id: uuid::Uuid::parse_str(&row.get::<String, _>("wallet_id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid wallet ID: {}", e)))?,
                asset_type: row.get("asset_type"),
                asset_code: row.get("asset_code"),
                asset_issuer: row.get("asset_issuer"),
                balance: row.get("balance"),
                last_updated: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("last_updated"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid last_updated date: {}", e)))?
                    .with_timezone(&chrono::Utc),
            };
            balances.push(balance);
        }

        Ok(balances)
    }
    #[allow(dead_code)]
    async fn create_exchange_transactions_table(&self) -> Result<()> {
        let query = r#"
        CREATE TABLE IF NOT EXISTS exchange_transactions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            from_currency TEXT NOT NULL,
            to_currency TEXT NOT NULL,
            from_amount REAL NOT NULL,
            to_amount REAL NOT NULL,
            exchange_rate REAL NOT NULL,
            fee_amount REAL NOT NULL,
            stellar_tx_hash TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )"#;

        sqlx::query(query)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create exchange_transactions table: {}", e)))?;

        Ok(())
    }

    pub async fn store_exchange_transaction(&self, tx: &crate::models::currency::ExchangeTransaction) -> Result<()> {
        let query = r#"
        INSERT INTO exchange_transactions (
            id, user_id, from_currency, to_currency, from_amount, to_amount, exchange_rate, fee_amount, stellar_tx_hash, status, created_at, completed_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#;
        sqlx::query(query)
            .bind(tx.id.to_string())
            .bind(tx.user_id.to_string())
            .bind(&tx.from_currency)
            .bind(&tx.to_currency)
            .bind(tx.from_amount)
            .bind(tx.to_amount)
            .bind(tx.exchange_rate)
            .bind(tx.fee_amount)
            .bind(&tx.stellar_tx_hash)
            .bind(tx.status.to_string())
            .bind(tx.created_at.to_rfc3339())
            .bind(tx.completed_at.map(|dt| dt.to_rfc3339()))
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to store exchange transaction: {}", e)))?;
        Ok(())
    }

    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }

    // Notification methods
    pub async fn store_notification(&self, notification: &crate::models::notification::Notification) -> Result<()> {
        let query = r#"
            INSERT INTO notifications (
                id, user_id, notification_type, title, message, priority, 
                channels, metadata, is_read, created_at, sent_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#;

        sqlx::query(query)
            .bind(notification.id.to_string())
            .bind(notification.user_id.to_string())
            .bind(format!("{:?}", notification.notification_type))
            .bind(&notification.title)
            .bind(&notification.message)
            .bind(format!("{:?}", notification.priority))
            .bind(serde_json::to_string(&notification.channels)?)
            .bind(notification.metadata.as_ref().map(serde_json::to_string).transpose()?)
            .bind(notification.is_read)
            .bind(notification.created_at.to_rfc3339())
            .bind(notification.sent_at.map(|dt| dt.to_rfc3339()))
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to store notification: {}", e)))?;

        Ok(())
    }

    pub async fn get_user_by_id(&self, user_id: &Uuid) -> Result<crate::models::user::User> {
        let query = r#"
            SELECT id, email, username, password_hash, is_verified, stellar_public_key, phone_number, is_phone_verified, phone_verification_code, phone_verified_at, created_at, updated_at, totp_secret, totp_enabled, backup_codes, is_deleted
            FROM users 
            WHERE id = ?1
        "#;

        let row = sqlx::query(query)
            .bind(user_id.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch user: {}", e)))?;

        let user = crate::models::user::User {
            id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                .map_err(|e| AppError::DatabaseError(format!("Invalid user ID: {}", e)))?,
            email: row.get("email"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            is_verified: row.get("is_verified"),
            stellar_public_key: row.get("stellar_public_key"),
            phone_number: row.get("phone_number"),
            is_phone_verified: row.get("is_phone_verified"),
            phone_verification_code: row.get("phone_verification_code"),
            phone_verified_at: row.get::<Option<String>, _>("phone_verified_at").and_then(|s| s.parse().ok()),
            totp_secret: row.get("totp_secret"),
            totp_enabled: row.get("totp_enabled"),
            backup_codes: row.get("backup_codes"),
            is_deleted: row.get("is_deleted"),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                .map_err(|e| AppError::DatabaseError(format!("Invalid updated_at date: {}", e)))?
                .with_timezone(&chrono::Utc),
        };

        Ok(user)
    }

    pub async fn mark_notification_sent(&self, notification_id: &Uuid) -> Result<()> {
        let query = r#"
            UPDATE notifications 
            SET sent_at = ?1 
            WHERE id = ?2
        "#;

        sqlx::query(query)
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(notification_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to mark notification sent: {}", e)))?;

        Ok(())
    }

    pub async fn get_user_notifications(&self, user_id: &Uuid, limit: Option<i64>) -> Result<Vec<crate::models::notification::Notification>> {
        let limit_clause = limit.map(|l| format!("LIMIT {}", l)).unwrap_or_default();
        let query = format!(
            r#"
            SELECT id, user_id, notification_type, title, message, priority, 
                   channels, metadata, is_read, created_at, sent_at
            FROM notifications 
            WHERE user_id = ?1 
            ORDER BY created_at DESC
            {}
            "#,
            limit_clause
        );

        let rows = sqlx::query(&query)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch notifications: {}", e)))?;

        let mut notifications = Vec::new();
        for row in rows {
            let notification = crate::models::notification::Notification {
                id: uuid::Uuid::parse_str(&row.get::<String, _>("id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid notification ID: {}", e)))?,
                user_id: uuid::Uuid::parse_str(&row.get::<String, _>("user_id"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid user ID: {}", e)))?,
                notification_type: match row.get::<String, _>("notification_type").as_str() {
                    "IncomingPayment" => crate::models::notification::NotificationType::IncomingPayment,
                    "OutgoingPayment" => crate::models::notification::NotificationType::OutgoingPayment,
                    "PaymentFailed" => crate::models::notification::NotificationType::PaymentFailed,
                    "BalanceChange" => crate::models::notification::NotificationType::BalanceChange,
                    "LowBalance" => crate::models::notification::NotificationType::LowBalance,
                    "SecurityAlert" => crate::models::notification::NotificationType::SecurityAlert,
                    "ExchangeCompleted" => crate::models::notification::NotificationType::ExchangeCompleted,
                    "ExchangeFailed" => crate::models::notification::NotificationType::ExchangeFailed,
                    "SystemAlert" => crate::models::notification::NotificationType::SystemAlert,
                    _ => crate::models::notification::NotificationType::SystemAlert,
                },
                title: row.get("title"),
                message: row.get("message"),
                priority: match row.get::<String, _>("priority").as_str() {
                    "Low" => crate::models::notification::NotificationPriority::Low,
                    "Medium" => crate::models::notification::NotificationPriority::Medium,
                    "High" => crate::models::notification::NotificationPriority::High,
                    "Critical" => crate::models::notification::NotificationPriority::Critical,
                    _ => crate::models::notification::NotificationPriority::Medium,
                },
                channels: serde_json::from_str(&row.get::<String, _>("channels"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid channels JSON: {}", e)))?,
                metadata: row.get::<Option<String>, _>("metadata")
                    .map(|s| serde_json::from_str(&s))
                    .transpose()
                    .map_err(|e| AppError::DatabaseError(format!("Invalid metadata JSON: {}", e)))?,
                is_read: row.get("is_read"),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                    .map_err(|e| AppError::DatabaseError(format!("Invalid created_at date: {}", e)))?
                    .with_timezone(&chrono::Utc),
                sent_at: row.get::<Option<String>, _>("sent_at")
                    .map(|s| chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&chrono::Utc)))
                    .transpose()
                    .map_err(|e| AppError::DatabaseError(format!("Invalid sent_at date: {}", e)))?,
            };
            notifications.push(notification);
        }

        Ok(notifications)
    }

    pub async fn mark_notification_read(&self, notification_id: &Uuid) -> Result<()> {
        let query = r#"
            UPDATE notifications 
            SET is_read = TRUE 
            WHERE id = ?1
        "#;

        sqlx::query(query)
            .bind(notification_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to mark notification read: {}", e)))?;

        Ok(())
    }

    // Mark all notifications as read for a user
    pub async fn mark_all_notifications_read(&self, user_id: &Uuid) -> Result<()> {
        let query = r#"
            UPDATE notifications
            SET is_read = TRUE
            WHERE user_id = ?1 AND is_read = FALSE
        "#;
        sqlx::query(query)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to mark all notifications as read: {}", e)))?;
        Ok(())
    }

    // Delete a single notification by ID
    pub async fn delete_notification(&self, notification_id: &Uuid) -> Result<()> {
        let query = r#"
            DELETE FROM notifications
            WHERE id = ?1
        "#;
        sqlx::query(query)
            .bind(notification_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete notification: {}", e)))?;
        Ok(())
    }

    // Delete all notifications for a user
    pub async fn delete_all_notifications(&self, user_id: &Uuid) -> Result<()> {
        let query = r#"
            DELETE FROM notifications
            WHERE user_id = ?1
        "#;
        sqlx::query(query)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete all notifications: {}", e)))?;
        Ok(())
    }

    // Get notification preferences for a user
    pub async fn get_notification_preferences(&self, user_id: &Uuid) -> Result<Option<crate::models::notification::NotificationPreferences>> {
        let query = r#"
            SELECT * FROM notification_preferences WHERE user_id = ?1
        "#;
        let row = sqlx::query(query)
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch notification preferences: {}", e)))?;
        if let Some(row) = row {
            Ok(Some(crate::models::notification::NotificationPreferences {
                user_id: Uuid::parse_str(&row.get::<String, _>("user_id")).unwrap(),
                email_enabled: row.get("email_enabled"),
                sms_enabled: row.get("sms_enabled"),
                push_enabled: row.get("push_enabled"),
                in_app_enabled: row.get("in_app_enabled"),
                incoming_payment_alerts: row.get("incoming_payment_alerts"),
                outgoing_payment_alerts: row.get("outgoing_payment_alerts"),
                payment_failure_alerts: row.get("payment_failure_alerts"),
                balance_change_alerts: row.get("balance_change_alerts"),
                low_balance_threshold: row.get("low_balance_threshold"),
                security_alerts: row.get("security_alerts"),
                exchange_alerts: row.get("exchange_alerts"),
                system_alerts: row.get("system_alerts"),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at")).unwrap().with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at")).unwrap().with_timezone(&chrono::Utc),
            }))
        } else {
            Ok(None)
        }
    }

    // Insert notification preferences (used for first-time setup)
    pub async fn set_notification_preferences(&self, prefs: &crate::models::notification::NotificationPreferences) -> Result<()> {
        let query = r#"
            INSERT INTO notification_preferences (
                user_id, email_enabled, sms_enabled, push_enabled, in_app_enabled,
                incoming_payment_alerts, outgoing_payment_alerts, payment_failure_alerts,
                balance_change_alerts, low_balance_threshold, security_alerts, exchange_alerts, system_alerts,
                created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#;
        sqlx::query(query)
            .bind(prefs.user_id.to_string())
            .bind(prefs.email_enabled)
            .bind(prefs.sms_enabled)
            .bind(prefs.push_enabled)
            .bind(prefs.in_app_enabled)
            .bind(prefs.incoming_payment_alerts)
            .bind(prefs.outgoing_payment_alerts)
            .bind(prefs.payment_failure_alerts)
            .bind(prefs.balance_change_alerts)
            .bind(prefs.low_balance_threshold)
            .bind(prefs.security_alerts)
            .bind(prefs.exchange_alerts)
            .bind(prefs.system_alerts)
            .bind(prefs.created_at.to_rfc3339())
            .bind(prefs.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to set notification preferences: {}", e)))?;
        Ok(())
    }

    // Update notification preferences
    pub async fn update_notification_preferences(&self, prefs: &crate::models::notification::NotificationPreferences) -> Result<()> {
        let query = r#"
            UPDATE notification_preferences SET
                email_enabled = ?2,
                sms_enabled = ?3,
                push_enabled = ?4,
                in_app_enabled = ?5,
                incoming_payment_alerts = ?6,
                outgoing_payment_alerts = ?7,
                payment_failure_alerts = ?8,
                balance_change_alerts = ?9,
                low_balance_threshold = ?10,
                security_alerts = ?11,
                exchange_alerts = ?12,
                system_alerts = ?13,
                updated_at = ?14
            WHERE user_id = ?1
        "#;
        sqlx::query(query)
            .bind(prefs.user_id.to_string())
            .bind(prefs.email_enabled)
            .bind(prefs.sms_enabled)
            .bind(prefs.push_enabled)
            .bind(prefs.in_app_enabled)
            .bind(prefs.incoming_payment_alerts)
            .bind(prefs.outgoing_payment_alerts)
            .bind(prefs.payment_failure_alerts)
            .bind(prefs.balance_change_alerts)
            .bind(prefs.low_balance_threshold)
            .bind(prefs.security_alerts)
            .bind(prefs.exchange_alerts)
            .bind(prefs.system_alerts)
            .bind(prefs.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update notification preferences: {}", e)))?;
        Ok(())
    }

    pub async fn update_user_profile(&self, user: &crate::models::user::User) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = r#"
            UPDATE users
            SET email = ?, username = ?, phone_number = ?, updated_at = ?
            WHERE id = ?
        "#;
        sqlx::query(query)
            .bind(&user.email)
            .bind(&user.username)
            .bind(&user.phone_number)
            .bind(&now)
            .bind(user.id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| crate::errors::AppError::DatabaseError(format!("Failed to update user profile: {}", e)))?;
        Ok(())
    }

    pub async fn update_user_password(&self, user_id: &Uuid, new_password_hash: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = r#"
            UPDATE users
            SET password_hash = ?, updated_at = ?
            WHERE id = ?
        "#;
        sqlx::query(query)
            .bind(new_password_hash)
            .bind(&now)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update user password: {}", e)))?;
        Ok(())
    }

    pub async fn update_user_phone_number_with_verification(&self, user_id: &Uuid, phone_number: &str, verification_code: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = r#"
            UPDATE users
            SET phone_number = ?, phone_verification_code = ?, updated_at = ?
            WHERE id = ?
        "#;
        sqlx::query(query)
            .bind(phone_number)
            .bind(verification_code)
            .bind(&now)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update user phone number: {}", e)))?;
        Ok(())
    }

    pub async fn verify_user_phone_code(&self, user_id: &Uuid, code: &str) -> Result<bool> {
        let user = self.get_user_by_id(user_id).await?;
        if let Some(stored_code) = &user.phone_verification_code {
            if stored_code == code {
                // Mark as verified
                let now = chrono::Utc::now().to_rfc3339();
                let query = r#"
                    UPDATE users
                    SET is_phone_verified = TRUE, phone_verified_at = ?, phone_verification_code = NULL, updated_at = ?
                    WHERE id = ?
                "#;
                sqlx::query(query)
                    .bind(&now)
                    .bind(&now)
                    .bind(user_id.to_string())
                    .execute(&self.pool)
                    .await
                    .map_err(|e| AppError::DatabaseError(format!("Failed to update phone verification: {}", e)))?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    // 2FA Methods
    pub async fn setup_2fa(&self, user_id: &Uuid, totp_secret: &str, backup_codes: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = r#"
            UPDATE users
            SET totp_secret = ?, totp_enabled = FALSE, backup_codes = ?, updated_at = ?
            WHERE id = ?
        "#;
        sqlx::query(query)
            .bind(totp_secret)
            .bind(backup_codes)
            .bind(&now)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to setup 2FA: {}", e)))?;
        Ok(())
    }

    pub async fn disable_2fa(&self, user_id: &Uuid) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = r#"
            UPDATE users
            SET totp_secret = NULL, totp_enabled = FALSE, backup_codes = NULL, updated_at = ?
            WHERE id = ?
        "#;
        sqlx::query(query)
            .bind(&now)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to disable 2FA: {}", e)))?;
        Ok(())
    }

    pub async fn verify_2fa(&self, user_id: &Uuid, totp_code: &str) -> Result<bool> {
        let user = self.get_user_by_id(user_id).await?;
        if let Some(secret) = user.totp_secret {
            // Use custom TOTP implementation
            let expected_code = self.generate_totp_code(&secret)?;
            Ok(totp_code == expected_code)
        } else {
            Ok(false)
        }
    }

    fn generate_totp_code(&self, secret: &str) -> Result<String> {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() / 30;
        
        let time_bytes = time.to_be_bytes();
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| AppError::DatabaseError("Invalid secret format".to_string()))?;
        
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&secret_bytes)
            .map_err(|e| AppError::DatabaseError(format!("HMAC creation failed: {}", e)))?;
        mac.update(&time_bytes);
        let result = mac.finalize();
        let hash = result.into_bytes();
        
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let code = ((hash[offset] as u32 & 0x7f) << 24) |
                   ((hash[offset + 1] as u32 & 0xff) << 16) |
                   ((hash[offset + 2] as u32 & 0xff) << 8) |
                   (hash[offset + 3] as u32 & 0xff);
        
        Ok(format!("{:06}", code % 1000000))
    }

    #[allow(dead_code)]
    pub async fn verify_backup_code(&self, user_id: &Uuid, backup_code: &str) -> Result<bool> {
        let user = self.get_user_by_id(user_id).await?;
        if let Some(codes_json) = user.backup_codes {
            let codes: Vec<String> = serde_json::from_str(&codes_json)
                .map_err(|e| AppError::DatabaseError(format!("Invalid backup codes format: {}", e)))?;
            Ok(codes.contains(&backup_code.to_string()))
        } else {
            Ok(false)
        }
    }

    // Account Deletion
    #[allow(dead_code)]
    pub async fn soft_delete_user(&self, user_id: &Uuid) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let query = r#"
            UPDATE users
            SET is_deleted = TRUE, updated_at = ?
            WHERE id = ?
        "#;
        sqlx::query(query)
            .bind(&now)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete user: {}", e)))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn hard_delete_user(&self, user_id: &Uuid) -> Result<()> {
        // Delete related data first
        sqlx::query("DELETE FROM notifications WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete notifications: {}", e)))?;

        sqlx::query("DELETE FROM stellar_wallets WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete wallets: {}", e)))?;

        sqlx::query("DELETE FROM notification_preferences WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete preferences: {}", e)))?;

        // Delete user sessions
        sqlx::query("DELETE FROM user_tokens WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete sessions: {}", e)))?;

        // Finally delete the user
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete user: {}", e)))?;

        Ok(())
    }

    pub async fn create_kyc_submission(&self, kyc: &KycSubmission) -> Result<()> {
        let query = r#"
            INSERT INTO kyc_submissions (id, user_id, full_name, id_type, id_number, id_photo_url, status, submitted_at, reviewed_at, rejection_reason)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#;
        sqlx::query(query)
            .bind(kyc.id.to_string())
            .bind(kyc.user_id.to_string())
            .bind(&kyc.full_name)
            .bind(&kyc.id_type)
            .bind(&kyc.id_number)
            .bind(&kyc.id_photo_url)
            .bind(&kyc.status)
            .bind(kyc.submitted_at.map(|dt| dt.to_rfc3339()))
            .bind(kyc.reviewed_at.map(|dt| dt.to_rfc3339()))
            .bind(&kyc.rejection_reason)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create KYC submission: {}", e)))?;
        Ok(())
    }

    pub async fn get_kyc_submission_by_user(&self, user_id: &Uuid) -> Result<Option<KycSubmission>> {
        let query = r#"
            SELECT * FROM kyc_submissions WHERE user_id = ?1 ORDER BY submitted_at DESC LIMIT 1
        "#;
        let row = sqlx::query(query)
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to fetch KYC submission: {}", e)))?;
        if let Some(row) = row {
            Ok(Some(KycSubmission {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap(),
                user_id: Uuid::parse_str(&row.get::<String, _>("user_id")).unwrap(),
                full_name: row.get("full_name"),
                id_type: row.get("id_type"),
                id_number: row.get("id_number"),
                id_photo_url: row.get("id_photo_url"),
                status: row.get("status"),
                submitted_at: row.get::<Option<String>, _>("submitted_at").and_then(|s| s.parse().ok()),
                reviewed_at: row.get::<Option<String>, _>("reviewed_at").and_then(|s| s.parse().ok()),
                rejection_reason: row.get("rejection_reason"),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn list_kyc_submissions(&self, limit: Option<i64>) -> Result<Vec<KycSubmission>> {
        let query = if let Some(lim) = limit {
            format!("SELECT * FROM kyc_submissions ORDER BY submitted_at DESC LIMIT {}", lim)
        } else {
            "SELECT * FROM kyc_submissions ORDER BY submitted_at DESC".to_string()
        };
        let rows = sqlx::query(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to list KYC submissions: {}", e)))?;
        Ok(rows.into_iter().map(|row| KycSubmission {
            id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap(),
            user_id: Uuid::parse_str(&row.get::<String, _>("user_id")).unwrap(),
            full_name: row.get("full_name"),
            id_type: row.get("id_type"),
            id_number: row.get("id_number"),
            id_photo_url: row.get("id_photo_url"),
            status: row.get("status"),
            submitted_at: row.get::<Option<String>, _>("submitted_at").and_then(|s| s.parse().ok()),
            reviewed_at: row.get::<Option<String>, _>("reviewed_at").and_then(|s| s.parse().ok()),
            rejection_reason: row.get("rejection_reason"),
        }).collect())
    }

    pub async fn update_kyc_status(&self, kyc_id: &Uuid, status: &str, reviewed_at: Option<DateTime<Utc>>, rejection_reason: Option<&str>) -> Result<()> {
        let query = r#"
            UPDATE kyc_submissions SET status = ?1, reviewed_at = ?2, rejection_reason = ?3 WHERE id = ?4
        "#;
        sqlx::query(query)
            .bind(status)
            .bind(reviewed_at.map(|dt| dt.to_rfc3339()))
            .bind(rejection_reason)
            .bind(kyc_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update KYC status: {}", e)))?;
        Ok(())
    }
}