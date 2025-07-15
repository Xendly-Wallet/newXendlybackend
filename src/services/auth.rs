use crate::database::sqlite::SqliteDatabase;
use crate::errors::{AppError, Result};
use crate::models::user::User;
use crate::services::jwt::{JwtManager, AuthenticatedUser};
use crate::utils::crypto::PasswordManager;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::sync::Arc;


pub enum Login2FAResult {
    Token(String),
    TwoFARequired { user_id: uuid::Uuid },
}

pub struct AuthService {
    jwt_manager: JwtManager,
    database: Arc<SqliteDatabase>,
}

impl AuthService {
    pub fn new(database: Arc<SqliteDatabase>) -> Self {
        // In production, this should come from environment variables
        let jwt_secret = std::env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set in environment for production!");
        
        Self {
            jwt_manager: JwtManager::new(jwt_secret),
            database,
        }
    }

    pub fn database(&self) -> Arc<SqliteDatabase> {
        self.database.clone()
    }

    pub async fn authenticate_user(&self, email_or_username: &str, password: &str) -> Result<User> {
        // Try to find user by email first, then by username
        let user = if email_or_username.contains('@') {
            self.database.get_user_by_email(email_or_username).await?
        } else {
            self.database.get_user_by_username(email_or_username).await?
        };

        let user = user.ok_or_else(|| AppError::AuthenticationError("User not found".to_string()))?;

        // Verify password using your existing PasswordManager
        if !PasswordManager::verify_password(password, &user.password_hash)? {
            return Err(AppError::AuthenticationError("Invalid password".to_string()));
        }

        Ok(user)
    }

    pub async fn login_and_generate_token(&self, email_or_username: &str, password: &str) -> Result<String> {
        // Authenticate the user
        let user = self.authenticate_user(email_or_username, password).await?;

        // Generate JWT token
        let token = self.jwt_manager.generate_token(&user.id, &user.username, &user.email)?;
        
        // Extract token ID from the token for storage
        let token_data = self.jwt_manager.validate_token(&token)?;
        let token_id = &token_data.claims.jti;
        
        // Create a hash of the token for secure storage
        let token_hash = self.hash_token(&token);
        
        // Calculate expiration time
        let expires_at = Utc::now() + Duration::hours(24);
        
        // Store token in database
        self.database.store_user_token(&user.id, token_id, &token_hash, expires_at).await?;
        
        // Clean up expired tokens
        let _ = self.database.cleanup_expired_tokens().await;
        
        println!("🎯 JWT token generated for user: {}", user.username);
        Ok(token)
    }

    pub async fn login_with_2fa_check(&self, email_or_username: &str, password: &str) -> Result<Login2FAResult> {
        let user = self.authenticate_user(email_or_username, password).await?;
        if user.totp_enabled {
            Ok(Login2FAResult::TwoFARequired { user_id: user.id })
        } else {
            let token = self.login_and_generate_token(email_or_username, password).await?;
            Ok(Login2FAResult::Token(token))
        }
    }

    pub async fn validate_token(&self, token: &str) -> Result<AuthenticatedUser> {
        // First validate JWT signature and expiration
        let token_data = self.jwt_manager.validate_token(token)?;
        let token_id = &token_data.claims.jti;
        
        // Check if token exists in database and is active
        if !self.database.is_token_valid(token_id).await? {
            return Err(AppError::AuthenticationError("Token not found or inactive in database".to_string()));
        }

        AuthenticatedUser::try_from(token_data.claims)
    }

    pub async fn refresh_token(&self, old_token: &str) -> Result<String> {
        // Validate the old token first
        let user = self.validate_token(old_token).await?;
        
        // Generate new token
        let new_token = self.jwt_manager.generate_token(&user.user_id, &user.username, &user.email)?;
        
        // Extract new token ID
        let token_data = self.jwt_manager.validate_token(&new_token)?;
        let new_token_id = &token_data.claims.jti;
        
        // Create hash of new token
        let new_token_hash = self.hash_token(&new_token);
        
        // Calculate expiration time
        let expires_at = Utc::now() + Duration::hours(24);
        
        // Revoke old token and store new one
        self.database.revoke_token(&user.token_id).await?;
        self.database.store_user_token(&user.user_id, new_token_id, &new_token_hash, expires_at).await?;
        
        println!("🔄 Token refreshed for user: {}", user.username);
        Ok(new_token)
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        let token_data = self.jwt_manager.validate_token(token)?;
        let token_id = &token_data.claims.jti;
        
        self.database.revoke_token(token_id).await?;
        Ok(())
    }

    pub async fn logout_all_devices(&self, token: &str) -> Result<()> {
        let user = self.validate_token(token).await?;
        self.database.revoke_all_user_tokens(&user.user_id).await?;
        Ok(())
    }

    pub async fn get_user_sessions_count(&self, token: &str) -> Result<i64> {
        let user = self.validate_token(token).await?;
        self.database.get_user_active_tokens_count(&user.user_id).await
    }

    /// Generate a JWT for a user by user_id (used in 2FA verification API)
    #[allow(dead_code)]
    pub async fn generate_jwt(&self, user_id: &uuid::Uuid) -> Result<String> {
        let user = self.database.get_user_by_id(user_id).await?;
        let token = self.jwt_manager.generate_token(&user.id, &user.username, &user.email)?;
        let token_data = self.jwt_manager.validate_token(&token)?;
        let token_id = &token_data.claims.jti;
        let token_hash = self.hash_token(&token);
        let expires_at = Utc::now() + Duration::hours(24);
        self.database.store_user_token(&user.id, token_id, &token_hash, expires_at).await?;
        let _ = self.database.cleanup_expired_tokens().await;
        Ok(token)
    }

    // Helper method to hash tokens for secure storage
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
