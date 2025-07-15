use crate::database::sqlite::SqliteDatabase;
use crate::errors::{AppError, Result};
use crate::models::user::{User, UserResponse};
use crate::utils::crypto::PasswordManager;
use crate::utils::validation::Validator;
use chrono::Utc;
use uuid::Uuid;
use rand::Rng;
use std::sync::Arc;

pub struct UserService {
    pub db: Arc<SqliteDatabase>,
}

impl UserService {
    pub async fn new(db: Arc<SqliteDatabase>) -> Result<Self> {
        Ok(Self { db })
    }

    pub async fn create_user(&self, email: &str, username: &str, password: &str, phone_number: Option<String>) -> Result<Uuid> {
        let user_id = Uuid::new_v4();
        let password_hash = crate::utils::crypto::PasswordManager::hash_password(password)?;
        
        let user = User {
            id: user_id,
            email: email.to_string(),
            username: username.to_string(),
            password_hash,
            is_verified: false,
            stellar_public_key: None,
            phone_number,
            is_phone_verified: false,
            phone_verification_code: None,
            phone_verified_at: None,
            totp_secret: None,
            totp_enabled: false,
            backup_codes: None,
            is_deleted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        self.db.create_user(&user).await?;
        Ok(user_id)
    }

    pub async fn authenticate_user(&self, email_or_username: &str, password: &str) -> Result<UserResponse> {
        // Try to find user by email first, then by username
        let user = if let Some(user) = self.db.get_user_by_email(email_or_username).await? {
            user
        } else if let Some(user) = self.db.get_user_by_username(email_or_username).await? {
            user
        } else {
            return Err(AppError::AuthenticationError("Invalid email/username or password".to_string()));
        };

        // Verify password
        if !PasswordManager::verify_password(password, &user.password_hash)? {
            return Err(AppError::AuthenticationError("Invalid email/username or password".to_string()));
        }

        println!("✅ Authentication successful for user: {}", user.username);
        Ok(user.into())
    }

    pub async fn get_user_count(&self) -> Result<i64> {
        self.db.get_user_count().await
    }

    pub async fn get_user_by_id(&self, user_id: &Uuid) -> Result<UserResponse> {
        let user = self.db.get_user_by_id(user_id).await?;
        Ok(user.into())
    }

    pub async fn get_user_model_by_id(&self, user_id: &Uuid) -> Result<crate::models::user::User> {
        self.db.get_user_by_id(user_id).await
    }

    pub async fn update_user_profile(&self, user: &crate::models::user::User) -> Result<()> {
        self.db.update_user_profile(user).await
    }

    pub async fn change_user_password(&self, user_id: &Uuid, current_password: &str, new_password: &str) -> Result<()> {
        // Fetch user
        let user = self.db.get_user_by_id(user_id).await?;
        // Verify current password
        if !PasswordManager::verify_password(current_password, &user.password_hash)? {
            return Err(AppError::AuthenticationError("Current password is incorrect".to_string()));
        }
        // Prevent using the same password
        let is_same = PasswordManager::verify_password(new_password, &user.password_hash)?;
        println!("[DEBUG] is_same_password: {}", is_same); 
        if is_same {
            return Err(AppError::ValidationError("New password must be different from the current password".to_string()));
        }
        // Validate new password
        Validator::validate_password(new_password)?;
        // Hash new password
        let new_hash = PasswordManager::hash_password(new_password)?;
        // Update in database
        self.db.update_user_password(user_id, &new_hash).await
    }

    pub async fn change_user_password_with_2fa(&self, user_id: &Uuid, current_password: &str, new_password: &str, totp_code: Option<String>) -> Result<()> {
        // Check if 2FA is enabled
        let user = self.db.get_user_by_id(user_id).await?;
        if user.totp_enabled {
            let code = totp_code.as_deref().unwrap_or("");
            let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(self.db.clone());
            if !two_factor_service.verify_totp(user_id, code).await.unwrap_or(false) {
                return Err(crate::errors::AppError::AuthenticationError("Invalid or missing 2FA code".to_string()));
            }
        }
        self.change_user_password(user_id, current_password, new_password).await
    }

    pub async fn update_user_phone_number_with_verification(&self, user_id: &Uuid, phone_number: &str) -> Result<String> {
        // Generate a verification code
        let verification_code = format!("{:06}", rand::thread_rng().gen_range(100000..999999));
        
        // Store the verification code and phone number
        self.db.update_user_phone_number_with_verification(user_id, phone_number, &verification_code).await?;
        
        // TODO: Send SMS with verification code
        println!("📱 Verification code sent to {}: {}", phone_number, verification_code);
        
        Ok(verification_code)
    }

    pub async fn verify_user_phone_code(&self, user_id: &Uuid, code: &str) -> Result<bool> {
        self.db.verify_user_phone_code(user_id, code).await
    }

    pub async fn delete_account_with_2fa(&self, user_id: &Uuid, password: &str, totp_code: Option<String>) -> Result<()> {
        let user = self.db.get_user_by_id(user_id).await?;
        if !crate::utils::crypto::PasswordManager::verify_password(password, &user.password_hash)? {
            return Err(crate::errors::AppError::AuthenticationError("Incorrect password".to_string()));
        }
        if user.totp_enabled {
            let code = totp_code.as_deref().unwrap_or("");
            let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(self.db.clone());
            if !two_factor_service.verify_totp(user_id, code).await.unwrap_or(false) {
                return Err(crate::errors::AppError::AuthenticationError("Invalid or missing 2FA code".to_string()));
            }
        }
        self.db.soft_delete_user(user_id).await
    }
}
