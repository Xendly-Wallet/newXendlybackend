use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub is_verified: bool,
    pub stellar_public_key: Option<String>,
    pub phone_number: Option<String>,
    pub is_phone_verified: bool,
    pub phone_verification_code: Option<String>,
    pub phone_verified_at: Option<DateTime<Utc>>,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub backup_codes: Option<String>, 
    pub is_deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    pub phone_number: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub is_verified: bool,
    pub stellar_public_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub phone_number: Option<String>,
    pub is_phone_verified: bool,
    pub phone_verification_code: Option<String>,
    pub phone_verified_at: Option<DateTime<Utc>>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            email: user.email,
            username: user.username,
            is_verified: user.is_verified,
            stellar_public_key: user.stellar_public_key,
            created_at: user.created_at,
            phone_number: user.phone_number,
            is_phone_verified: user.is_phone_verified,
            phone_verification_code: user.phone_verification_code,
            phone_verified_at: user.phone_verified_at,
        }
    }
}
