use crate::errors::{AppError, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      
    pub username: String, 
    pub email: String,    
    pub exp: i64,         
    pub iat: i64,         
    pub jti: String,      
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims2FASetup {
    pub sub: String,      // user_id
    pub username: String,
    pub email: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub purpose: String, // should be "2fa_setup"
}

pub struct JwtManager {
    secret: String,
}

impl JwtManager {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    pub fn generate_token(&self, user_id: &Uuid, username: &str, email: &str) -> Result<String> {
        let now = Utc::now();
        let expiration = now + Duration::hours(24); // Token expires in 24 hours
        let jti = Uuid::new_v4().to_string(); // Unique token ID

        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            jti,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|e| AppError::AuthenticationError(format!("Failed to generate token: {}", e)))?;

        Ok(token)
    }

    pub fn validate_token(&self, token: &str) -> Result<TokenData<Claims>> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )
        .map_err(|e| AppError::AuthenticationError(format!("Invalid token: {}", e)))?;

        Ok(token_data)
    }
    #[allow(dead_code)]
    pub fn refresh_token(&self, token: &str) -> Result<String> {
        let token_data = self.validate_token(token)?;
        let claims = token_data.claims;
        
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|e| AppError::ValidationError(format!("Invalid user ID in token: {}", e)))?;
        
        // Generate new token with same user data
        self.generate_token(&user_id, &claims.username, &claims.email)
    }

    pub fn generate_2fa_setup_token(&self, user_id: &Uuid, username: &str, email: &str) -> Result<String> {
        let now = Utc::now();
        let expiration = now + Duration::minutes(5); // Token expires in 5 minutes
        let jti = Uuid::new_v4().to_string();
        let claims = Claims2FASetup {
            sub: user_id.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            jti,
            purpose: "2fa_setup".to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|e| AppError::AuthenticationError(format!("Failed to generate 2FA setup token: {}", e)))?;
        Ok(token)
    }

    pub fn validate_2fa_setup_token(&self, token: &str) -> Result<TokenData<Claims2FASetup>> {
        let token_data = decode::<Claims2FASetup>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )
        .map_err(|e| AppError::AuthenticationError(format!("Invalid 2FA setup token: {}", e)))?;
        if token_data.claims.purpose != "2fa_setup" {
            return Err(AppError::AuthenticationError("Invalid 2FA setup token purpose".to_string()));
        }
        Ok(token_data)
    }
}

#[derive(Debug)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub token_id: String,
}

impl TryFrom<Claims> for AuthenticatedUser {
    type Error = AppError;

    fn try_from(claims: Claims) -> Result<Self> {
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|e| AppError::ValidationError(format!("Invalid user ID in token: {}", e)))?;

        Ok(Self {
            user_id,
            username: claims.username,
            email: claims.email,
            token_id: claims.jti,
        })
    }
}
