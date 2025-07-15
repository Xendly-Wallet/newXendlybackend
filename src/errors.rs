use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    
    #[error("Stellar error: {0}")]
    StellarError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("JWT error: {0}")]
    JwtError(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[allow(dead_code)]
    #[error("IO error: {0}")]
    IoError(String),
    
    #[allow(dead_code)]
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[allow(dead_code)]
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DatabaseError(err.to_string())
    }
}

impl From<argon2::Error> for AppError {
    fn from(err: argon2::Error) -> Self {
        AppError::EncryptionError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AppError::JwtError(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::SerializationError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
