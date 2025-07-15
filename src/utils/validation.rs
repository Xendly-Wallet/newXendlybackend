use crate::errors::{AppError, Result};
use regex::Regex;

pub struct Validator;

impl Validator {
    pub fn validate_email(email: &str) -> Result<()> {
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .map_err(|e| AppError::InternalError(format!("Regex error: {}", e)))?;
        
        if !email_regex.is_match(email) {
            return Err(AppError::ValidationError("Invalid email format".to_string()));
        }
        
        if email.len() > 254 {
            return Err(AppError::ValidationError("Email too long".to_string()));
        }
        
        Ok(())
    }

    pub fn validate_username(username: &str) -> Result<()> {
        if username.len() < 3 {
            return Err(AppError::ValidationError("Username must be at least 3 characters long".to_string()));
        }
        
        if username.len() > 30 {
            return Err(AppError::ValidationError("Username must be less than 30 characters".to_string()));
        }
        
        let username_regex = Regex::new(r"^[a-zA-Z0-9_-]+$")
            .map_err(|e| AppError::InternalError(format!("Regex error: {}", e)))?;
        
        if !username_regex.is_match(username) {
            return Err(AppError::ValidationError("Username can only contain letters, numbers, underscores, and hyphens".to_string()));
        }
        
        Ok(())
    }

    pub fn validate_password(password: &str) -> Result<()> {
        if password.len() < 8 {
            return Err(AppError::ValidationError("Password must be at least 8 characters long".to_string()));
        }
        
        if password.len() > 128 {
            return Err(AppError::ValidationError("Password must be less than 128 characters".to_string()));
        }
        
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));
        
        if !has_uppercase {
            return Err(AppError::ValidationError("Password must contain at least one uppercase letter".to_string()));
        }
        
        if !has_lowercase {
            return Err(AppError::ValidationError("Password must contain at least one lowercase letter".to_string()));
        }
        
        if !has_digit {
            return Err(AppError::ValidationError("Password must contain at least one digit".to_string()));
        }
        
        if !has_special {
            return Err(AppError::ValidationError("Password must contain at least one special character".to_string()));
        }
        
        Ok(())
    }

    /// Validates a wallet name. (Unused, kept for future UI validation)
    #[allow(dead_code)]
    pub fn validate_wallet_name(name: &str) -> Result<()> {
        let name = name.trim();
        if name.len() < 3 {
            return Err(AppError::ValidationError("Wallet name must be at least 3 characters long".to_string()));
        }
        if name.len() > 30 {
            return Err(AppError::ValidationError("Wallet name must be less than 30 characters".to_string()));
        }
        let name_regex = Regex::new(r"^[a-zA-Z0-9 _-]+$")
            .map_err(|e| AppError::InternalError(format!("Regex error: {}", e)))?;
        if !name_regex.is_match(name) {
            return Err(AppError::ValidationError("Wallet name can only contain letters, numbers, spaces, underscores, and hyphens".to_string()));
        }
        Ok(())
    }

    /// Validates a phone number. (Unused, kept for future UI validation)
    #[allow(dead_code)]
    pub fn validate_phone(phone: &str) -> Result<()> {
        let phone = phone.trim();
        // E.164: +[country][number], or fallback to 8-15 digits
        let phone_regex = Regex::new(r"^(\+\d{8,15}|\d{8,15})$")
            .map_err(|e| AppError::InternalError(format!("Regex error: {}", e)))?;
        if !phone_regex.is_match(phone) {
            return Err(AppError::ValidationError("Invalid phone number format. Use +countrycode and 8-15 digits.".to_string()));
        }
        Ok(())
    }

    /// Validates a memo. (Unused, kept for future UI validation)
    #[allow(dead_code)]
    pub fn validate_memo(memo: &str) -> Result<()> {
        if memo.len() > 28 {
            return Err(AppError::ValidationError("Memo must be 28 characters or less (Stellar limit)".to_string()));
        }
        Ok(())
    }
}
