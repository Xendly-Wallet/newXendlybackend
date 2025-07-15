use crate::cli::CLI;
use crate::database::sqlite::SqliteDatabase;
use crate::errors::Result;
use crate::services::auth::AuthService;
use colored::Colorize;
use std::sync::Arc;

pub struct JwtHandler {
    auth_service: AuthService,
}

impl JwtHandler {
    pub async fn new() -> Result<Self> {
        let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
        let auth_service = AuthService::new(database);
        
        Ok(Self { auth_service })
    }

    pub async fn login_interactive(&self) -> Result<()> {
        println!("\n{}", "🔐 JWT Login".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        let email_or_username = CLI::get_input("📧 Enter your email or username:")?;
        let password = CLI::get_password("🔒 Enter your password:")?;

        // Call the 2FA-aware login logic
        match self.auth_service.login_with_2fa_check(&email_or_username, &password).await {
            Ok(crate::services::auth::Login2FAResult::Token(token)) => {
                println!("\n{}", "✅ Login successful!".green().bold());
                println!("{}", "🔑 Your JWT Token:".cyan().bold());
                println!("{}", "━".repeat(80).blue());
                println!("{}", token.yellow());
                println!("{}", "━".repeat(80).blue());
                println!("{}", "⚠️  Keep this token secure! It expires in 24 hours.".yellow());
            }
            Ok(crate::services::auth::Login2FAResult::TwoFARequired { user_id }) => {
                println!("\n{}", "🛡️  Two-Factor Authentication Required!".yellow().bold());
                let totp_code = CLI::get_input("Enter your 2FA code from your authenticator app:")?;
                // Call the /api/auth/2fa-verify logic
                let db = self.auth_service.database();
                let user = db.get_user_by_id(&user_id).await?;
                let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
                match two_factor_service.verify_totp(&user_id, &totp_code).await {
                    Ok(true) => {
                        let token = self.auth_service.login_and_generate_token(&user.email, &password).await?;
                        println!("\n{}", "✅ Login successful!".green().bold());
                        println!("{}", "🔑 Your JWT Token:".cyan().bold());
                        println!("{}", "━".repeat(80).blue());
                        println!("{}", token.yellow());
                        println!("{}", "━".repeat(80).blue());
                        println!("{}", "⚠️  Keep this token secure! It expires in 24 hours.".yellow());
                    }
                    _ => {
                        CLI::print_error("Invalid 2FA code. Login failed.");
                    }
                }
            }
            Err(e) => {
                CLI::print_error(&format!("Login failed: {}", e));
            }
        }

        Ok(())
    }
//validates the jwt token
    pub async fn validate_token_interactive(&self) -> Result<()> {
        println!("\n{}", "✅ JWT Token Validation".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        let token = CLI::get_input("🔑 Enter your JWT token:")?;

        match self.auth_service.validate_token(&token).await {
            Ok(user) => {
                println!("\n{}", "✅ Token is valid!".green().bold());
                println!("👤 User ID: {}", user.user_id.to_string().cyan());
                println!("📧 Username: {}", user.username.cyan());
                println!("📧 Email: {}", user.email.cyan());
                println!("🆔 Token ID: {}", user.token_id.cyan());
            }
            Err(e) => {
                CLI::print_error(&format!("Token validation failed: {}", e));
            }
        }

        Ok(())
    }
//refreshes the jwt token
    pub async fn refresh_token_interactive(&self) -> Result<()> {
        println!("\n{}", "🔄 JWT Token Refresh".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        let old_token = CLI::get_input("🔑 Enter your current JWT token:")?;

        match self.auth_service.refresh_token(&old_token).await {
            Ok(new_token) => {
                println!("\n{}", "✅ Token refreshed successfully!".green().bold());
                println!("{}", "🔑 Your new JWT Token:".cyan().bold());
                println!("{}", "━".repeat(80).blue());
                println!("{}", new_token.yellow());
                println!("{}", "━".repeat(80).blue());
            }
            Err(e) => {
                CLI::print_error(&format!("Token refresh failed: {}", e));
            }
        }

        Ok(())
    }

    pub async fn logout_interactive(&self) -> Result<()> {
        println!("\n{}", "🚪 JWT Logout".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        let token = CLI::get_input("🔑 Enter your JWT token to revoke:")?;

        match self.auth_service.logout(&token).await {
            Ok(_) => {
                println!("\n{}", "✅ Successfully logged out! Token has been revoked.".green().bold());
            }
            Err(e) => {
                CLI::print_error(&format!("Logout failed: {}", e));
            }
        }

        Ok(())
    }

    pub async fn logout_all_devices_interactive(&self) -> Result<()> {
        println!("\n{}", "🚫 Logout All Devices".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        let token = CLI::get_input("🔑 Enter your JWT token:")?;

        match self.auth_service.logout_all_devices(&token).await {
            Ok(_) => {
                println!("\n{}", "✅ Successfully logged out from all devices!".green().bold());
            }
            Err(e) => {
                CLI::print_error(&format!("Logout all devices failed: {}", e));
            }
        }

        Ok(())
    }

    pub async fn show_sessions_interactive(&self) -> Result<()> {
        println!("\n{}", "📱 Active Sessions".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        let token = CLI::get_input("🔑 Enter your JWT token:")?;

        match self.auth_service.get_user_sessions_count(&token).await {
            Ok(count) => {
                println!("\n{}", "📊 Session Information:".cyan().bold());
                println!("Active sessions: {}", count.to_string().green().bold());
            }
            Err(e) => {
                CLI::print_error(&format!("Failed to get session count: {}", e));
            }
        }

        Ok(())
    }
}