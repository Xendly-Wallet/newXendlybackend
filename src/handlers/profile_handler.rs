use crate::services::auth::AuthService;
use crate::services::user_service::UserService;
use crate::services::two_factor_service::TwoFactorService;
use crate::cli::CLI;
use crate::errors::Result;
use colored::Colorize;
use std::sync::Arc;
use crate::database::sqlite::SqliteDatabase;

pub struct ProfileHandler {
    auth_service: AuthService,
    user_service: UserService,
    two_factor_service: TwoFactorService,
}

impl ProfileHandler {
    pub async fn new(auth_service: AuthService, user_service: UserService, database: Arc<SqliteDatabase>) -> Self {
        let two_factor_service = TwoFactorService::new(database);
        Self { auth_service, user_service, two_factor_service }
    }

    pub async fn show_profile_menu(&self) -> Result<()> {
        println!("\n{}", "👤 Profile Management".cyan().bold());
        println!("{}", "=".repeat(40).blue());

        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = match self.auth_service.validate_token(&token).await {
            Ok(user) => user,
            Err(e) => {
                CLI::print_error(&format!("Invalid token: {}", e));
                return Ok(());
            }
        };

        let profile = self.user_service.get_user_by_id(&user.user_id).await?;
        self.display_profile(&profile).await;

        loop {
            println!("\n{}", "Profile Options:".yellow().bold());
            println!("1. ✏️  Update Profile");
            println!("2. 🔒 Change Password");
            println!("3. 📱 Add/Update Phone Number");
            println!("4. 🛡️  2FA Settings");
            println!("5. ❌ Delete Account");
            println!("0. 🔙 Back to Main Menu");
            let choice = CLI::get_input("Select an option:")?;
            match choice.trim() {
                "1" => self.update_user_profile(&user.user_id).await?,
                "2" => self.change_user_password(&user.user_id).await?,
                "3" => self.add_update_phone_number(&user.user_id).await?,
                "4" => self.setup_2fa(&user.user_id).await?,
                "5" => {
                    self.delete_account(&user.user_id).await?;
                    break;
                },
                "0" => break,
                _ => CLI::print_error("Invalid option. Please try again."),
            }
        }
        Ok(())
    }

    async fn display_profile(&self, profile: &crate::models::user::UserResponse) {
        println!("\n{}", "📄 Profile Information".cyan().bold());
        println!("Username: {}", profile.username.green().bold());
        println!("Email: {}", profile.email.yellow());
        println!("Verified: {}", if profile.is_verified { "✅".green() } else { "❌".red() });
        if let Some(pubkey) = &profile.stellar_public_key {
            println!("Stellar Public Key: {}", pubkey.blue());
        }
        match &profile.phone_number {
            Some(num) if !num.is_empty() => println!("Phone Number: {}", num.cyan()),
            _ => println!("Phone Number: {}", "None on record".yellow()),
        }
        println!("Created At: {}", profile.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed());
        println!("{}", "=".repeat(40).blue());
    }

    async fn update_user_profile(&self, user_id: &uuid::Uuid) -> Result<()> {
        println!("\n{}", "✏️  Update Profile".cyan().bold());
        println!("{}", "-".repeat(40).blue());
        let mut user = self.user_service.get_user_model_by_id(user_id).await?;
        let new_email = CLI::get_input(&format!("New email [{}]:", user.email))?;
        let new_username = CLI::get_input(&format!("New username [{}]:", user.username))?;
        if !new_email.trim().is_empty() {
            user.email = new_email.trim().to_string();
        }
        if !new_username.trim().is_empty() {
            user.username = new_username.trim().to_string();
        }
        match self.user_service.update_user_profile(&user).await {
            Ok(_) => println!("{}", "✅ Profile updated successfully!".green()),
            Err(e) => CLI::print_error(&format!("Failed to update profile: {}", e)),
        }
        Ok(())
    }

    async fn change_user_password(&self, user_id: &uuid::Uuid) -> Result<()> {
        println!("\n{}", "🔒 Change Password".cyan().bold());
        println!("{}", "-".repeat(40).blue());
        let current_password = CLI::get_input("Current password:")?;
        let new_password = CLI::get_input("New password:")?;
        let confirm_password = CLI::get_input("Confirm new password:")?;
        if new_password != confirm_password {
            CLI::print_error("New passwords do not match.");
            return Ok(());
        }
        // Check if 2FA is enabled for the user
        let user_record = self.user_service.db.get_user_by_id(user_id).await?;
        let mut totp_code: Option<String> = None;
        if user_record.totp_enabled {
            let code = CLI::get_input("Enter your 2FA code from your authenticator app:")?;
            totp_code = Some(code);
        }
        // Call API/service with TOTP code
        match self.user_service.change_user_password_with_2fa(user_id, &current_password, &new_password, totp_code).await {
            Ok(_) => println!("{}", "✅ Password changed successfully!".green()),
            Err(e) => CLI::print_error(&format!("Failed to change password: {}", e)),
        }
        Ok(())
    }

    async fn add_update_phone_number(&self, user_id: &uuid::Uuid) -> Result<()> {
        println!("\n{}", "📱 Add/Update Phone Number".cyan().bold());
        println!("{}", "-".repeat(40).blue());
        let countries = [
            ("Kenya", "+254", 9),
            ("Uganda", "+256", 9),
            ("Tanzania", "+255", 9),
            ("Rwanda", "+250", 9),
            ("South Africa", "+27", 9),
            ("Nigeria", "+234", 10),
        ];
        println!("Supported countries:");
        for (i, (name, code, _)) in countries.iter().enumerate() {
            println!("{}. {} ({})", i + 1, name, code);
        }
        let country_choice = CLI::get_input("Select your country:")?;
        let idx = match country_choice.trim().parse::<usize>() {
            Ok(i) if i > 0 && i <= countries.len() => i - 1,
            _ => {
                CLI::print_error("Invalid country selection.");
                return Ok(());
            }
        };
        let (country, code, number_len) = countries[idx];
        println!("Selected: {} ({})", country, code);
        let phone = CLI::get_input(&format!("Enter phone number (without country code, {} digits):", number_len))?;
        if phone.trim().len() != number_len || !phone.chars().all(|c| c.is_ascii_digit()) {
            CLI::print_error(&format!("Phone number must be {} digits.", number_len));
            return Ok(());
        }
        let full_number = format!("{}{}", code, phone.trim());
        match self.user_service.update_user_phone_number_with_verification(user_id, &full_number).await {
            Ok(_verification_code) => {
                println!("A verification code has been sent to your phone.");
                let entered = CLI::get_input("Enter the verification code:")?;
                match self.user_service.verify_user_phone_code(user_id, &entered).await {
                    Ok(true) => println!("{}", "✅ Phone number verified successfully!".green()),
                    Ok(false) => CLI::print_error("Verification code is incorrect."),
                    Err(e) => CLI::print_error(&format!("Failed to verify phone: {}", e)),
                }
            }
            Err(e) => CLI::print_error(&format!("Failed to update phone number: {}", e)),
        }
        Ok(())
    }

    async fn setup_2fa(&self, user_id: &uuid::Uuid) -> Result<()> {
        println!("\n{}", "🛡️  2FA Settings".cyan().bold());
        println!("{}", "-".repeat(40).blue());
        
        // Check if 2FA is already enabled
        let user_record = self.user_service.db.get_user_by_id(user_id).await?;
        if self.two_factor_service.is_2fa_enabled(user_id).await? || user_record.totp_enabled {
            println!("2FA is currently enabled.");
            let choice = CLI::get_input("Do you want to disable 2FA? (y/N):")?;
            if choice.trim().to_lowercase() == "y" {
                let confirm = CLI::get_input("Are you sure? This will remove 2FA protection. (y/N):")?;
                if confirm.trim().to_lowercase() == "y" {
                    let code = CLI::get_input("Enter your 2FA code from your authenticator app:")?;
                    match self.two_factor_service.verify_totp(user_id, &code).await {
                        Ok(true) => {
                            match self.two_factor_service.disable_2fa(user_id).await {
                                Ok(_) => println!("{}", "✅ 2FA disabled successfully!".green()),
                                Err(e) => CLI::print_error(&format!("Failed to disable 2FA: {}", e)),
                            }
                        }
                        _ => CLI::print_error("Invalid 2FA code. 2FA not disabled."),
                    }
                }
            }
            return Ok(());
        }

        // Setup new 2FA
        let user = self.user_service.get_user_by_id(user_id).await?;
        println!("Setting up Two-Factor Authentication...");
        
        match self.two_factor_service.setup_2fa(user_id, &user.email).await {
            Ok((secret, _backup_codes_json, backup_codes)) => {
                let qr_svg = self.two_factor_service.generate_qr_code_svg(&secret, &user.email, "Xendly")?;
                println!("Scan this QR code with your authenticator app:");
                println!("{}", qr_svg);
                println!("Backup codes (save these in a safe place):");
                for code in &backup_codes {
                    println!("- {}", code);
                }
                println!("2FA setup complete! Please enable 2FA in your app.");
            }
            Err(e) => CLI::print_error(&format!("Failed to setup 2FA: {}", e)),
        }
        Ok(())
    }

    async fn delete_account(&self, user_id: &uuid::Uuid) -> Result<()> {
        println!("\n{}", "❌ Delete Account".red().bold());
        println!("{}", "-".repeat(40).red());
        
        println!("{}", "⚠️  WARNING: This action is irreversible!".red().bold());
        println!("This will permanently delete your account and all associated data:");
        println!("• User profile and settings");
        println!("• All wallets and balances");
        println!("• Transaction history");
        println!("• Notifications and preferences");
        
        let confirm1 = CLI::get_input("Type 'DELETE' to confirm account deletion:")?;
        if confirm1.trim() != "DELETE" {
            println!("Account deletion cancelled.");
            return Ok(());
        }
        
        let confirm2 = CLI::get_input("Are you absolutely sure? Type 'YES' to proceed:")?;
        if confirm2.trim() != "YES" {
            println!("Account deletion cancelled.");
            return Ok(());
        }
        
        let password = CLI::get_input("Enter your password to confirm:")?;
        // Check if 2FA is enabled for the user
        let user_record = self.user_service.db.get_user_by_id(user_id).await?;
        let mut totp_code: Option<String> = None;
        if user_record.totp_enabled {
            let code = CLI::get_input("Enter your 2FA code from your authenticator app:")?;
            totp_code = Some(code);
        }
        // Call API/service with TOTP code
        match self.user_service.delete_account_with_2fa(user_id, &password, totp_code).await {
            Ok(_) => println!("{}", "✅ Account deleted successfully!".green()),
            Err(e) => CLI::print_error(&format!("Failed to delete account: {}", e)),
        }
        Ok(())
    }
} 