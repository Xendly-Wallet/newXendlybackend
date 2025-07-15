use crate::cli::CLI;
use crate::errors::Result;
use crate::services::user_service::UserService;
use crate::utils::validation::Validator;
use colored::Colorize;
use std::sync::Arc;
use crate::database::sqlite::SqliteDatabase;

pub struct AccountHandler {
    user_service: UserService,
}

impl AccountHandler {
    pub async fn new(db: Arc<SqliteDatabase>) -> Result<Self> {
        let user_service = UserService::new(db.clone()).await?;
        Ok(Self { user_service })
    }
//displays the account summary and confirms the creation of the account
    pub async fn create_account_interactive(&self) -> Result<()> {
        CLI::print_header();
        CLI::print_info("Let's create your Stellar Wallet account!");
        println!();

        // Get email
        let email = loop {
            let email = CLI::get_input("📧 Enter your email address:")?;
            
            if email.is_empty() {
                CLI::print_error("Email cannot be empty");
                continue;
            }
//validates the email address
            match Validator::validate_email(&email) {
                Ok(()) => break email,
                Err(e) => {
                    CLI::print_error(&e.to_string());
                    continue;
                }
            }
        };

        // Get username
        let username = loop {
            let username = CLI::get_input("👤 Choose a username:")?;
            
            if username.is_empty() {
                CLI::print_error("Username cannot be empty");
                continue;
            }

            match Validator::validate_username(&username) {
                Ok(()) => break username,
                Err(e) => {
                    CLI::print_error(&e.to_string());
                    continue;
                }
            }
        };

        // Get phone number
        let countries = [
            ("Kenya", "+254", 9),
            ("Uganda", "+256", 9),
            ("Tanzania", "+255", 9),
            ("Rwanda", "+250", 9),
            ("South Africa", "+27", 9),
            ("Nigeria", "+234", 10),
        ];
        println!("Supported countries for phone number:");
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

        // Get password with confirmation
        println!();
        CLI::display_password_requirements();
        
        let password = loop {
            let password = CLI::get_password("🔒 Enter your password:")?;
            
            if password.is_empty() {
                CLI::print_error("Password cannot be empty");
                continue;
            }

            // Validate password strength
            match Validator::validate_password(&password) {
                Ok(()) => {
                    // Confirm password
                    let confirm_password = CLI::get_password("🔒 Confirm your password:")?;
                    
                    if password != confirm_password {
                        CLI::print_error("Passwords do not match. Please try again.");
                        continue;
                    }
                    
                    break password;
                }
                Err(e) => {
                    CLI::print_error(&e.to_string());
                    continue;
                }
            }
        };

        // Display summary and confirm
        println!();
        println!("{}", "Account Summary:".yellow().bold());
        println!("📧 Email: {}", email);
        println!("👤 Username: {}", username);
        println!("📞 Phone: {}", full_number);
        println!("🔒 Password: {}", "*".repeat(password.len()));
        println!();

        if !CLI::confirm_action("Do you want to create this account?")? {
            CLI::print_info("Account creation cancelled.");
            return Ok(());
        }

        // Create the account
        match self.user_service.create_user(&email, &username, &password, Some(full_number)).await {
            Ok(user_id) => {
                println!();
                CLI::print_success("🎉 Account created successfully!");
                println!();
                println!("{}", "Account Details:".green().bold());
                println!("🆔 User ID: {}", user_id);
                println!("📧 Email: {}", email);
                println!("👤 Username: {}", username);
                println!("📅 Created: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                println!("✉️  Verification Status: Pending");
                println!();
                CLI::print_info("Your account has been saved to the database!");
            }
            Err(e) => {
                CLI::print_error(&format!("Failed to create account: {}", e));
                return Err(e);
            }
        }

        Ok(())
    }
    #[allow(dead_code)]
    pub async fn login_interactive(&self) -> Result<()> {
        CLI::print_header();
        CLI::print_info("Welcome back! Please log in to your account.");
        println!();

        // Get email or username
        let identifier = loop {
            let input = CLI::get_input("📧 Enter your email or username:")?;
            
            if input.is_empty() {
                CLI::print_error("Email/username cannot be empty");
                continue;
            }
            
            break input;
        };

        // Get password
        let password = CLI::get_password("🔒 Enter your password:")?;

        if password.is_empty() {
            CLI::print_error("Password cannot be empty");
            return Ok(());
        }

        // Attempt login
        match self.user_service.authenticate_user(&identifier, &password).await {
            Ok(user) => {
                println!();
                CLI::print_success("🎉 Login successful!");
                println!();
                println!("{}", "Welcome back!".green().bold());
                println!("👤 Username: {}", user.username);
                println!("📧 Email: {}", user.email);
                println!("📅 Last login: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
                println!();
                
                CLI::print_info("Login feature completed! Dashboard coming soon...");
            }
            Err(e) => {
                CLI::print_error(&format!("Login failed: {}", e));
                return Err(e);
            }
        }

        Ok(())
    }
    #[allow(dead_code)]
    pub async fn show_stats(&self) -> Result<()> {
        let user_count = self.user_service.get_user_count().await?;
        
        println!();
        println!("{}", "📊 Database Statistics:".cyan().bold());
        println!("👥 Total Users: {}", user_count);
        println!();
        
        Ok(())
    }
}
