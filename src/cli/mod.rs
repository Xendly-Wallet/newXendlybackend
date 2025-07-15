mod commands;
pub use commands::*;

use crate::errors::{AppError, Result};
use colored::Colorize;
use std::io::{self, Write};

pub struct CLI;

impl CLI {
    pub fn print_header() {
        println!("{}", "=".repeat(50).bright_blue());
        println!("{}", "    🌟 Stellar Wallet - Command Line Interface    ".bright_yellow().bold());
        println!("{}", "=".repeat(50).bright_blue());
        println!();
    }

    pub fn print_success(message: &str) {
        println!("{} {}", "✅".green(), message.green());
    }

    pub fn print_error(message: &str) {
        println!("{} {}", "❌".red(), message.red());
    }

    pub fn print_info(message: &str) {
        println!("{} {}", "ℹ️".blue(), message.blue());
    }

    pub fn get_input(prompt: &str) -> Result<String> {
        print!("{} ", prompt.cyan());
        io::stdout().flush().map_err(|e| AppError::InternalError(format!("IO error: {}", e)))?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)
            .map_err(|e| AppError::InternalError(format!("Failed to read input: {}", e)))?;
        
        Ok(input.trim().to_string())
    }

    pub fn get_password(prompt: &str) -> Result<String> {
        print!("{} ", prompt.cyan());
        io::stdout().flush().map_err(|e| AppError::InternalError(format!("IO error: {}", e)))?;
        
        rpassword::read_password()
            .map_err(|e| AppError::InternalError(format!("Failed to read password: {}", e)))
    }

    pub fn confirm_action(prompt: &str) -> Result<bool> {
        loop {
            let input = Self::get_input(&format!("{} (y/n):", prompt))?;
            match input.to_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => Self::print_error("Please enter 'y' for yes or 'n' for no"),
            }
        }
    }

    pub fn display_password_requirements() {
        println!("{}", "Password Requirements:".yellow().bold());
        println!("  • At least 8 characters long");
        println!("  • Contains uppercase letter (A-Z)");
        println!("  • Contains lowercase letter (a-z)");
        println!("  • Contains at least one digit (0-9)");
        println!("  • Contains special character (!@#$%^&*()_+-=[]{{}}|;:,.<>?)");
        println!();
    }

    pub fn print_help() {
        println!("\n{}", "Available Commands:".cyan().bold());
        println!("  transfer send <source_wallet> <recipient_address> <amount> [memo]");
        println!("    Send XLM to another Stellar address");
        println!();
        println!("  transfer history <wallet_address>");
        println!("    View transaction history for a wallet");
        println!();
        println!("  help");
        println!("    Show this help message");
        println!();
    }

    pub fn print_notifications_help() {
        println!("\n{}", "Notifications Commands:".cyan().bold());
        println!("  notifications mark-all-read");
        println!("    Mark all notifications as read");
        println!("  notifications delete <notification_id>");
        println!("    Delete a notification by ID");
        println!("  notifications delete-all");
        println!("    Delete all notifications");
        println!("  notifications prefs");
        println!("    View or set notification preferences");
        println!();
    }
}
