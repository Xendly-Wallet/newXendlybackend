mod cli;
mod database;
mod errors;
mod handlers;
mod models;
mod services;
mod utils;

use cli::CLI;
use handlers::{
    account_handler::AccountHandler,
    jwt_handler::JwtHandler,
    wallet_handler::WalletHandler,
    exchange_handler::ExchangeHandler,
    transfer_handler::TransferHandler,
};
use colored::Colorize;

use newbackend::api;
use std::sync::Arc;
use crate::database::sqlite::SqliteDatabase;
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().json().flatten_event(true))
        .init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    dotenv::dotenv().ok();
    // Start both CLI and HTTP server (for now)
    let http = tokio::spawn(async move {
        api::start_http_server().await;
    });
    let cli = tokio::spawn(async move {
        if let Err(e) = run().await {
            eprintln!("{}", format!("Application error: {}", e).red());
            std::process::exit(1);
        }
    });
    let _ = tokio::try_join!(http, cli);
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    // If no arguments provided, show interactive menu
    if args.len() == 1 {
        return run_interactive().await;
    }

    // Handle command-line arguments
    match args[1].as_str() {
        "transfer" => {
            let transfer_args = &args[2..];
            cli::handle_transfer_command(transfer_args).await?;
        }
        "notifications" => {
            let notif_args = &args[2..];
            cli::handle_notifications_command(notif_args).await?;
        }
        "help" => {
            CLI::print_help();
            CLI::print_notifications_help();
        }
        _ => {
            println!("{}", "Unknown command. Use 'help' to see available commands.".red());
        }
    }

    Ok(())
}

async fn run_interactive() -> Result<(), Box<dyn std::error::Error>> {
    CLI::print_header();
    
    let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
    loop {
        println!("\n{}", "🌟 Stellar Wallet Manager".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        println!("1. 👤 Create Account");
        println!("2. 🔐 Login (JWT)");
        println!("3. ✅ Validate JWT Token");
        println!("4. 🔄 Refresh JWT Token");
        println!("5. 💱 Currency Exchange");
        println!("6. 👛 Wallet Management");
        println!("7. 🚪 Logout");
        println!("8. 🚫 Logout All Devices");
        println!("9. 📱 Show Active Sessions");
        println!("10. 📋 View Notifications");
        println!("11. 👤 Profile Management");
        println!("12. 🔔 Notifications Menu");
        println!("{}", "─".repeat(40).blue());
        println!("0. 🚪 Exit");
        
        let choice = CLI::get_input("Select an option:")?;
        
        match choice.trim() {
            "1" => {
                let handler = AccountHandler::new(database.clone()).await?;
                if let Err(e) = handler.create_account_interactive().await {
                    CLI::print_error(&format!("Account creation failed: {}", e));
                }
            }
            "2" => {
                let handler = JwtHandler::new().await?;
                if let Err(e) = handler.login_interactive().await {
                    CLI::print_error(&format!("Login failed: {}", e));
                }
            }
            "3" => {
                let handler = JwtHandler::new().await?;
                if let Err(e) = handler.validate_token_interactive().await {
                    CLI::print_error(&format!("Token validation failed: {}", e));
                }
            }
            "4" => {
                let handler = JwtHandler::new().await?;
                if let Err(e) = handler.refresh_token_interactive().await {
                    CLI::print_error(&format!("Token refresh failed: {}", e));
                }
            }
            "5" => {
                let exchange_handler = ExchangeHandler::new().await?;
                exchange_handler.show_exchange_menu().await?;
            }
            "6" => {
                let wallet_handler = WalletHandler::new().await?;
                wallet_handler.show_wallet_menu().await?;
            }
            "7" => {
                let handler = JwtHandler::new().await?;
                if let Err(e) = handler.logout_interactive().await {
                    CLI::print_error(&format!("Logout failed: {}", e));
                }
            }
            "8" => {
                let handler = JwtHandler::new().await?;
                if let Err(e) = handler.logout_all_devices_interactive().await {
                    CLI::print_error(&format!("Logout all devices failed: {}", e));
                }
            }
            "9" => {
                let handler = JwtHandler::new().await?;
                if let Err(e) = handler.show_sessions_interactive().await {
                    CLI::print_error(&format!("Show sessions failed: {}", e));
                }
            }
            "10" => {
                // View Notifications
                use crate::services::notification_service::NotificationService;
                use crate::services::auth::AuthService;
                use std::sync::Arc;
                use crate::database::sqlite::SqliteDatabase;
                let token = CLI::get_input("🔑 Enter your JWT token:")?;
                let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
                let auth_service = AuthService::new(database.clone());
                let notification_service = NotificationService::new(database.clone());
                match auth_service.validate_token(&token).await {
                    Ok(user) => {
                        let notifications = notification_service.get_user_notifications(&user.user_id, Some(20)).await;
                        match notifications {
                            Ok(nots) => {
                                if nots.is_empty() {
                                    println!("{}", "No notifications found.".yellow());
                                } else {
                                    println!("\n{}", "🔔 Your Notifications:".cyan().bold());
                                    for (i, n) in nots.iter().enumerate() {
                                        println!("{}. {}", i + 1, n.title.green().bold());
                                        println!("   {}", n.message);
                                        println!("   Date: {}", n.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                                        println!("   Status: {}", if n.is_read { "Read" } else { "Unread" });
                                        println!("");
                                        // Mark as read if not already
                                        if !n.is_read {
                                            let _ = notification_service.mark_notification_read(&n.id).await;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                CLI::print_error(&format!("Failed to fetch notifications: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        CLI::print_error(&format!("Invalid token: {}", e));
                    }
                }
            }
            "11" => {
                use crate::handlers::profile_handler::ProfileHandler;
                use crate::services::auth::AuthService;
                use crate::services::user_service::UserService;
                use std::sync::Arc;
                use crate::database::sqlite::SqliteDatabase;
                let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
                let auth_service = AuthService::new(database.clone());
                let user_service = UserService::new(database.clone()).await?;
                let profile_handler = ProfileHandler::new(auth_service, user_service, database.clone()).await;
                profile_handler.show_profile_menu().await?;
            }
            "12" => {
                loop {
                    println!("\n{}", "Notifications Menu".cyan().bold());
                    println!("1. View Notifications");
                    println!("2. Mark All as Read");
                    println!("3. Delete Notification by ID");
                    println!("4. Delete All Notifications");
                    println!("5. Preferences");
                    println!("0. Back");
                    let notif_choice = CLI::get_input("Select an option:")?;
                    match notif_choice.trim() {
                        "1" => {
                            // View notifications (reuse option 10 logic)
                            use crate::services::notification_service::NotificationService;
                            use crate::services::auth::AuthService;
                            use std::sync::Arc;
                            use crate::database::sqlite::SqliteDatabase;
                            let token = CLI::get_input("🔑 Enter your JWT token:")?;
                            let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
                            let auth_service = AuthService::new(database.clone());
                            let notification_service = NotificationService::new(database.clone());
                            match auth_service.validate_token(&token).await {
                                Ok(user) => {
                                    let notifications = notification_service.get_user_notifications(&user.user_id, Some(20)).await;
                                    match notifications {
                                        Ok(nots) => {
                                            if nots.is_empty() {
                                                println!("{}", "No notifications found.".yellow());
                                            } else {
                                                println!("\n{}", "🔔 Your Notifications:".cyan().bold());
                                                for (i, n) in nots.iter().enumerate() {
                                                    println!("{}. {}", i + 1, n.title.green().bold());
                                                    println!("   {}", n.message);
                                                    println!("   Date: {}", n.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                                                    println!("   Status: {}", if n.is_read { "Read" } else { "Unread" });
                                                    println!("");
                                                    if !n.is_read {
                                                        let _ = notification_service.mark_notification_read(&n.id).await;
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            CLI::print_error(&format!("Failed to fetch notifications: {}", e));
                                        }
                                    }
                                }
                                Err(e) => {
                                    CLI::print_error(&format!("Invalid token: {}", e));
                                }
                            }
                        }
                        "2" => {
                            cli::handle_notifications_command(&["mark-all-read".to_string()]).await?;
                        }
                        "3" => {
                            let id = CLI::get_input("Enter notification ID to delete:")?;
                            cli::handle_notifications_command(&["delete".to_string(), id]).await?;
                        }
                        "4" => {
                            cli::handle_notifications_command(&["delete-all".to_string()]).await?;
                        }
                        "5" => {
                            cli::handle_notifications_command(&["prefs".to_string()]).await?;
                        }
                        "0" => break,
                        _ => CLI::print_error("Invalid option. Please try again."),
                    }
                }
            }
            "0" => {
                println!("{}", "👋 Goodbye!".green().bold());
                break;
            }
            _ => {
                CLI::print_error("Invalid option. Please try again.");
            }
        }
    }
    
    Ok(())
}

pub fn display_main_menu() {
    clear_screen();
    println!("{}", "=".repeat(60).bright_blue());
    println!("{}", "           🌟 STELLAR WALLET BACKEND 🌟           ".bright_yellow().bold());
    println!("{}", "=".repeat(60).bright_blue());
    println!();
    println!("{}", "Main Menu:".cyan().bold());
    println!("  1. 📝 Create New Account");
    println!("  2. 🔐 Login to Account");
    println!("  3. 🎯 JWT Login (Generate Token)");
    println!("  4. ✅ Validate JWT Token");
    println!("  5. 🔄 Refresh JWT Token");
    println!("  6. 👛 Wallet Management");
    println!("  7. 💱 Currency Exchange");
    println!("  8. 🚪 JWT Logout");
    println!("  9. 🚫 Logout All Devices");
    println!(" 10. 📱 Show Active Sessions");
    println!(" 11. 📋 View Notifications");
    println!(" 12. 🚪 Exit");
    println!();
}

pub fn wait_for_enter() {
    let _ = CLI::get_input("Press Enter to continue...");
}

pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}
