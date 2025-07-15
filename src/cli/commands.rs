#[allow(unused_imports)]
use crate::errors::Result;
use crate::handlers::transfer_handler::TransferHandler;
//use crate::handlers::wallet_handler::WalletHandler;
use crate::cli::CLI;
use colored::Colorize;
use crate::services::notification_service::NotificationService;
use crate::services::auth::AuthService;
use crate::database::sqlite::SqliteDatabase;
use std::sync::Arc;
use uuid::Uuid;
use crate::models::notification::NotificationPreferences;
use chrono::Utc;

pub async fn handle_transfer_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("{}", "Transfer command usage:".cyan().bold());
        println!("  transfer send <source_wallet> <recipient_address> <amount> [memo]");
        println!("  transfer history <wallet_address>");
        return Ok(());
    }

    match args[0].as_str() {
        "send" => {
            if args.len() < 4 {
                println!("{}", "Error: Missing required arguments".red().bold());
                println!("Usage: transfer send <source_wallet> <recipient_address> <amount> [memo]");
                return Ok(());
            }

            let source_wallet = &args[1];
            let recipient_address = &args[2];
            let amount = args[3].parse::<f64>()
                .map_err(|_| crate::errors::AppError::ValidationError("Invalid amount".to_string()))?;
            let memo = args.get(4).cloned();

            let transfer_handler = TransferHandler::new().await?;
            
            // Get JWT token
            let _token = CLI::get_input("Enter your JWT token:")?;
            
            // Get wallet password
            let password = CLI::get_password("Enter wallet password:")?;

            println!("\n{}", "📝 Transfer Summary".cyan().bold());
            println!("From: {}", source_wallet.yellow());
            println!("To: {}", recipient_address.yellow());
            println!("Amount: {} XLM", amount.to_string().green());
            if let Some(memo_text) = &memo {
                println!("Memo: {}", memo_text.cyan());
            }

            if CLI::confirm_action("Confirm transfer?")? {
                match transfer_handler.stellar_service.send_payment(
                    source_wallet,
                    recipient_address,
                    amount,
                    memo,
                    &password
                ).await {
                    Ok(transaction_hash) => {
                        println!("\n{}", "✅ Transfer successful!".green().bold());
                        println!("Transaction Hash: {}", transaction_hash.yellow());
                    }
                    Err(e) => {
                        println!("{}", format!("❌ Transfer failed: {}", e).red().bold());
                    }
                }
            } else {
                println!("{}", "Transfer cancelled.".yellow());
            }
        }
        "history" => {
            if args.len() < 2 {
                println!("{}", "Error: Missing wallet address".red().bold());
                println!("Usage: transfer history <wallet_address>");
                return Ok(());
            }

            let wallet_address = &args[1];
            let transfer_handler = TransferHandler::new().await?;

            match transfer_handler.stellar_service.get_transaction_history(wallet_address).await {
                Ok(transactions) => {
                    if transactions.is_empty() {
                        println!("{}", "No transactions found for this wallet.".yellow());
                        return Ok(());
                    }

                    println!("\n{}", format!("Found {} transactions:", transactions.len()).green().bold());
                    println!();

                    for (index, tx) in transactions.iter().enumerate() {
                        println!("{}. Transaction Hash: {}", index + 1, tx.hash.yellow());
                        println!("   Type: {}", tx.transaction_type.cyan());
                        println!("   Amount: {} XLM", tx.amount.green());
                        println!("   From: {}", tx.from.yellow());
                        println!("   To: {}", tx.to.yellow());
                        if let Some(memo) = &tx.memo {
                            println!("   Memo: {}", memo.cyan());
                        }
                        println!("   Date: {}", tx.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().blue());
                        println!();
                    }
                }
                Err(e) => {
                    println!("{}", format!("Failed to fetch transaction history: {}", e).red().bold());
                }
            }
        }
        _ => {
            println!("{}", "Error: Unknown transfer command".red().bold());
            println!("Available commands: send, history");
        }
    }

    Ok(())
} 

pub async fn handle_notifications_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("{}", "Notifications command usage:".cyan().bold());
        println!("  notifications mark-all-read");
        println!("  notifications delete <notification_id>");
        println!("  notifications delete-all");
        println!("  notifications prefs");
        return Ok(());
    }

    let token = CLI::get_input("Enter your JWT token:")?;
    let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
    let auth_service = AuthService::new(database.clone());
    let notification_service = NotificationService::new(database.clone());
    let user = match auth_service.validate_token(&token).await {
        Ok(u) => u,
        Err(e) => {
            CLI::print_error(&format!("Invalid token: {}", e));
            return Ok(());
        }
    };

    match args[0].as_str() {
        "mark-all-read" => {
            if CLI::confirm_action("Mark all notifications as read?")? {
                match notification_service.mark_all_notifications_read(&user.user_id).await {
                    Ok(_) => CLI::print_success("All notifications marked as read."),
                    Err(e) => CLI::print_error(&format!("Failed to mark all as read: {}", e)),
                }
            }
        }
        "delete" => {
            if args.len() < 2 {
                CLI::print_error("Usage: notifications delete <notification_id>");
                return Ok(());
            }
            let id = match Uuid::parse_str(&args[1]) {
                Ok(uuid) => uuid,
                Err(_) => {
                    CLI::print_error("Invalid notification ID format");
                    return Ok(());
                }
            };
            if CLI::confirm_action(&format!("Delete notification {}?", id))? {
                match notification_service.delete_notification(&id).await {
                    Ok(_) => CLI::print_success("Notification deleted."),
                    Err(e) => CLI::print_error(&format!("Failed to delete notification: {}", e)),
                }
            }
        }
        "delete-all" => {
            if CLI::confirm_action("Delete ALL notifications? This cannot be undone.")? {
                match notification_service.delete_all_notifications(&user.user_id).await {
                    Ok(_) => CLI::print_success("All notifications deleted."),
                    Err(e) => CLI::print_error(&format!("Failed to delete all notifications: {}", e)),
                }
            }
        }
        "prefs" => {
            // View and set notification preferences interactively
            let prefs = notification_service.get_notification_preferences(&user.user_id).await?;
            let mut prefs = if let Some(p) = prefs {
                p
            } else {
                NotificationPreferences {
                    user_id: user.user_id,
                    email_enabled: true,
                    sms_enabled: false,
                    push_enabled: false,
                    in_app_enabled: true,
                    incoming_payment_alerts: true,
                    outgoing_payment_alerts: true,
                    payment_failure_alerts: true,
                    balance_change_alerts: true,
                    low_balance_threshold: None,
                    security_alerts: true,
                    exchange_alerts: true,
                    system_alerts: true,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }
            };
            println!("\n{}", "Current Notification Preferences:".cyan().bold());
            println!("  1. Email Enabled: {}", prefs.email_enabled);
            println!("  2. SMS Enabled: {}", prefs.sms_enabled);
            println!("  3. Push Enabled: {}", prefs.push_enabled);
            println!("  4. In-App Enabled: {}", prefs.in_app_enabled);
            println!("  5. Incoming Payment Alerts: {}", prefs.incoming_payment_alerts);
            println!("  6. Outgoing Payment Alerts: {}", prefs.outgoing_payment_alerts);
            println!("  7. Payment Failure Alerts: {}", prefs.payment_failure_alerts);
            println!("  8. Balance Change Alerts: {}", prefs.balance_change_alerts);
            println!("  9. Low Balance Threshold: {:?}", prefs.low_balance_threshold);
            println!(" 10. Security Alerts: {}", prefs.security_alerts);
            println!(" 11. Exchange Alerts: {}", prefs.exchange_alerts);
            println!(" 12. System Alerts: {}", prefs.system_alerts);
            println!("\nType the number to toggle/set, or press Enter to save and exit.");
            loop {
                let input = CLI::get_input("Change which setting? (or Enter to finish):")?;
                if input.trim().is_empty() { break; }
                match input.trim() {
                    "1" => { prefs.email_enabled = !prefs.email_enabled; println!("Email Enabled: {}", prefs.email_enabled); },
                    "2" => { prefs.sms_enabled = !prefs.sms_enabled; println!("SMS Enabled: {}", prefs.sms_enabled); },
                    "3" => { prefs.push_enabled = !prefs.push_enabled; println!("Push Enabled: {}", prefs.push_enabled); },
                    "4" => { prefs.in_app_enabled = !prefs.in_app_enabled; println!("In-App Enabled: {}", prefs.in_app_enabled); },
                    "5" => { prefs.incoming_payment_alerts = !prefs.incoming_payment_alerts; println!("Incoming Payment Alerts: {}", prefs.incoming_payment_alerts); },
                    "6" => { prefs.outgoing_payment_alerts = !prefs.outgoing_payment_alerts; println!("Outgoing Payment Alerts: {}", prefs.outgoing_payment_alerts); },
                    "7" => { prefs.payment_failure_alerts = !prefs.payment_failure_alerts; println!("Payment Failure Alerts: {}", prefs.payment_failure_alerts); },
                    "8" => { prefs.balance_change_alerts = !prefs.balance_change_alerts; println!("Balance Change Alerts: {}", prefs.balance_change_alerts); },
                    "9" => {
                        let val = CLI::get_input("Set low balance threshold (empty to clear):")?;
                        if val.trim().is_empty() {
                            prefs.low_balance_threshold = None;
                        } else if let Ok(v) = val.trim().parse::<f64>() {
                            prefs.low_balance_threshold = Some(v);
                        } else {
                            CLI::print_error("Invalid number");
                        }
                        println!("Low Balance Threshold: {:?}", prefs.low_balance_threshold);
                    },
                    "10" => { prefs.security_alerts = !prefs.security_alerts; println!("Security Alerts: {}", prefs.security_alerts); },
                    "11" => { prefs.exchange_alerts = !prefs.exchange_alerts; println!("Exchange Alerts: {}", prefs.exchange_alerts); },
                    "12" => { prefs.system_alerts = !prefs.system_alerts; println!("System Alerts: {}", prefs.system_alerts); },
                    _ => CLI::print_error("Unknown setting number"),
                }
            }
            prefs.updated_at = Utc::now();
            if notification_service.get_notification_preferences(&user.user_id).await?.is_some() {
                match notification_service.update_notification_preferences(&prefs).await {
                    Ok(_) => CLI::print_success("Preferences updated."),
                    Err(e) => CLI::print_error(&format!("Failed to update preferences: {}", e)),
                }
            } else {
                match notification_service.set_notification_preferences(&prefs).await {
                    Ok(_) => CLI::print_success("Preferences set."),
                    Err(e) => CLI::print_error(&format!("Failed to set preferences: {}", e)),
                }
            }
        }
        _ => {
            CLI::print_error("Unknown notifications command");
            println!("Available: mark-all-read, delete <id>, delete-all, prefs");
        }
    }
    Ok(())
} 