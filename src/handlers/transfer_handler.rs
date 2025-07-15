use crate::cli::CLI;
use crate::database::sqlite::SqliteDatabase;
use crate::errors::Result;
use crate::services::auth::AuthService;
use crate::services::stellar_service::StellarService;
use colored::Colorize;
use std::sync::Arc;
use crate::services::notification_service::NotificationService;
use std::io::Write;

pub struct TransferHandler {
    auth_service: AuthService,
    pub stellar_service: StellarService,
    database: Arc<SqliteDatabase>,
    notification_service: NotificationService,
}

impl TransferHandler {
    pub async fn new() -> Result<Self> {
        let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
        let auth_service = AuthService::new(database.clone());
        let stellar_service = StellarService::new(database.clone());
        let notification_service = NotificationService::new(database.clone());
        Ok(Self {
            auth_service,
            stellar_service,
            database,
            notification_service,
        })
    }

    pub async fn show_transfer_menu(&self) -> Result<()> {
        loop {
            println!("\n{}", "💸 Money Transfer".cyan().bold());
            println!("{}", "=".repeat(50).blue());
            println!("1. 💰 Send Money");
            println!("2. 📥 Receive Money");
            println!("3. 📋 View Transfer History");
            println!("4. 📊 View Receive History");
            println!("5. 🔙 Back to Wallet Menu");
            println!("{}", "=".repeat(50).blue());

            let choice = CLI::get_input("Select an option:")?;

            match choice.trim() {
                "1" => self.send_money_interactive().await?,
                "2" => self.receive_money_interactive().await?,
                "3" => self.view_transfer_history_interactive().await?,
                "4" => self.view_receive_history_interactive().await?,
                "5" => break,
                _ => CLI::print_error("Invalid option. Please try again."),
            }
        }

        Ok(())
    }

    pub async fn send_money_interactive(&self) -> Result<()> {
        println!("\n{}", "💸 Send Money".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // Authenticate user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets to send from.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose source wallet
        println!("Select source wallet:");
        for (index, wallet) in wallets.iter().enumerate() {
            println!("{}. {} ({}) - Balance: {} XLM", 
                index + 1, 
                wallet.wallet_name, 
                wallet.public_key,
                wallet.balance_xlm.as_ref().unwrap_or(&"Unknown".to_string())
            );
        }

        let choice = CLI::get_input("Enter wallet number:")?;
        let wallet_index: usize = choice.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid wallet number".to_string()))?;

        if wallet_index == 0 || wallet_index > wallets.len() {
            return Err(crate::errors::AppError::ValidationError("Invalid wallet selection".to_string()));
        }

        let source_wallet = &wallets[wallet_index - 1];
        
        // Get recipient details
        let recipient_address = CLI::get_input("Enter recipient's Stellar address (starts with G):")?;
        let amount = CLI::get_input("Enter amount to send:")?;
        let amount: f64 = amount.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid amount".to_string()))?;
        
        // Get wallet password for signing
        let password = CLI::get_password("Enter wallet password to confirm transfer:")?;
        
        // Get memo (optional)
        let memo = CLI::get_input("Enter memo (optional, press Enter to skip):")?;
        
        println!("\n{}", "📝 Transfer Summary".cyan().bold());
        println!("From: {}", source_wallet.public_key.yellow());
        println!("To: {}", recipient_address.yellow());
        println!("Amount: {} XLM", amount.to_string().green());
        if !memo.is_empty() {
            println!("Memo: {}", memo.cyan());
        }
        
        let confirm = CLI::get_input("Confirm transfer? (y/n):")?;
        if confirm.to_lowercase() != "y" && confirm.to_lowercase() != "yes" {
            println!("{}", "Transfer cancelled.".yellow());
            return Ok(());
        }

        // Check if 2FA is enabled for the user
        let user_record = self.database.get_user_by_id(&user.user_id).await?;
        if user_record.totp_enabled {
        }

        // Execute transfer
        let send_result = self.stellar_service.send_payment(
            &source_wallet.public_key,
            &recipient_address,
            amount,
            if memo.is_empty() { None } else { Some(memo.clone()) },
            &password
        ).await;
        match send_result {
            Ok(transaction_hash) => {
                println!("\n{}", "✅ Transfer successful!".green().bold());
                println!("Transaction Hash: {}", transaction_hash.yellow());
                
                // Update wallet balance
                if let Ok(wallet_info) = self.stellar_service.get_wallet_info(&source_wallet.public_key).await {
                    let _ = self.database.update_wallet_balance(
                        &source_wallet.id,
                        &wallet_info.balance_xlm,
                        Some(wallet_info.sequence_number)
                    ).await;
                    println!("💰 New Balance: {} XLM", wallet_info.balance_xlm.green());
                }
                // Fetch sender's email and send notifications
                if let Ok(user) = self.database.get_user_by_id(&source_wallet.user_id).await {
                    let amount_str = amount.to_string();
                    // Outgoing notification for sender
                    let _ = self.notification_service.send_outgoing_payment_notification(
                        &user.id,
                        &user.email,
                        &amount_str,
                        "XLM",
                        &recipient_address,
                        &transaction_hash,
                        if memo.is_empty() { None } else { Some(memo.as_str()) }
                    ).await;
                }
                // Fetch recipient user by wallet public key and send incoming notification if registered
                if let Ok(Some(recipient_wallet)) = self.database.get_wallet_by_public_key(&recipient_address).await {
                    if let Ok(recipient_user) = self.database.get_user_by_id(&recipient_wallet.user_id).await {
                        let amount_str = amount.to_string();
                        let _ = self.notification_service.send_incoming_payment_notification(
                            &recipient_user.id,
                            &recipient_user.email,
                            &amount_str,
                            "XLM",
                            &source_wallet.public_key,
                            &transaction_hash,
                            if memo.is_empty() { None } else { Some(memo.as_str()) }
                        ).await;
                    }
                }
            }
            Err(e) => {
                println!("{}", format!("❌ Transfer failed: {}", e).red().bold());
                // Fetch sender's email and send payment failed notification
                if let Ok(user) = self.database.get_user_by_id(&source_wallet.user_id).await {
                    let amount_str = amount.to_string();
                    let _ = self.notification_service.send_payment_failed_notification(
                        &user.id,
                        &user.email,
                        &amount_str,
                        "XLM",
                        &recipient_address,
                        &e.to_string(),
                        if memo.is_empty() { None } else { Some(memo.as_str()) }
                    ).await;
                }
            }
        }

        Ok(())
    }

    pub async fn receive_money_interactive(&self) -> Result<()> {
        println!("\n{}", "📥 Receive Money".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // Authenticate user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets to receive to.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select wallet to receive money:");
        for (index, wallet) in wallets.iter().enumerate() {
            println!("{}. {} ({})", index + 1, wallet.wallet_name, wallet.public_key);
        }

        let choice = CLI::get_input("Enter wallet number:")?;
        let wallet_index: usize = choice.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid wallet number".to_string()))?;

        if wallet_index == 0 || wallet_index > wallets.len() {
            return Err(crate::errors::AppError::ValidationError("Invalid wallet selection".to_string()));
        }

        let selected_wallet = &wallets[wallet_index - 1];
        
        // Show receive options
        loop {
            println!("\n{}", "📥 Receive Options".cyan().bold());
            println!("{}", "=".repeat(30).blue());
            println!("1. 📋 Show Receive Address");
            println!("2. 📱 Generate QR Code");
            println!("3. 📊 Check Recent Receipts");
            println!("4. 🔙 Back to Transfer Menu");
            println!("{}", "=".repeat(30).blue());

            let receive_choice = CLI::get_input("Select an option:")?;

            match receive_choice.trim() {
                "1" => self.show_receive_address(selected_wallet).await?,
                "2" => self.generate_qr_code(selected_wallet).await?,
                "3" => self.check_recent_receipts(selected_wallet).await?,
                "4" => break,
                _ => CLI::print_error("Invalid option. Please try again."),
            }
        }

        Ok(())
    }

    async fn show_receive_address(&self, wallet: &crate::models::stellar_wallet::StellarWallet) -> Result<()> {
        println!("\n{}", "📋 Your Receive Address".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        println!("📝 Wallet Name: {}", wallet.wallet_name.yellow());
        println!("🌟 Public Key: {}", wallet.public_key.green().bold());
        println!("📅 Created: {}", wallet.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
        
        if let Some(last_sync) = wallet.last_sync_at {
            println!("🔄 Last Sync: {}", last_sync.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        
        println!("\n{}", "💡 Instructions:".cyan().bold());
        println!("• Share this address with anyone who wants to send you money");
        println!("• The sender needs your public key to make the transfer");
        println!("• You can receive XLM and other Stellar assets");
        println!("• Transactions are usually confirmed within 5 seconds");
        
        println!("\n{}", "⚠️  Security Tips:".yellow().bold());
        println!("• Only share your public key, never your secret key");
        println!("• Verify the address before sharing");
        println!("• Check your balance after receiving funds");
        
        Ok(())
    }

    async fn generate_qr_code(&self, wallet: &crate::models::stellar_wallet::StellarWallet) -> Result<()> {
        println!("\n{}", "📱 QR Code Generation".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // Generate QR code for the public key
        let qr_code = qrcode::QrCode::new(&wallet.public_key)
            .map_err(|e| crate::errors::AppError::ValidationError(format!("Failed to generate QR code: {}", e)))?;
        
        // Convert to SVG
        let svg_string = qr_code.render()
            .min_dimensions(200, 200)
            .dark_color(qrcode::render::svg::Color("#000000"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build();
        
        // Save QR code to file
        let filename = format!("qr_code_{}.svg", wallet.wallet_name.replace(" ", "_"));
        let mut file = std::fs::File::create(&filename)
            .map_err(|e| crate::errors::AppError::ValidationError(format!("Failed to create QR code file: {}", e)))?;
        
        file.write_all(svg_string.as_bytes())
            .map_err(|e| crate::errors::AppError::ValidationError(format!("Failed to write QR code: {}", e)))?;
        
        println!("✅ QR Code generated successfully!");
        println!("📁 File saved as: {}", filename.green());
        println!("🌟 Public Key: {}", wallet.public_key.yellow());
        println!("📝 Wallet Name: {}", wallet.wallet_name.cyan());
        
        println!("\n{}", "💡 How to use:".cyan().bold());
        println!("• Open the SVG file in any web browser");
        println!("• Print it or share it digitally");
        println!("• Others can scan it to get your address");
        println!("• Works with most QR code scanner apps");
        
        Ok(())
    }

    async fn check_recent_receipts(&self, wallet: &crate::models::stellar_wallet::StellarWallet) -> Result<()> {
        println!("\n{}", "📊 Recent Receipts".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // Get recent incoming transactions
        match self.stellar_service.get_transaction_history(&wallet.public_key).await {
            Ok(transactions) => {
                // Filter for incoming transactions (where 'to' is our wallet)
                let incoming_transactions: Vec<_> = transactions
                    .into_iter()
                    .filter(|tx| tx.to == wallet.public_key)
                    .collect();
                
                if incoming_transactions.is_empty() {
                    println!("{}", "No incoming transactions found.".yellow());
                    println!("💡 Share your address to start receiving money!");
                    return Ok(());
                }

                println!("{}", format!("Found {} incoming transactions:", incoming_transactions.len()).green().bold());
                println!();

                for (index, tx) in incoming_transactions.iter().enumerate() {
                    println!("{}. Transaction Hash: {}", index + 1, tx.hash.yellow());
                    println!("   💰 Amount: {} XLM", tx.amount.green().bold());
                    println!("   👤 From: {}", tx.from.cyan());
                    println!("   📅 Date: {}", tx.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().blue());
                    if let Some(memo) = &tx.memo {
                        println!("   📝 Memo: {}", memo.magenta());
                    }
                    println!("   ✅ Status: {}", "Received".green());
                    println!();
                }
                
                // Show total received
                let total_received: f64 = incoming_transactions
                    .iter()
                    .filter_map(|tx| tx.amount.parse::<f64>().ok())
                    .sum();
                
                println!("{}", "📈 Summary:".cyan().bold());
                println!("💰 Total Received: {} XLM", total_received.to_string().green().bold());
                println!("📊 Transaction Count: {}", incoming_transactions.len().to_string().blue());
            }
            Err(e) => {
                println!("{}", format!("Failed to fetch transaction history: {}", e).red().bold());
            }
        }

        Ok(())
    }

    pub async fn view_transfer_history_interactive(&self) -> Result<()> {
        println!("\n{}", "📋 Transfer History".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // Authenticate user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select wallet to view history:");
        for (index, wallet) in wallets.iter().enumerate() {
            println!("{}. {} ({})", index + 1, wallet.wallet_name, wallet.public_key);
        }

        let choice = CLI::get_input("Enter wallet number:")?;
        let wallet_index: usize = choice.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid wallet number".to_string()))?;

        if wallet_index == 0 || wallet_index > wallets.len() {
            return Err(crate::errors::AppError::ValidationError("Invalid wallet selection".to_string()));
        }

        let selected_wallet = &wallets[wallet_index - 1];
        
        // Get transaction history from Stellar network
        match self.stellar_service.get_transaction_history(&selected_wallet.public_key).await {
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

        Ok(())
    }

    pub async fn view_receive_history_interactive(&self) -> Result<()> {
        println!("\n{}", "📊 Receive History".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // Authenticate user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select wallet to view receive history:");
        for (index, wallet) in wallets.iter().enumerate() {
            println!("{}. {} ({})", index + 1, wallet.wallet_name, wallet.public_key);
        }

        let choice = CLI::get_input("Enter wallet number:")?;
        let wallet_index: usize = choice.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid wallet number".to_string()))?;

        if wallet_index == 0 || wallet_index > wallets.len() {
            return Err(crate::errors::AppError::ValidationError("Invalid wallet selection".to_string()));
        }

        let selected_wallet = &wallets[wallet_index - 1];
        
        // Show detailed receive history
        self.check_recent_receipts(selected_wallet).await?;

        Ok(())
    }
} 