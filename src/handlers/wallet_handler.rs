use crate::cli::CLI;
use crate::database::sqlite::SqliteDatabase;
use crate::errors::Result;
use crate::services::auth::AuthService;
use crate::services::stellar_service::StellarService;
use crate::models::stellar_wallet::{StellarWallet};
use colored::*;
use std::sync::Arc;
use std::collections::HashMap;
use crate::TransferHandler;
use std::io::Write;

pub struct WalletHandler {
    auth_service: AuthService,
    stellar_service: StellarService,
    database: Arc<SqliteDatabase>,
}

impl WalletHandler {
    pub async fn new() -> Result<Self> {
        let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
        let auth_service = AuthService::new(database.clone());
        let stellar_service = StellarService::new(database.clone()); // Pass database to StellarService
        
        Ok(Self { 
            auth_service,
            stellar_service,
            database,
        })
    }

    pub async fn show_wallet_menu(&self) -> Result<()> {
        loop {
            println!("\n{}", "👛 Stellar Wallet Management".cyan().bold());
            println!("{}", "=".repeat(50).blue());
            println!("1. 🆕 Create New Wallet");
            println!("2. 📥 Import Existing Wallet");
            println!("3. 📋 List All Wallets");
            println!("4. 🔄 Sync Wallet");
            println!("5. 📊 Show Wallet Details");
            println!("6. 💰 Show Wallet Balance");
            println!("7. 💰 Fund Testnet Wallet");
            println!("8. 💸 Send Money");
            println!("9. 📥 Receive Money");
            println!("10. 🔧 Wallet Maintenance");
            println!("11. 🔙 Back to Main Menu");
            println!("{}", "=".repeat(50).blue());

            let choice = CLI::get_input("Select an option:")?;

            match choice.trim() {
                "1" => self.create_wallet_interactive().await?,
                "2" => self.import_wallet_interactive().await?,
                "3" => self.list_wallets_interactive().await?,
                "4" => self.sync_wallet_interactive().await?,
                "5" => self.show_wallet_details_interactive().await?,
                "6" => self.show_wallet_balance_interactive().await?,
                "7" => self.fund_testnet_wallet_interactive().await?,
                "8" => {
                    let transfer_handler = TransferHandler::new().await?;
                    transfer_handler.show_transfer_menu().await?;
                }
                "9" => self.receive_money_interactive().await?,
                "10" => self.show_maintenance_menu().await?,
                "11" => break,
                _ => CLI::print_error("Invalid option. Please try again."),
            }
        }

        Ok(())
    }

    pub async fn create_wallet_interactive(&self) -> Result<()> {
        println!("\n{}", "🌟 Create New Stellar Wallet".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        let wallet_name = CLI::get_input("📝 Enter wallet name:")?;
        let password = CLI::get_password("🔒 Enter password to encrypt wallet (can be different from login password):")?;
        
       
        let wallet = self.stellar_service.create_wallet(&user.user_id, &wallet_name, &password)?;
        
      
        self.database.create_stellar_wallet(&wallet).await?;
        
        println!("\n{}", "✅ Stellar wallet created successfully!".green().bold());
        println!("🌟 Public Key: {}", wallet.public_key.yellow());
        println!("📝 Wallet Name: {}", wallet.wallet_name.cyan());
        println!("{}", "⚠️  IMPORTANT: Save your wallet details securely!".red().bold());
        println!("{}", "💡 Your wallet needs to be funded before you can use it.".yellow());
        
        // Ask if user wants to fund the wallet (testnet only)
        if self.stellar_service.horizon_url.contains("testnet") {
            let fund_choice = CLI::get_input("💰 Would you like to fund this wallet with test XLM? (y/n):")?;
            if fund_choice.to_lowercase() == "y" || fund_choice.to_lowercase() == "yes" {
                match self.stellar_service.fund_testnet_account(&wallet.public_key).await {
                    Ok(_) => {
                        println!("{}", "✅ Wallet funded with test XLM!".green().bold());
                        
                        // Update wallet balance
                        if let Ok(wallet_info) = self.stellar_service.get_wallet_info(&wallet.public_key).await {
                            let _ = self.database.update_wallet_balance(
                                &wallet.id, 
                                &wallet_info.balance_xlm, 
                                Some(wallet_info.sequence_number)
                            ).await;
                            println!("💰 Balance: {} XLM", wallet_info.balance_xlm.green());
                        }
                    }
                    Err(e) => {
                        println!("{}", format!("⚠️ Failed to fund wallet: {}", e).yellow());
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn import_wallet_interactive(&self) -> Result<()> {
        println!("\n{}", "📥 Import Existing Stellar Wallet".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // First, authenticate the user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get wallet details
        let wallet_name = CLI::get_input("📝 Enter wallet name:")?;
        let secret_key = CLI::get_password("🔐 Enter your Stellar secret key (starts with S):")?;
        //let public_key = CLI::get_input("🔐 Enter your Stellar Public key (starts with G):")?;
        let password = CLI::get_password("🔒 Enter password to encrypt wallet:")?;
        
        // Import the wallet
        let wallet = self.stellar_service.import_wallet(&user.user_id, &wallet_name, &secret_key, &password)?;
        //let wallet = self.stellar_service.import_wallet(&user.user_id, &wallet_name, &public_key, &password)?;
        // Get wallet info from network
        match self.stellar_service.get_wallet_info(&wallet.public_key).await {
            Ok(wallet_info) => {
                let mut updated_wallet = wallet;
                updated_wallet.balance_xlm = Some(wallet_info.balance_xlm.clone());
                updated_wallet.sequence_number = Some(wallet_info.sequence_number);
                
                // Save to database
                self.database.create_stellar_wallet(&updated_wallet).await?;
                
                println!("\n{}", "✅ Stellar wallet imported successfully!".green().bold());
                println!("🌟 Public Key: {}", updated_wallet.public_key.yellow());
                println!("📝 Wallet Name: {}", updated_wallet.wallet_name.cyan());
                println!("💰 Balance: {} XLM", wallet_info.balance_xlm.green());
                println!("🔢 Sequence Number: {}", wallet_info.sequence_number);
                
                if wallet_info.is_funded {
                    println!("{}", "✅ Wallet is funded and ready to use!".green());
                } else {
                    println!("{}", "⚠️ Wallet is not funded yet.".yellow());
                }
            }
            Err(e) => {
                // Still save the wallet even if we can't get network info
                self.database.create_stellar_wallet(&wallet).await?;
                println!("\n{}", "✅ Stellar wallet imported successfully!".green().bold());
                println!("🌟 Public Key: {}", wallet.public_key.yellow());
                println!("📝 Wallet Name: {}", wallet.wallet_name.cyan());
                println!("{}", format!("⚠️ Could not fetch network info: {}", e).yellow());
            }
        }

        Ok(())
    }

    pub async fn list_wallets_interactive(&self) -> Result<()> {
        println!("\n{}", "📱 Your Stellar Wallets".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // First, authenticate the user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets yet.".yellow());
            println!("{}", "💡 Use 'Create Wallet' or 'Import Wallet' to get started!".cyan());
            return Ok(());
        }

        println!("\n{}", format!("Found {} wallet(s):", wallets.len()).green().bold());
        println!();

        for (index, wallet) in wallets.iter().enumerate() {
            println!("{}", format!("{}. {}", index + 1, wallet.wallet_name).cyan().bold());
            println!("   🌟 Public Key: {}", wallet.public_key.yellow());
            println!("   💰 Balance: {} XLM", wallet.balance_xlm.as_ref().unwrap_or(&"Unknown".to_string()).green());
            
            if let Some(last_sync) = wallet.last_sync_at {
                println!("   🔄 Last Sync: {}", last_sync.format("%Y-%m-%d %H:%M:%S UTC").to_string().blue());
            } else {
                println!("   🔄 Last Sync: {}", "Never".red());
            }
            
            println!("   📅 Created: {}", wallet.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().blue());
            println!();
        }

        Ok(())
    }

    pub async fn sync_wallet_interactive(&self) -> Result<()> {
        println!("\n{}", "🔄 Sync Wallet with Stellar Network".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // First, authenticate the user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets to sync.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to sync:");
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
        
        println!("🔄 Syncing wallet: {}", selected_wallet.wallet_name.cyan());
        
        // Get latest info from Stellar network
        match self.stellar_service.get_wallet_info(&selected_wallet.public_key).await {
            Ok(wallet_info) => {
                // Update database
                let old_balance = selected_wallet.balance_xlm.as_ref().and_then(|b| b.parse::<f64>().ok()).unwrap_or(0.0);
                let new_balance = wallet_info.balance_xlm.parse::<f64>().unwrap_or(0.0);
                self.database.update_wallet_balance(
                    &selected_wallet.id,
                    &wallet_info.balance_xlm,
                    Some(wallet_info.sequence_number)
                ).await?;

                if (old_balance - new_balance).abs() > f64::EPSILON {
                    // Send balance change notification
                    if let Ok(user) = self.database.get_user_by_id(&selected_wallet.user_id).await {
                        let notification_service = crate::services::notification_service::NotificationService::new(self.database.clone());
                        let _ = notification_service
                            .send_balance_change_notification(
                                &user.id,
                                &user.email,
                                old_balance,
                                new_balance,
                                "XLM",
                                Some("Wallet sync"),
                            ).await;
                        // Send low balance notification if needed
                        let _ = notification_service
                            .send_low_balance_notification(
                                &user.id,
                                &user.email,
                                new_balance,
                                "XLM",
                            ).await;
                    }
                }

                println!("\n{}", "✅ Wallet synced successfully!".green().bold());
                println!("💰 Current Balance: {} XLM", wallet_info.balance_xlm.green());
                println!("🔢 Sequence Number: {}", wallet_info.sequence_number);
                
                if wallet_info.is_funded {
                    println!("{}", "✅ Wallet is active on the network".green());
                } else {
                    println!("{}", "⚠️ Wallet is not funded yet".yellow());
                }
            }
            Err(e) => {
                println!("{}", format!("❌ Failed to sync wallet: {}", e).red());
            }
        }

        Ok(())
    }

    pub async fn show_wallet_details_interactive(&self) -> Result<()> {
        println!("\n{}", "🔍 Wallet Details".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // First, authenticate the user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to view details:");
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
        
        println!("\n{}", "📋 Wallet Information".cyan().bold());
        println!("{}", "━".repeat(50).blue());
        println!("📝 Name: {}", selected_wallet.wallet_name.yellow());
        println!("🌟 Public Key: {}", selected_wallet.public_key.yellow());
        println!("💰 Stored Balance: {} XLM", selected_wallet.balance_xlm.as_ref().unwrap_or(&"Unknown".to_string()).green());
        
        if let Some(seq) = selected_wallet.sequence_number {
            println!("🔢 Sequence Number: {}", seq);
        }
        
        println!("📅 Created: {}", selected_wallet.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("🔄 Updated: {}", selected_wallet.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));
        
        if let Some(last_sync) = selected_wallet.last_sync_at {
            println!("🔄 Last Sync: {}", last_sync.format("%Y-%m-%d %H:%M:%S UTC"));
        } else {
            println!("🔄 Last Sync: {}", "Never".red());
        }

        // Get live balance from network
        println!("\n{}", "🌐 Fetching live data from Stellar network...".cyan());
        match self.stellar_service.get_wallet_balances(&selected_wallet.public_key).await {
            Ok(balances) => {
                println!("\n{}", "💰 Live Balances:".green().bold());
                for balance in balances {
                    if balance.asset_type == "native" {
                        println!("   XLM: {}", balance.balance.green());
                    } else {
                        println!("   {}: {}", balance.asset_code, balance.balance.green());
                    }
                }
            }
            Err(e) => {
                println!("{}", format!("⚠️ Could not fetch live balance: {}", e).yellow());
            }
        }

        // Get asset balances from local database
        println!("\n{}", "💾 Local Asset Balances:".blue().bold());
        match self.database.get_wallet_asset_balances(&selected_wallet.id).await {
            Ok(asset_balances) => {
                if asset_balances.is_empty() {
                    println!("   {}", "No additional assets found in local database".dimmed());
                } else {
                    for asset_balance in asset_balances {
                        let asset_name = if asset_balance.asset_code == "XLM" {
                            "XLM (Local)".to_string()
                        } else {
                            asset_balance.asset_code.clone()
                        };
                        println!("   {}: {} (Last updated: {})", 
                            asset_name.blue(), 
                            asset_balance.balance.green(),
                            asset_balance.last_updated.format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed()
                        );
                    }
                }
            }
            Err(e) => {
                println!("{}", format!("⚠️ Could not fetch local asset balances: {}", e).yellow());
            }
        }

        // Show combined summary
        println!("\n{}", "📊 Balance Summary:".cyan().bold());
        println!("{}", "━".repeat(50).blue());
        
        // Get both live and local balances for comparison
        let mut all_assets = HashMap::new();
        
        // Add live balances
        if let Ok(live_balances) = self.stellar_service.get_wallet_balances(&selected_wallet.public_key).await {
            for balance in live_balances {
                let asset_key = if balance.asset_type == "native" {
                    "XLM".to_string()
                } else {
                    balance.asset_code.clone()
                };
                all_assets.insert(asset_key, ("Live".to_string(), balance.balance));
            }
        }
        
        // Add local balances
        if let Ok(local_balances) = self.database.get_wallet_asset_balances(&selected_wallet.id).await {
            for balance in local_balances {
                let source = if balance.asset_code == "XLM" { "Local" } else { "Local" };
                all_assets.insert(balance.asset_code.clone(), (source.to_string(), balance.balance));
            }
        }
        
        // Display combined summary
        for (asset, (source, amount)) in all_assets {
            let source_label = if source == "Live" { "🌐" } else { "💾" };
            println!("   {} {}: {} ({})", source_label, asset, amount.green(), source);
        }

        Ok(())
    }

    pub async fn show_wallet_balance_interactive(&self) -> Result<()> {
        println!("\n{}", "💰 Wallet Balance".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // First, authenticate the user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to view balance:");
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
        
        // Display wallet balances using the existing function
        self.display_wallet_balances(selected_wallet).await?;

        Ok(())
    }

    pub async fn fund_testnet_wallet_interactive(&self) -> Result<()> {
        println!("\n{}", "💰 Fund Testnet Wallet".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // Check if we're on testnet
        if !self.stellar_service.horizon_url.contains("testnet") {
            println!("{}", "❌ This feature is only available on testnet!".red().bold());
            return Ok(());
        }
        
        // First, authenticate the user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets to fund.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to fund:");
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
        
        println!("💰 Funding wallet: {}", selected_wallet.wallet_name.cyan());
        
        match self.stellar_service.fund_testnet_account(&selected_wallet.public_key).await {
            Ok(_) => {
                println!("{}", "✅ Wallet funded successfully!".green().bold());
                
                // Update wallet balance
                if let Ok(wallet_info) = self.stellar_service.get_wallet_info(&selected_wallet.public_key).await {
                    let _ = self.database.update_wallet_balance(
                        &selected_wallet.id,
                        &wallet_info.balance_xlm,
                        Some(wallet_info.sequence_number)
                    ).await;
                    println!("💰 New Balance: {} XLM", wallet_info.balance_xlm.green());
                }
            }
            Err(e) => {
                println!("{}", format!("❌ Failed to fund wallet: {}", e).red());
            }
        }

        Ok(())
    }

    pub async fn receive_money_interactive(&self) -> Result<()> {
        println!("\n{}", "📥 Receive Money".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // First, authenticate the user
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
            println!("4. 🔙 Back to Wallet Menu");
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

    pub async fn show_maintenance_menu(&self) -> Result<()> {
        loop {
            println!("\n{}", "🔧 Wallet Maintenance".cyan().bold());
            println!("{}", "=".repeat(50).blue());
            println!("1. 🔍 Debug Wallet Encryption");
            println!("2. 🔄 Re-encrypt Wallet");
            println!("3. 🛠️  Recreate Wallet");
            println!("4. 🚨 Recover Wallet");
            println!("5. 💰 Sync Wallet Balance");
            println!("6. 🔙 Back to Wallet Menu");
            println!("{}", "=".repeat(50).blue());

            let choice = CLI::get_input("Select an option:")?;

            match choice.trim() {
                "1" => self.debug_wallet_encryption_interactive().await?,
                "2" => self.reencrypt_wallet_interactive().await?,
                "3" => self.recreate_wallet_interactive().await?,
                "4" => self.recover_wallet_interactive().await?,
                "5" => self.sync_wallet_balance_interactive().await?,
                "6" => break,
                _ => CLI::print_error("Invalid option. Please try again."),
            }
        }

        Ok(())
    }

    async fn debug_wallet_encryption_interactive(&self) -> Result<()> {
        println!("\n{}", "🔍 Debug Wallet Encryption".cyan().bold());
        println!("{}", "=".repeat(50).blue());

        // Get user's wallets
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        let wallets = self.database.get_user_wallets(&user.user_id).await?;

        if wallets.is_empty() {
            println!("{}", "📭 No wallets found.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to debug:");
        for (i, wallet) in wallets.iter().enumerate() {
            println!("{}. {} ({})", i + 1, wallet.wallet_name, wallet.public_key);
        }

        let choice = CLI::get_input("Enter wallet number:")?;
        let wallet_index: usize = choice.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid wallet number".to_string()))?;

        if wallet_index == 0 || wallet_index > wallets.len() {
            return Err(crate::errors::AppError::ValidationError("Invalid wallet selection".to_string()));
        }

        let selected_wallet = &wallets[wallet_index - 1];
        self.stellar_service.debug_wallet_encryption(&selected_wallet.public_key).await?;

        Ok(())
    }

    async fn reencrypt_wallet_interactive(&self) -> Result<()> {
        println!("\n{}", "🔄 Re-encrypt Wallet".cyan().bold());
        println!("{}", "=".repeat(50).blue());

        // Get user's wallets
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        let wallets = self.database.get_user_wallets(&user.user_id).await?;

        if wallets.is_empty() {
            println!("{}", "📭 No wallets found.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to re-encrypt:");
        for (i, wallet) in wallets.iter().enumerate() {
            println!("{}. {} ({})", i + 1, wallet.wallet_name, wallet.public_key);
        }

        let choice = CLI::get_input("Enter wallet number:")?;
        let wallet_index: usize = choice.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid wallet number".to_string()))?;

        if wallet_index == 0 || wallet_index > wallets.len() {
            return Err(crate::errors::AppError::ValidationError("Invalid wallet selection".to_string()));
        }

        let selected_wallet = &wallets[wallet_index - 1];
        
        let old_password = CLI::get_password("Enter current wallet password:")?;
        let new_password = CLI::get_password("Enter new wallet password:")?;
        let confirm_password = CLI::get_password("Confirm new wallet password:")?;

        if new_password != confirm_password {
            return Err(crate::errors::AppError::ValidationError("Passwords do not match".to_string()));
        }

        let new_encrypted = self.stellar_service.re_encrypt_wallet(
            &old_password,
            &new_password,
            &selected_wallet.encrypted_secret_key
        )?;

        // Update the wallet in the database with new encrypted key
        self.database.update_wallet_encryption(&selected_wallet.id, &new_encrypted).await?;

        println!("{}", "✅ Wallet re-encrypted successfully!".green().bold());
        Ok(())
    }

    async fn recreate_wallet_interactive(&self) -> Result<()> {
        println!("\n{}", "🛠️  Recreate Wallet".cyan().bold());
        println!("{}", "=".repeat(50).blue());
        println!("{}", "⚠️  This will create a new wallet with your secret key.".yellow());
        println!("{}", "Make sure you have your secret key ready.".yellow());

        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;

        let wallet_name = CLI::get_input("📝 Enter new wallet name:")?;
        let secret_key = CLI::get_password("🔐 Enter your Stellar secret key (starts with S):")?;
        let password = CLI::get_password("🔒 Enter new password to encrypt wallet:")?;

        let new_wallet = self.stellar_service.recreate_wallet_with_secret(
            &user.user_id,
            &wallet_name,
            &secret_key,
            &password
        ).await?;

        // Save to database
        self.database.create_stellar_wallet(&new_wallet).await?;

        println!("{}", "✅ Wallet recreated successfully!".green().bold());
        println!("🌟 Public Key: {}", new_wallet.public_key.yellow());
        println!("📝 Wallet Name: {}", new_wallet.wallet_name.cyan());

        Ok(())
    }

    async fn recover_wallet_interactive(&self) -> Result<()> {
        println!("\n{}", "🚨 Recover Wallet".cyan().bold());
        println!("{}", "=".repeat(50).blue());

        // Get user's wallets
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        let wallets = self.database.get_user_wallets(&user.user_id).await?;

        if wallets.is_empty() {
            println!("{}", "📭 No wallets found.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to recover:");
        for (i, wallet) in wallets.iter().enumerate() {
            println!("{}. {} ({})", i + 1, wallet.wallet_name, wallet.public_key);
        }

        let choice = CLI::get_input("Enter wallet number:")?;
        let wallet_index: usize = choice.parse()
            .map_err(|_| crate::errors::AppError::ValidationError("Invalid wallet number".to_string()))?;

        if wallet_index == 0 || wallet_index > wallets.len() {
            return Err(crate::errors::AppError::ValidationError("Invalid wallet selection".to_string()));
        }

        let selected_wallet = &wallets[wallet_index - 1];
        let password = CLI::get_password("Enter wallet password:")?;

        match self.stellar_service.recover_wallet(&selected_wallet.public_key, &password).await {
            Ok(_) => println!("{}", "✅ Wallet recovery successful!".green().bold()),
            Err(e) => println!("{}", format!("❌ Recovery failed: {}", e).red().bold()),
        }

        Ok(())
    }

    async fn display_wallet_balances(&self, wallet: &StellarWallet) -> Result<()> {
        let balances = self.stellar_service.get_wallet_balances(&wallet.public_key).await?;
        
        println!("\n{}", "💰 Wallet Balances".cyan().bold());
        println!("{}", "=".repeat(50).blue());
        
        for balance in balances {
            let asset_name = if balance.asset_code == "XLM" {
                "Stellar Lumens (XLM)".to_string()
            } else {
                balance.asset_code.clone()
            };
            
            println!("🪙 {}: {} {}", 
                asset_name.yellow(),
                balance.balance.cyan(),
                if let Some(issuer) = &balance.asset_issuer {
                    format!("(Issuer: {})", issuer.chars().take(4).collect::<String>() + "...")
                } else {
                    "".to_string()
                }
            );
        }
        
        Ok(())
    }

    async fn sync_wallet_balances(&self, wallet: &StellarWallet) -> Result<()> {
        println!("\n🔄 Syncing wallet balances...");
        
        let balances = self.stellar_service.get_wallet_balances(&wallet.public_key).await?;
        let mut all_assets = HashMap::new();
        
        // Process local balances
        for balance in balances {
            let source = if balance.asset_code == "XLM" { "Local" } else { "Local" };
            all_assets.insert(balance.asset_code.clone(), (source.to_string(), balance.balance));
        }
        
        // Display results
        println!("\n📊 Updated Balances:");
        println!("{}", "=".repeat(50).blue());
        
        for (asset, (source, balance)) in all_assets {
            println!("🪙 {} ({}):", asset.yellow(), source.dimmed());
            println!("   Balance: {}", balance.cyan());
        }
        
        println!("\n✅ Wallet sync complete!");
        Ok(())
    }

    async fn sync_wallet_balance_interactive(&self) -> Result<()> {
        println!("\n{}", "💰 Sync Wallet Balance".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        // First, authenticate the user
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = self.auth_service.validate_token(&token).await?;
        
        // Get user's wallets
        let wallets = self.database.get_user_wallets(&user.user_id).await?;
        
        if wallets.is_empty() {
            println!("{}", "📭 You don't have any wallets.".yellow());
            return Ok(());
        }

        // Show wallets and let user choose
        println!("Select a wallet to sync balance:");
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
        
        println!("🔄 Syncing wallet balance: {}", selected_wallet.wallet_name.cyan());
        
        // Sync wallet balance
        self.sync_wallet_balances(selected_wallet).await?;

        Ok(())
    }
}