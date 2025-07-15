use crate::cli::CLI;
use crate::errors::Result;
use crate::models::currency::*;
use crate::services::auth::AuthService;
use crate::services::exchange_service::ExchangeService;
use crate::database::sqlite::SqliteDatabase;
use colored::Colorize;
use std::sync::Arc;
use chrono::Utc;


pub struct ExchangeHandler {
    exchange_service: ExchangeService,
    auth_service: AuthService,
}

impl ExchangeHandler {
    pub async fn new() -> Result<Self> {
        let database = Arc::new(SqliteDatabase::new("stellar_wallet.db").await?);
        let auth_service = AuthService::new(database.clone());
        let exchange_service = ExchangeService::new(database);

        Ok(Self {
            exchange_service,
            auth_service,
        })
    }

    pub async fn show_exchange_menu(&self) -> Result<()> {
        loop {
            println!("\n{}", "💱 Currency Exchange".cyan().bold());
            println!("{}", "=".repeat(50).blue());
            println!("1. 📊 View Exchange Rates");
            println!("2. 💸 Exchange Currency");
            println!("3. 📋 Supported Currencies");
            println!("4. 📜 Exchange History");
            println!("5. 🔙 Back to Main Menu");
            println!("{}", "=".repeat(50).blue());

            let choice = CLI::get_input("Select an option:")?;

            match choice.trim() {
                "1" => self.show_exchange_rates().await?,
                "2" => self.exchange_currency_interactive().await?,
                "3" => self.show_supported_currencies().await?,
                "4" => self.show_exchange_history().await?,
                "5" => break,
                _ => CLI::print_error("Invalid option. Please try again."),
            }
        }

        Ok(())
    }
    pub async fn show_exchange_rates(&self) -> Result<()> {
        println!("\n{}", "📊 Current Exchange Rates (via Stellar DEX)".cyan().bold());
        println!("{}", "=".repeat(60).blue());

        println!("{:<15} {:<15} {:<15} {:<15}", "From", "To", "Rate", "Last Updated");
        println!("{}", "-".repeat(80).blue());

        // Display major pairs
        let major_pairs = [
            ("XLM", "USD"), ("USD", "XLM"),
            ("XLM", "KES"), ("KES", "XLM"),
            ("XLM", "NGN"), ("NGN", "XLM"),
            ("XLM", "GHS"), ("GHS", "XLM"),
            ("XLM", "USDT"), ("USDT", "XLM"),
            ("USD", "KES"), ("USD", "NGN"), ("USD", "GHS"),
        ];

        for (from, to) in major_pairs.iter() {
            // Use a sample amount (e.g., 1.0) for preview
            match self.exchange_service.get_exchange_rate(from, to, 1.0).await {
                Ok((rate, _path)) => {
                    println!("{:<15} {:<15} {:<15.6} {:<15}",
                        from.green(),
                        to.yellow(),
                        format!("{:.6}", rate).cyan(),
                        Utc::now().format("%H:%M:%S").to_string().dimmed()
                    );
                }
                Err(_e) => {
                    // Optionally print error or skip
                }
            }
        }

        println!("\n{}", "💡 Rates are real-time and sourced directly from Stellar's decentralized exchange (DEX).".dimmed());
        println!("{}", "🔄 Press 'R' to refresh rates or any other key to continue...".dimmed());
        let input = CLI::get_input("")?;
        if input.trim().to_uppercase() == "R" {
            return Box::pin(self.show_exchange_rates()).await;
        }
        Ok(())
    }

    pub async fn show_supported_currencies(&self) -> Result<()> {
        println!("\n{}", "🌍 Supported Currencies (Stellar DEX)".cyan().bold());
        println!("{}", "=".repeat(70).blue());

        let currencies = self.exchange_service.get_supported_currencies();
        
        println!("{:<8} {:<20} {:<10} {:<15}", "Code", "Name", "Symbol", "Type");
        println!("{}", "-".repeat(70).blue());

        for currency in currencies {
            let currency_type = if currency.is_native { "Native" } else { "Asset" };
            let status = if currency.is_active { "✅" } else { "❌" };
            
            println!("{:<8} {:<20} {:<10} {:<15} {}", 
                currency.code.green().bold(),
                currency.name.cyan(),
                currency.symbol.yellow(),
                currency_type.blue(),
                status
            );
        }

        println!("\n{}", "💡 All currencies are traded on Stellar's decentralized exchange (DEX).".dimmed());
        Ok(())
    }

    pub async fn exchange_currency_interactive(&self) -> Result<()> {
        println!("\n{}", "💸 Currency Exchange (via Stellar DEX)".cyan().bold());
        println!("{}", "=".repeat(50).blue());

        // Get and validate user token
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = match self.auth_service.validate_token(&token).await {
            Ok(user) => user,
            Err(e) => {
                CLI::print_error(&format!("Invalid token: {}", e));
                return Ok(());
            }
        };

        println!("\n{} {}", "👋 Welcome,".green(), user.username.cyan().bold());

        // Show available currencies
        println!("\n{}", "Available currencies:".yellow().bold());
        let currencies = self.exchange_service.get_supported_currencies();
        for (i, currency) in currencies.iter().enumerate() {
            println!("{}. {} ({}) - {}", 
                i + 1, 
                currency.code.green(), 
                currency.symbol.yellow(), 
                currency.name.cyan()
            );
        }

        // Get exchange details
        let from_currency = loop {
            let input = CLI::get_input("\n💰 From currency (e.g., XLM):")?.to_uppercase();
            if currencies.iter().any(|c| c.code == input && c.is_active) {
                break input;
            } else {
                CLI::print_error("Invalid currency. Please choose from the supported list.");
            }
        };

        let to_currency = loop {
            let input = CLI::get_input("💱 To currency (e.g., USD):")?.to_uppercase();
            if currencies.iter().any(|c| c.code == input && c.is_active) {
                if input == from_currency {
                    CLI::print_error("Cannot exchange to the same currency.");
                    continue;
                }
                break input;
            } else {
                CLI::print_error("Invalid currency. Please choose from the supported list.");
            }
        };

        let amount = loop {
            let input = CLI::get_input(&format!("💵 Amount to exchange ({}):", from_currency))?;
            match input.parse::<f64>() {
                Ok(amt) if amt > 0.0 => break amt,
                Ok(_) => CLI::print_error("Amount must be greater than 0."),
                Err(_) => CLI::print_error("Please enter a valid number."),
            }
        };

        // Get available wallets for source currency
        println!("\n💼 Select source wallet for {}:", from_currency);
        let source_wallets = self.exchange_service.get_user_wallets_for_currency(&user.user_id, &from_currency).await?;
        if source_wallets.is_empty() {
            CLI::print_error(&format!("No wallets available for {}", from_currency));
            return Ok(());
        }

        // Display source wallets
        for (i, wallet) in source_wallets.iter().enumerate() {
            println!("{}. {} ({})", i + 1, wallet.wallet_name, wallet.public_key);
        }

        // Get source wallet selection
        let source_wallet = loop {
            let choice = CLI::get_input("Enter source wallet number:")?;
            match choice.parse::<usize>() {
                Ok(idx) if idx > 0 && idx <= source_wallets.len() => {
                    break &source_wallets[idx - 1];
                }
                _ => {
                    CLI::print_error("Invalid wallet selection. Please try again.");
                }
            }
        };

        // Get available wallets for destination currency
        println!("\n💼 Select destination wallet for {}:", to_currency);
        let dest_wallets = self.exchange_service.get_user_wallets_for_currency(&user.user_id, &to_currency).await?;
        if dest_wallets.is_empty() {
            CLI::print_error(&format!("No wallets available for {}", to_currency));
            return Ok(());
        }

        // Display destination wallets
        for (i, wallet) in dest_wallets.iter().enumerate() {
            println!("{}. {} ({})", i + 1, wallet.wallet_name, wallet.public_key);
        }

        // Get destination wallet selection
        let dest_wallet = loop {
            let choice = CLI::get_input("Enter destination wallet number:")?;
            match choice.parse::<usize>() {
                Ok(idx) if idx > 0 && idx <= dest_wallets.len() => {
                    break &dest_wallets[idx - 1];
                }
                _ => {
                    CLI::print_error("Invalid wallet selection. Please try again.");
                }
            }
        };

        // Create exchange request
        let request = ExchangeRequest {
            user_id: user.user_id,
            from_currency: from_currency.clone(),
            to_currency: to_currency.clone(),
            amount,
            source_wallet_id: source_wallet.id,
            destination_wallet_id: dest_wallet.id,
        };

        // Show exchange preview and get confirmation
        let preview = self.exchange_service.calculate_exchange_preview(&request).await?;
        self.display_exchange_preview(&preview)?;

        let confirm = CLI::get_input("\n🤔 Proceed with exchange? (y/n):")?;
        if confirm.to_lowercase() != "y" && confirm.to_lowercase() != "yes" {
            println!("{}", "Exchange cancelled.".yellow());
            return Ok(());
        }

        // Execute the exchange
        self.execute_exchange_transaction(&request).await?;

        Ok(())
    }

    fn display_exchange_preview(&self, preview: &ExchangePreview) -> Result<()> {
        println!("\n{}", "📋 Exchange Preview (Stellar DEX)".cyan().bold());
        println!("{}", "=".repeat(40).blue());
        
        println!("💰 You pay: {} {}", 
            format!("{:.6}", preview.from_amount).red().bold(), 
            preview.from_currency.red().bold()
        );
        
        println!("💸 You receive: {} {}", 
            format!("{:.6}", preview.to_amount).green().bold(), 
            preview.to_currency.green().bold()
        );
        
        println!("📊 Exchange rate: 1 {} = {:.6} {}", 
            preview.from_currency.cyan(), 
            preview.exchange_rate, 
            preview.to_currency.cyan()
        );
        
        println!("💳 Network fee: {} {}", 
            format!("{:.6}", preview.estimated_fee).yellow(), 
            preview.from_currency.yellow()
        );
        
        println!("💯 Total cost: {} {}", 
            format!("{:.6}", preview.total_cost).magenta().bold(), 
            preview.from_currency.magenta().bold()
        );
        
        println!("⏰ Rate timestamp: {}", Utc::now().format("%H:%M:%S").to_string().dimmed());
        println!("{}", "=".repeat(40).blue());
        println!("{}", "⚡ Transaction will be processed on Stellar DEX (on-chain)".dimmed());
        println!("{}", "⏱️  Estimated time: ~5 seconds".dimmed());

        Ok(())
    }

    async fn execute_exchange_transaction(&self, request: &ExchangeRequest) -> Result<()> {
        println!("\n{}", "⚡ Processing exchange...".yellow().bold());
        
        // Show progress indicator
        for i in 1..=3 {
            print!("{}Processing{} ", "⏳".yellow(), ".".repeat(i));
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
            print!("\r");
        }
        
        match self.exchange_service.handle_exchange(
            &request.user_id,
            &request.from_currency,
            &request.to_currency,
            request.amount,
            request.source_wallet_id,
            request.destination_wallet_id
        ).await {
            Ok(transaction) => {
                println!("\n{}", "✅ Exchange Successful!".green().bold());
                self.display_transaction_result(&transaction)?;
            }
            Err(e) => {
                CLI::print_error(&format!("❌ Exchange failed: {}", e));
                println!("{}", "💡 Please check your balance and try again.".yellow());
            }
        }

        Ok(())
    }

    fn display_transaction_result(&self, transaction: &ExchangeTransaction) -> Result<()> {
        println!("\n{}", "📄 Transaction Details (Stellar DEX)".cyan().bold());
        println!("{}", "=".repeat(50).blue());
        
        println!("🆔 Transaction ID: {}", transaction.id.to_string().cyan());
        
        if let Some(tx_hash) = &transaction.stellar_tx_hash {
            println!("🔗 Stellar TX Hash: {}", tx_hash.blue());
        }
        
        println!("📊 Exchange: {} {} → {} {}", 
            format!("{:.6}", transaction.from_amount).red(),
            transaction.from_currency.red(),
            format!("{:.6}", transaction.to_amount).green(),
            transaction.to_currency.green()
        );
        
        println!("💳 Fee: {} {}", 
            format!("{:.6}", transaction.fee_amount).yellow(),
            transaction.from_currency.yellow()
        );
        
        println!("📈 Rate: {:.6}", transaction.exchange_rate);
        println!("⏰ Completed: {}", transaction.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("✅ Status: {}", format!("{}", transaction.status).green().bold());
        
        println!("\n{}", "🎉 Your exchange has been completed on Stellar's decentralized exchange!".green().bold());
        println!("{}", "💰 New balance will reflect in your wallet immediately.".cyan());

        Ok(())
    }

    pub async fn show_exchange_history(&self) -> Result<()> {
        println!("\n{}", "📊 Exchange History".cyan().bold());
        println!("{}", "=".repeat(50).blue());
        
        let token = CLI::get_input("🔑 Enter your JWT token:")?;
        let user = match self.auth_service.validate_token(&token).await {
            Ok(user) => user,
            Err(e) => {
                CLI::print_error(&format!("Invalid token: {}", e));
                return Ok(());
            }
        };

        // Get exchange history from the database
        let transactions = self.exchange_service.get_user_exchange_history(&user.user_id).await?;

        if transactions.is_empty() {
            println!("\n{}", "📝 No exchange history found.".yellow());
            println!("{}", "💡 Complete your first exchange to see history here.".dimmed());
            return Ok(());
        }

        println!("👤 Exchange history for: {}", user.username.cyan().bold());
        println!("{}", "=".repeat(70).blue());
        println!("{:<10} {:<15} {:<15} {:<15} {:<15}", 
            "Date", "From", "To", "Amount", "Status"
        );
        println!("{}", "-".repeat(70).blue());

        for tx in transactions {
            println!("{:<10} {:<15} {:<15} {:<15.6} {:<15}",
                tx.created_at.format("%Y-%m-%d"),
                format!("{} {}", tx.from_amount, tx.from_currency).red(),
                format!("{} {}", tx.to_amount, tx.to_currency).green(),
                tx.exchange_rate,
                tx.status.to_string().yellow()
            );
        }

        Ok(())
    }
}