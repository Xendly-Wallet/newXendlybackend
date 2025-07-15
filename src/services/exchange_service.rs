use crate::errors::Result;
use crate::models::currency::*;
use crate::models::stellar_wallet::StellarWallet;
use crate::database::sqlite::SqliteDatabase;
use crate::services::stellar_service::{StellarService, PathPaymentResult};
use chrono::Utc;
use uuid::Uuid;
use chrono::DateTime;
use sqlx::Row;
use std::sync::Arc;

#[allow(dead_code)]
pub struct ExchangeService {
    supported_currencies: Vec<SupportedCurrency>,
    database: Arc<SqliteDatabase>,
    stellar_service: StellarService,
}

impl ExchangeService {
    pub fn new(database: Arc<SqliteDatabase>) -> Self {
        let supported_currencies = vec![
            SupportedCurrency {
                code: "XLM".to_string(),
                name: "Stellar Lumens".to_string(),
                symbol: "XLM".to_string(),
                asset_issuer: None,
                is_native: true,
                is_active: true,
            },
            SupportedCurrency {
                code: "USDC".to_string(),
                name: "USD Coin".to_string(),
                symbol: "$".to_string(),
                asset_issuer: Some("GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_string()),
                is_native: false,
                is_active: true,
            },
            SupportedCurrency {
                code: "USDT".to_string(),
                name: "Tether USD".to_string(),
                symbol: "USDT".to_string(),
                asset_issuer: Some("GCQTGZQQ5G4PTM2GL7CDIFKUBIPEC52BROAQIAPW53XBRJVN6ZJVTG6V".to_string()),
                is_native: false,
                is_active: true,
            },
            // For now, we'll keep KES, NGN, and GHS as mock currencies
            // until we have real Stellar anchors for them
            SupportedCurrency {
                code: "KES".to_string(),
                name: "Kenyan Shilling".to_string(),
                symbol: "KSh".to_string(),
                asset_issuer: Some("MOCK_KES_ANCHOR".to_string()),
                is_native: false,
                is_active: true,
            },
            SupportedCurrency {
                code: "NGN".to_string(),
                name: "Nigerian Naira".to_string(),
                symbol: "₦".to_string(),
                asset_issuer: Some("MOCK_NGN_ANCHOR".to_string()),
                is_native: false,
                is_active: true,
            },
            SupportedCurrency {
                code: "GHS".to_string(),
                name: "Ghanaian Cedi".to_string(),
                symbol: "₵".to_string(),
                asset_issuer: Some("MOCK_GHS_ANCHOR".to_string()),
                is_native: false,
                is_active: true,
            },
        ];

        Self {
            supported_currencies,
            database: database.clone(),
            stellar_service: StellarService::new(database),
        }
    }

    pub fn get_supported_currencies(&self) -> &Vec<SupportedCurrency> {
        &self.supported_currencies
    }

    /// Get real-time exchange rates using Stellar DEX (no more CoinGecko/FastForex/fallback)
    pub async fn get_exchange_rate(&self, from: &str, to: &str, amount: f64) -> Result<(f64, Vec<String>)> {
        // Use StellarService to get the best path and rate, passing supported_currencies
        self.stellar_service.get_best_path(from, to, amount, &self.supported_currencies).await
    }

    /// Preview a currency exchange using Stellar DEX pathfinding
    pub async fn calculate_exchange_preview(&self, request: &ExchangeRequest) -> Result<ExchangePreview> {
        let (rate, path) = self.get_exchange_rate(&request.from_currency, &request.to_currency, request.amount).await?;
        let to_amount = request.amount * rate;
        let estimated_fee = request.amount * 0.001; // 0.1% fee (can be adjusted)
        let total_cost = request.amount + estimated_fee;
        Ok(ExchangePreview {
            from_currency: request.from_currency.clone(),
            to_currency: request.to_currency.clone(),
            from_amount: request.amount,
            to_amount,
            exchange_rate: rate,
            estimated_fee,
            total_cost,
        })
    }

    /// Execute a currency exchange using Stellar DEX path payment
    pub async fn execute_exchange(&self, request: &ExchangeRequest) -> Result<ExchangeTransaction> {
        // Preview to get rate and path
        let (rate, path) = self.get_exchange_rate(&request.from_currency, &request.to_currency, request.amount).await?;
        let to_amount = request.amount * rate;
        let estimated_fee = request.amount * 0.001;
        let total_cost = request.amount + estimated_fee;
        // Get wallets
        let source_wallet = self.database.get_wallet_by_id(&request.source_wallet_id).await?;
        let destination_wallet = self.database.get_wallet_by_id(&request.destination_wallet_id).await?;
        // Perform path payment on Stellar
        let payment_result: PathPaymentResult = self.stellar_service.send_path_payment(
            &source_wallet,
            &destination_wallet,
            &request.from_currency,
            &request.to_currency,
            request.amount,
            &path
        ).await?;
        // Record transaction
        let transaction = ExchangeTransaction {
            id: Uuid::new_v4(),
            user_id: request.user_id,
            from_currency: request.from_currency.clone(),
            to_currency: request.to_currency.clone(),
            from_amount: request.amount,
            to_amount,
            exchange_rate: rate,
            fee_amount: estimated_fee,
            stellar_tx_hash: Some(payment_result.tx_hash),
            status: ExchangeStatus::Completed,
            created_at: Utc::now(),
            completed_at: Some(Utc::now()),
        };
        self.database.store_exchange_transaction(&transaction).await?;
        Ok(transaction)
    }

    pub async fn validate_exchange_request(&self, request: &ExchangeRequest) -> Result<()> {
        // Validate currencies are supported
        let from_supported = self.supported_currencies.iter()
            .any(|c| c.code == request.from_currency && c.is_active);
        let to_supported = self.supported_currencies.iter()
            .any(|c| c.code == request.to_currency && c.is_active);

        if !from_supported {
            return Err(crate::errors::AppError::ValidationError(
                format!("Currency {} is not supported", request.from_currency)
            ));
        }

        if !to_supported {
            return Err(crate::errors::AppError::ValidationError(
                format!("Currency {} is not supported", request.to_currency)
            ));
        }

        if request.from_currency == request.to_currency {
            return Err(crate::errors::AppError::ValidationError(
                "Cannot exchange same currency".to_string()
            ));
        }

        if request.amount <= 0.0 {
            return Err(crate::errors::AppError::ValidationError(
                "Amount must be greater than 0".to_string()
            ));
        }

        // Validate that source and destination wallets exist and belong to the user
        let source_wallet = self.database.get_wallet_by_id(&request.source_wallet_id).await?;

        let destination_wallet = self.database.get_wallet_by_id(&request.destination_wallet_id).await?;

        // Verify wallet ownership
        if source_wallet.user_id != request.user_id {
            return Err(crate::errors::AppError::ValidationError(
                "Source wallet does not belong to the user".to_string()
            ));
        }

        if destination_wallet.user_id != request.user_id {
            return Err(crate::errors::AppError::ValidationError(
                "Destination wallet does not belong to the user".to_string()
            ));
        }

        Ok(())
    }

    pub async fn get_user_wallets_for_currency(&self, user_id: &Uuid, _currency_code: &str) -> Result<Vec<StellarWallet>> {
        // Get all user's wallets
        let wallets = self.database.get_user_wallets(user_id).await?;
        
        // For now, return all wallets since any wallet can hold any asset
        // In the future, we might want to filter based on which wallets already hold the currency
        Ok(wallets)
    }

    pub async fn handle_exchange(&self, user_id: &Uuid, from_currency: &str, to_currency: &str, amount: f64, source_wallet_id: Uuid, destination_wallet_id: Uuid) -> Result<ExchangeTransaction> {
        // Create exchange request with wallet information
        let request = ExchangeRequest {
            user_id: *user_id,
            from_currency: from_currency.to_string(),
            to_currency: to_currency.to_string(),
            amount,
            source_wallet_id,
            destination_wallet_id,
        };

        // Validate the request
        self.validate_exchange_request(&request).await?;

        // Execute the exchange
        self.execute_exchange(&request).await
    }

    pub async fn get_user_exchange_history(&self, user_id: &Uuid) -> Result<Vec<ExchangeTransaction>> {
        // Get exchange history from the database
        let query = r#"
            SELECT id, user_id, from_currency, to_currency, from_amount, to_amount, 
                   exchange_rate, fee_amount, stellar_tx_hash, status, created_at, completed_at
            FROM exchange_transactions
            WHERE user_id = ?
            ORDER BY created_at DESC
        "#;

        let rows = sqlx::query(query)
            .bind(user_id.to_string())
            .fetch_all(self.database.get_pool())
            .await
            .map_err(|e| crate::errors::AppError::DatabaseError(format!("Failed to fetch exchange history: {}", e)))?;

        let transactions = rows.iter().map(|row: &sqlx::sqlite::SqliteRow| {
            ExchangeTransaction {
                id: Uuid::parse_str(row.get("id")).unwrap_or_default(),
                user_id: Uuid::parse_str(row.get("user_id")).unwrap_or_default(),
                from_currency: row.get("from_currency"),
                to_currency: row.get("to_currency"),
                from_amount: row.get("from_amount"),
                to_amount: row.get("to_amount"),
                exchange_rate: row.get("exchange_rate"),
                fee_amount: row.get("fee_amount"),
                stellar_tx_hash: row.get("stellar_tx_hash"),
                status: match row.get::<&str, _>("status").to_lowercase().as_str() {
                    "pending" => ExchangeStatus::Pending,
                    "processing" => ExchangeStatus::Processing,
                    "completed" => ExchangeStatus::Completed,
                    "failed" => ExchangeStatus::Failed,
                    "cancelled" => ExchangeStatus::Cancelled,
                    _ => ExchangeStatus::Failed,
                },
                created_at: DateTime::parse_from_rfc3339(row.get("created_at"))
                    .unwrap_or_default()
                    .with_timezone(&Utc),
                completed_at: row.get::<Option<String>, _>("completed_at")
                    .and_then(|s: String| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
            }
        }).collect();

        Ok(transactions)
    }
}