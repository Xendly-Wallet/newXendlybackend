use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedCurrency {
    pub code: String,
    pub name: String,
    pub symbol: String,
    pub asset_issuer: Option<String>,
    pub is_native: bool,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeRate {
    pub from_currency: String,
    pub to_currency: String,
    pub rate: f64,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeRequest {
    pub user_id: Uuid,
    pub from_currency: String,
    pub to_currency: String,
    pub amount: f64,
    pub source_wallet_id: Uuid,
    pub destination_wallet_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangePreview {
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: f64,
    pub to_amount: f64,
    pub exchange_rate: f64,
    pub estimated_fee: f64,
    pub total_cost: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeTransaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub from_currency: String,
    pub to_currency: String,
    pub from_amount: f64,
    pub to_amount: f64,
    pub exchange_rate: f64,
    pub fee_amount: f64,
    pub stellar_tx_hash: Option<String>,
    pub status: ExchangeStatus,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ExchangeStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for ExchangeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExchangeStatus::Pending => write!(f, "Pending"),
            ExchangeStatus::Processing => write!(f, "Processing"),
            ExchangeStatus::Completed => write!(f, "Completed"),
            ExchangeStatus::Failed => write!(f, "Failed"),
            ExchangeStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}