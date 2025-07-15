use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StellarWallet {
    pub id: Uuid,
    pub user_id: Uuid,
    pub public_key: String,
    pub encrypted_secret_key: String,  
    pub wallet_name: String,
    pub is_active: bool,
    pub balance_xlm: Option<String>,   
    pub sequence_number: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_sync_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub transaction_hash: String,
    pub transaction_type: String,  
    pub amount: String,
    pub asset_code: String,        
    pub asset_issuer: Option<String>,
    pub from_address: String,
    pub to_address: String,
    pub memo: Option<String>,
    pub fee: String,
    pub status: String,           
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    pub asset_type: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    pub balance: String,
    pub limit: Option<String>,
    pub buying_liabilities: String,
    pub selling_liabilities: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetBalance {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub asset_type: String,      
    pub asset_code: String,      
    pub asset_issuer: Option<String>,
    pub balance: String,         
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    pub wallet_name: String,
    pub password: String,  
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportWalletRequest {
    pub wallet_name: String,
    pub secret_key: String,
    pub password: String,  
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    pub public_key: String,
    pub wallet_name: String,
    pub balance_xlm: String,
    pub is_funded: bool,
    pub sequence_number: i64,
}