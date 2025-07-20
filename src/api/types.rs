use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;
use crate::models::stellar_wallet::AssetBalance;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    pub phone_number: Option<String>,
    // Add KYC fields as needed
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email_or_username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
    pub two_fa_required: bool,
    pub user_id: Option<uuid::Uuid>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TwoFAVerifyRequest {
    pub user_id: uuid::Uuid,
    pub totp_code: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TwoFAVerifyResponse {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateResponse {
    pub valid: bool,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RefreshResponse {
    pub token: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LogoutResponse {
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionsResponse {
    pub active_sessions: u32,
} 

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWalletRequest {
    pub wallet_name: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateWalletResponse {
    pub wallet_id: uuid::Uuid,
    pub public_key: String,
    pub wallet_name: String,
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportWalletRequest {
    pub wallet_name: String,
    pub secret_key: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportWalletResponse {
    pub wallet_id: uuid::Uuid,
    pub public_key: String,
    pub wallet_name: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WalletListResponse {
    pub wallets: Vec<WalletSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WalletSummary {
    pub wallet_id: uuid::Uuid,
    pub wallet_name: String,
    pub public_key: String,
    pub balances: Vec<AssetBalance>, // New: all asset balances (XLM, USDC, etc.)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WalletDetailsResponse {
    pub wallet_id: uuid::Uuid,
    pub wallet_name: String,
    pub public_key: String,
    pub balance_xlm: Option<String>,
    pub balances: Vec<AssetBalance>, // New: all asset balances (XLM, USDC, etc.)
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WalletBalanceResponse {
    pub balance_xlm: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WalletMultiAssetBalanceResponse {
    pub balances: Vec<AssetBalance>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendPaymentRequest {
    /// Destination Stellar address (public key)
    pub destination: String,
    /// Amount to send (in asset units)
    pub amount: f64,
    /// Asset code to send (e.g. "XLM" or "USDC"). Issuer is handled by backend.
    pub asset_code: Option<String>,
    /// Optional memo for the transaction
    pub memo: Option<String>,
    /// Wallet password for signing
    pub password: String,
    /// TOTP code for 2FA (required if 2FA is enabled)
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SendPaymentResponse {
    pub transaction_hash: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TransactionHistoryResponse {
    pub transactions: Vec<TransactionSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TransactionSummary {
    pub hash: String,
    pub amount: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub from: String,
    pub to: String,
    pub memo: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String, // New: transaction status (pending, completed, failed, etc.)
} 

#[derive(Debug, Serialize, ToSchema)]
pub struct FundWalletResponse {
    pub wallet_id: uuid::Uuid,
    pub public_key: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReceiveWalletResponse {
    pub wallet_id: uuid::Uuid,
    pub public_key: String,
    pub qr_code_url: Option<String>,
    pub supported_assets: Vec<AssetBalance>,
    pub message: String,
} 

#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationItem {
    pub id: uuid::Uuid,
    pub title: String,
    pub message: String,
    pub date: chrono::DateTime<chrono::Utc>,
    pub status: String, // e.g. "Unread" or "Read"
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationResponse {
    pub notifications: Vec<NotificationItem>,
} 

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub user_id: uuid::Uuid,
    pub current_password: String,
    pub new_password: String,
    /// TOTP code for 2FA (required if 2FA is enabled)
    pub totp_code: Option<String>,
} 

#[derive(Debug, Deserialize, ToSchema)]
pub struct Disable2FARequest {
    pub user_id: uuid::Uuid,
    /// TOTP code for 2FA (required)
    pub totp_code: String,
} 

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteAccountRequest {
    pub user_id: uuid::Uuid,
    pub password: String,
    /// TOTP code for 2FA (required if 2FA is enabled)
    pub totp_code: Option<String>,
} 

#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileResponse {
    pub user_id: uuid::Uuid,
    pub email: String,
    pub username: String,
    pub is_verified: bool,
    pub phone_number: Option<String>,
    pub is_phone_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub phone_number: Option<String>, // Allow updating phone number
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePhoneRequest {
    pub phone_number: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SendPhoneVerificationRequest {
    pub phone_number: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SendPhoneVerificationResponse {
    pub message: String,
    pub success: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyPhoneCodeRequest {
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyPhoneCodeResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TwoFAStatusResponse {
    pub enabled: bool,
    pub setup_complete: bool,
    pub backup_codes_remaining: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TwoFASetupResponse {
    pub qr_code_svg: String,
    pub secret_key: String,
    pub backup_codes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Enable2FARequest {
    pub totp_code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Enable2FAResponse {
    pub success: bool,
    pub message: String,
    pub backup_codes: Vec<String>,
} 

#[derive(Debug, Deserialize, ToSchema)]
pub struct KycSubmitRequest {
    pub full_name: String,
    pub id_type: String,
    pub id_number: String,
    pub id_photo_url: String, // For MVP, accept a file path or base64 string
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KycStatusResponse {
    pub status: String,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KycSubmissionResponse {
    pub id: Uuid,
    pub full_name: String,
    pub id_type: String,
    pub id_number: String,
    pub id_photo_url: String,
    pub status: String,
    pub submitted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rejection_reason: Option<String>,
} 

#[derive(Debug, Serialize, ToSchema)]
pub struct KycFileUploadResponse {
    pub file_url: String,
} 

#[derive(Debug, Serialize, ToSchema)]
pub struct KycAdminListResponse {
    pub submissions: Vec<KycSubmissionResponse>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct KycReviewRequest {
    pub status: String, // "approved" or "rejected"
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KycReviewResponse {
    pub success: bool,
    pub message: String,
} 