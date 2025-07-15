use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    IncomingPayment,
    OutgoingPayment,
    PaymentFailed,
    BalanceChange,
    LowBalance,
    SecurityAlert,
    ExchangeCompleted,
    ExchangeFailed,
    SystemAlert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    Email,
    SMS,
    Push,
    InApp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub notification_type: NotificationType,
    pub title: String,
    pub message: String,
    pub priority: NotificationPriority,
    pub channels: Vec<NotificationChannel>,
    pub metadata: Option<serde_json::Value>,
    pub is_read: bool,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NotificationPreferences {
    pub user_id: Uuid,
    pub email_enabled: bool,
    pub sms_enabled: bool,
    pub push_enabled: bool,
    pub in_app_enabled: bool,
    pub incoming_payment_alerts: bool,
    pub outgoing_payment_alerts: bool,
    pub payment_failure_alerts: bool,
    pub balance_change_alerts: bool,
    pub low_balance_threshold: Option<f64>,
    pub security_alerts: bool,
    pub exchange_alerts: bool,
    pub system_alerts: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplate {
    pub id: Uuid,
    pub template_name: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
    pub variables: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Notification metadata structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentNotificationMetadata {
    pub transaction_hash: String,
    pub amount: String,
    pub currency: String,
    pub from_address: Option<String>,
    pub to_address: Option<String>,
    pub memo: Option<String>,
    pub fee: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceChangeMetadata {
    pub old_balance: String,
    pub new_balance: String,
    pub change_amount: String,
    pub currency: String,
    pub change_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlertMetadata {
    pub alert_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub location: Option<String>,
    pub timestamp: DateTime<Utc>,
} 