use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KycSubmission {
    pub id: Uuid,
    pub user_id: Uuid,
    pub full_name: String,
    pub id_type: String,
    pub id_number: String,
    pub id_photo_url: String,
    pub status: String, // "not_submitted", "pending", "approved", "rejected"
    pub submitted_at: Option<DateTime<Utc>>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub rejection_reason: Option<String>,
} 