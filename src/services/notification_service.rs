use crate::errors::Result;
use crate::models::notification::*;
use crate::database::sqlite::SqliteDatabase;
use chrono::Utc;
use serde_json;
use std::sync::Arc;
use uuid::Uuid;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

pub struct NotificationService {
    database: Arc<SqliteDatabase>,
    from_email: String,
}

impl NotificationService {
    pub fn new(database: Arc<SqliteDatabase>) -> Self {
        Self {
            database,
            from_email: std::env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@stellarwallet.com".to_string()),
        }
    }

    // Send incoming payment notification
    pub async fn send_incoming_payment_notification(
        &self,
        user_id: &Uuid,
        recipient_email: &str,
        amount: &str,
        currency: &str,
        from_address: &str,
        transaction_hash: &str,
        memo: Option<&str>
    ) -> Result<()> {
        let title = format!("💰 You received {} {}!", amount, currency);
        let message = format!(
            "You just received {} {} from {}. Transaction hash: {}",
            amount, currency, from_address, transaction_hash
        );

        // Create notification record
        let notification = Notification {
            id: Uuid::new_v4(),
            user_id: *user_id,
            notification_type: NotificationType::IncomingPayment,
            title: title.clone(),
            message: message.clone(),
            priority: NotificationPriority::High,
            channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            metadata: Some(serde_json::json!({
                "transaction_hash": transaction_hash,
                "amount": amount,
                "currency": currency,
                "from_address": from_address,
                "memo": memo
            })),
            is_read: false,
            created_at: Utc::now(),
            sent_at: None,
        };

        // Store notification in database
        self.database.store_notification(&notification).await?;

        // Send email notification via SMTP
        if let Err(e) = Self::send_email_smtp(&self.from_email, recipient_email, &title, &message).await {
            eprintln!("Failed to send email notification: {}", e);
        }

        // Print notification to console
        println!("🔔 Notification: {}", title);
        println!("📧 Message: {}", message);

        // Update sent_at timestamp
        self.database.mark_notification_sent(&notification.id).await?;

        Ok(())
    }

    // Send outgoing payment notification
    pub async fn send_outgoing_payment_notification(
        &self,
        user_id: &Uuid,
        sender_email: &str,
        amount: &str,
        currency: &str,
        to_address: &str,
        transaction_hash: &str,
        memo: Option<&str>
    ) -> Result<()> {
        let title = format!("🚀 You sent {} {}!", amount, currency);
        let message = format!(
            "You just sent {} {} to {}. Transaction hash: {}",
            amount, currency, to_address, transaction_hash
        );

        // Create notification record
        let notification = Notification {
            id: Uuid::new_v4(),
            user_id: *user_id,
            notification_type: NotificationType::OutgoingPayment,
            title: title.clone(),
            message: message.clone(),
            priority: NotificationPriority::High,
            channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            metadata: Some(serde_json::json!({
                "transaction_hash": transaction_hash,
                "amount": amount,
                "currency": currency,
                "to_address": to_address,
                "memo": memo
            })),
            is_read: false,
            created_at: Utc::now(),
            sent_at: None,
        };

        // Store notification in database
        self.database.store_notification(&notification).await?;

        // Send email notification via SMTP
        if let Err(e) = Self::send_email_smtp(&self.from_email, sender_email, &title, &message).await {
            eprintln!("Failed to send email notification: {}", e);
        }

        // Print notification to console
        println!("🔔 Notification: {}", title);
        println!("📧 Message: {}", message);

        // Update sent_at timestamp
        self.database.mark_notification_sent(&notification.id).await?;

        Ok(())
    }

    // Send payment failed notification
    pub async fn send_payment_failed_notification(
        &self,
        user_id: &Uuid,
        email: &str,
        amount: &str,
        currency: &str,
        destination: &str,
        reason: &str,
        memo: Option<&str>,
    ) -> Result<()> {
        // Check user preferences
        if let Some(prefs) = self.get_notification_preferences(user_id).await? {
            if !prefs.payment_failure_alerts {
                return Ok(()); // User opted out
            }
        }
        let title = format!("❌ Payment Failed: {} {} to {}", amount, currency, destination);
        let message = format!(
            "Your payment of {} {} to {} failed. Reason: {}{}",
            amount,
            currency,
            destination,
            reason,
            if let Some(m) = memo { format!("\nMemo: {}", m) } else { String::new() }
        );
        let notification = Notification {
            id: Uuid::new_v4(),
            user_id: *user_id,
            notification_type: NotificationType::PaymentFailed,
            title: title.clone(),
            message: message.clone(),
            priority: NotificationPriority::High,
            channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            metadata: Some(serde_json::json!({
                "amount": amount,
                "currency": currency,
                "destination": destination,
                "reason": reason,
                "memo": memo
            })),
            is_read: false,
            created_at: Utc::now(),
            sent_at: None,
        };
        self.database.store_notification(&notification).await?;
        // Send email if enabled
        if let Some(prefs) = self.get_notification_preferences(user_id).await? {
            if prefs.email_enabled {
                let _ = Self::send_email_smtp(&self.from_email, email, &title, &message).await;
            }
        }
        println!("🔔 Notification: {}", title);
        println!("📧 Message: {}", message);
        self.database.mark_notification_sent(&notification.id).await?;
        Ok(())
    }

    // Send balance change notification
    pub async fn send_balance_change_notification(
        &self,
        user_id: &Uuid,
        email: &str,
        old_balance: f64,
        new_balance: f64,
        currency: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        // Check user preferences
        if let Some(prefs) = self.get_notification_preferences(user_id).await? {
            if !prefs.balance_change_alerts {
                return Ok(()); // User opted out
            }
        }
        let change_amount = new_balance - old_balance;
        let change_percentage = if old_balance.abs() > f64::EPSILON {
            (change_amount / old_balance) * 100.0
        } else {
            0.0
        };
        let title = format!("💱 Balance Change: {} {} → {} {}", old_balance, currency, new_balance, currency);
        let message = format!(
            "Your wallet balance changed from {} {} to {} {} (change: {:+} {}, {:.2}% change){}",
            old_balance,
            currency,
            new_balance,
            currency,
            change_amount,
            currency,
            change_percentage,
            if let Some(r) = reason { format!("\nReason: {}", r) } else { String::new() }
        );
        let notification = Notification {
            id: Uuid::new_v4(),
            user_id: *user_id,
            notification_type: NotificationType::BalanceChange,
            title: title.clone(),
            message: message.clone(),
            priority: NotificationPriority::Medium,
            channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            metadata: Some(serde_json::json!({
                "old_balance": old_balance,
                "new_balance": new_balance,
                "change_amount": change_amount,
                "currency": currency,
                "change_percentage": change_percentage,
                "reason": reason
            })),
            is_read: false,
            created_at: Utc::now(),
            sent_at: None,
        };
        self.database.store_notification(&notification).await?;
        // Send email if enabled
        if let Some(prefs) = self.get_notification_preferences(user_id).await? {
            if prefs.email_enabled {
                let _ = Self::send_email_smtp(&self.from_email, email, &title, &message).await;
            }
        }
        println!("🔔 Notification: {}", title);
        println!("📧 Message: {}", message);
        self.database.mark_notification_sent(&notification.id).await?;
        Ok(())
    }

    // Send low balance notification (avoid spamming: only send if not already sent for this threshold)
    pub async fn send_low_balance_notification(
        &self,
        user_id: &Uuid,
        email: &str,
        balance: f64,
        currency: &str,
    ) -> Result<()> {
        // Check user preferences
        let prefs = match self.get_notification_preferences(user_id).await? {
            Some(p) => p,
            None => return Ok(()),
        };
        let threshold = match prefs.low_balance_threshold {
            Some(t) => t,
            None => return Ok(()),
        };
        if !prefs.balance_change_alerts {
            return Ok(()); // User opted out
        }
        if balance >= threshold {
            return Ok(()); // Not below threshold
        }
        // Avoid spamming: check if a LowBalance notification was sent recently (e.g., last 24h)
        let recent = self.database.get_user_notifications(user_id, Some(10)).await?.into_iter()
            .filter(|n| matches!(n.notification_type, NotificationType::LowBalance))
            .filter(|n| n.created_at > Utc::now() - chrono::Duration::hours(24))
            .any(|n| {
                if let Some(meta) = &n.metadata {
                    meta.get("threshold").and_then(|t| t.as_f64()) == Some(threshold)
                } else {
                    false
                }
            });
        if recent {
            return Ok(()); // Already notified recently for this threshold
        }
        let title = format!("⚠️ Low Balance: {} {} (Threshold: {} {})", balance, currency, threshold, currency);
        let message = format!(
            "Your wallet balance is low: {} {} (threshold: {} {}). Please fund your wallet to avoid interruptions.",
            balance, currency, threshold, currency
        );
        let notification = Notification {
            id: Uuid::new_v4(),
            user_id: *user_id,
            notification_type: NotificationType::LowBalance,
            title: title.clone(),
            message: message.clone(),
            priority: NotificationPriority::High,
            channels: vec![NotificationChannel::Email, NotificationChannel::InApp],
            metadata: Some(serde_json::json!({
                "balance": balance,
                "currency": currency,
                "threshold": threshold
            })),
            is_read: false,
            created_at: Utc::now(),
            sent_at: None,
        };
        self.database.store_notification(&notification).await?;
        if prefs.email_enabled {
            let _ = Self::send_email_smtp(&self.from_email, email, &title, &message).await;
        }
        println!("🔔 Notification: {}", title);
        println!("📧 Message: {}", message);
        self.database.mark_notification_sent(&notification.id).await?;
        Ok(())
    }

    // Send email notification via SMTP
    async fn send_email_smtp(_from_email: &str, to_email: &str, subject: &str, body: &str) -> std::result::Result<(), String> {
        // Hardcoded SMTP configuration for production
        let smtp_server = "smtp.gmail.com";
        let smtp_port: u16 = 587;
        let smtp_username = "625deon@gmail.com";
        //let smtp_password = "nful ozuw xuvg mxhq";
        let smtp_password = "viar thtx qfri zrlc";
        let from_email = "625deon@gmail.com";

        let email = Message::builder()
            .from(from_email.parse().map_err(|e| format!("From parse error: {}", e))?)
            .to(to_email.parse().map_err(|e| format!("To parse error: {}", e))?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| format!("Message build error: {}", e))?;

        let creds = Credentials::new(smtp_username.to_string(), smtp_password.to_string());

        //let mailer = SmtpTransport::relay(smtp_server)
        let mailer = SmtpTransport::starttls_relay(smtp_server)
            .map_err(|e| format!("SMTP relay error: {}", e))?
            .port(smtp_port)
            .credentials(creds)
            .build();

        mailer.send(&email).map_err(|e| format!("Send error: {}", e))?;
        Ok(())
    }

    // Get user's notifications
    pub async fn get_user_notifications(&self, user_id: &Uuid, limit: Option<i64>) -> Result<Vec<Notification>> {
        self.database.get_user_notifications(user_id, limit).await
    }

    // Mark notification as read
    pub async fn mark_notification_read(&self, notification_id: &Uuid) -> Result<()> {
        self.database.mark_notification_read(notification_id).await
    }

    // Mark all notifications as read for a user
    pub async fn mark_all_notifications_read(&self, user_id: &Uuid) -> Result<()> {
        self.database.mark_all_notifications_read(user_id).await
    }

    // Delete a single notification by ID
    pub async fn delete_notification(&self, notification_id: &Uuid) -> Result<()> {
        self.database.delete_notification(notification_id).await
    }

    // Delete all notifications for a user
    pub async fn delete_all_notifications(&self, user_id: &Uuid) -> Result<()> {
        self.database.delete_all_notifications(user_id).await
    }

    // Get notification preferences for a user
    pub async fn get_notification_preferences(&self, user_id: &Uuid) -> Result<Option<NotificationPreferences>> {
        self.database.get_notification_preferences(user_id).await
    }

    // Set notification preferences (insert)
    pub async fn set_notification_preferences(&self, prefs: &NotificationPreferences) -> Result<()> {
        self.database.set_notification_preferences(prefs).await
    }

    // Update notification preferences
    pub async fn update_notification_preferences(&self, prefs: &NotificationPreferences) -> Result<()> {
        self.database.update_notification_preferences(prefs).await
    }
} 