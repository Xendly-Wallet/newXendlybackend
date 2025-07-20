use reqwest::Client;
use std::env;
use serde_json;

pub async fn send_sms_africastalking(to: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let creds = env::var("BULK_SMS_API")?;
    let mut parts = creds.splitn(2, ':');
    let username = parts.next().ok_or("Missing username in BULK_SMS_API")?;
    let api_key = parts.next().ok_or("Missing api_key in BULK_SMS_API")?;
    let sender = env::var("BULK_SMS_SENDER").unwrap_or_else(|_| "Xendly".to_string());
    let url = "https://api.africastalking.com/version1/messaging/bulk";
    let payload = [
        ("username", username),
        ("to", to),
        ("message", message),
        ("from", &sender),
    ];
    let client = Client::new();
    let res = client
        .post(url)
        .header("apiKey", api_key)
        .form(&payload)
        .send()
        .await?;
    if res.status().is_success() {
        Ok(())
    } else {
        let err_text = res.text().await.unwrap_or_default();
        Err(format!("Failed to send SMS: {}", err_text).into())
    }
}

/// Send a welcome SMS to new users
/// Includes account details and next steps
pub async fn send_welcome_sms(phone_number: &str, username: &str, email: &str) -> Result<(), Box<dyn std::error::Error>> {
    let welcome_message = format!(
        "🎉 Welcome to Xendly!\n\n\
        Your account has been created successfully.\n\
        Username: {}\n\
        Email: {}\n\n\
        Next steps:\n\
        • Log in to your account\n\
        • Create your first wallet\n\
        • Start sending and receiving payments\n\n\
        Need help? Contact us at support@xendly.com\n\
        Visit: https://xendly.com\n\n\
        Thank you for choosing Xendly! 🚀",
        username, email
    );
    
    send_sms_africastalking(phone_number, &welcome_message).await
}

/// Send a phone verification SMS
pub async fn send_verification_sms(phone_number: &str, code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let verification_message = format!(
        "🔐 Xendly Phone Verification\n\n\
        Your verification code is: {}\n\n\
        This code is valid for 10 minutes.\n\
        If you didn't request this code, please ignore this message.\n\n\
        Xendly Team",
        code
    );
    
    send_sms_africastalking(phone_number, &verification_message).await
}

/// Test Africa's Talking credentials
pub async fn test_africastalking_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let creds = env::var("BULK_SMS_API")?;
    let mut parts = creds.splitn(2, ':');
    let username = parts.next().ok_or("Missing username in BULK_SMS_API")?;
    let api_key = parts.next().ok_or("Missing api_key in BULK_SMS_API")?;
    
    println!("Testing credentials:");
    println!("Username: {}", username);
    println!("API Key: {}...", &api_key[..8]);
    
    let url = "https://api.africastalking.com/version1/messaging/bulk";
    let payload = serde_json::json!({
        "username": username,
        "phoneNumbers": ["+254712345678"],
        "message": "Test message from Xendly",
        "from": "Xendly"
    });
    
    let client = Client::new();
    let res = client
        .post(url)
        .header("apiKey", api_key)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;
    
    println!("Response status: {}", res.status());
    let body = res.text().await?;
    println!("Response body: {}", body);
    
    Ok(())
} 