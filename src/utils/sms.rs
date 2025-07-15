use reqwest::Client;
use serde_json::json;
use std::env;

#[allow(dead_code)]
pub async fn send_sms_infobip(to: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let api_key = env::var("INFOBIP_API_KEY")?;
    let base_url = env::var("INFOBIP_BASE_URL")?;
    let sender = env::var("INFOBIP_SENDER").expect("INFOBIP_SENDER must be set in environment for production!");

    let url = format!("https://{}/sms/2/text/advanced", base_url);

    let payload = json!({
        "messages": [{
            "from": sender,
            "destinations": [{ "to": to }],
            "text": message
        }]
    });

    let client = Client::new();
    let res = client
        .post(&url)
        .header("Authorization", format!("App {}", api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("Failed to send SMS: {:?}", res.text().await?).into())
    }
} 