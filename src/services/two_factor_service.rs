use crate::errors::Result;
use crate::database::sqlite::SqliteDatabase;
use uuid::Uuid;
use qrcode::QrCode;
use base32::Alphabet;
use rand::Rng;
use std::sync::Arc;

pub struct TwoFactorService {
    database: Arc<SqliteDatabase>,
}

impl TwoFactorService {
    pub fn new(database: Arc<SqliteDatabase>) -> Self {
        Self { database }
    }

    /// Generate a new TOTP secret and backup codes
    pub async fn setup_2fa(&self, user_id: &Uuid, _email: &str) -> Result<(String, String, Vec<String>)> {
        let secret = self.generate_totp_secret();
        let backup_codes = self.generate_backup_codes();
        let backup_codes_json = serde_json::to_string(&backup_codes)?;
        self.database.setup_2fa(user_id, &secret, &backup_codes_json).await?;
        Ok((secret, backup_codes_json, backup_codes))
    }

    /// Generate QR code SVG for authenticator apps (in-memory, not file)
    pub fn generate_qr_code_svg(&self, secret: &str, email: &str, issuer: &str) -> Result<String> {
        let totp_url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            issuer, email, secret, issuer
        );
        let code = QrCode::new(&totp_url)
            .map_err(|e| crate::errors::AppError::InternalError(format!("QR code generation failed: {}", e)))?;
        let svg_string = code.render()
            .min_dimensions(200, 200)
            .dark_color(qrcode::render::svg::Color("#000000"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build();
        Ok(svg_string)
    }

    /// Verify a TOTP code
    pub async fn verify_totp(&self, user_id: &Uuid, code: &str) -> Result<bool> {
        self.database.verify_2fa(user_id, code).await
    }

    /// Disable 2FA for a user
    pub async fn disable_2fa(&self, user_id: &Uuid) -> Result<()> {
        self.database.disable_2fa(user_id).await
    }

    /// Check if 2FA is enabled for a user
    pub async fn is_2fa_enabled(&self, user_id: &Uuid) -> Result<bool> {
        let user = self.database.get_user_by_id(user_id).await?;
        Ok(user.totp_enabled)
    }

    /// Generate setup data for 2FA (QR code SVG, secret, backup codes)
    #[allow(dead_code)]
    pub async fn generate_setup_data(&self, user_id: &Uuid) -> Result<(String, String, Vec<String>)> {
        let user = self.database.get_user_by_id(user_id).await?;
        let secret = self.generate_totp_secret();
        let backup_codes = self.generate_backup_codes();
        let qr_code_svg = self.generate_qr_code_svg(&secret, &user.email, "Xendly")?;
        let backup_codes_json = serde_json::to_string(&backup_codes)?;
        self.database.setup_2fa(user_id, &secret, &backup_codes_json).await?;
        Ok((qr_code_svg, secret, backup_codes))
    }

    /// Enable 2FA for a user after verifying the TOTP code (used in API)
    #[allow(dead_code)]
    pub async fn enable_2fa(&self, user_id: &Uuid, totp_code: &str) -> Result<Vec<String>> {
        if !self.verify_totp(user_id, totp_code).await? {
            return Err(crate::errors::AppError::ValidationError("Invalid TOTP code".to_string()));
        }
        // Update the user's totp_enabled field directly
        let mut user = self.database.get_user_by_id(user_id).await?;
        user.totp_enabled = true;
        self.database.update_user_profile(&user).await?;
        let user = self.database.get_user_by_id(user_id).await?;
        if let Some(backup_codes_json) = user.backup_codes {
            let backup_codes: Vec<String> = serde_json::from_str(&backup_codes_json)?;
            Ok(backup_codes)
        } else {
            Ok(vec![])
        }
    }

    /// Generate a random TOTP secret
    fn generate_totp_secret(&self) -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..20).map(|_| rng.gen()).collect();
        base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes)
    }

    /// Generate backup codes
    fn generate_backup_codes(&self) -> Vec<String> {
        let mut rng = rand::thread_rng();
        (0..10).map(|_| {
            format!("{:08}", rng.gen_range(0..100000000))
        }).collect()
    }
} 