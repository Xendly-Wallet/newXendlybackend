use axum::{Router, routing::{post, get, delete, put}, Json, extract::{FromRequestParts}, http::{StatusCode, request::Parts, header::AUTHORIZATION}, response::IntoResponse};
use axum::extract::Path;
use crate::api::types::*;
use crate::database::sqlite::GLOBAL_DB;
use crate::database::sqlite::SqliteDatabase;
use crate::utils::crypto::PasswordManager;
use uuid::Uuid;
use std::sync::Arc;
use crate::services::auth::AuthService;
use crate::services::jwt::JwtManager;
use crate::services::stellar_service::StellarService;
use serde::Serialize;
use tracing::{info, error};
use crate::utils::validation::Validator;
use qrcode::QrCode;
use qrcode::render::svg;
use base64::{engine::general_purpose, Engine as _};

// JWT extractor for Authorization: Bearer ...
pub struct AuthBearer(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthBearer
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(auth) = parts.headers.get(AUTHORIZATION) {
            if let Ok(auth_str) = auth.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    return Ok(AuthBearer(token.to_string()));
                }
            }
        }
        Err((StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header".to_string()))
    }
}

// Helper to extract user from JWT
async fn user_from_token(token: &str, _db: Arc<SqliteDatabase>) -> Result<crate::services::jwt::AuthenticatedUser, (StatusCode, String)> {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set in environment for production!");
    let jwt_manager = JwtManager::new(jwt_secret);
    let token_data = jwt_manager.validate_token(token).map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e)))?;
    crate::services::jwt::AuthenticatedUser::try_from(token_data.claims).map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e)))
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SupportedAsset {
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub display_name: String,
}

/// Main API router
#[allow(dead_code)] // Not used, kept for possible future router composition
pub fn api_router() -> Router {
    Router::new()
        .nest("/auth", auth_router())
        .nest("/wallets", wallet_router())
        .nest("/profile", profile_router())
        .nest("/notifications", notifications_router())
        .route("/assets", get(list_supported_assets))
}

/// Auth API endpoints
pub fn auth_router() -> Router {
    Router::new()
        // .route("/register", post(register)) // Removed to avoid duplicate registration
        .route("/2fa-verify", post(two_fa_verify))
        .route("/change-password", post(change_password))
        .route("/disable-2fa", post(disable_2fa))
        .route("/delete-account", post(delete_account))
        .route("/validate", post(validate))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(sessions))
}

#[utoipa::path(post, path = "/api/auth/register", request_body = RegisterRequest, responses((status = 200, body = RegisterResponse)))]
pub async fn register(
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let email = req.email.trim().to_string();
    let username = req.username.trim().to_string();
    // Validate email, username, password, phone
    if let Err(_e) = Validator::validate_email(&email) {
        return (StatusCode::BAD_REQUEST, Json(RegisterResponse {
            user_id: Uuid::nil(),
            message: "Invalid email address.".to_string(),
        }));
    }
    if let Err(_e) = Validator::validate_username(&username) {
        return (StatusCode::BAD_REQUEST, Json(RegisterResponse {
            user_id: Uuid::nil(),
            message: "Invalid username.".to_string(),
        }));
    }
    if let Err(_e) = Validator::validate_password(&req.password) {
        return (StatusCode::BAD_REQUEST, Json(RegisterResponse {
            user_id: Uuid::nil(),
            message: "Invalid password.".to_string(),
        }));
    }
    if let Some(phone) = &req.phone_number {
        if let Err(_e) = Validator::validate_phone(phone) {
            return (StatusCode::BAD_REQUEST, Json(RegisterResponse {
                user_id: Uuid::nil(),
                message: "Invalid phone number.".to_string(),
            }));
        }
    }
    // Check if user already exists
    if let Ok(Some(_)) = db.get_user_by_email(&email).await {
        info!(action = "register_email_conflict", user = %email);
        return (StatusCode::CONFLICT, Json(RegisterResponse {
            user_id: Uuid::nil(),
            message: "This email is already registered. Try logging in or use a different email.".to_string(),
        }));
    }
    if let Ok(Some(_)) = db.get_user_by_username(&username).await {
        info!(action = "register_username_conflict", user = %username);
        return (StatusCode::CONFLICT, Json(RegisterResponse {
            user_id: Uuid::nil(),
            message: "This username is already taken. Please choose another.".to_string(),
        }));
    }
    // Hash password
    let password_hash = match PasswordManager::hash_password(&req.password) {
        Ok(hash) => hash,
        Err(e) => {
            error!(action = "register_password_hash_failed", user = %email, error = %e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(RegisterResponse {
                user_id: Uuid::nil(),
                message: "An internal error occurred. Please try again later.".to_string(),
            }));
        }
    };
    // Create user
    let user_id = Uuid::new_v4();
    let user = crate::models::user::User {
        id: user_id,
        email: email.clone(),
        username,
        password_hash,
        is_verified: false,
        stellar_public_key: None,
        phone_number: req.phone_number,
        is_phone_verified: false,
        phone_verification_code: None,
        phone_verified_at: None,
        totp_secret: None,
        totp_enabled: false,
        backup_codes: None,
        is_deleted: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    if let Err(e) = db.create_user(&user).await {
        error!(action = "register_user_create_failed", user = %email, error = %e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(RegisterResponse {
            user_id: Uuid::nil(),
            message: "Could not create account. Please check your details and try again.".to_string(),
        }));
    }
    info!(action = "register_success", user = %email);
    (StatusCode::OK, Json(RegisterResponse {
        user_id,
        message: "User registered successfully".to_string(),
    }))
}

#[utoipa::path(post, path = "/api/auth/login", request_body = LoginRequest, responses((status = 200, body = LoginResponse)))]
pub async fn login(
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let auth_service = AuthService::new(db.clone());
    match auth_service.login_with_2fa_check(&req.email_or_username, &req.password).await {
        Ok(crate::services::auth::Login2FAResult::Token(token)) => {
            info!(action = "login_success", user = %req.email_or_username);
            (StatusCode::OK, Json(LoginResponse {
                token,
                expires_in: 86400,
                two_fa_required: false,
                user_id: None,
            }))
        }
        Ok(crate::services::auth::Login2FAResult::TwoFARequired { user_id }) => {
            info!(action = "login_2fa_required", user = %req.email_or_username);
            (StatusCode::OK, Json(LoginResponse {
                token: "".to_string(),
                expires_in: 0,
                two_fa_required: true,
                user_id: Some(user_id),
            }))
        }
        Err(e) => {
            error!(action = "login_failed", user = %req.email_or_username, error = %e);
            (StatusCode::UNAUTHORIZED, Json(LoginResponse {
                token: "".to_string(),
                expires_in: 0,
                two_fa_required: false,
                user_id: None,
            }))
        }
    }
}

#[utoipa::path(post, path = "/api/auth/validate", request_body = TokenRequest, responses((status = 200, body = ValidateResponse)))]
pub async fn validate(
    Json(req): Json<TokenRequest>,
) -> impl IntoResponse {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let auth_service = AuthService::new(db.clone());
    match auth_service.validate_token(&req.token).await {
        Ok(user) => (StatusCode::OK, Json(ValidateResponse {
            valid: true,
            user_id: Some(user.user_id),
            username: Some(user.username),
            email: Some(user.email),
        })),
        Err(_e) => (StatusCode::UNAUTHORIZED, Json(ValidateResponse {
            valid: false,
            user_id: None,
            username: None,
            email: None,
        })),
    }
}

#[utoipa::path(post, path = "/api/auth/refresh", request_body = TokenRequest, responses((status = 200, body = RefreshResponse)))]
pub async fn refresh(
    Json(req): Json<TokenRequest>,
) -> impl IntoResponse {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let auth_service = AuthService::new(db.clone());
    match auth_service.refresh_token(&req.token).await {
        Ok(token) => (StatusCode::OK, Json(RefreshResponse {
            token,
            expires_in: 86400,
        })),
        Err(_e) => (StatusCode::UNAUTHORIZED, Json(RefreshResponse {
            token: "".to_string(),
            expires_in: 0,
        })),
    }
}

#[utoipa::path(post, path = "/api/auth/logout", request_body = TokenRequest, responses((status = 200, body = LogoutResponse)))]
pub async fn logout(
    Json(req): Json<TokenRequest>,
) -> impl IntoResponse {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let auth_service = AuthService::new(db.clone());
    match auth_service.logout(&req.token).await {
        Ok(_) => (StatusCode::OK, Json(LogoutResponse {
            message: "Logged out successfully".to_string(),
        })),
        Err(_e) => (StatusCode::UNAUTHORIZED, Json(LogoutResponse {
            message: "Logout failed".to_string(),
        })),
    }
}

#[utoipa::path(post, path = "/api/auth/logout-all", request_body = TokenRequest, responses((status = 200, body = LogoutResponse)))]
pub async fn logout_all(
    Json(req): Json<TokenRequest>,
) -> impl IntoResponse {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let auth_service = AuthService::new(db.clone());
    match auth_service.logout_all_devices(&req.token).await {
        Ok(_) => (StatusCode::OK, Json(LogoutResponse {
            message: "Logged out all sessions successfully".to_string(),
        })),
        Err(_e) => (StatusCode::UNAUTHORIZED, Json(LogoutResponse {
            message: "Logout all sessions failed".to_string(),
        })),
    }
}

#[utoipa::path(get, path = "/api/auth/sessions", responses((status = 200, body = SessionsResponse)))]
pub async fn sessions() -> Json<SessionsResponse> {
    Json(SessionsResponse {
        active_sessions: 1,
    })
}

#[utoipa::path(post, path = "/api/auth/2fa-verify", request_body = TwoFAVerifyRequest, responses((status = 200, body = TwoFAVerifyResponse), (status = 401, description = "Invalid TOTP or user")))]
pub async fn two_fa_verify(
    Json(req): Json<TwoFAVerifyRequest>,
) -> impl IntoResponse {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let user = match db.get_user_by_id(&req.user_id).await {
        Ok(u) => u,
        Err(_) => return (StatusCode::UNAUTHORIZED, Json(TwoFAVerifyResponse { token: "".to_string(), expires_in: 0 })),
    };
    let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
    match two_factor_service.verify_totp(&req.user_id, &req.totp_code).await {
        Ok(true) => {
            let auth_service = AuthService::new(db.clone());
            match auth_service.generate_jwt(&user.id).await {
                Ok(token) => (StatusCode::OK, Json(TwoFAVerifyResponse { token, expires_in: 86400 })),
                Err(e) => {
                    error!(action = "2fa_jwt_issue_failed", user_id = %user.id, error = %e);
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(TwoFAVerifyResponse { token: "".to_string(), expires_in: 0 }))
                }
            }
        }
        _ => (StatusCode::UNAUTHORIZED, Json(TwoFAVerifyResponse { token: "".to_string(), expires_in: 0 })),
    }
}

#[utoipa::path(post, path = "/api/auth/change-password", request_body = ChangePasswordRequest, responses((status = 200, description = "Password changed successfully"), (status = 401, description = "Unauthorized or invalid JWT or TOTP"), (status = 400, description = "Validation error")))]
pub async fn change_password(
    AuthBearer(token): AuthBearer,
    Json(req): Json<ChangePasswordRequest>,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => return StatusCode::UNAUTHORIZED,
    };
    let user_record = match db.get_user_by_id(&req.user_id).await {
        Ok(u) => u,
        Err(_) => return StatusCode::UNAUTHORIZED,
    };
    if user_record.totp_enabled {
        let totp_code = req.totp_code.as_deref().unwrap_or("");
        let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
        match two_factor_service.verify_totp(&req.user_id, totp_code).await {
            Ok(true) => {},
            _ => return StatusCode::UNAUTHORIZED,
        }
    }
    let user_service = crate::services::user_service::UserService { db: db.clone() };
    match user_service.change_user_password(&req.user_id, &req.current_password, &req.new_password).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            error!(action = "change_password_failed", user_id = %req.user_id, error = %e);
            StatusCode::BAD_REQUEST
        }
    }
}

#[utoipa::path(post, path = "/api/auth/disable-2fa", request_body = Disable2FARequest, responses((status = 200, description = "2FA disabled successfully"), (status = 401, description = "Unauthorized or invalid JWT or TOTP"), (status = 400, description = "Validation error")))]
pub async fn disable_2fa(
    AuthBearer(token): AuthBearer,
    Json(req): Json<Disable2FARequest>,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => return StatusCode::UNAUTHORIZED,
    };
    let user_record = match db.get_user_by_id(&req.user_id).await {
        Ok(u) => u,
        Err(_) => return StatusCode::UNAUTHORIZED,
    };
    if !user_record.totp_enabled {
        return StatusCode::BAD_REQUEST;
    }
    let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
    match two_factor_service.verify_totp(&req.user_id, &req.totp_code).await {
        Ok(true) => {},
        _ => return StatusCode::UNAUTHORIZED,
    }
    match two_factor_service.disable_2fa(&req.user_id).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            error!(action = "disable_2fa_failed", user_id = %req.user_id, error = %e);
            StatusCode::BAD_REQUEST
        }
    }
}

#[utoipa::path(post, path = "/api/auth/delete-account", request_body = DeleteAccountRequest, responses((status = 200, description = "Account deleted successfully"), (status = 401, description = "Unauthorized or invalid JWT, password, or TOTP"), (status = 400, description = "Validation error")))]
pub async fn delete_account(
    AuthBearer(token): AuthBearer,
    Json(req): Json<DeleteAccountRequest>,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => return StatusCode::UNAUTHORIZED,
    };
    let user_record = match db.get_user_by_id(&req.user_id).await {
        Ok(u) => u,
        Err(_) => return StatusCode::UNAUTHORIZED,
    };
    // Verify password
    if !crate::utils::crypto::PasswordManager::verify_password(&req.password, &user_record.password_hash).unwrap_or(false) {
        return StatusCode::UNAUTHORIZED;
    }
    // If 2FA is enabled, verify TOTP
    if user_record.totp_enabled {
        let totp_code = req.totp_code.as_deref().unwrap_or("");
        let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
        match two_factor_service.verify_totp(&req.user_id, totp_code).await {
            Ok(true) => {},
            _ => return StatusCode::UNAUTHORIZED,
        }
    }
    match db.soft_delete_user(&req.user_id).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

#[utoipa::path(post, path = "/api/wallets", request_body = CreateWalletRequest, responses((status = 200, body = CreateWalletResponse)))]
pub async fn create_wallet(
    AuthBearer(token): AuthBearer,
    Json(req): Json<CreateWalletRequest>,
) -> (StatusCode, Json<CreateWalletResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    // Authenticate user
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(CreateWalletResponse {
                    wallet_id: Uuid::nil(),
                    public_key: "".to_string(),
                    wallet_name: req.wallet_name.clone(),
                    message: "You must be logged in to create a wallet.".to_string(),
                }),
            );
        }
    };
    // Validate wallet name and password
    if let Err(_e) = Validator::validate_wallet_name(&req.wallet_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(CreateWalletResponse {
                wallet_id: Uuid::nil(),
                public_key: "".to_string(),
                wallet_name: req.wallet_name.clone(),
                message: "Invalid wallet name.".to_string(),
            }),
        );
    }
    if let Err(_e) = Validator::validate_password(&req.password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(CreateWalletResponse {
                wallet_id: Uuid::nil(),
                public_key: "".to_string(),
                wallet_name: req.wallet_name.clone(),
                message: "Invalid password.".to_string(),
            }),
        );
    }
    // Create wallet
    let stellar_service = StellarService::new(db.clone());
    let wallet = match stellar_service.create_wallet(&_user.user_id, &req.wallet_name, &req.password) {
        Ok(w) => w,
        Err(e) => {
            error!(action = "create_wallet_failed", user_id = %_user.user_id, error = %e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(CreateWalletResponse {
                    wallet_id: Uuid::nil(),
                    public_key: "".to_string(),
                    wallet_name: req.wallet_name.clone(),
                    message: "Could not create wallet. Please check your details and try again.".to_string(),
                }),
            );
        }
    };
    // Save to database
    if let Err(e) = db.create_stellar_wallet(&wallet).await {
        error!(action = "save_wallet_failed", user_id = %_user.user_id, error = %e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(CreateWalletResponse {
                wallet_id: Uuid::nil(),
                public_key: "".to_string(),
                wallet_name: req.wallet_name.clone(),
                message: "Could not save wallet. Please try again later.".to_string(),
            }),
        );
    }
    (
        StatusCode::OK,
        Json(CreateWalletResponse {
            wallet_id: wallet.id,
            public_key: wallet.public_key,
            wallet_name: wallet.wallet_name,
            message: "Wallet created successfully".to_string(),
        }),
    )
}

#[utoipa::path(post, path = "/api/wallets/import", request_body = ImportWalletRequest, responses((status = 200, body = ImportWalletResponse)))]
pub async fn import_wallet(
    AuthBearer(token): AuthBearer,
    Json(req): Json<ImportWalletRequest>,
) -> (StatusCode, Json<ImportWalletResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ImportWalletResponse {
                    wallet_id: Uuid::nil(),
                    public_key: "".to_string(),
                    wallet_name: req.wallet_name.clone(),
                    message: "You must be logged in to import a wallet.".to_string(),
                }),
            );
        }
    };
    let stellar_service = StellarService::new(db.clone());
    let wallet = match stellar_service.import_wallet(&_user.user_id, &req.wallet_name, &req.secret_key, &req.password) {
        Ok(w) => w,
        Err(e) => {
            error!(action = "import_wallet_failed", user_id = %_user.user_id, error = %e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ImportWalletResponse {
                    wallet_id: Uuid::nil(),
                    public_key: "".to_string(),
                    wallet_name: req.wallet_name.clone(),
                    message: "Could not import wallet. Please check your details and try again.".to_string(),
                }),
            );
        }
    };
    if let Err(e) = db.create_stellar_wallet(&wallet).await {
        error!(action = "save_imported_wallet_failed", user_id = %_user.user_id, error = %e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ImportWalletResponse {
                wallet_id: Uuid::nil(),
                public_key: "".to_string(),
                wallet_name: req.wallet_name.clone(),
                message: "Could not save imported wallet. Please try again later.".to_string(),
            }),
        );
    }
    (
        StatusCode::OK,
        Json(ImportWalletResponse {
            wallet_id: wallet.id,
            public_key: wallet.public_key,
            wallet_name: wallet.wallet_name,
            message: "Wallet imported successfully".to_string(),
        }),
    )
}

#[utoipa::path(get, path = "/api/wallets", responses((status = 200, body = WalletListResponse)))]
pub async fn list_wallets(
    AuthBearer(token): AuthBearer,
) -> (StatusCode, Json<WalletListResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone();
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(WalletListResponse { wallets: vec![] }),
            );
        }
    };
    let wallets = db.get_user_wallets(&_user.user_id).await.unwrap_or_default();
    let stellar_service = StellarService::new(db.clone());
    let mut summaries = Vec::new();
    for w in wallets.iter() {
        let balances = stellar_service.get_wallet_balances(&w.public_key).await.unwrap_or_default();
        summaries.push(WalletSummary {
            wallet_id: w.id,
            wallet_name: w.wallet_name.clone(),
            public_key: w.public_key.clone(),
            balances,
        });
    }
    (StatusCode::OK, Json(WalletListResponse { wallets: summaries }))
}

#[utoipa::path(get, path = "/api/wallets/{id}", responses((status = 200, body = WalletDetailsResponse)))]
pub async fn wallet_details(
    AuthBearer(token): AuthBearer,
    Path(wallet_id): Path<Uuid>,
) -> (StatusCode, Json<WalletDetailsResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone();
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(WalletDetailsResponse {
                    wallet_id,
                    wallet_name: "".to_string(),
                    public_key: "".to_string(),
                    balance_xlm: None,
                    balances: vec![],
                    created_at: chrono::Utc::now(),
                }),
            );
        }
    };
    let wallet = match db.get_wallet_by_id(&wallet_id).await {
        Ok(w) if w.user_id == _user.user_id => w,
        Ok(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(WalletDetailsResponse {
                    wallet_id,
                    wallet_name: "".to_string(),
                    public_key: "".to_string(),
                    balance_xlm: None,
                    balances: vec![],
                    created_at: chrono::Utc::now(),
                }),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WalletDetailsResponse {
                    wallet_id,
                    wallet_name: "".to_string(),
                    public_key: "".to_string(),
                    balance_xlm: None,
                    balances: vec![],
                    created_at: chrono::Utc::now(),
                }),
            );
        }
    };
    let stellar_service = StellarService::new(db.clone());
    let balances = stellar_service.get_wallet_balances(&wallet.public_key).await.unwrap_or_default();
    (StatusCode::OK, Json(WalletDetailsResponse {
        wallet_id: wallet.id,
        wallet_name: wallet.wallet_name,
        public_key: wallet.public_key,
        balance_xlm: wallet.balance_xlm.clone(),
        balances,
        created_at: wallet.created_at,
    }))
}

#[utoipa::path(get, path = "/api/wallets/{id}/balance", responses((status = 200, body = WalletMultiAssetBalanceResponse)))]
pub async fn wallet_balance(
    AuthBearer(token): AuthBearer,
    Path(wallet_id): Path<Uuid>,
) -> (StatusCode, Json<WalletMultiAssetBalanceResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(WalletMultiAssetBalanceResponse { balances: vec![] }),
            );
        }
    };
    let wallet = match db.get_wallet_by_id(&wallet_id).await {
        Ok(w) if w.user_id == _user.user_id => w,
        Ok(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(WalletMultiAssetBalanceResponse { balances: vec![] }),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WalletMultiAssetBalanceResponse { balances: vec![] }),
            );
        }
    };
    let stellar_service = StellarService::new(db.clone());
    let balances = stellar_service.get_wallet_balances(&wallet.public_key).await.unwrap_or_default();
    (StatusCode::OK, Json(WalletMultiAssetBalanceResponse { balances }))
}

#[utoipa::path(
    post,
    path = "/api/wallets/{id}/send",
    request_body = SendPaymentRequest,
    responses(
        (status = 200, body = SendPaymentResponse, description = "Payment sent successfully"),
        (status = 400, body = SendPaymentResponse, description = "Validation or Stellar error, e.g. invalid sequence number or op_no_destination"),
        (status = 401, body = SendPaymentResponse, description = "Unauthorized or invalid JWT"),
        (status = 500, body = SendPaymentResponse, description = "Internal server error")
    ),
    tag = "Wallet",
    params(
        ("id" = Uuid, Path, description = "Wallet ID to send from")
    )
)]
pub async fn send_payment(
    AuthBearer(token): AuthBearer,
    Path(wallet_id): Path<Uuid>,
    Json(req): Json<SendPaymentRequest>,
) -> (StatusCode, Json<SendPaymentResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "You must be logged in to send payments.".to_string() }),
            );
        }
    };
    // Validate amount
    if req.amount <= 0.0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "Amount must be greater than 0.".to_string() }),
        );
    }
    // Validate destination address
    if !req.destination.trim().starts_with('G') {
        return (
            StatusCode::BAD_REQUEST,
            Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "Invalid destination Stellar address format.".to_string() }),
        );
    }
    // Validate memo
    if let Some(memo) = &req.memo {
        if let Err(_e) = Validator::validate_memo(memo) {
            return (
                StatusCode::BAD_REQUEST,
                Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "Invalid memo.".to_string() }),
            );
        }
    }
    // Check if 2FA is enabled for the user
    let user_record = match db.get_user_by_id(&_user.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "Account not found. Please log in again.".to_string() }),
            );
        }
    };
    if user_record.totp_enabled {
        let totp_code = req.totp_code.as_deref().unwrap_or("");
        let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
        match two_factor_service.verify_totp(&_user.user_id, totp_code).await {
            Ok(true) => {},
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "The 2FA code is incorrect or missing. Please try again.".to_string() }),
                );
            }
        }
    }
    let wallet = match db.get_wallet_by_id(&wallet_id).await {
        Ok(w) if w.user_id == _user.user_id => w,
        Ok(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "Wallet not found. Please check your wallet selection.".to_string() }),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "Failed to get wallet. Please try again later.".to_string() }),
            );
        }
    };
    // --- Asset issuer lookup logic ---
    let asset_code_upper = req.asset_code.as_deref().map(|c| c.to_uppercase());
    let (asset_code, _asset_issuer) = match asset_code_upper.as_deref() {
        Some("USDC") => (Some("USDC".to_string()), Some("GA5ZSE7V3Y3P5YF3VJZQ2Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5".to_string())),
        Some("XLM") | None => (Some("XLM".to_string()), None),
        Some(_other) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "You can only send XLM or USDC at this time.".to_string() }),
            );
        }
    };
    let stellar_service = StellarService::new(db.clone());
    let tx_hash = match stellar_service.send_payment_asset(
        &wallet.public_key,
        &req.destination,
        req.amount,
        asset_code,
        req.memo.clone(),
        &req.password,
    ).await {
        Ok(h) => h,
        Err(e) => {
            error!(action = "send_payment_failed", user_id = %_user.user_id, wallet_id = %wallet_id, error = %e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SendPaymentResponse { transaction_hash: "".to_string(), message: "Failed to send payment. Please check your details and try again.".to_string() }),
            );
        }
    };
    info!(action = "send_payment", user_id = %_user.user_id, wallet_id = %wallet_id);
    (StatusCode::OK, Json(SendPaymentResponse { transaction_hash: tx_hash, message: "Payment sent successfully".to_string() }))
}

#[utoipa::path(get, path = "/api/wallets/{id}/transactions", responses((status = 200, body = TransactionHistoryResponse)))]
pub async fn wallet_transactions(
    AuthBearer(token): AuthBearer,
    Path(wallet_id): Path<Uuid>,
) -> (StatusCode, Json<TransactionHistoryResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(TransactionHistoryResponse { transactions: vec![] }),
            );
        }
    };
    let wallet = match db.get_wallet_by_id(&wallet_id).await {
        Ok(w) if w.user_id == _user.user_id => w,
        Ok(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(TransactionHistoryResponse { transactions: vec![] }),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TransactionHistoryResponse { transactions: vec![] }),
            );
        }
    };
    let stellar_service = StellarService::new(db.clone());
    let txs = stellar_service.get_transaction_history(&wallet.public_key).await.unwrap_or_default();
    let summaries = txs.into_iter().map(|t| TransactionSummary {
        hash: t.hash,
        amount: t.amount,
        asset_code: t.asset_code,
        asset_issuer: t.asset_issuer,
        from: t.from,
        to: t.to,
        memo: t.memo,
        created_at: t.created_at,
        status: t.status, // Add status from transaction
    }).collect();
    (StatusCode::OK, Json(TransactionHistoryResponse { transactions: summaries }))
}

#[utoipa::path(
    post,
    path = "/api/wallets/{id}/sync",
    responses(
        (status = 200, body = WalletDetailsResponse, description = "Wallet synced successfully"),
        (status = 401, body = WalletDetailsResponse, description = "Unauthorized or invalid JWT"),
        (status = 404, body = WalletDetailsResponse, description = "Wallet not found"),
        (status = 500, body = WalletDetailsResponse, description = "Internal server error")
    ),
    tag = "Wallet",
    params(
        ("id" = Uuid, Path, description = "Wallet ID to sync")
    )
)]
pub async fn sync_wallet(
    AuthBearer(token): AuthBearer,
    Path(wallet_id): Path<Uuid>,
) -> (StatusCode, Json<WalletDetailsResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(WalletDetailsResponse {
                    wallet_id,
                    wallet_name: "".to_string(),
                    public_key: "".to_string(),
                    balance_xlm: None,
                    balances: vec![],
                    created_at: chrono::Utc::now(),
                }),
            );
        }
    };
    let wallet = match db.get_wallet_by_id(&wallet_id).await {
        Ok(w) if w.user_id == _user.user_id => w,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(WalletDetailsResponse {
                    wallet_id,
                    wallet_name: "".to_string(),
                    public_key: "".to_string(),
                    balance_xlm: None,
                    balances: vec![],
                    created_at: chrono::Utc::now(),
                }),
            );
        }
    };
    let stellar_service = StellarService::new(db.clone());
    let info = match stellar_service.get_wallet_info(&wallet.public_key).await {
        Ok(i) => i,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WalletDetailsResponse {
                    wallet_id,
                    wallet_name: wallet.wallet_name,
                    public_key: wallet.public_key,
                    balance_xlm: None,
                    balances: vec![],
                    created_at: wallet.created_at,
                }),
            );
        }
    };
    // Update wallet in DB
    let _ = db.update_wallet_balance(&wallet_id, &info.balance_xlm, Some(info.sequence_number)).await;
    (
        StatusCode::OK,
        Json(WalletDetailsResponse {
            wallet_id: wallet.id,
            wallet_name: wallet.wallet_name,
            public_key: wallet.public_key,
            balance_xlm: Some(info.balance_xlm),
            balances: vec![],
            created_at: wallet.created_at,
        })
    )
}

#[utoipa::path(
    post,
    path = "/api/wallets/{id}/fund",
    responses(
        (status = 200, body = FundWalletResponse, description = "Wallet funded successfully (testnet only)"),
        (status = 400, body = FundWalletResponse, description = "Wallet not found or already funded"),
        (status = 401, body = FundWalletResponse, description = "Unauthorized or invalid JWT"),
        (status = 500, body = FundWalletResponse, description = "Internal server error")
    ),
    tag = "Wallet",
    params(
        ("id" = Uuid, Path, description = "Wallet ID to fund")
    )
)]
pub async fn fund_wallet(
    AuthBearer(token): AuthBearer,
    Path(wallet_id): Path<Uuid>,
) -> (StatusCode, Json<FundWalletResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(FundWalletResponse {
                    wallet_id,
                    public_key: "".to_string(),
                    message: "Unauthorized or invalid JWT".to_string(),
                }),
            );
        }
    };
    let wallet = match db.get_wallet_by_id(&wallet_id).await {
        Ok(w) if w.user_id == _user.user_id => w,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(FundWalletResponse {
                    wallet_id,
                    public_key: "".to_string(),
                    message: "Wallet not found".to_string(),
                }),
            );
        }
    };
    let stellar_service = StellarService::new(db.clone());
    match stellar_service.fund_testnet_account(&wallet.public_key).await {
        Ok(_) => (
            StatusCode::OK,
            Json(FundWalletResponse {
                wallet_id: wallet.id,
                public_key: wallet.public_key,
                message: "Wallet funded successfully (testnet)".to_string(),
            })
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(FundWalletResponse {
                wallet_id: wallet.id,
                public_key: wallet.public_key,
                message: format!("Failed to fund wallet: {}", e),
            })
        )
    }
}

#[utoipa::path(
    get,
    path = "/api/wallets/{id}/receive",
    responses(
        (status = 200, body = ReceiveWalletResponse, description = "Wallet receive info (public key, QR code URL, supported assets)"),
        (status = 401, body = ReceiveWalletResponse, description = "Unauthorized or invalid JWT"),
        (status = 404, body = ReceiveWalletResponse, description = "Wallet not found"),
        (status = 500, body = ReceiveWalletResponse, description = "Internal server error")
    ),
    tag = "Wallet",
    params(
        ("id" = Uuid, Path, description = "Wallet ID to receive into")
    )
)]
pub async fn receive_wallet(
    AuthBearer(token): AuthBearer,
    Path(wallet_id): Path<Uuid>,
) -> (StatusCode, Json<ReceiveWalletResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ReceiveWalletResponse {
                    wallet_id,
                    public_key: "".to_string(),
                    qr_code_url: None,
                    supported_assets: vec![],
                    message: "You must be logged in to view receive information.".to_string(),
                }),
            );
        }
    };
    let wallet = match db.get_wallet_by_id(&wallet_id).await {
        Ok(w) if w.user_id == _user.user_id => w,
        Ok(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ReceiveWalletResponse {
                    wallet_id,
                    public_key: "".to_string(),
                    qr_code_url: None,
                    supported_assets: vec![],
                    message: "Wallet not found. Please check your wallet selection.".to_string(),
                }),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ReceiveWalletResponse {
                    wallet_id,
                    public_key: "".to_string(),
                    qr_code_url: None,
                    supported_assets: vec![],
                    message: "Failed to get wallet. Please try again later.".to_string(),
                }),
            );
        }
    };
    // Generate QR code SVG and encode as data URI
    let qr_code_url = match QrCode::new(&wallet.public_key) {
        Ok(qr_code) => {
            let svg = qr_code.render::<svg::Color>()
                .min_dimensions(200, 200)
                .dark_color(svg::Color("#000000"))
                .light_color(svg::Color("#ffffff"))
                .build();
            let svg_base64 = general_purpose::STANDARD.encode(svg.as_bytes());
            Some(format!("data:image/svg+xml;base64,{}", svg_base64))
        },
        Err(_) => None,
    };
    let stellar_service = StellarService::new(db.clone());
    let supported_assets = stellar_service.get_wallet_balances(&wallet.public_key).await.unwrap_or_default();
    (
        StatusCode::OK,
        Json(ReceiveWalletResponse {
            wallet_id: wallet.id,
            public_key: wallet.public_key,
            qr_code_url,
            supported_assets,
            message: "Share this address to receive XLM or USDC payments.".to_string(),
        })
    )
}

#[utoipa::path(
    get,
    path = "/api/notifications",
    responses(
        (status = 200, body = NotificationResponse, description = "List of user notifications"),
        (status = 401, body = NotificationResponse, description = "Unauthorized or invalid JWT"),
        (status = 500, body = NotificationResponse, description = "Internal server error")
    ),
    tag = "Notification"
)]
pub async fn view_notifications(
    AuthBearer(token): AuthBearer,
) -> (StatusCode, Json<NotificationResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(NotificationResponse { notifications: vec![] }),
            );
        }
    };
    let notifications = match db.get_user_notifications(&_user.user_id, Some(50)).await {
        Ok(list) => list,
        Err(e) => {
            error!(action = "fetch_notifications_failed", user_id = %_user.user_id, error = %e);
            vec![]
        }
    };
    let items = notifications.into_iter().map(|n| NotificationItem {
        id: n.id,
        title: n.title,
        message: n.message,
        date: n.created_at,
        status: if n.is_read { "Read".to_string() } else { "Unread".to_string() },
    }).collect();
    (StatusCode::OK, Json(NotificationResponse { notifications: items }))
}

#[utoipa::path(
    post,
    path = "/api/notifications/{id}/mark-read",
    responses((status = 200, description = "Notification marked as read"), (status = 401, description = "Unauthorized")),
    tag = "Notification",
    params(("id" = Uuid, Path, description = "Notification ID to mark as read"))
)]
pub async fn mark_notification_read(
    AuthBearer(token): AuthBearer,
    Path(notification_id): Path<Uuid>,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _)) => return StatusCode::UNAUTHORIZED,
    };
    // Optionally: check notification belongs to user
    let _ = db.mark_notification_read(&notification_id).await;
    StatusCode::OK
}

#[utoipa::path(
    delete,
    path = "/api/notifications/{id}",
    responses((status = 200, description = "Notification deleted"), (status = 401, description = "Unauthorized")),
    tag = "Notification",
    params(("id" = Uuid, Path, description = "Notification ID to delete"))
)]
pub async fn delete_notification(
    AuthBearer(token): AuthBearer,
    Path(notification_id): Path<Uuid>,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _)) => return StatusCode::UNAUTHORIZED,
    };
    // Optionally: check notification belongs to user
    let _ = db.delete_notification(&notification_id).await;
    StatusCode::OK
}

#[utoipa::path(
    post,
    path = "/api/notifications/mark-all-read",
    responses((status = 200, description = "All notifications marked as read"), (status = 401, description = "Unauthorized")),
    tag = "Notification"
)]
pub async fn mark_all_notifications_read(
    AuthBearer(token): AuthBearer,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _)) => return StatusCode::UNAUTHORIZED,
    };
    let _ = db.mark_all_notifications_read(&_user.user_id).await;
    StatusCode::OK
}

#[utoipa::path(
    delete,
    path = "/api/notifications/delete-all",
    responses((status = 200, description = "All notifications deleted"), (status = 401, description = "Unauthorized")),
    tag = "Notification"
)]
pub async fn delete_all_notifications(
    AuthBearer(token): AuthBearer,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _)) => return StatusCode::UNAUTHORIZED,
    };
    let _ = db.delete_all_notifications(&_user.user_id).await;
    StatusCode::OK
}

#[utoipa::path(
    get,
    path = "/api/notifications/preferences",
    responses((status = 200, body = NotificationPreferences, description = "Get notification preferences"), (status = 401, description = "Unauthorized")),
    tag = "Notification"
)]
pub async fn get_notification_preferences(
    AuthBearer(token): AuthBearer,
) -> (StatusCode, Json<Option<crate::models::notification::NotificationPreferences>>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _)) => return (StatusCode::UNAUTHORIZED, Json(None)),
    };
    let prefs = db.get_notification_preferences(&_user.user_id).await.unwrap_or(None);
    (StatusCode::OK, Json(prefs))
}

#[utoipa::path(
    put,
    path = "/api/notifications/preferences",
    request_body = NotificationPreferences,
    responses((status = 200, description = "Preferences updated"), (status = 401, description = "Unauthorized")),
    tag = "Notification"
)]
pub async fn update_notification_preferences(
    AuthBearer(token): AuthBearer,
    Json(prefs): Json<crate::models::notification::NotificationPreferences>,
) -> StatusCode {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let _user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _)) => return StatusCode::UNAUTHORIZED,
    };
    // Only allow updating own preferences
    if prefs.user_id != _user.user_id {
        return StatusCode::UNAUTHORIZED;
    }
    let _ = db.update_notification_preferences(&prefs).await;
    StatusCode::OK
}

#[utoipa::path(get, path = "/api/profile", responses((status = 200, body = ProfileResponse), (status = 401, description = "Unauthorized")))]
pub async fn get_profile(
    AuthBearer(token): AuthBearer,
) -> (StatusCode, Json<ProfileResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (StatusCode::UNAUTHORIZED, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
    };
    let user_record = match db.get_user_by_id(&user.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
    };
    (StatusCode::OK, Json(ProfileResponse {
        user_id: user_record.id,
        email: user_record.email,
        username: user_record.username,
        is_verified: user_record.is_verified,
        phone_number: user_record.phone_number,
        is_phone_verified: user_record.is_phone_verified,
        created_at: user_record.created_at,
    }))
}

#[utoipa::path(put, path = "/api/profile", request_body = UpdateProfileRequest, responses((status = 200, body = ProfileResponse), (status = 401, description = "Unauthorized")))]
pub async fn update_profile(
    AuthBearer(token): AuthBearer,
    Json(req): Json<UpdateProfileRequest>,
) -> (StatusCode, Json<ProfileResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (StatusCode::UNAUTHORIZED, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
    };
    let mut user_record = match db.get_user_by_id(&user.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
    };
    if let Some(email) = req.email {
        if let Err(_e) = Validator::validate_email(&email) {
            return (StatusCode::BAD_REQUEST, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
        user_record.email = email;
    }
    if let Some(username) = req.username {
        if let Err(_e) = Validator::validate_username(&username) {
            return (StatusCode::BAD_REQUEST, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
        user_record.username = username;
    }
    if let Some(ref phone) = req.phone_number {
        if let Err(_e) = Validator::validate_phone(phone) {
            return (StatusCode::BAD_REQUEST, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
    }
    user_record.phone_number = req.phone_number.clone();
    if let Err(e) = db.update_user_profile(&user_record).await {
        error!(action = "update_profile_failed", user_id = %user.user_id, error = %e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ProfileResponse {
            user_id: uuid::Uuid::nil(),
            email: "".to_string(),
            username: "".to_string(),
            is_verified: false,
            phone_number: None,
            is_phone_verified: false,
            created_at: chrono::Utc::now(),
        }));
    }
    (StatusCode::OK, Json(ProfileResponse {
        user_id: user_record.id,
        email: user_record.email,
        username: user_record.username,
        is_verified: user_record.is_verified,
        phone_number: user_record.phone_number,
        is_phone_verified: user_record.is_phone_verified,
        created_at: user_record.created_at,
    }))
}

#[utoipa::path(put, path = "/api/profile/phone", request_body = UpdatePhoneRequest, responses((status = 200, body = ProfileResponse), (status = 401, description = "Unauthorized")))]
pub async fn update_phone(
    AuthBearer(token): AuthBearer,
    Json(req): Json<UpdatePhoneRequest>,
) -> (StatusCode, Json<ProfileResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (StatusCode::UNAUTHORIZED, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
    };
    let mut user_record = match db.get_user_by_id(&user.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(ProfileResponse {
                user_id: uuid::Uuid::nil(),
                email: "".to_string(),
                username: "".to_string(),
                is_verified: false,
                phone_number: None,
                is_phone_verified: false,
                created_at: chrono::Utc::now(),
            }));
        }
    };
    if let Err(_e) = Validator::validate_phone(&req.phone_number) {
        return (StatusCode::BAD_REQUEST, Json(ProfileResponse {
            user_id: uuid::Uuid::nil(),
            email: "".to_string(),
            username: "".to_string(),
            is_verified: false,
            phone_number: None,
            is_phone_verified: false,
            created_at: chrono::Utc::now(),
        }));
    }
    user_record.phone_number = Some(req.phone_number.clone());
    if let Err(e) = db.update_user_profile(&user_record).await {
        error!(action = "update_phone_failed", user_id = %user.user_id, error = %e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ProfileResponse {
            user_id: uuid::Uuid::nil(),
            email: "".to_string(),
            username: "".to_string(),
            is_verified: false,
            phone_number: None,
            is_phone_verified: false,
            created_at: chrono::Utc::now(),
        }));
    }
    (StatusCode::OK, Json(ProfileResponse {
        user_id: user_record.id,
        email: user_record.email,
        username: user_record.username,
        is_verified: user_record.is_verified,
        phone_number: user_record.phone_number,
        is_phone_verified: user_record.is_phone_verified,
        created_at: user_record.created_at,
    }))
}

#[utoipa::path(get, path = "/api/profile/2fa/status", responses((status = 200, body = TwoFAStatusResponse), (status = 401, description = "Unauthorized")))]
pub async fn get_2fa_status(
    AuthBearer(token): AuthBearer,
) -> (StatusCode, Json<TwoFAStatusResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (StatusCode::UNAUTHORIZED, Json(TwoFAStatusResponse {
                enabled: false,
                setup_complete: false,
                backup_codes_remaining: None,
            }));
        }
    };
    let user_record = match db.get_user_by_id(&user.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(TwoFAStatusResponse {
                enabled: false,
                setup_complete: false,
                backup_codes_remaining: None,
            }));
        }
    };
    
    let backup_codes_remaining = if user_record.totp_enabled {
        // Count remaining backup codes
        if let Some(backup_codes) = &user_record.backup_codes {
            let codes: Vec<String> = serde_json::from_str(backup_codes).unwrap_or_default();
            Some(codes.len() as i32)
        } else {
            Some(0)
        }
    } else {
        None
    };
    
    (StatusCode::OK, Json(TwoFAStatusResponse {
        enabled: user_record.totp_enabled,
        setup_complete: user_record.totp_enabled && user_record.totp_secret.is_some(),
        backup_codes_remaining,
    }))
}

#[utoipa::path(get, path = "/api/profile/2fa/setup", responses((status = 200, body = TwoFASetupResponse), (status = 401, description = "Unauthorized"), (status = 400, description = "2FA already enabled")))]
pub async fn setup_2fa(
    AuthBearer(token): AuthBearer,
) -> (StatusCode, Json<TwoFASetupResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (StatusCode::UNAUTHORIZED, Json(TwoFASetupResponse {
                qr_code_svg: "".to_string(),
                secret_key: "".to_string(),
                backup_codes: vec![],
                message: "Unauthorized".to_string(),
            }));
        }
    };
    let user_record = match db.get_user_by_id(&user.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, Json(TwoFASetupResponse {
                qr_code_svg: "".to_string(),
                secret_key: "".to_string(),
                backup_codes: vec![],
                message: "User not found".to_string(),
            }));
        }
    };
    
    if user_record.totp_enabled {
        return (StatusCode::BAD_REQUEST, Json(TwoFASetupResponse {
            qr_code_svg: "".to_string(),
            secret_key: "".to_string(),
            backup_codes: vec![],
            message: "2FA is already enabled".to_string(),
        }));
    }
    
    let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
    match two_factor_service.generate_setup_data(&user.user_id).await {
        Ok((qr_code_svg, secret_key, backup_codes)) => {
            (StatusCode::OK, Json(TwoFASetupResponse {
                qr_code_svg,
                secret_key,
                backup_codes,
                message: "Scan the QR code with your authenticator app, then use the TOTP code to enable 2FA".to_string(),
            }))
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(TwoFASetupResponse {
                qr_code_svg: "".to_string(),
                secret_key: "".to_string(),
                backup_codes: vec![],
                message: "Failed to generate 2FA setup data".to_string(),
            }))
        }
    }
}

#[utoipa::path(post, path = "/api/profile/2fa/enable", request_body = Enable2FARequest, responses((status = 200, body = Enable2FAResponse), (status = 401, description = "Unauthorized or invalid TOTP"), (status = 400, description = "2FA already enabled")))]
pub async fn enable_2fa(
    AuthBearer(token): AuthBearer,
    Json(req): Json<Enable2FARequest>,
) -> (StatusCode, Json<Enable2FAResponse>) {
    let db = GLOBAL_DB.get().unwrap().clone(); // TODO: Replace with global singleton
    let user = match user_from_token(&token, db.clone()).await {
        Ok(u) => u,
        Err((_status, _msg)) => {
            return (StatusCode::UNAUTHORIZED, Json(Enable2FAResponse {
                success: false,
                message: "You must be logged in to enable 2FA.".to_string(),
                backup_codes: vec![],
            }));
        }
    };
    
    let two_factor_service = crate::services::two_factor_service::TwoFactorService::new(db.clone());
    match two_factor_service.enable_2fa(&user.user_id, &req.totp_code).await {
        Ok(backup_codes) => {
            (StatusCode::OK, Json(Enable2FAResponse {
                success: true,
                message: "2FA enabled successfully. Save your backup codes in a secure location.".to_string(),
                backup_codes,
            }))
        }
        Err(e) => {
            error!(action = "enable_2fa_failed", user_id = %user.user_id, error = %e);
            (StatusCode::UNAUTHORIZED, Json(Enable2FAResponse {
                success: false,
                message: "Failed to enable 2FA. Please check your code and try again.".to_string(),
                backup_codes: vec![],
            }))
        }
    }
}

/// Profile API endpoints
pub fn profile_router() -> Router {
    Router::new()
        .route("/", get(get_profile))
        .route("/", put(update_profile))
        .route("/phone", put(update_phone))
        .route("/2fa/status", get(get_2fa_status))
        .route("/2fa/setup", get(setup_2fa))
        .route("/2fa/enable", post(enable_2fa))
} 

// Update wallet_router to include all endpoints
pub fn wallet_router() -> Router {
    Router::new()
        .route("/", post(create_wallet))
        .route("/import", post(import_wallet))
        .route("/", get(list_wallets))
        .route("/:id", get(wallet_details))
        .route("/:id/balance", get(wallet_balance))
        .route("/:id/transactions", get(wallet_transactions))
        .route("/:id/sync", post(sync_wallet))
        .route("/:id/fund", post(fund_wallet))
        .route("/:id/receive", get(receive_wallet))
} 

#[utoipa::path(
    get,
    path = "/api/assets",
    responses((status = 200, body = [SupportedAsset], description = "List of supported assets")),
    tag = "Asset"
)]
pub async fn list_supported_assets() -> axum::Json<Vec<SupportedAsset>> {
    axum::Json(vec![
        SupportedAsset {
            asset_code: "XLM".to_string(),
            asset_issuer: None,
            display_name: "Stellar Lumens (XLM)".to_string(),
        },
        SupportedAsset {
            asset_code: "USDC".to_string(),
            asset_issuer: Some("GA5ZSE7V3Y3P5YF3VJZQ2Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5".to_string()),
            display_name: "USD Coin (USDC)".to_string(),
        },
    ])
} 

pub fn notifications_router() -> Router {
    Router::new()
        .route("/", get(view_notifications))
        .route("/:id/mark-read", post(mark_notification_read))
        .route("/:id", delete(delete_notification))
        .route("/mark-all-read", post(mark_all_notifications_read))
        .route("/delete-all", delete(delete_all_notifications))
        .route("/preferences", get(get_notification_preferences))
        .route("/preferences", put(update_notification_preferences))
} 