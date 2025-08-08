use axum::{Router, response::IntoResponse, Json};
use std::net::SocketAddr;
use utoipa::OpenApi;
use utoipa::Modify;
use utoipa_swagger_ui::SwaggerUi;
use utoipa_redoc::{Redoc, Servable};
use std::sync::Arc;
use crate::database::sqlite::SqliteDatabase;
use serde_json::Value;
use crate::utils::middleware::{RateLimiter, global_rate_limiter};
use axum::Extension;
use crate::database::sqlite::GLOBAL_DB;
use uuid::Uuid;
use axum::{http::HeaderValue};
use tower_http::cors::{CorsLayer, Any};
use hyper::Method;
use axum::{routing::options, http::StatusCode};
use axum::routing::post;

mod routes;
mod types;
pub mod docs;

#[derive(OpenApi)]
#[openapi(
    paths(
        routes::register,
        routes::login,
        routes::validate,
        routes::refresh,
        routes::logout,
        routes::logout_all,
        routes::sessions,
        // Wallet endpoints:
        routes::create_wallet,
        routes::import_wallet,
        routes::list_wallets,
        routes::wallet_details,
        routes::wallet_balance,
        routes::send_payment,
        routes::wallet_transactions,
        routes::sync_wallet,
        routes::fund_wallet,
        routes::receive_wallet,
        // Notification endpoints:
        routes::view_notifications,
        routes::mark_notification_read,
        routes::delete_notification,
        routes::mark_all_notifications_read,
        routes::delete_all_notifications,
        routes::get_notification_preferences,
        routes::update_notification_preferences,
        routes::two_fa_verify,
        routes::disable_2fa,
        routes::delete_account,
        routes::change_password,
        routes::get_profile,
        routes::update_profile,
        routes::update_phone,
        routes::send_phone_verification,
        routes::verify_phone_code,
        routes::get_2fa_status,
        routes::setup_2fa,
        routes::enable_2fa,
        routes::kyc_upload_id,
        routes::admin_kyc_list,
        routes::admin_kyc_review,
    ),
    components(
        schemas(
            types::RegisterRequest,
            types::RegisterResponse,
            types::LoginRequest,
            types::LoginResponse,
            types::TokenRequest,
            types::ValidateResponse,
            types::RefreshResponse,
            types::LogoutResponse,
            types::SessionsResponse,
            // Wallet types:
            types::CreateWalletRequest,
            types::CreateWalletResponse,
            types::ImportWalletRequest,
            types::ImportWalletResponse,
            types::WalletListResponse,
            types::WalletSummary,
            types::WalletDetailsResponse,
            types::WalletBalanceResponse,
            types::SendPaymentRequest,
            types::SendPaymentResponse,
            types::TransactionHistoryResponse,
            types::TransactionSummary,
            types::FundWalletResponse,
            types::ReceiveWalletResponse,
            types::NotificationResponse,
            types::NotificationItem,
            types::TwoFAVerifyRequest,
            types::TwoFAVerifyResponse,
            types::Disable2FARequest,
            types::ChangePasswordRequest,
            types::DeleteAccountRequest,
            types::ProfileResponse,
            types::UpdateProfileRequest,
            types::UpdatePhoneRequest,
            types::SendPhoneVerificationRequest,
            types::SendPhoneVerificationResponse,
            types::VerifyPhoneCodeRequest,
            types::VerifyPhoneCodeResponse,
            types::TwoFAStatusResponse,
            types::TwoFASetupResponse,
            types::Enable2FARequest,
            types::Enable2FAResponse,
            
            crate::models::notification::NotificationPreferences,
            
        )
    ),
    tags(
        (name = "Auth", description = "Authentication endpoints"),
        (name = "Wallet", description = "Stellar wallet management endpoints. ⚠️ Most endpoints require JWT authentication. Use the Authorize button and paste your token as 'Bearer <token>'!"),
        (name = "Profile", description = "User profile management endpoints"),
        (name = "Notification", description = "Notification management endpoints")
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{SecurityScheme, HttpAuthScheme, HttpBuilder};
        openapi.components.as_mut().unwrap().add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build()
            ),
        );
        openapi.security = Some(vec![utoipa::openapi::security::SecurityRequirement::new("bearerAuth", Vec::<String>::new())]);
    }
}

// Configurable rate limit (requests per second per IP)
fn get_rate_limit_per_sec() -> u64 {
    std::env::var("RATE_LIMIT_PER_SEC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

pub async fn request_id_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let request_id = Uuid::new_v4().to_string();
    req.extensions_mut().insert(request_id.clone());
    let span = tracing::info_span!("request", request_id = %request_id, method = %req.method(), uri = %req.uri());
    let _enter = span.enter();
    next.run(req).await
}

/// Main entry point for the Xendly API server.
/// Sets up all routes, middleware, and documentation endpoints.
pub async fn start_http_server() {
    let openapi = ApiDoc::openapi();
    let db = Arc::new(SqliteDatabase::new("stellar_wallet.db").await.unwrap());
    GLOBAL_DB.set(db.clone()).unwrap();
    let limiter = Arc::new(RateLimiter::new(get_rate_limit_per_sec(), 1)); // 5 req/sec/IP by default
    let shared_state = (limiter.clone(), db.clone());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/auth/login", options(|| async { StatusCode::NO_CONTENT }))
        .route("/api/auth/register", options(|| async { StatusCode::NO_CONTENT }))
        .route("/*path", options(|| async { StatusCode::NO_CONTENT })) // fallback for other paths
        .nest("/api/auth", routes::auth_router())
        .nest("/api/wallets", routes::wallet_router())
        .nest("/api/profile", routes::profile_router())
        .nest("/api/notifications", routes::notifications_router())
        .route("/api/assets", axum::routing::get(routes::list_supported_assets))
        .route("/health", axum::routing::get(health_check))
        .route("/api/admin/kyc/list", axum::routing::get(routes::admin_kyc_list))
        .route("/api/admin/kyc/:id/review", axum::routing::post(routes::admin_kyc_review))
        // OpenAPI Documentation Routes
        .route("/docs/openapi.json", axum::routing::get(openapi_json))
        .route("/docs/swagger.json", axum::routing::get(openapi_json))
        .route("/docs/api-docs.json", axum::routing::get(openapi_json))
        .route("/docs/redoc", axum::routing::get(redoc_ui))
        .route("/docs/markdown", axum::routing::get(api_markdown))
        .route("/docs", axum::routing::get(api_documentation))
        // Swagger UI
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", openapi.clone()))
        // Redoc UI
        .merge(Redoc::with_url("/api/redoc", openapi))
        .layer(Extension(shared_state))
        .layer(cors)
        .layer(axum::middleware::from_fn(request_id_middleware));

    // ✅ Render binding to 0.0.0.0 and using PORT from env
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();

    println!("🚀 HTTP API running at http://{}/health", addr);
    println!("📚 API Documentation available at: http://{}/api/docs", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app,
    )
    
    .await
    .unwrap();
}

async fn health_check() -> impl IntoResponse {
    "OK"
}

/// Export OpenAPI specification as JSON
async fn openapi_json() -> Json<Value> {
    let openapi = ApiDoc::openapi();
    Json(serde_json::to_value(openapi).unwrap())
}

/// Serves the Redoc UI for API documentation.
async fn redoc_ui() -> impl IntoResponse {
    let html = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Xendly API Documentation</title>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
        <style>
            body {
                margin: 0;
                padding: 0;
            }
        </style>
    </head>
    <body>
        <redoc spec-url="/docs/openapi.json"></redoc>
        <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
    </body>
    </html>
    "#;
    axum::response::Html(html)
}

/// Serves the API documentation as downloadable Markdown.
async fn api_markdown() -> impl IntoResponse {
    let markdown = docs::generate_markdown_docs();
    axum::response::Response::builder()
        .header("Content-Type", "text/markdown")
        .header("Content-Disposition", "attachment; filename=\"API_DOCUMENTATION.md\"")
        .body(axum::body::Body::from(markdown))
        .unwrap()
}

/// Serves the main API documentation HTML page.
async fn api_documentation() -> impl IntoResponse {
    let html = docs::generate_documentation_html();
    axum::response::Html(html)
} 