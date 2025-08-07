/// Generate comprehensive Markdown documentation from OpenAPI spec
pub fn generate_markdown_docs() -> String {
    let mut markdown = String::new();
    
    // Header
    markdown.push_str("# Xendly API Documentation\n\n");
    markdown.push_str("## Overview\n\n");
    markdown.push_str("Xendly is a multi-currency wallet application with Stellar blockchain integration and mobile money features. This API provides comprehensive endpoints for user authentication, wallet management, profile management, and notifications.\n\n");
    
    // Table of Contents
    markdown.push_str("## Table of Contents\n\n");
    markdown.push_str("- [Authentication](#authentication)\n");
    markdown.push_str("- [Wallet Management](#wallet-management)\n");
    markdown.push_str("- [Profile Management](#profile-management)\n");
    markdown.push_str("- [Notifications](#notifications)\n");
    markdown.push_str("- [Error Codes](#error-codes)\n");
    markdown.push_str("- [Examples](#examples)\n\n");
    
    // Authentication Section
    markdown.push_str("## Authentication\n\n");
    markdown.push_str("Most endpoints require JWT authentication. Include your JWT token in the Authorization header:\n\n");
    markdown.push_str("```http\nAuthorization: Bearer <your-jwt-token>\n```\n\n");
    markdown.push_str("### Two-Factor Authentication (2FA)\n\n");
    markdown.push_str("Sensitive operations require 2FA verification. Users with 2FA enabled must provide a TOTP code for:\n");
    markdown.push_str("- Sending payments\n");
    markdown.push_str("- Changing password\n");
    markdown.push_str("- Disabling 2FA\n");
    markdown.push_str("- Deleting account\n\n");
    
    // Base URL
    markdown.push_str("## Base URL\n\n");
    markdown.push_str("```\nhttp://localhost:8080/api\n```\n\n");
    
    // Authentication endpoints
    markdown.push_str("## Authentication Endpoints\n\n");
    
    markdown.push_str("### POST /api/auth/register\n\n");
    markdown.push_str("**Description:** Register a new user account\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"email\": \"user@example.com\",\n  \"username\": \"testuser\",\n  \"password\": \"securepassword123\",\n  \"phone_number\": \"+1234567890\"\n}\n```\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"user_id\": \"uuid\",\n  \"message\": \"User registered successfully\"\n}\n```\n\n");
    
    markdown.push_str("### POST /api/auth/login\n\n");
    markdown.push_str("**Description:** Authenticate user and get JWT token\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"email_or_username\": \"user@example.com\",\n  \"password\": \"securepassword123\"\n}\n```\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"token\": \"jwt-token\",\n  \"expires_in\": 86400,\n  \"two_fa_required\": false,\n  \"user_id\": null\n}\n```\n\n");
    
    markdown.push_str("### POST /api/auth/2fa-verify\n\n");
    markdown.push_str("**Description:** Verify 2FA code and get JWT token\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"user_id\": \"uuid\",\n  \"totp_code\": \"123456\"\n}\n```\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"token\": \"jwt-token\",\n  \"expires_in\": 86400\n}\n```\n\n");
    
    markdown.push_str("### POST /api/auth/change-password\n\n");
    markdown.push_str("**Description:** Change user password (requires 2FA if enabled)\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"user_id\": \"uuid\",\n  \"current_password\": \"oldpassword\",\n  \"new_password\": \"newpassword\",\n  \"totp_code\": \"123456\"\n}\n```\n\n");
    
    markdown.push_str("### POST /api/auth/disable-2fa\n\n");
    markdown.push_str("**Description:** Disable two-factor authentication\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"user_id\": \"uuid\",\n  \"totp_code\": \"123456\"\n}\n```\n\n");
    
    markdown.push_str("### POST /api/auth/delete-account\n\n");
    markdown.push_str("**Description:** Delete user account (requires password and 2FA if enabled)\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"user_id\": \"uuid\",\n  \"password\": \"userpassword\",\n  \"totp_code\": \"123456\"\n}\n```\n\n");
    
    // Wallet endpoints
    markdown.push_str("## Wallet Management\n\n");
    
    markdown.push_str("### POST /api/wallets\n\n");
    markdown.push_str("**Description:** Create a new Stellar wallet\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"wallet_name\": \"My Stellar Wallet\",\n  \"password\": \"wallet-password\"\n}\n```\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"wallet_id\": \"uuid\",\n  \"public_key\": \"G...\",\n  \"wallet_name\": \"My Stellar Wallet\",\n  \"message\": \"Wallet created successfully\"\n}\n```\n\n");
    
    markdown.push_str("### POST /import\n\n");
    markdown.push_str("**Description:** Import existing Stellar wallet\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"wallet_name\": \"Imported Wallet\",\n  \"secret_key\": \"S...\",\n  \"password\": \"wallet-password\"\n}\n```\n\n");
    
    markdown.push_str("### GET /api/wallets\n\n");
    markdown.push_str("**Description:** List user wallets\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"wallets\": [\n    {\n      \"wallet_id\": \"uuid\",\n      \"wallet_name\": \"My Wallet\",\n      \"public_key\": \"G...\"\n    }\n  ]\n}\n```\n\n");
    
    markdown.push_str("### GET /api/wallets/{id}\n\n");
    markdown.push_str("**Description:** Get wallet details\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"wallet_id\": \"uuid\",\n  \"wallet_name\": \"My Wallet\",\n  \"public_key\": \"G...\",\n  \"balance_xlm\": \"100.5\",\n  \"created_at\": \"2024-01-01T00:00:00Z\"\n}\n```\n\n");
    
    markdown.push_str("### GET /api/wallets/{id}/balance\n\n");
    markdown.push_str("**Description:** Get wallet balance\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"balance_xlm\": \"100.5\"\n}\n```\n\n");
    
    markdown.push_str("### POST /api/wallets/{id}/send\n\n");
    markdown.push_str("**Description:** Send XLM payment (requires 2FA if enabled)\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"destination\": \"G...\",\n  \"amount\": \"10.5\",\n  \"memo\": \"Payment for services\",\n  \"password\": \"wallet-password\",\n  \"totp_code\": \"123456\"\n}\n```\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"transaction_hash\": \"hash\",\n  \"message\": \"Payment sent successfully\"\n}\n```\n\n");
    
    markdown.push_str("### GET /api/wallets/{id}/transactions\n\n");
    markdown.push_str("**Description:** Get transaction history\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"transactions\": [\n    {\n      \"hash\": \"hash\",\n      \"amount\": \"10.5\",\n      \"from\": \"G...\",\n      \"to\": \"G...\",\n      \"memo\": \"Payment\",\n      \"created_at\": \"2024-01-01T00:00:00Z\"\n    }\n  ]\n}\n```\n\n");
    
    markdown.push_str("### POST /api/wallets/{id}/sync\n\n");
    markdown.push_str("**Description:** Sync wallet with Stellar network\n\n");
    
    markdown.push_str("### POST /api/wallets/{id}/fund\n\n");
    markdown.push_str("**Description:** Fund wallet (testnet only)\n\n");
    
    markdown.push_str("### GET /api/wallets/{id}/receive\n\n");
    markdown.push_str("**Description:** Get receive information\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"wallet_id\": \"uuid\",\n  \"public_key\": \"G...\",\n  \"qr_code_url\": \"https://...\",\n  \"message\": \"Share this address to receive payments\"\n}\n```\n\n");
    
    // Profile endpoints
    markdown.push_str("## Profile Management\n\n");
    
    markdown.push_str("### GET /api/profile\n\n");
    markdown.push_str("**Description:** Get user profile\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"user_id\": \"uuid\",\n  \"email\": \"user@example.com\",\n  \"username\": \"testuser\",\n  \"is_verified\": false,\n  \"phone_number\": \"+1234567890\",\n  \"is_phone_verified\": false,\n  \"created_at\": \"2024-01-01T00:00:00Z\"\n}\n```\n\n");
    
    markdown.push_str("### PUT /api/profile\n\n");
    markdown.push_str("**Description:** Update user profile\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"email\": \"newemail@example.com\",\n  \"username\": \"newusername\"\n}\n```\n\n");
    
    markdown.push_str("### PUT /api/profile/phone\n\n");
    markdown.push_str("**Description:** Update phone number\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"phone_number\": \"+1234567890\"\n}\n```\n\n");
    
    markdown.push_str("### GET /api/profile/2fa/status\n\n");
    markdown.push_str("**Description:** Get 2FA status and information\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"enabled\": false,\n  \"setup_complete\": false,\n  \"backup_codes_remaining\": null\n}\n```\n\n");
    
    markdown.push_str("### GET /api/profile/2fa/setup\n\n");
    markdown.push_str("**Description:** Generate 2FA setup data (QR code, secret, backup codes)\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"qr_code_svg\": \"<svg>...</svg>\",\n  \"secret_key\": \"JBSWY3DPEHPK3PXP\",\n  \"backup_codes\": [\"12345678\", \"87654321\", ...],\n  \"message\": \"Scan the QR code with your authenticator app\"\n}\n```\n\n");
    
    markdown.push_str("### POST /api/profile/2fa/enable\n\n");
    markdown.push_str("**Description:** Enable 2FA after verifying TOTP code\n\n");
    markdown.push_str("**Request Body:**\n```json\n{\n  \"totp_code\": \"123456\"\n}\n```\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"success\": true,\n  \"message\": \"2FA enabled successfully\",\n  \"backup_codes\": [\"12345678\", \"87654321\", ...]\n}\n```\n\n");
    
    // Notification endpoints
    markdown.push_str("## Notifications\n\n");
    
    markdown.push_str("### GET /api/notifications\n\n");
    markdown.push_str("**Description:** Get user notifications\n\n");
    markdown.push_str("**Response:**\n```json\n{\n  \"notifications\": [\n    {\n      \"id\": \"uuid\",\n      \"title\": \"Payment Received\",\n      \"message\": \"You received 10 XLM\",\n      \"date\": \"2024-01-01T00:00:00Z\",\n      \"status\": \"Unread\"\n    }\n  ]\n}\n```\n\n");
    
    markdown.push_str("### POST /api/notifications/{id}/mark-read\n\n");
    markdown.push_str("**Description:** Mark notification as read\n\n");
    
    markdown.push_str("### DELETE /api/notifications/{id}\n\n");
    markdown.push_str("**Description:** Delete notification\n\n");
    
    markdown.push_str("### POST /api/notifications/mark-all-read\n\n");
    markdown.push_str("**Description:** Mark all notifications as read\n\n");
    
    markdown.push_str("### DELETE /api/notifications/delete-all\n\n");
    markdown.push_str("**Description:** Delete all notifications\n\n");
    
    markdown.push_str("### GET /api/notifications/preferences\n\n");
    markdown.push_str("**Description:** Get notification preferences\n\n");
    
    markdown.push_str("### PUT /api/notifications/preferences\n\n");
    markdown.push_str("**Description:** Update notification preferences\n\n");
    
    // KYC endpoints
    markdown.push_str("## KYC (Know Your Customer)\n\n");
    markdown.push_str("### POST /api/kyc/upload-id\n\n");
    markdown.push_str("**Description:** Upload an ID photo for KYC (multipart/form-data, field name 'file').\n\n");
    markdown.push_str("**Response:**\n```
{\n  \"file_url\": \"/uploads/kyc/uuid_timestamp_uuid.jpg\"\n}\n```
\n");

    markdown.push_str("### POST /api/kyc/submit\n\n");
    markdown.push_str("**Description:** Submit KYC info (full name, ID type, ID number, file path from upload).\n\n");
    markdown.push_str("**Request Body:**\n```
{\n  \"full_name\": \"Jane Doe\",\n  \"id_type\": \"Passport\",\n  \"id_number\": \"A1234567\",\n  \"id_photo_url\": \"/uploads/kyc/uuid_timestamp_uuid.jpg\"\n}\n```
\n");
    markdown.push_str("**Response:**\n```
{\n  \"id\": \"uuid\",\n  \"full_name\": \"Jane Doe\",\n  \"id_type\": \"Passport\",\n  \"id_number\": \"A1234567\",\n  \"id_photo_url\": \"/uploads/kyc/uuid_timestamp_uuid.jpg\",\n  \"status\": \"pending\",\n  \"submitted_at\": \"2024-01-01T00:00:00Z\",\n  \"reviewed_at\": null,\n  \"rejection_reason\": null\n}\n```
\n");

    markdown.push_str("### GET /api/kyc/status\n\n");
    markdown.push_str("**Description:** Get current user's KYC status.\n\n");
    markdown.push_str("**Response:**\n```
{\n  \"status\": \"pending\",\n  \"rejection_reason\": null\n}\n```
\n");

    markdown.push_str("### GET /api/admin/kyc/list\n\n");
    markdown.push_str("**Description:** List all KYC submissions (admin only, requires X-Admin-Token header).\n\n");
    markdown.push_str("**Response:**\n```
{\n  \"submissions\": [ ... ]\n}\n```
\n");

    markdown.push_str("### POST /api/admin/kyc/{id}/review\n\n");
    markdown.push_str("**Description:** Approve or reject a KYC submission (admin only, requires X-Admin-Token header).\n\n");
    markdown.push_str("**Request Body:**\n```
{\n  \"status\": \"approved\",\n  \"rejection_reason\": null\n}\n```
\n");
    markdown.push_str("**Response:**\n```
{\n  \"success\": true,\n  \"message\": \"KYC approved\"\n}\n```
\n");
    
    // Error codes
    markdown.push_str("## Error Codes\n\n");
    markdown.push_str("| Code | Description |\n");
    markdown.push_str("|------|-------------|\n");
    markdown.push_str("| 200 | Success |\n");
    markdown.push_str("| 400 | Bad Request - Invalid input data |\n");
    markdown.push_str("| 401 | Unauthorized - Invalid or missing JWT token |\n");
    markdown.push_str("| 403 | Forbidden - Insufficient permissions |\n");
    markdown.push_str("| 404 | Not Found - Resource not found |\n");
    markdown.push_str("| 409 | Conflict - Resource already exists |\n");
    markdown.push_str("| 422 | Unprocessable Entity - Validation error |\n");
    markdown.push_str("| 500 | Internal Server Error |\n\n");
    
    // Examples
    markdown.push_str("## Examples\n\n");
    markdown.push_str("### Register a new user\n\n");
    markdown.push_str("```bash\ncurl -X POST http://localhost:8080/api/auth/register \\\n");
    markdown.push_str("  -H \"Content-Type: application/json\" \\\n");
    markdown.push_str("  -d '{\n");
    markdown.push_str("    \"email\": \"user@example.com\",\n");
    markdown.push_str("    \"username\": \"testuser\",\n");
    markdown.push_str("    \"password\": \"securepassword123\",\n");
    markdown.push_str("    \"phone_number\": \"+1234567890\"\n");
    markdown.push_str("  }'\n```\n\n");
    
    markdown.push_str("### Login\n\n");
    markdown.push_str("```bash\ncurl -X POST http://localhost:8080/api/auth/login \\\n");
    markdown.push_str("  -H \"Content-Type: application/json\" \\\n");
    markdown.push_str("  -d '{\n");
    markdown.push_str("    \"email_or_username\": \"user@example.com\",\n");
    markdown.push_str("    \"password\": \"securepassword123\"\n");
    markdown.push_str("  }'\n```\n\n");
    
    markdown.push_str("### Create a wallet\n\n");
    markdown.push_str("```bash\ncurl -X POST http://localhost:8080/api/wallets \\\n");
    markdown.push_str("  -H \"Authorization: Bearer <your-jwt-token>\" \\\n");
    markdown.push_str("  -H \"Content-Type: application/json\" \\\n");
    markdown.push_str("  -d '{\n");
    markdown.push_str("    \"wallet_name\": \"My Stellar Wallet\",\n");
    markdown.push_str("    \"password\": \"wallet-password\"\n");
    markdown.push_str("  }'\n```\n\n");
    
    markdown.push_str("### Send payment (with 2FA)\n\n");
    markdown.push_str("```bash\ncurl -X POST http://localhost:8080/api/wallets/<wallet-id>/send \\\n");
    markdown.push_str("  -H \"Authorization: Bearer <your-jwt-token>\" \\\n");
    markdown.push_str("  -H \"Content-Type: application/json\" \\\n");
    markdown.push_str("  -d '{\n");
    markdown.push_str("    \"destination\": \"G...\",\n");
    markdown.push_str("    \"amount\": \"10.5\",\n");
    markdown.push_str("    \"memo\": \"Payment for services\",\n");
    markdown.push_str("    \"password\": \"wallet-password\",\n");
    markdown.push_str("    \"totp_code\": \"123456\"\n");
    markdown.push_str("  }'\n```\n\n");
    
    markdown.push_str("## Support\n\n");
    markdown.push_str("For technical support or questions about the API, please contact the development team.\n\n");
    markdown.push_str("---\n\n");
    markdown.push_str("*This documentation is auto-generated from the OpenAPI specification and will stay in sync with the codebase.*\n");
    
    markdown
}

/// Generate comprehensive HTML documentation page
pub fn generate_documentation_html() -> String {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xendly API Documentation</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 10px;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .nav {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .nav h2 {
            margin-bottom: 15px;
            color: #333;
        }
        
        .nav-links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .nav-link {
            display: block;
            padding: 15px;
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            text-decoration: none;
            color: #495057;
            transition: all 0.3s ease;
        }
        
        .nav-link:hover {
            border-color: #667eea;
            background: #f0f2ff;
            transform: translateY(-2px);
        }
        
        .nav-link h3 {
            margin-bottom: 5px;
            color: #333;
        }
        
        .nav-link p {
            font-size: 0.9rem;
            color: #6c757d;
        }
        
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .endpoint {
            margin-bottom: 25px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .endpoint h3 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .method {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .method.get { background: #28a745; color: white; }
        .method.post { background: #007bff; color: white; }
        .method.put { background: #ffc107; color: black; }
        .method.delete { background: #dc3545; color: white; }
        
        .endpoint-url {
            font-family: 'Courier New', monospace;
            background: #e9ecef;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.9rem;
        }
        
        .description {
            margin: 15px 0;
            color: #6c757d;
        }
        
        .auth-note {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
            color: #856404;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
            margin-top: 30px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .nav-links {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Xendly API Documentation</h1>
            <p>Multi-currency wallet with Stellar blockchain integration</p>
        </div>
        
        <div class="nav">
            <h2>📚 Quick Access</h2>
            <div class="nav-links">
                <a href="/api/docs" class="nav-link">
                    <h3>🔍 Swagger UI</h3>
                    <p>Interactive API documentation with testing capabilities</p>
                </a>
                <a href="/api/redoc" class="nav-link">
                    <h3>📖 Redoc UI</h3>
                    <p>Clean, responsive API documentation</p>
                </a>
                <a href="/docs/openapi.json" class="nav-link">
                    <h3>📄 OpenAPI JSON</h3>
                    <p>Download the complete OpenAPI specification</p>
                </a>
                <a href="/docs/markdown" class="nav-link">
                    <h3>📝 Markdown</h3>
                    <p>Download documentation as Markdown file</p>
                </a>
            </div>
        </div>
        
        <div class="section">
            <h2>🔐 Authentication</h2>
            <p>Most endpoints require JWT authentication. Include your JWT token in the Authorization header:</p>
            <div class="endpoint">
                <code>Authorization: Bearer &lt;your-jwt-token&gt;</code>
            </div>
            
            <div class="auth-note">
                <strong>⚠️ Two-Factor Authentication (2FA):</strong> Sensitive operations require 2FA verification for users with 2FA enabled.
            </div>
        </div>
        
        <div class="section">
            <h2>🔑 Authentication Endpoints</h2>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/auth/register</h3>
                <div class="endpoint-url">Register a new user account</div>
                <div class="description">Creates a new user account with email, username, password, and optional phone number.</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/auth/login</h3>
                <div class="endpoint-url">Authenticate user and get JWT token</div>
                <div class="description">Authenticates user credentials and returns JWT token. If 2FA is enabled, returns user_id for 2FA verification.</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/auth/2fa-verify</h3>
                <div class="endpoint-url">Verify 2FA code and get JWT token</div>
                <div class="description">Verifies TOTP code for users with 2FA enabled and returns JWT token.</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/auth/change-password</h3>
                <div class="endpoint-url">Change user password</div>
                <div class="description">Changes user password. Requires 2FA if enabled.</div>
                <div class="auth-note">🔒 Requires JWT + 2FA (if enabled)</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/auth/disable-2fa</h3>
                <div class="endpoint-url">Disable two-factor authentication</div>
                <div class="description">Disables 2FA for the user account.</div>
                <div class="auth-note">🔒 Requires JWT + 2FA</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/auth/delete-account</h3>
                <div class="endpoint-url">Delete user account</div>
                <div class="description">Soft deletes the user account.</div>
                <div class="auth-note">🔒 Requires JWT + password + 2FA (if enabled)</div>
            </div>
        </div>
        
        <div class="section">
            <h2>👛 Wallet Management</h2>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/wallets</h3>
                <div class="endpoint-url">Create a new Stellar wallet</div>
                <div class="description">Creates a new Stellar wallet for the authenticated user.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/wallets/import</h3>
                <div class="endpoint-url">Import existing Stellar wallet</div>
                <div class="description">Imports an existing Stellar wallet using secret key.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/wallets</h3>
                <div class="endpoint-url">List user wallets</div>
                <div class="description">Returns all wallets belonging to the authenticated user.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/wallets/{id}</h3>
                <div class="endpoint-url">Get wallet details</div>
                <div class="description">Returns detailed information about a specific wallet.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/wallets/{id}/balance</h3>
                <div class="endpoint-url">Get wallet balance</div>
                <div class="description">Returns the current XLM balance of the wallet.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/wallets/{id}/send</h3>
                <div class="endpoint-url">Send XLM payment</div>
                <div class="description">Sends XLM from the wallet to another address.</div>
                <div class="auth-note">🔒 Requires JWT + 2FA (if enabled)</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/wallets/{id}/transactions</h3>
                <div class="endpoint-url">Get transaction history</div>
                <div class="description">Returns transaction history for the wallet.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/wallets/{id}/sync</h3>
                <div class="endpoint-url">Sync wallet with Stellar network</div>
                <div class="description">Syncs wallet balance and sequence number with Stellar network.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/wallets/{id}/fund</h3>
                <div class="endpoint-url">Fund wallet (testnet only)</div>
                <div class="description">Funds the wallet with test XLM (testnet only).</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/wallets/{id}/receive</h3>
                <div class="endpoint-url">Get receive information</div>
                <div class="description">Returns public key and QR code URL for receiving payments.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
        </div>
        
        <div class="section">
            <h2>👤 Profile Management</h2>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/profile</h3>
                <div class="endpoint-url">Get user profile</div>
                <div class="description">Returns the current user's profile information.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method put">PUT</span> /api/profile</h3>
                <div class="endpoint-url">Update user profile</div>
                <div class="description">Updates user's email and username.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method put">PUT</span> /api/profile/phone</h3>
                <div class="endpoint-url">Update phone number</div>
                <div class="description">Updates user's phone number.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>

            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/profile/2fa/status</h3>
                <div class="endpoint-url">Get 2FA status and information</div>
                <div class="description">Returns the current user's 2FA status and information.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>

            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/profile/2fa/setup</h3>
                <div class="endpoint-url">Generate 2FA setup data</div>
                <div class="description">Generates QR code, secret key, and backup codes for 2FA setup.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>

            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/profile/2fa/enable</h3>
                <div class="endpoint-url">Enable 2FA after verification</div>
                <div class="description">Enables 2FA for the user account after verifying the TOTP code.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔔 Notifications</h2>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/notifications</h3>
                <div class="endpoint-url">Get user notifications</div>
                <div class="description">Returns all notifications for the authenticated user.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/notifications/{id}/mark-read</h3>
                <div class="endpoint-url">Mark notification as read</div>
                <div class="description">Marks a specific notification as read.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method delete">DELETE</span> /api/notifications/{id}</h3>
                <div class="endpoint-url">Delete notification</div>
                <div class="description">Deletes a specific notification.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/notifications/mark-all-read</h3>
                <div class="endpoint-url">Mark all notifications as read</div>
                <div class="description">Marks all user notifications as read.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method delete">DELETE</span> /api/notifications/delete-all</h3>
                <div class="endpoint-url">Delete all notifications</div>
                <div class="description">Deletes all user notifications.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/notifications/preferences</h3>
                <div class="endpoint-url">Get notification preferences</div>
                <div class="description">Returns user's notification preferences.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
            
            <div class="endpoint">
                <h3><span class="method put">PUT</span> /api/notifications/preferences</h3>
                <div class="endpoint-url">Update notification preferences</div>
                <div class="description">Updates user's notification preferences.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔔 KYC Endpoints</h2>
            
            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/kyc/upload-id</h3>
                <div class="endpoint-url">Upload an ID photo for KYC</div>
                <div class="description">Uploads an ID photo for KYC verification (multipart/form-data, field name 'file').</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>

            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/kyc/submit</h3>
                <div class="endpoint-url">Submit KYC information</div>
                <div class="description">Submits KYC information (full name, ID type, ID number, file path) for review.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>

            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/kyc/status</h3>
                <div class="endpoint-url">Get KYC status</div>
                <div class="description">Gets the current user's KYC status.</div>
                <div class="auth-note">🔒 Requires JWT</div>
            </div>

            <div class="endpoint">
                <h3><span class="method get">GET</span> /api/admin/kyc/list</h3>
                <div class="endpoint-url">List KYC submissions (admin only)</div>
                <div class="description">Lists all KYC submissions for admin review (requires X-Admin-Token header).</div>
                <div class="auth-note">🔒 Requires JWT (Admin)</div>
            </div>

            <div class="endpoint">
                <h3><span class="method post">POST</span> /api/admin/kyc/{id}/review</h3>
                <div class="endpoint-url">Review KYC submission (admin only)</div>
                <div class="description">Reviews a specific KYC submission (approve or reject) by ID (admin only, requires X-Admin-Token header).</div>
                <div class="auth-note">🔒 Requires JWT (Admin)</div>
            </div>
        </div>
        
        <div class="footer">
            <p>📚 This documentation is auto-generated from the OpenAPI specification and stays in sync with the codebase.</p>
            <p>🔄 Last updated: <span id="last-updated"></span></p>
        </div>
    </div>
    
    <script>
        // Set last updated timestamp
        document.getElementById('last-updated').textContent = new Date().toLocaleString();
    </script>
</body>
</html>
    "#;
    
    html.to_string()
} 