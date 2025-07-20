# Xendly API Documentation

## Overview

Xendly is a multi-currency wallet application with Stellar blockchain integration and mobile money features. This API provides comprehensive endpoints for user authentication, wallet management, profile management, and notifications.

## Table of Contents

- [Authentication](#authentication)
- [Wallet Management](#wallet-management)
- [Profile Management](#profile-management)
- [Notifications](#notifications)
- [Error Codes](#error-codes)
- [Examples](#examples)

## Authentication

Most endpoints require JWT authentication. Include your JWT token in the Authorization header:

```http
Authorization: Bearer <your-jwt-token>
```

### Two-Factor Authentication (2FA)

Sensitive operations require 2FA verification. Users with 2FA enabled must provide a TOTP code for:
- Sending payments
- Changing password
- Disabling 2FA
- Deleting account

## Base URL

```
http://localhost:8080/api
```

## Authentication Endpoints

### POST /api/auth/register

**Description:** Register a new user account

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "testuser",
  "password": "securepassword123",
  "phone_number": "+1234567890"
}
```

**Response:**
```json
{
  "user_id": "uuid",
  "message": "User registered successfully"
}
```

**Notes:**
- If a phone number is provided, a welcome SMS will be sent automatically
- The welcome SMS includes account details and next steps
- SMS delivery failures won't prevent account creation

### POST /api/auth/login

**Description:** Authenticate user and get JWT token

**Request Body:**
```json
{
  "email_or_username": "user@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "token": "jwt-token",
  "expires_in": 86400,
  "two_fa_required": false,
  "user_id": null
}
```

### POST /api/auth/2fa-verify

**Description:** Verify 2FA code and get JWT token

**Request Body:**
```json
{
  "user_id": "uuid",
  "totp_code": "123456"
}
```

**Response:**
```json
{
  "token": "jwt-token",
  "expires_in": 86400
}
```

### POST /api/auth/change-password

**Description:** Change user password (requires 2FA if enabled)

**Request Body:**
```json
{
  "user_id": "uuid",
  "current_password": "oldpassword",
  "new_password": "newpassword",
  "totp_code": "123456"
}
```

### POST /api/auth/disable-2fa

**Description:** Disable two-factor authentication

**Request Body:**
```json
{
  "user_id": "uuid",
  "totp_code": "123456"
}
```

### POST /api/auth/delete-account

**Description:** Delete user account (requires password and 2FA if enabled)

**Request Body:**
```json
{
  "user_id": "uuid",
  "password": "userpassword",
  "totp_code": "123456"
}
```

## Wallet Management

### POST /api/wallets

**Description:** Create a new Stellar wallet

**Request Body:**
```json
{
  "wallet_name": "My Stellar Wallet",
  "password": "wallet-password"
}
```

**Response:**
```json
{
  "wallet_id": "uuid",
  "public_key": "G...",
  "wallet_name": "My Stellar Wallet",
  "message": "Wallet created successfully"
}
```

### POST /api/wallets/import

**Description:** Import existing Stellar wallet

**Request Body:**
```json
{
  "wallet_name": "Imported Wallet",
  "secret_key": "S...",
  "password": "wallet-password"
}
```

### GET /api/wallets

**Description:** List user wallets

**Response:**
```json
{
  "wallets": [
    {
      "wallet_id": "uuid",
      "wallet_name": "My Wallet",
      "public_key": "G..."
    }
  ]
}
```

### GET /api/wallets/{id}

**Description:** Get wallet details

**Response:**
```json
{
  "wallet_id": "uuid",
  "wallet_name": "My Wallet",
  "public_key": "G...",
  "balance_xlm": "100.5",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### GET /api/wallets/{id}/balance

**Description:** Get wallet balance

**Response:**
```json
{
  "balance_xlm": "100.5"
}
```

### POST /api/wallets/{id}/send

**Description:** Send XLM payment (requires 2FA if enabled)

**Request Body:**
```json
{
  "destination": "G...",
  "amount": "10.5",
  "memo": "Payment for services",
  "password": "wallet-password",
  "totp_code": "123456"
}
```

**Response:**
```json
{
  "transaction_hash": "hash",
  "message": "Payment sent successfully"
}
```

### GET /api/wallets/{id}/transactions

**Description:** Get transaction history

**Response:**
```json
{
  "transactions": [
    {
      "hash": "hash",
      "amount": "10.5",
      "from": "G...",
      "to": "G...",
      "memo": "Payment",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### POST /api/wallets/{id}/sync

**Description:** Sync wallet with Stellar network

### POST /api/wallets/{id}/fund

**Description:** Fund wallet (testnet only)

### GET /api/wallets/{id}/receive

**Description:** Get receive information

**Response:**
```json
{
  "wallet_id": "uuid",
  "public_key": "G...",
  "qr_code_url": "https://...",
  "message": "Share this address to receive payments"
}
```

## Profile Management

### GET /api/profile

**Description:** Get user profile

**Response:**
```json
{
  "user_id": "uuid",
  "email": "user@example.com",
  "username": "testuser",
  "is_verified": false,
  "phone_number": "+1234567890",
  "is_phone_verified": false,
  "created_at": "2024-01-01T00:00:00Z"
}
```

### PUT /api/profile

**Description:** Update user profile

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "username": "newusername"
}
```

### PUT /api/profile/phone

**Description:** Update phone number

**Request Body:**
```json
{
  "phone_number": "+1234567890"
}
```

### POST /api/profile/phone/send-verification

**Description:** Send SMS verification code to phone number

**Request Body:**
```json
{
  "phone_number": "+1234567890"
}
```

**Response:**
```json
{
  "message": "Verification code sent successfully",
  "success": true
}
```

### POST /api/profile/phone/verify

**Description:** Verify phone number with SMS code

**Request Body:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "message": "Phone number verified successfully",
  "success": true
}
```

**Verification SMS Example:**
```
🔐 Xendly Phone Verification

Your verification code is: 123456

This code is valid for 10 minutes.
If you didn't request this code, please ignore this message.

Xendly Team
```

## Notifications

### GET /api/notifications

**Description:** Get user notifications

**Response:**
```json
{
  "notifications": [
    {
      "id": "uuid",
      "title": "Payment Received",
      "message": "You received 10 XLM",
      "date": "2024-01-01T00:00:00Z",
      "status": "Unread"
    }
  ]
}
```

### POST /api/notifications/{id}/mark-read

**Description:** Mark notification as read

### DELETE /api/notifications/{id}

**Description:** Delete notification

### POST /api/notifications/mark-all-read

**Description:** Mark all notifications as read

### DELETE /api/notifications/delete-all

**Description:** Delete all notifications

### GET /api/notifications/preferences

**Description:** Get notification preferences

### PUT /api/notifications/preferences

**Description:** Update notification preferences

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid input data |
| 401 | Unauthorized - Invalid or missing JWT token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation error |
| 500 | Internal Server Error |

## Examples

### Register a new user

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "securepassword123",
    "phone_number": "+1234567890"
  }'
```

**Welcome SMS Example:**
```
🎉 Welcome to Xendly!

Your account has been created successfully.
Username: testuser
Email: user@example.com

Next steps:
• Log in to your account
• Create your first wallet
• Start sending and receiving payments

Need help? Contact us at support@xendly.com
Visit: https://xendly.com

Thank you for choosing Xendly! 🚀
```

### Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email_or_username": "user@example.com",
    "password": "securepassword123"
  }'
```

### Create a wallet

```bash
curl -X POST http://localhost:8080/api/wallets \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "wallet_name": "My Stellar Wallet",
    "password": "wallet-password"
  }'
```

### Send payment (with 2FA)

```bash
curl -X POST http://localhost:8080/api/wallets/<wallet-id>/send \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "G...",
    "amount": "10.5",
    "memo": "Payment for services",
    "password": "wallet-password",
    "totp_code": "123456"
  }'
```

### Verify phone number

```bash
# Step 1: Send verification code
curl -X POST http://localhost:8080/api/profile/phone/send-verification \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+1234567890"
  }'

# Step 2: Verify the code received via SMS
curl -X POST http://localhost:8080/api/profile/phone/verify \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456"
  }'
```

## Support

For technical support or questions about the API, please contact the development team.

---

*This documentation is auto-generated from the OpenAPI specification and will stay in sync with the codebase.*
