# Xendly Backend

A scalable, production-ready Rust backend for a multi-asset wallet and payment platform, supporting Stellar-based assets (XLM, USDC), secure authentication, notifications, and robust API documentation.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Features Accomplished So Far](#features-accomplished-so-far)
- [What Remains To Be Done](#what-remains-to-be-done)
- [Codebase Structure](#codebase-structure)
- [Getting Started](#getting-started)
- [API Usage](#api-usage)
- [Security & Best Practices](#security--best-practices)
- [Scalability & Future Roadmap](#scalability--future-roadmap)
- [Contribution Guidelines](#contribution-guidelines)
- [FAQ](#faq)
- [License](#license)
- [Contact](#contact)

---

## Project Overview

**Xendly Backend** is a robust, async-first Rust backend for a modern multi-asset wallet and payment platform. It enables users to securely create and manage Stellar wallets (XLM, USDC), perform payments and exchanges, receive notifications, and interact with a fully documented API. Designed for scalability, security, and ease of integration with frontend/mobile clients.

**Key Goals:**
- Enable users to create/manage Stellar wallets (XLM, USDC)
- Secure payments, transfers, and asset exchange
- Strong authentication (JWT, 2FA), notifications, and QR code support
- Clean, well-documented, and testable API for frontend/mobile clients

---

## Features Accomplished So Far

- **User Authentication:**
  - JWT-based login, registration, password reset, and 2FA (SMS)
- **Profile Management:**
  - View/update user profile, change password, manage notification preferences
- **Wallet Management:**
  - Create, view, and manage Stellar wallets (XLM, USDC)
  - Generate QR codes for wallet public keys (SVG, base64 data URI)
- **Payments & Transfers:**
  - Send/receive payments, internal transfers, and asset selection (XLM/USDC)
- **Asset Exchange:**
  - Exchange between supported assets (XLM, USDC)
- **Notifications:**
  - Real-time and historical notifications (security, transaction, system)
- **API Documentation:**
  - Complete OpenAPI/Swagger UI with all endpoints, models, and error responses
- **Security:**
  - Strong password policies, JWT, 2FA, and secure error handling
- **Code Quality:**
  - Idiomatic, async-first Rust (tokio, axum), Clippy clean, documented
- **Testing:**
  - Endpoints tested for all major flows (auth, wallet, payments, notifications)
- **Database:**
  - SQLite integration for user, wallet, and transaction data

---

## What Remains To Be Done

- **Production Deployment:**
  - Dockerization and deployment scripts
  - Cloud/CI integration (optional)
- **Advanced Features:**
  - Webhooks for external integrations
  - Admin dashboard endpoints
  - Rate limiting and abuse prevention
- **Testing:**
  - More comprehensive integration and property-based tests
- **Monitoring:**
  - Logging, metrics, and health checks
- **Frontend Integration:**
  - Finalize and test with production frontend/mobile clients
- **Documentation:**
  - Expand developer and API usage guides
- **Scalability:**
  - Migration to Postgres (optional, for scale)
  - Horizontal scaling and load balancing

---

## Codebase Structure

```plaintext
backend/
  ├── API_DOCUMENTATION.md      # Additional API docs (if any)
  ├── Cargo.toml                # Rust dependencies and metadata
  ├── src/
  │   ├── api/                  # HTTP API layer (routes, types, docs)
  │   │   ├── docs.rs           # OpenAPI/Swagger schema definitions
  │   │   ├── mod.rs            # API module root
  │   │   ├── routes.rs         # All HTTP route handlers
  │   │   └── types.rs          # API request/response types
  │   ├── cli/                  # CLI commands (for admin/dev use)
  │   ├── database/             # Database layer (SQLite, migrations)
  │   ├── errors.rs             # Centralized error types/handling
  │   ├── handlers/             # Business logic handlers (per feature)
  │   ├── lib.rs                # Library root (shared app state, setup)
  │   ├── main.rs               # Application entry point (server startup)
  │   ├── models/               # Data models (User, Wallet, etc.)
  │   ├── qr_codes/             # QR code generation utilities
  │   ├── services/             # Service layer (auth, notifications, etc.)
  │   ├── stellar_wallet.db     # SQLite database file (dev only)
  │   └── utils/                # Utilities (crypto, validation, middleware)
  └── .gitignore
```

**Key Directories Explained:**

- `src/api/`: All HTTP API endpoints, OpenAPI docs, and request/response types.
- `src/handlers/`: Core business logic for each feature (account, wallet, transfer, etc.).
- `src/services/`: Service abstractions (auth, notifications, Stellar, 2FA).
- `src/models/`: Data models, database schema representations.
- `src/database/`: Database connection, migrations, and helpers.
- `src/utils/`: Shared utilities (crypto, validation, middleware, SMS).
- `src/cli/`: Command-line tools for admin/dev tasks.
- `src/qr_codes/`: QR code generation logic.

---

## Getting Started

### Prerequisites

- Rust (latest stable, install via [rustup](https://rustup.rs/))
- SQLite (for local development)
- [Optional] Docker (for deployment)
- Environment variables for secrets (see below)

### Setup

1. **Clone the repository:**
   ```sh
   git clone https://github.com/your-org/xendly-backend.git
   cd xendly-backend/backend
   ```

2. **Install dependencies:**
   ```sh
   cargo build
   ```

3. **Set environment variables:**  
   Create a `.env` file or set these in your shell:
   ```env
   DATABASE_URL=sqlite://./src/stellar_wallet.db
   JWT_SECRET=your_jwt_secret
   SMS_API_KEY=your_sms_api_key
   # ...other secrets as needed
   ```

4. **Run database migrations (if any):**
   - For SQLite, the schema is auto-created on first run.
   - For Postgres (future), use migration scripts.

5. **Start the server:**
   ```sh
   cargo run
   ```

6. **Access the API docs:**  
   Open [http://localhost:8000/api/docs](http://localhost:8000/api/docs) for Swagger UI.

---

## API Usage

- **All endpoints are documented in Swagger/OpenAPI UI.**
- Example endpoints:
  - `POST /api/auth/register` – Register a new user
  - `POST /api/auth/login` – Login and receive JWT
  - `GET /api/profile` – Get user profile (JWT required)
  - `POST /api/wallets` – Create a new Stellar wallet (XLM/USDC)
  - `GET /api/wallets/{id}/receive` – Get wallet public key and QR code
  - `POST /api/payments/send` – Send payment to another user/wallet
  - `POST /api/exchange` – Exchange assets (XLM/USDC)
  - `GET /api/notifications` – List user notifications

**Authentication:**  
Most endpoints require a JWT in the `Authorization: Bearer <token>` header.

**Password Policy:**  
Minimum 8 characters, must include uppercase, lowercase, digit, and special character.

**Asset Support:**  
Only XLM and USDC are supported for all wallet and payment operations.

**Error Handling:**  
All error responses are standardized and documented in the API schema.

---

## Security & Best Practices

- **JWT Authentication:** All sensitive endpoints require JWT.
- **2FA:** Optional SMS-based two-factor authentication.
- **Password Policy:** Enforced on registration and password change.
- **Secrets:** All secrets (JWT, SMS API keys) must be set via environment variables.
- **Input Validation:** All user input is validated and sanitized.
- **Error Responses:** No sensitive information is leaked in errors.

---

## Scalability & Future Roadmap

- **Current:**  
  - SQLite for local/dev, async-first Rust (tokio, axum), modular codebase.
- **Planned:**  
  - Postgres support for production
  - Horizontal scaling (stateless API)
  - Advanced monitoring/logging
  - Webhooks and external integrations

---

## Contribution Guidelines

- Fork the repo and create a feature branch.
- Write clear, idiomatic, and async-first Rust code.
- Add/maintain doc comments and OpenAPI annotations.
- Run `cargo check` and `cargo clippy` before PRs.
- Ensure all new endpoints are documented in Swagger/OpenAPI.
- Write tests for new features.
- Submit a pull request with a clear description.

---

## FAQ

**Q: How do I reset my password?**  
A: Use the `/api/auth/reset-password` endpoint. You’ll receive a reset code via SMS.

**Q: How do I get a QR code for my wallet?**  
A: Call `/api/wallets/{id}/receive` – the response includes a `qr_code_url` (SVG data URI).

**Q: What assets are supported?**  
A: Only XLM and USDC are supported for wallets, payments, and exchanges.

**Q: How do I see all API endpoints?**  
A: Visit `/api/docs` for the full Swagger/OpenAPI UI.

**Q: How do I run tests?**  
A: (If tests are implemented) Run `cargo test`.

---

## License

MIT or Apache 2.0 (choose and update as appropriate).

---

## Contact

For questions, open an issue or contact the maintainers.
