# Xendly Backend

A scalable, production-ready Rust backend powering **Xendly** — a modern multi-asset wallet and cross-border payment platform for East Africa, built on Stellar. It enables fast, secure money transfers, real-time FX with USDC, and local cash payouts via mobile money.

---

## Table of Contents

* [Project Overview](#project-overview)
* [Features Accomplished So Far](#features-accomplished-so-far)
* [What Remains To Be Done](#what-remains-to-be-done)
* [Codebase Structure](#codebase-structure)
* [Getting Started](#getting-started)
* [API Usage](#api-usage)
* [Security & Best Practices](#security--best-practices)
* [Scalability & Future Roadmap](#scalability--future-roadmap)
* [Contribution Guidelines](#contribution-guidelines)
* [FAQ](#faq)
* [License](#license)
* [Contact](#contact)

---

## Project Overview

**Xendly Backend** is the financial engine behind **Xendly** — an intelligent, cross-border wallet designed to make sending and receiving money across East Africa fast, transparent, and effortless.

Here’s how Xendly works behind the scenes:

* Users deposit local currency (KES, UGX, ETB) via cash-in agents or mobile money.
* The backend credits the user’s Stellar wallet with digital tokens, bridging the local money into blockchain.
* Funds are stored securely; users can send money locally or across borders.
* For cross-border transfers, Xendly swaps the sender’s currency into USDC (a stable digital asset) on Stellar’s decentralized exchange, and then into the receiver’s local currency.
* Finally, recipients can keep funds in the wallet, spend directly, or withdraw instantly to their local mobile number (e.g., M-Pesa, Telebirr, MTN, Airtel).

✅ **Deposit locally → Store securely → Send globally → Withdraw locally.**

Built entirely in async Rust (Axum, Tokio), the backend exposes a clean API, handles payments, authentication (JWT, 2FA), notifications, and ensures high performance, scalability, and robust security.

---

## Features Accomplished So Far

* **User Authentication**

  * JWT login, registration, password reset, optional SMS-based 2FA
* **Profile Management**

  * View/update profile, change password, manage notification preferences
* **Wallet Management**

  * Create and manage Stellar wallets (XLM, USDC)
  * Generate QR codes for receiving funds
* **Payments & Transfers**

  * Send/receive payments locally and cross-border (powered by Stellar DEX)
* **Asset Exchange**

  * Swap between supported assets (XLM, USDC)
* **Notifications**

  * Real-time alerts and historical logs for transactions and security
* **API Documentation**

  * Complete OpenAPI/Swagger UI covering all endpoints and models
* **Security**

  * Strong password policy, 2FA, JWT, and sanitized error responses
* **Code Quality**

  * Idiomatic, async-first Rust, Clippy clean, well-commented
* **Database**

  * SQLite integration (with plans for Postgres in production)
* **Testing**

  * Tests covering major flows: auth, wallet, payments, notifications

---

## What Remains To Be Done

* **Production-grade Deployment**

  * Dockerization, CI/CD pipelines, environment config
* **Advanced Features**

  * Rate limiting, abuse prevention, admin dashboard, external webhooks
* **Monitoring & Observability**

  * Structured logging, metrics, health checks, error tracking
* **Database**

  * Migration to Postgres for scalability
* **Local Payout Rails**

  * Integrate M-Pesa, Telebirr, MTN, Airtel for cash-in/out
* **KYC & Compliance**

  * Partner with providers or build lightweight ID verification
* **Frontend Integration**

  * Connect and test with production mobile/web apps
* **More Testing**

  * End-to-end integration, property-based tests

---

## Codebase Structure

```plaintext
backend/
├── API_DOCUMENTATION.md     # Extra API docs (if any)
├── Cargo.toml               # Project metadata and dependencies
├── src/
│   ├── api/                 # HTTP API layer: routes, types, OpenAPI docs
│   ├── cli/                 # CLI commands (admin/dev utilities)
│   ├── database/            # Database setup, helpers, migrations
│   ├── errors.rs            # Centralized error definitions and handling
│   ├── handlers/            # Business logic (auth, wallet, transfers)
│   ├── lib.rs               # Shared app state, common setup
│   ├── main.rs              # Application entry point
│   ├── models/              # Data models, schemas
│   ├── qr_codes/            # QR code generation
│   ├── services/            # Services: Stellar, auth, SMS, etc.
│   └── utils/               # Validation, crypto, middleware, helpers
└── .gitignore
```

---

## Getting Started

### Prerequisites

* Rust (latest stable, via [rustup.rs](https://rustup.rs/))
* SQLite (for local dev)
* Optional: Docker (for deployment)

### Setup

```sh
# Clone repository
git clone https://github.com/your-org/xendly-backend.git
cd xendly-backend/backend

# Build
cargo build

# Set secrets (example .env)
echo "DATABASE_URL=sqlite://./src/stellar_wallet.db" >> .env
echo "JWT_SECRET=your_jwt_secret" >> .env
echo "SMS_API_KEY=your_sms_api_key" >> .env

# Start server
cargo run
```

### API Docs

Access [http://localhost:8000/api/docs](http://localhost:8000/api/docs) for full Swagger UI.

---

## API Usage

**Sample Endpoints:**

* `POST /api/auth/register` — Create account
* `POST /api/auth/login` — Login, receive JWT
* `GET /api/profile` — View profile (JWT required)
* `POST /api/wallets` — Create Stellar wallet
* `POST /api/payments/send` — Send funds
* `POST /api/exchange` — Swap XLM ↔ USDC
* `GET /api/notifications` — List alerts

**Auth:** Use `Authorization: Bearer <token>` header.
**Password policy:** 8+ chars, mixed case, digit, special character.
**Error responses:** Standardized, no sensitive info.

---

## Security & Best Practices

* JWT auth & 2FA (SMS)
* Secrets in env vars (never hardcoded)
* Strong password rules, sanitized errors
* Input validation on all endpoints
* Rate limiting & structured logging (planned)

---

## Scalability & Future Roadmap

| Phase      | Goal                                                           |
| ---------- | -------------------------------------------------------------- |
| MVP        | SQLite, Stellar, USDC, local sends, cross-border swap          |
| Production | Postgres, Docker, CI/CD, monitoring, KYC, payout rails         |
| Expansion  | More African countries, local currency anchors, merchant tools |

---

## Contribution Guidelines

* Fork, branch, and keep PRs small
* Use idiomatic, async Rust (Axum/Tokio)
* Add/maintain OpenAPI docs and comments
* Run `cargo check` + `cargo clippy`
* Write tests for new logic

---

## FAQ

> **Q: How do users deposit local currency?**
> Users deposit via local mobile money or agents; funds appear in their Xendly wallet.

> **Q: What currencies?**
> Initially KES, UGX, ETB backed by USDC for cross-border swaps.

> **Q: Can users withdraw to mobile?**
> Yes — users can withdraw directly to their mobile number (M-Pesa, Telebirr, etc.).

> **Q: Which assets?**
> XLM, USDC, and local currency tokens when anchors exist.

> **Q: See endpoints?**
> `/api/docs` Swagger UI.

---

## License

MIT or Apache 2.0 — update as needed.

---

## Contact

Questions? Open an issue or reach out to maintainers.

---
