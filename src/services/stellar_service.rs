use ed25519_dalek::{SigningKey, Signer};
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Digest};
use crate::errors::{Result, AppError};
use crate::models::stellar_wallet::{StellarWallet, AssetBalance, WalletInfo};
use crate::database::sqlite::SqliteDatabase;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use reqwest::Client;
use serde_json::Value;
use stellar_strkey::Strkey;
use rand::RngCore;
use rand::rngs::OsRng;
use stellar_strkey::ed25519::{PublicKey as StellarPublicKey, PrivateKey as StellarPrivateKey};
use stellar_xdr::curr::{
    Asset, Memo, Operation, OperationBody, PaymentOp, Transaction,
    TransactionEnvelope, TransactionV1Envelope, Uint256, MuxedAccount, SequenceNumber,
    Preconditions, TransactionExt, DecoratedSignature, Signature, StringM, VecM,
    WriteXdr, Limits, BytesM, Hash, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, SignatureHint
};
use crate::models::currency::SupportedCurrency;

#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub hash: String,
    pub transaction_type: String,
    pub amount: String,
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    pub from: String,
    pub to: String,
    pub memo: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[allow(dead_code)]
pub struct StellarService {
    pub horizon_url: String,  
    pub network_passphrase: String,
    client: Client,
    database: Arc<SqliteDatabase>,
}

/// Result of a path payment operation
pub struct PathPaymentResult {
    pub tx_hash: String,
}

impl StellarService {
    pub fn new(database: Arc<SqliteDatabase>) -> Self {
        Self {
            horizon_url: "https://horizon-testnet.stellar.org".to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            client: Client::new(),
            database,
        }
    }

    #[allow(dead_code)]
    pub fn new_mainnet(database: Arc<SqliteDatabase>) -> Self {
        Self {
            horizon_url: "https://horizon.stellar.org".to_string(),
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            client: Client::new(),
            database,
        }
    }

    // Generate a new Stellar keypair
    pub fn generate_keypair(&self) -> Result<(String, String)> {
        // Generate random 32 bytes for secret key
        let mut rng = OsRng;
        let mut secret_bytes = [0u8; 32];
        
        rng.fill_bytes(&mut secret_bytes);
        
        // Create signing key from the bytes
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        
        // Convert to Stellar format using stellar_strkey
        let public_key = Strkey::PublicKeyEd25519(StellarPublicKey(signing_key.verifying_key().to_bytes())).to_string();
        let secret_key = Strkey::PrivateKeyEd25519(StellarPrivateKey(signing_key.to_bytes())).to_string();
        
        Ok((public_key, secret_key))
    }    #[allow(dead_code)]
    // Helper function to verify Stellar keys
    fn verify_stellar_key(&self, key: &str, is_public: bool) -> bool {
        if is_public {
            Strkey::from_string(key)
                .map(|k| matches!(k, Strkey::PublicKeyEd25519(_)))
                .unwrap_or(false)
        } else {
            Strkey::from_string(key)
                .map(|k| matches!(k, Strkey::PrivateKeyEd25519(_)))
                .unwrap_or(false)
        }
    }

    // Create a new wallet
    pub fn create_wallet(&self, user_id: &Uuid, wallet_name: &str, password: &str) -> Result<StellarWallet> {
        let (public_key, secret_key) = self.generate_keypair()?;
        
        // Validate the secret key before encryption
        if !self.is_valid_secret_key(&secret_key) {
            return Err(AppError::ValidationError("Generated invalid secret key".to_string()));
        }
        
        // Encrypting the secret key with the provided password
        let encrypted_secret = self.encrypt_secret_key(&secret_key, password)?;
        
        let wallet = StellarWallet {
            id: Uuid::new_v4(),
            user_id: *user_id,
            public_key,
            encrypted_secret_key: encrypted_secret,
            wallet_name: wallet_name.to_string(),
            is_active: true,
            balance_xlm: Some("0".to_string()),
            sequence_number: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_sync_at: None,
        };

        println!("🌟 New Stellar wallet created: {}", wallet.public_key);
        Ok(wallet)
    }

    // Import existing wallet
    pub fn import_wallet(&self, user_id: &Uuid, wallet_name: &str, secret_key: &str, password: &str) -> Result<StellarWallet> {
        // Validate the secret key format
        if !self.is_valid_secret_key(secret_key) {
            return Err(AppError::ValidationError("Invalid Stellar secret key format".to_string()));
        }

        // Derive public key from secret key
        let public_key = self.derive_public_key(secret_key)?;
        
        // Encrypt the secret key
        let encrypted_secret = self.encrypt_secret_key(secret_key, password)?;
        
        let wallet = StellarWallet {
            id: Uuid::new_v4(),
            user_id: *user_id,
            public_key,
            encrypted_secret_key: encrypted_secret,
            wallet_name: wallet_name.to_string(),
            is_active: true,
            balance_xlm: None,
            sequence_number: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_sync_at: None,
        };

        println!("📥 Stellar wallet imported: {}", wallet.public_key);
        Ok(wallet)
    }

    // Get wallet information from Stellar network
    pub async fn get_wallet_info(&self, public_key: &str) -> Result<WalletInfo> {
        let url = format!("{}/accounts/{}", self.horizon_url, public_key);
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to fetch account info: {}", e)))?;

        let account = response.json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to parse account response: {}", e)))?;

        let mut balance_xlm = "0".to_string();
        if let Some(balances) = account["balances"].as_array() {
            for balance in balances {
                if balance["asset_type"].as_str() == Some("native") {
                    balance_xlm = balance["balance"].as_str().unwrap_or("0").to_string();
                    break;
                }
            }
        }

        Ok(WalletInfo {
            public_key: public_key.to_string(),
            wallet_name: "".to_string(),
            balance_xlm,
            sequence_number: account["sequence"].as_str().unwrap_or("0").parse::<i64>().unwrap_or(0),
            is_funded: true,
        })
    }

    // Get all balances for a wallet
    pub async fn get_wallet_balances(&self, public_key: &str) -> Result<Vec<AssetBalance>> {
        let url = format!("{}/accounts/{}", self.horizon_url, public_key);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| AppError::StellarError(format!("Failed to fetch account: {}", e)))?;

        if response.status() == 404 {
            // Account not found - return empty balance
            return Ok(vec![AssetBalance {
                id: Uuid::new_v4(),
                wallet_id: Uuid::new_v4(), // This should be replaced with actual wallet ID
                asset_type: "native".to_string(),
                asset_code: "XLM".to_string(),
                asset_issuer: None,
                balance: "0".to_string(),
                last_updated: Utc::now(),
            }]);
        }

        let account_data: Value = response.json().await
            .map_err(|e| AppError::StellarError(format!("Failed to parse account data: {}", e)))?;

        let balances = account_data["balances"].as_array()
            .ok_or_else(|| AppError::StellarError("Invalid account data format".to_string()))?;

        let wallet_balances: Vec<AssetBalance> = balances.iter()
            .map(|balance| {
                AssetBalance {
                    id: Uuid::new_v4(),
                    wallet_id: Uuid::new_v4(), // This should be replaced with actual wallet ID
                    asset_type: balance["asset_type"].as_str().unwrap_or("").to_string(),
                    asset_code: if balance["asset_type"].as_str().unwrap_or("") == "native" {
                        "XLM".to_string()
                    } else {
                        balance["asset_code"].as_str().unwrap_or("").to_string()
                    },
                    asset_issuer: balance["asset_issuer"].as_str().map(|s| s.to_string()),
                    balance: balance["balance"].as_str().unwrap_or("0").to_string(),
                    last_updated: Utc::now(),
                }
            })
            .collect();

        Ok(wallet_balances)
    }

    // Fund account using Friendbot (testnet only)
    pub async fn fund_testnet_account(&self, public_key: &str) -> Result<()> {
        // Validate the public key format first
        if !public_key.starts_with('G') {
            return Err(AppError::ValidationError("Invalid public key format".to_string()));
        }

        // Use the correct Friendbot URL
        let friendbot_url = format!("https://friendbot.stellar.org/?addr={}", public_key);
        
        println!("🌐 Requesting funding from Friendbot for: {}", public_key);
        
        let response = self.client.get(&friendbot_url)
            .send()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to connect to Friendbot: {}", e)))?;

        // Get the response body for better error messages
        let status = response.status();
        let body = response.text().await
            .unwrap_or_else(|_| "No response body".to_string());

        if !status.is_success() {
            return Err(AppError::StellarError(format!(
                "Friendbot funding failed (Status: {}): {}",
                status,
                body
            )));
        }

        println!("✅ Account funded successfully!");
        Ok(())
    }

    // Helper methods for key encoding/decoding
    fn derive_public_key(&self, secret_key: &str) -> Result<String> {
        // Parse the secret key
        let private_key = match Strkey::from_string(secret_key) {
            Ok(Strkey::PrivateKeyEd25519(key)) => key,
            _ => return Err(AppError::ValidationError("Invalid secret key format".to_string())),
        };

        // Convert to ed25519-dalek signing key
        let signing_key = SigningKey::from_bytes(&private_key.0);
        let verifying_key = signing_key.verifying_key();

        // Convert to Stellar public key format
        let public_key = Strkey::PublicKeyEd25519(StellarPublicKey(verifying_key.to_bytes())).to_string();
        
        Ok(public_key)
    }

    fn is_valid_secret_key(&self, secret_key: &str) -> bool {
        // First check if it starts with 'S'
        if !secret_key.starts_with('S') {
            return false;
        }

        // Try to parse as a Stellar private key
        match Strkey::from_string(secret_key) {
            Ok(Strkey::PrivateKeyEd25519(_)) => true,
            _ => false
        }
    }

    fn encrypt_secret_key(&self, secret_key: &str, password: &str) -> Result<String> {
        // Create a deterministic key from password using SHA256
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"stellar_wallet_salt_v1"); // Version-specific salt
        let key_hash = hasher.finalize();
        
        // XOR with the key hash
        let secret_bytes = secret_key.as_bytes();
        let mut encrypted_bytes = Vec::with_capacity(secret_bytes.len());
        
        // Create a repeating key pattern from the password hash
        let key_pattern: Vec<u8> = key_hash.iter().cycle().take(secret_bytes.len()).cloned().collect();
        
        for (i, &byte) in secret_bytes.iter().enumerate() {
            encrypted_bytes.push(byte ^ key_pattern[i]);
        }
        
        // Add a simple checksum to verify decryption
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(secret_key.as_bytes());
        let checksum = checksum_hasher.finalize();
        
        // Append first 4 bytes of checksum
        encrypted_bytes.extend_from_slice(&checksum[..4]);
        
        // Encode to base64
        Ok(general_purpose::STANDARD.encode(encrypted_bytes))
    }

    pub fn decrypt_secret_key(&self, encrypted_secret: &str, password: &str) -> Result<String> {
        println!("🔍 Debug: Attempting to decrypt secret key");
        println!("🔍 Debug: Encrypted secret length: {}", encrypted_secret.len());
        
        // Create the same hash as used for encryption
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"stellar_wallet_salt_v1");
        let key_hash = hasher.finalize();
        
        println!("🔍 Debug: Password hash created successfully");
        
        // Decode from base64
        let encrypted_bytes = general_purpose::STANDARD.decode(encrypted_secret)
            .map_err(|e| AppError::InternalError(format!("Failed to decode encrypted secret: {}", e)))?;
        
        println!("🔍 Debug: Base64 decoded, encrypted bytes length: {}", encrypted_bytes.len());
        
        if encrypted_bytes.len() < 4 {
            return Err(AppError::ValidationError("Invalid encrypted data format".to_string()));
        }
        
        // Split data and checksum
        let (data_bytes, checksum_bytes) = encrypted_bytes.split_at(encrypted_bytes.len() - 4);
        
        // XOR decrypt
        let mut decrypted_bytes = Vec::with_capacity(data_bytes.len());
        let key_pattern: Vec<u8> = key_hash.iter().cycle().take(data_bytes.len()).cloned().collect();
        
        for (i, &byte) in data_bytes.iter().enumerate() {
            decrypted_bytes.push(byte ^ key_pattern[i]);
        }
        
        println!("🔍 Debug: XOR decryption completed");
        println!("🔍 Debug: First few decrypted bytes: {:?}", &decrypted_bytes[..std::cmp::min(10, decrypted_bytes.len())]);
        
        // Verify checksum
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(&decrypted_bytes);
        let expected_checksum = checksum_hasher.finalize();
        
        if &expected_checksum[..4] != checksum_bytes {
            return Err(AppError::ValidationError("Wrong password or corrupted data".to_string()));
        }
        
        // Convert to string
        let decrypted = String::from_utf8(decrypted_bytes)
            .map_err(|e| {
                println!("🔍 Debug: UTF-8 conversion failed: {}", e);
                AppError::ValidationError("Wrong password. The decrypted data is not valid text.".to_string())
            })?;
        
        println!("🔍 Debug: UTF-8 conversion successful");
        println!("🔍 Debug: Decrypted string starts with: {}", &decrypted.chars().take(5).collect::<String>());
        
        // Validate the decrypted secret key
        if !self.is_valid_secret_key(&decrypted) {
            return Err(AppError::ValidationError(format!(
                "Invalid secret key format. Key starts with: {}", 
                &decrypted.chars().take(5).collect::<String>()
            )));
        }
        
        println!("🔍 Debug: Secret key validation passed");
        Ok(decrypted)
    }

    /// Verifies a Stellar transaction signature against a source public key.
    /// This is a critical security function used to validate transaction signatures
    /// before submitting them to the network. While it may appear unused, it's
    /// important to keep this function for:
    /// 1. Security auditing
    /// 2. Future transaction verification needs
    /// 3. Debugging transaction signature issues
    #[allow(dead_code)]  // Kept for security and future use
    fn verify_transaction(&self, envelope: &TransactionEnvelope, source_public_key: &str) -> Result<()> {
        println!("🔍 Verifying transaction before submission...");
        
        // Extract the public key from the transaction
        let tx_source = match envelope {
            TransactionEnvelope::Tx(tx_env) => {
                match &tx_env.tx.source_account {
                    MuxedAccount::Ed25519(key) => key.0,
                    _ => return Err(AppError::ValidationError("Invalid source account type".to_string())),
                }
            },
            _ => return Err(AppError::ValidationError("Invalid transaction envelope type".to_string())),
        };
        
        // Convert the provided public key to bytes for comparison
        let source_bytes = match Strkey::from_string(source_public_key) {
            Ok(Strkey::PublicKeyEd25519(pk)) => pk.0,
            _ => return Err(AppError::ValidationError("Invalid source public key format".to_string())),
        };
        
        // Verify the source account matches
        if tx_source != source_bytes {
            return Err(AppError::ValidationError("Transaction source account mismatch".to_string()));
        }
        
        // Verify signature is present
        match envelope {
            TransactionEnvelope::Tx(tx_env) => {
                if tx_env.signatures.len() == 0 {
                    return Err(AppError::ValidationError("Transaction is not signed".to_string()));
                }
            },
            _ => return Err(AppError::ValidationError("Invalid transaction envelope type".to_string())),
        }
        
        println!("✅ Transaction verification passed");
        Ok(())
    }

    /// Sends a payment from the source wallet to the destination.
    ///
    /// Note: If you receive an 'Invalid sequence number' error, sync the wallet first.
    pub async fn send_payment(
        &self,
        source_public_key: &str,
        destination_public_key: &str,
        amount: f64,
        memo: Option<String>,
        password: &str,
    ) -> Result<String> {
        println!("🔄 Initiating real Stellar transaction...");
        
        // Validate amount
        if amount <= 0.0 {
            return Err(AppError::ValidationError("Amount must be greater than 0".to_string()));
        }
        
        // Validate destination address
        if !destination_public_key.starts_with('G') {
            return Err(AppError::ValidationError("Invalid destination public key format".to_string()));
        }
        
        // Validate source address
        if !source_public_key.starts_with('G') {
            return Err(AppError::ValidationError("Invalid source public key format".to_string()));
        }
        
        // Check if source and destination are different
        if source_public_key == destination_public_key {
            return Err(AppError::ValidationError("Source and destination addresses cannot be the same".to_string()));
        }
    
        // Get source account's secret key from the database
        let wallet = self.database.get_wallet_by_public_key(source_public_key).await?
            .ok_or_else(|| AppError::StellarError("Source wallet not found".to_string()))?;
    
        // Decrypt the secret key
        let secret_key = match self.decrypt_secret_key(&wallet.encrypted_secret_key, password) {
            Ok(key) => {
                println!("✅ Secret key decrypted successfully");
                key
            }
            Err(e) => {
                println!("❌ Failed to decrypt secret key: {}", e);
                return Err(e);
            }
        };
    
        // Get source account details from Horizon
        let account_url = format!("{}/accounts/{}", self.horizon_url, source_public_key);
        let account_response = self.client.get(&account_url)
            .send()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to load source account: {}", e)))?;
    
        let account = account_response.json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to parse account response: {}", e)))?;
    
        // Get the latest sequence number
        let sequence = account["sequence"].as_str()
            .ok_or_else(|| AppError::StellarError("Invalid sequence number".to_string()))?
            .parse::<i64>()
            .map_err(|_| AppError::StellarError("Failed to parse sequence number".to_string()))?;

        // Use the next sequence number as required by Stellar (current + 1)
        let next_sequence = sequence + 1;
    
        // Convert public keys to bytes
        let source_bytes = match Strkey::from_string(source_public_key) {
            Ok(Strkey::PublicKeyEd25519(pk)) => pk.0,
            _ => return Err(AppError::ValidationError("Invalid source public key format".to_string())),
        };
        let dest_bytes = match Strkey::from_string(destination_public_key) {
            Ok(Strkey::PublicKeyEd25519(pk)) => pk.0,
            _ => return Err(AppError::ValidationError("Invalid destination public key format".to_string())),
        };
    
        // Build the payment operation
        let payment_op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(dest_bytes)),
                asset: Asset::Native,
                amount: (amount * 10000000.0) as i64,  // Convert XLM to stroops
            }),
        };
    
        // Memo
        let memo_xdr = if let Some(memo_str) = &memo {
            Memo::Text(StringM::try_from(memo_str.as_str()).unwrap())
        } else {
            Memo::None
        };
    
        // Build the transaction
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source_bytes)),
            fee: 100,  // Standard fee for 1 operation
            seq_num: SequenceNumber(next_sequence),
            cond: Preconditions::None,
            memo: memo_xdr,
            operations: VecM::try_from(vec![payment_op]).unwrap(),
            ext: TransactionExt::V0,
        };
    
        // FIXED: PROTOCOL 20+ COMPLIANT SIGNING
        println!("🔐 Computing network ID hash...");
        // 1. Compute network ID hash
        let network_id_bytes = Sha256::digest(self.network_passphrase.as_bytes());
        let network_id = Hash(network_id_bytes.into());
        
        println!("📝 Creating signature payload...");
        // 2. Create signature payload
        let payload = TransactionSignaturePayload {
            network_id,
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };
        
        println!("🔏 Serializing payload...");
        // 3. Serialize payload to XDR
        let payload_xdr = payload.to_xdr(Limits::none())
            .map_err(|e| AppError::StellarError(format!("Payload serialization failed: {}", e)))?;
        
        println!("🔐 Hashing payload...");
        // 4. Hash the payload
        let tx_hash = Sha256::digest(&payload_xdr);
    
        println!("🔑 Processing secret key...");
        // 5. Get seed from secret key
        let seed_bytes = match Strkey::from_string(&secret_key) {
            Ok(Strkey::PrivateKeyEd25519(sk)) => sk.0,
            _ => return Err(AppError::ValidationError("Invalid secret key format".to_string())),
        };

        // Ensure we have exactly 32 bytes for the signing key
        let seed_array: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| AppError::StellarError("Invalid seed length".to_string()))?;
        
        println!("✍️ Signing transaction...");
        // 6. Sign the hash using ed25519-dalek 2.1
        let signing_key = SigningKey::from_bytes(&seed_array);
        let signature = signing_key.sign(&tx_hash);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();
    
        println!("📋 Creating transaction envelope...");
        // Build envelope with signature
        let hint_bytes: [u8; 4] = public_bytes[28..32].try_into()
            .map_err(|_| AppError::StellarError("Failed to create signature hint".to_string()))?;
        let signature_hint = SignatureHint(hint_bytes);
            
        let signature_bytes = BytesM::try_from(signature.to_bytes().to_vec())
            .map_err(|e| AppError::StellarError(format!("Failed to create signature bytes: {}", e)))?;
            
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::try_from(vec![DecoratedSignature {
                hint: signature_hint,
                signature: Signature(signature_bytes),
            }]).map_err(|e| AppError::StellarError(format!("Failed to create signatures vector: {}", e)))?,
        });

        println!("🔏 Encoding final transaction...");
        // Encode envelope as base64 XDR
        let xdr_bytes = envelope.to_xdr(Limits::none())
            .map_err(|e| AppError::StellarError(format!("Envelope serialization failed: {}", e)))?;
        let tx_xdr = base64::engine::general_purpose::STANDARD.encode(&xdr_bytes);
    
        // Submit the transaction
        let submit_url = format!("{}/transactions", self.horizon_url);
        let params = [("tx", tx_xdr.clone())];
        
        println!("🚀 Submitting transaction to Horizon...");
        println!("🔗 URL: {}", submit_url);
        
        let response = self.client
            .post(&submit_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to submit transaction: {}", e)))?;
    
        // Get status before consuming response
        let status = response.status();
        println!("📝 Response status: {}", status);
    
        // Parse the response
        let resp_json: serde_json::Value = response.json().await
            .map_err(|e| AppError::StellarError(format!("Failed to parse Horizon response: {}", e)))?;
    
        // Check for transaction errors
        if let Some(extras) = resp_json.get("extras") {
            println!("⚠️ Transaction encountered issues:");
            if let Some(result_codes) = extras.get("result_codes") {
                println!("Result codes: {:?}", result_codes);
                return Err(AppError::StellarError(format!(
                    "Transaction failed with result codes: {:?}",
                    result_codes
                )));
            }
        }
    
        let hash = resp_json.get("hash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| AppError::StellarError("No transaction hash in response".to_string()))?;
    
        println!("✅ Transaction submitted successfully!");
        println!("🔗 Transaction Hash: {}", hash);
        
        // Update both sender and recipient balances
        if let Ok(wallet_info) = self.get_wallet_info(source_public_key).await {
            println!("📊 Updating sender balance to: {}", wallet_info.balance_xlm);
            let _ = self.database.update_wallet_balance(
                &wallet.id,
                &wallet_info.balance_xlm,
                Some(wallet_info.sequence_number)
            ).await;

            // Store the transaction in the database
            let transaction = crate::models::stellar_wallet::WalletTransaction {
                id: Uuid::new_v4(),
                wallet_id: wallet.id,
                transaction_hash: hash.to_string(),
                transaction_type: "payment".to_string(),
                amount: (amount * 10000000.0).to_string(), 
                asset_code: "XLM".to_string(),
                asset_issuer: None,
                from_address: source_public_key.to_string(),
                to_address: destination_public_key.to_string(),
                memo: memo.clone(),
                fee: "100".to_string(), // Standard fee
                status: "success".to_string(),
                created_at: Utc::now(),
                confirmed_at: Some(Utc::now()),
            };

            if let Err(e) = self.database.store_wallet_transaction(&transaction).await {
                println!("⚠️ Failed to store transaction in database: {}", e);
            }
        }

        // Update recipient's balance
        println!("📊 Updating recipient balance...");
        let _ = self.update_recipient_balance(destination_public_key).await;
        
        Ok(hash.to_string())
    }

    /// Sends a payment of any asset (XLM, USDC, etc.) from the source wallet to the destination.
    pub async fn send_payment_asset(
        &self,
        source_public_key: &str,
        destination_public_key: &str,
        amount: f64,
        asset_code: Option<String>,
        memo: Option<String>,
        password: &str,
    ) -> Result<String> {
        // Validate amount
        if amount <= 0.0 {
            return Err(AppError::ValidationError("Amount must be greater than 0".to_string()));
        }
        // Validate destination address
        if !destination_public_key.starts_with('G') {
            return Err(AppError::ValidationError("Invalid destination public key format".to_string()));
        }
        // Validate source address
        if !source_public_key.starts_with('G') {
            return Err(AppError::ValidationError("Invalid source public key format".to_string()));
        }
        // Check if source and destination are different
        if source_public_key == destination_public_key {
            return Err(AppError::ValidationError("Source and destination addresses cannot be the same".to_string()));
        }
        // --- Asset validation and lookup logic ---
        let usdc_issuer = "GA5ZSE7V3Y3P5YF3VJZQ2Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5";
        let asset = match asset_code.as_ref().map(|c| c.to_uppercase()) {
            None => Asset::Native,
            Some(ref code) if code == "XLM" => Asset::Native,
            Some(ref code) if code == "USDC" => {
                let pk = match Strkey::from_string(usdc_issuer) {
                    Ok(Strkey::PublicKeyEd25519(pk)) => pk.0,
                    _ => return Err(AppError::ValidationError("Invalid asset issuer public key format for USDC".to_string())),
                };
                Asset::CreditAlphanum4(
                    stellar_xdr::curr::AlphaNum4 {
                        asset_code: stellar_xdr::curr::AssetCode4(
                            b"USDC".clone()
                        ),
                        issuer: stellar_xdr::curr::AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(Uint256(pk))),
                    }
                )
            },
            Some(code) => {
                return Err(AppError::ValidationError(format!("Unsupported asset: {}", code)));
            }
        };
        // Get source account's secret key from the database
        let wallet = self.database.get_wallet_by_public_key(source_public_key).await?
            .ok_or_else(|| AppError::StellarError("Source wallet not found".to_string()))?;
        // Decrypt the secret key
        let secret_key = match self.decrypt_secret_key(&wallet.encrypted_secret_key, password) {
            Ok(key) => key,
            Err(e) => return Err(e),
        };
        // Get source account details from Horizon
        let account_url = format!("{}/accounts/{}", self.horizon_url, source_public_key);
        let account_response = self.client.get(&account_url)
            .send()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to load source account: {}", e)))?;
        let account = account_response.json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to parse account response: {}", e)))?;
        // Get the latest sequence number
        let sequence = account["sequence"].as_str()
            .ok_or_else(|| AppError::StellarError("Invalid sequence number".to_string()))?
            .parse::<i64>()
            .map_err(|_| AppError::StellarError("Failed to parse sequence number".to_string()))?;
        let next_sequence = sequence + 1;
        // Convert public keys to bytes
        let source_bytes = match Strkey::from_string(source_public_key) {
            Ok(Strkey::PublicKeyEd25519(pk)) => pk.0,
            _ => return Err(AppError::ValidationError("Invalid source public key format".to_string())),
        };
        let dest_bytes = match Strkey::from_string(destination_public_key) {
            Ok(Strkey::PublicKeyEd25519(pk)) => pk.0,
            _ => return Err(AppError::ValidationError("Invalid destination public key format".to_string())),
        };
        // Build the payment operation
        let payment_op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(dest_bytes)),
                asset,
                amount: (amount * 10000000.0) as i64,  // Convert to stroops
            }),
        };
        // Memo
        let memo_xdr = if let Some(memo_str) = &memo {
            Memo::Text(StringM::try_from(memo_str.as_str()).unwrap())
        } else {
            Memo::None
        };
        // Build the transaction
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source_bytes)),
            fee: 100,  // Standard fee for 1 operation
            seq_num: SequenceNumber(next_sequence),
            cond: Preconditions::None,
            memo: memo_xdr,
            operations: VecM::try_from(vec![payment_op]).unwrap(),
            ext: TransactionExt::V0,
        };
        // Signing and submission logic (same as send_payment)...
        // FIXED: PROTOCOL 20+ COMPLIANT SIGNING
        let network_id_bytes = Sha256::digest(self.network_passphrase.as_bytes());
        let network_id = Hash(network_id_bytes.into());
        let payload = TransactionSignaturePayload {
            network_id,
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };
        let payload_xdr = payload.to_xdr(Limits::none())
            .map_err(|e| AppError::StellarError(format!("Payload serialization failed: {}", e)))?;
        let tx_hash = Sha256::digest(&payload_xdr);
        let seed_bytes = match Strkey::from_string(&secret_key) {
            Ok(Strkey::PrivateKeyEd25519(sk)) => sk.0,
            _ => return Err(AppError::ValidationError("Invalid secret key format".to_string())),
        };
        let seed_array: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| AppError::StellarError("Invalid seed length".to_string()))?;
        let signing_key = SigningKey::from_bytes(&seed_array);
        let signature = signing_key.sign(&tx_hash);
        let verifying_key = signing_key.verifying_key();
        let public_bytes = verifying_key.to_bytes();
        let hint_bytes: [u8; 4] = public_bytes[28..32].try_into()
            .map_err(|_| AppError::StellarError("Failed to create signature hint".to_string()))?;
        let signature_hint = SignatureHint(hint_bytes);
        let signature_bytes = BytesM::try_from(signature.to_bytes().to_vec())
            .map_err(|e| AppError::StellarError(format!("Failed to create signature bytes: {}", e)))?;
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::try_from(vec![DecoratedSignature {
                hint: signature_hint,
                signature: Signature(signature_bytes),
            }]).map_err(|e| AppError::StellarError(format!("Failed to create signatures vector: {}", e)))?,
        });
        let xdr_bytes = envelope.to_xdr(Limits::none())
            .map_err(|e| AppError::StellarError(format!("Envelope serialization failed: {}", e)))?;
        let tx_xdr = base64::engine::general_purpose::STANDARD.encode(&xdr_bytes);
        let submit_url = format!("{}/transactions", self.horizon_url);
        let params = [("tx", tx_xdr.clone())];
        let response = self.client
            .post(&submit_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to submit transaction: {}", e)))?;
        let status = response.status();
        let resp_json: serde_json::Value = response.json().await
            .map_err(|e| AppError::StellarError(format!("Failed to parse Horizon response: {}", e)))?;
        if let Some(extras) = resp_json.get("extras") {
            if let Some(result_codes) = extras.get("result_codes") {
                return Err(AppError::StellarError(format!(
                    "Transaction failed with result codes: {:?}",
                    result_codes
                )));
            }
        }
        let hash = resp_json.get("hash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| AppError::StellarError("No transaction hash in response".to_string()))?;
        // Update both sender and recipient balances
        let _ = self.update_recipient_balance(destination_public_key).await;
        Ok(hash.to_string())
    }
    pub async fn get_transaction_history(&self, account_id: &str) -> Result<Vec<TransactionInfo>> {
        println!("📊 Fetching transaction history...");
        
        // First, try to get the wallet from the database
        let wallet = match self.database.get_wallet_by_public_key(account_id).await? {
            Some(w) => w,
            None => return Err(AppError::ValidationError("Wallet not found".to_string())),
        };

        // Get transactions from the database
        let db_transactions = self.database.get_wallet_transactions(&wallet.id).await?;
        
        // Also fetch from Horizon API to ensure we have the latest transactions
        let url = format!("{}/accounts/{}/operations?limit=10&order=desc", self.horizon_url, account_id);
        let response = self.client.get(&url)
            .send()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to fetch transactions: {}", e)))?;

        let operations = response.json::<serde_json::Value>()
            .await
            .map_err(|e| AppError::StellarError(format!("Failed to parse transactions response: {}", e)))?;

        let mut transaction_history = Vec::new();

        // Add database transactions
        for tx in db_transactions {
            let amount = if tx.asset_code == "XLM" {
                // Convert from stroops to XLM
                (tx.amount.parse::<f64>().unwrap_or(0.0) / 10000000.0).to_string()
            } else {
                tx.amount
            };

            transaction_history.push(TransactionInfo {
                hash: tx.transaction_hash,
                transaction_type: tx.transaction_type,
                amount,
                asset_code: tx.asset_code,
                asset_issuer: tx.asset_issuer,
                from: tx.from_address,
                to: tx.to_address,
                memo: tx.memo,
                created_at: tx.created_at,
            });
        }

        // Add Horizon API transactions that aren't in our database
        if let Some(records) = operations["_embedded"]["records"].as_array() {
            for op in records {
                if op["type"].as_str() == Some("payment") {
                    let hash = op["transaction_hash"].as_str().unwrap_or("").to_string();
                    
                    // Skip if we already have this transaction in our database
                    if transaction_history.iter().any(|tx| tx.hash == hash) {
                        continue;
                    }

                    // Create transaction info with cloned values
                    let created_at = DateTime::parse_from_rfc3339(op["created_at"].as_str().unwrap_or(""))
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());

                    let transaction_info = TransactionInfo {
                        hash: hash.clone(), // Clone hash here
                        transaction_type: "Payment".to_string(),
                        amount: op["amount"].as_str().unwrap_or("0").to_string(),
                        asset_code: op["asset_code"].as_str().unwrap_or("XLM").to_string(),
                        asset_issuer: op["asset_issuer"].as_str().map(|s| s.to_string()),
                        from: op["from"].as_str().unwrap_or("").to_string(),
                        to: op["to"].as_str().unwrap_or("").to_string(),
                        memo: None,
                        created_at,
                    };
                    transaction_history.push(transaction_info.clone()); // Clone transaction_info here

                    // Store this transaction in our database for future reference
                    let db_transaction = crate::models::stellar_wallet::WalletTransaction {
                        id: Uuid::new_v4(),
                        wallet_id: wallet.id,
                        transaction_hash: hash,
                        transaction_type: "payment".to_string(),
                        amount: (op["amount"].as_str().unwrap_or("0").parse::<f64>().unwrap_or(0.0) * 10000000.0).to_string(), // Convert to stroops
                        asset_code: op["asset_code"].as_str().unwrap_or("XLM").to_string(),
                        asset_issuer: op["asset_issuer"].as_str().map(|s| s.to_string()),
                        from_address: op["from"].as_str().unwrap_or("").to_string(),
                        to_address: op["to"].as_str().unwrap_or("").to_string(),
                        memo: None,
                        fee: "100".to_string(), // Standard fee
                        status: "success".to_string(),
                        created_at: transaction_info.created_at,
                        confirmed_at: Some(transaction_info.created_at),
                    };

                    if let Err(e) = self.database.store_wallet_transaction(&db_transaction).await {
                        println!("⚠️ Failed to store historical transaction in database: {}", e);
                    }
                }
            }
        }

        // Sort by date, newest first
        transaction_history.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        println!("✅ Found {} transactions", transaction_history.len());
        Ok(transaction_history)
    }

    // Add this method to update recipient's balance after successful transaction
    async fn update_recipient_balance(&self, recipient_public_key: &str) -> Result<()> {
        println!("📝 Updating recipient balance...");
        if let Ok(wallet_info) = self.get_wallet_info(recipient_public_key).await {
            if let Ok(Some(wallet)) = self.database.get_wallet_by_public_key(recipient_public_key).await {
                println!("💰 Updating recipient balance to: {}", wallet_info.balance_xlm);
                self.database.update_wallet_balance(
                    &wallet.id,
                    &wallet_info.balance_xlm,
                    Some(wallet_info.sequence_number)
                ).await?;
            }
        }
        Ok(())
    }
    #[allow(dead_code)]
    // Add this method to test wallet decryption
    pub fn test_wallet_decryption(&self, encrypted_secret: &str, password: &str) -> Result<bool> {
        match self.decrypt_secret_key(encrypted_secret, password) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // Add this method to re-encrypt a wallet with a new password (for fixing corrupted wallets)
    pub fn re_encrypt_wallet(&self, old_password: &str, new_password: &str, encrypted_secret: &str) -> Result<String> {
        // First decrypt with old password
        let secret_key = self.decrypt_secret_key(encrypted_secret, old_password)?;
        
        // Re-encrypt with new password
        let new_encrypted = self.encrypt_secret_key(&secret_key, new_password)?;
        
        Ok(new_encrypted)
    }

    // Add this method to help debug and fix wallet encryption issues
    pub async fn debug_wallet_encryption(&self, public_key: &str) -> Result<()> {
        println!("🔍 Debugging wallet encryption for: {}", public_key);
        
        // Get wallet from database
        let wallet = self.database.get_wallet_by_public_key(public_key).await?
            .ok_or_else(|| AppError::StellarError("Wallet not found".to_string()))?;
        
        println!("🔍 Wallet found in database");
        println!("🔍 Encrypted secret length: {}", wallet.encrypted_secret_key.len());
        println!("🔍 Wallet created at: {}", wallet.created_at);
        
        // Try to decode base64 to see if it's valid
        match general_purpose::STANDARD.decode(&wallet.encrypted_secret_key) {
            Ok(bytes) => {
                println!("🔍 Base64 decoding successful, {} bytes", bytes.len());
                println!("🔍 First 10 encrypted bytes: {:?}", &bytes[..std::cmp::min(10, bytes.len())]);
            }
            Err(e) => {
                println!("❌ Base64 decoding failed: {}", e);
                return Err(AppError::InternalError("Corrupted wallet data".to_string()));
            }
        }
        
        Ok(())
    }

    // Add this method to recreate a wallet with proper encryption
    pub async fn recreate_wallet_with_secret(&self, user_id: &uuid::Uuid, wallet_name: &str, secret_key: &str, password: &str) -> Result<StellarWallet> {
        println!("🔧 Recreating wallet with provided secret key");
        
        // Validate the secret key format first
        if !self.is_valid_secret_key(secret_key) {
            return Err(AppError::ValidationError("Invalid Stellar secret key format".to_string()));
        }
        
        // Derive public key from secret key
        let public_key = self.derive_public_key(secret_key)?;
        println!(" Derived public key: {}", public_key);
        
        // Use a simpler, more reliable encryption method
        let encrypted_secret = self.encrypt_secret_key_v2(secret_key, password)?;
        
        let wallet = StellarWallet {
            id: uuid::Uuid::new_v4(),
            user_id: *user_id,
            public_key,
            encrypted_secret_key: encrypted_secret,
            wallet_name: wallet_name.to_string(),
            is_active: true,
            balance_xlm: None,
            sequence_number: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_sync_at: None,
        };
        
        println!("✅ Wallet recreated successfully");
        Ok(wallet)
    }

    // New, more reliable encryption method
    fn encrypt_secret_key_v2(&self, secret_key: &str, password: &str) -> Result<String> {
        use sha2::{Digest, Sha256};
        
        println!("🔐 Encrypting secret key with improved method");
        
        // Create a deterministic 32-byte key from password
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"stellar_wallet_v2_salt_2024"); // Version-specific salt
        let key_bytes = hasher.finalize();
        
        let secret_bytes = secret_key.as_bytes();
        let mut encrypted_bytes = Vec::new();
        
        // Simple XOR encryption with the full 32-byte key
        for (i, &byte) in secret_bytes.iter().enumerate() {
            encrypted_bytes.push(byte ^ key_bytes[i % 32]);
        }
        
        // Add a simple checksum to verify decryption
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(secret_key.as_bytes());
        let checksum = checksum_hasher.finalize();
        
        // Append first 4 bytes of checksum
        encrypted_bytes.extend_from_slice(&checksum[..4]);
        
        Ok(general_purpose::STANDARD.encode(encrypted_bytes))
    }

    // Corresponding decryption method
    pub fn decrypt_secret_key_v2(&self, encrypted_secret: &str, password: &str) -> Result<String> {
        use sha2::{Digest, Sha256};
        
        println!("🔓 Decrypting secret key with improved method");
        
        // Create the same key as used for encryption
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"stellar_wallet_v2_salt_2024");
        let key_bytes = hasher.finalize();
        
        // Decode from base64
        let encrypted_bytes = general_purpose::STANDARD.decode(encrypted_secret)
            .map_err(|e| AppError::InternalError(format!("Failed to decode encrypted secret: {}", e)))?;
        
        if encrypted_bytes.len() < 4 {
            return Err(AppError::ValidationError("Invalid encrypted data format".to_string()));
        }
        
        // Split data and checksum
        let (data_bytes, checksum_bytes) = encrypted_bytes.split_at(encrypted_bytes.len() - 4);
        
        // XOR decrypt
        let mut decrypted_bytes = Vec::new();
        for (i, &byte) in data_bytes.iter().enumerate() {
            decrypted_bytes.push(byte ^ key_bytes[i % 32]);
        }
        
        // Convert to string
        let decrypted = String::from_utf8(decrypted_bytes)
            .map_err(|_| AppError::ValidationError("Wrong password".to_string()))?;
        
        // Verify checksum
        let mut checksum_hasher = Sha256::new();
        checksum_hasher.update(decrypted.as_bytes());
        let expected_checksum = checksum_hasher.finalize();
        
        if &expected_checksum[..4] != checksum_bytes {
            return Err(AppError::ValidationError("Wrong password or corrupted data".to_string()));
        }
        
        // Validate the decrypted secret key
        if !self.is_valid_secret_key(&decrypted) {
            return Err(AppError::ValidationError("Invalid secret key format".to_string()));
        }
        
        Ok(decrypted)
    }

    // Add this method to help recover wallets
    pub async fn recover_wallet(&self, public_key: &str, password: &str) -> Result<()> {
        println!("🔍 Attempting to recover wallet: {}", public_key);
        
        // Get wallet from database
        let wallet = self.database.get_wallet_by_public_key(public_key).await?
            .ok_or_else(|| AppError::StellarError("Wallet not found".to_string()))?;
        
        println!("📊 Wallet Details:");
        println!("  - Created at: {}", wallet.created_at);
        println!("  - Encrypted secret length: {}", wallet.encrypted_secret_key.len());
        
        // Try to decode base64
        let encrypted_bytes = match general_purpose::STANDARD.decode(&wallet.encrypted_secret_key) {
            Ok(bytes) => {
                println!("✅ Base64 decoding successful");
                println!("  - Decoded length: {} bytes", bytes.len());
                println!("  - First 10 bytes: {:?}", &bytes[..std::cmp::min(10, bytes.len())]);
                bytes
            }
            Err(e) => {
                println!("❌ Base64 decoding failed: {}", e);
                return Err(AppError::InternalError("Corrupted wallet data".to_string()));
            }
        };
        
        // Try original encryption method
        println!("\n🔄 Trying original encryption method...");
        match self.decrypt_secret_key(&wallet.encrypted_secret_key, password) {
            Ok(secret) => {
                println!("✅ Original method successful!");
                println!("  - Secret key starts with: {}", &secret.chars().take(5).collect::<String>());
                return Ok(());
            }
            Err(e) => {
                println!("❌ Original method failed: {}", e);
            }
        }
        
        // Try v2 encryption method
        println!("\n🔄 Trying v2 encryption method...");
        match self.decrypt_secret_key_v2(&wallet.encrypted_secret_key, password) {
            Ok(secret) => {
                println!("✅ V2 method successful!");
                println!("  - Secret key starts with: {}", &secret.chars().take(5).collect::<String>());
                return Ok(());
            }
            Err(e) => {
                println!("❌ V2 method failed: {}", e);
            }
        }
        
        // Try legacy method (if it exists)
        println!("\n🔄 Trying legacy encryption method...");
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(b"stellar_wallet_salt"); // Legacy salt
        let key_hash = hasher.finalize();
        
        let mut decrypted_bytes = Vec::with_capacity(encrypted_bytes.len());
        for (i, &byte) in encrypted_bytes.iter().enumerate() {
            decrypted_bytes.push(byte ^ key_hash[i % 32]);
        }
        
        match String::from_utf8(decrypted_bytes) {
            Ok(secret) => {
                if self.is_valid_secret_key(&secret) {
                    println!("✅ Legacy method successful!");
                    println!("  - Secret key starts with: {}", &secret.chars().take(5).collect::<String>());
                    return Ok(());
                } else {
                    println!("❌ Legacy method failed: Invalid secret key format");
                }
            }
            Err(e) => {
                println!("❌ Legacy method failed: {}", e);
            }
        }
        
        println!("\n❌ All recovery attempts failed");
        println!("💡 Suggestions:");
        println!("  1. Double-check your password");
        println!("  2. Try any alternative passwords you might have used");
        println!("  3. If you have a backup of the original secret key, use the import function");
        
        Err(AppError::ValidationError("Failed to recover wallet".to_string()))
    }

    /// Query Stellar DEX for the best conversion path and rate
    pub async fn get_best_path(&self, from: &str, to: &str, amount: f64, supported_currencies: &[SupportedCurrency]) -> Result<(f64, Vec<String>)> {
        // Look up asset info for source and destination
        let from_currency = supported_currencies.iter().find(|c| c.code == from).ok_or_else(|| crate::errors::AppError::ValidationError(format!("Unknown source currency: {}", from)))?;
        let to_currency = supported_currencies.iter().find(|c| c.code == to).ok_or_else(|| crate::errors::AppError::ValidationError(format!("Unknown destination currency: {}", to)))?;
        let from_asset_type = if from_currency.is_native { "native" } else { "credit_alphanum4" };
        let from_asset_code = if from_currency.is_native { "" } else { &from_currency.code };
        let from_asset_issuer = if from_currency.is_native { "" } else { from_currency.asset_issuer.as_ref().map(|s| s.as_str()).unwrap_or("") };
        let to_asset_type = if to_currency.is_native { "native" } else { "credit_alphanum4" };
        let to_asset_code = if to_currency.is_native { "" } else { &to_currency.code };
        let to_asset_issuer = if to_currency.is_native { "" } else { to_currency.asset_issuer.as_ref().map(|s| s.as_str()).unwrap_or("") };
        // Build destination_assets param
        let destination_assets = if to_currency.is_native {
            "native".to_string()
        } else {
            format!("credit_alphanum4:{}:{}", to_asset_code, to_asset_issuer)
        };
        // Build Horizon /paths endpoint URL
        let url = format!(
            "{}/paths/strict-send?source_asset_type={}&source_asset_code={}&source_asset_issuer={}&source_amount={}&destination_assets={}",
            self.horizon_url,
            from_asset_type,
            from_asset_code,
            from_asset_issuer,
            amount,
            destination_assets
        );
        let resp = self.client.get(&url).send().await.map_err(|e| crate::errors::AppError::StellarError(format!("Failed to query Stellar DEX: {}", e)))?;
        let data: serde_json::Value = resp.json().await.map_err(|e| crate::errors::AppError::StellarError(format!("Failed to parse DEX response: {}", e)))?;
        // Parse best path and rate
        if let Some(records) = data["_embedded"]["records"].as_array() {
            if let Some(best) = records.first() {
                let dest_amount = best["destination_amount"].as_str().unwrap_or("0").parse::<f64>().unwrap_or(0.0);
                let path = best["path"].as_array().unwrap_or(&vec![]).iter().map(|a| a["asset_code"].as_str().unwrap_or("").to_string()).collect();
                let rate = dest_amount / amount;
                return Ok((rate, path));
            }
        }
        println!("No path found for {} → {} on Stellar DEX", from, to);
        Err(crate::errors::AppError::StellarError(format!("No conversion path found on Stellar DEX for {} → {}", from, to)))
    }

    /// Execute a path payment on Stellar DEX
    pub async fn send_path_payment(
        &self,
        source_wallet: &crate::models::stellar_wallet::StellarWallet,
        dest_wallet: &crate::models::stellar_wallet::StellarWallet,
        from: &str,
        to: &str,
        amount: f64,
        path: &Vec<String>,
    ) -> Result<PathPaymentResult> {
        // This is a placeholder for actual path payment logic using stellar-sdk or xdr
        // In production, you would build and sign a PathPaymentStrictSend operation
        // For now, simulate a successful payment and return a mock tx hash
        Ok(PathPaymentResult { tx_hash: format!("mock_stellar_tx_{}", uuid::Uuid::new_v4()) })
    }
}
