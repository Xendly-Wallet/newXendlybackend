use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
    Extension,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use crate::database::sqlite::SqliteDatabase;
use dashmap::DashMap;
use once_cell::sync::Lazy;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub count: u64,
    pub window_start: Instant,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RateLimiter {
    pub requests_per_second: u64,
    pub window_duration: Duration,
    pub entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl RateLimiter {
    pub fn new(requests_per_second: u64, window_duration_secs: u64) -> Self {
        Self {
            requests_per_second,
            window_duration: Duration::from_secs(window_duration_secs),
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn check_rate_limit(&self, key: &str) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();

        match entries.get_mut(key) {
            Some(entry) => {
                // Check if we're still in the same window
                if now.duration_since(entry.window_start) < self.window_duration {
                    if entry.count >= self.requests_per_second {
                        return false; // Rate limit exceeded
                    }
                    entry.count += 1;
                } else {
                    // New window
                    entry.count = 1;
                    entry.window_start = now;
                }
            }
            None => {
                // First request from this key
                entries.insert(key.to_string(), RateLimitEntry {
                    count: 1,
                    window_start: now,
                });
            }
        }

        // Clean up old entries periodically
        entries.retain(|_, entry| {
            now.duration_since(entry.window_start) < self.window_duration
        });

        true
    }
}

static RATE_LIMITER: Lazy<DashMap<String, (u32, Instant)>> = Lazy::new(DashMap::new);

pub async fn global_rate_limiter(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Extract IP from request extensions
    let ip = request
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let now = Instant::now();
    let mut entry = RATE_LIMITER.entry(ip).or_insert((0, now));

    // Reset window if expired
    if now.duration_since(entry.1) > Duration::from_secs(1) {
        *entry = (1, now);
    } else {
        entry.0 += 1;
    }

    if entry.0 > 5 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

#[allow(dead_code)]
pub async fn rate_limiter_middleware(
    Extension((limiter, _db)): Extension<(Arc<RateLimiter>, Arc<SqliteDatabase>)>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract IP from request extensions (works with axum::serve and TcpListener)
    let ip = request.extensions().get::<SocketAddr>().map(|addr| addr.ip().to_string());
    if let Some(ip) = ip {
        if !limiter.check_rate_limit(&ip) {
            println!("🚫 Rate limit exceeded for IP: {}", ip);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    } else {
        // If IP cannot be determined, allow the request (or optionally, rate limit globally)
        println!("⚠️ Could not extract client IP for rate limiting");
    }
    Ok(next.run(request).await)
}
