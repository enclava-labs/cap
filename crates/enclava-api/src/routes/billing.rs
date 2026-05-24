use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::models::Subscription;
use crate::state::AppState;

/// Tier pricing in sats/month.
fn tier_price_sats(tier: &str) -> Option<u64> {
    match tier {
        "free" => Some(0),
        "pro" => Some(100_000),        // placeholder
        "enterprise" => Some(500_000), // placeholder
        _ => None,
    }
}

#[derive(Debug, Serialize)]
pub struct TierInfo {
    pub name: String,
    pub max_apps: u32,
    pub max_cpu: String,
    pub max_memory: String,
    pub max_storage: String,
    pub price_sats: u64,
}

/// Look up tier limits by name. Used by apps.rs and deployments.rs for quota enforcement.
pub fn tier_limits(tier: &str) -> Option<TierInfo> {
    match tier {
        "free" => Some(TierInfo {
            name: "free".to_string(),
            max_apps: 1,
            max_cpu: "1".to_string(),
            max_memory: "1Gi".to_string(),
            max_storage: "5Gi".to_string(),
            price_sats: 0,
        }),
        "pro" => Some(TierInfo {
            name: "pro".to_string(),
            max_apps: 5,
            max_cpu: "4".to_string(),
            max_memory: "8Gi".to_string(),
            max_storage: "50Gi".to_string(),
            price_sats: 100_000,
        }),
        "enterprise" => Some(TierInfo {
            name: "enterprise".to_string(),
            max_apps: u32::MAX,
            max_cpu: "32".to_string(),
            max_memory: "64Gi".to_string(),
            max_storage: "500Gi".to_string(),
            price_sats: 500_000,
        }),
        _ => None,
    }
}

/// GET /billing/tiers -- available tiers + pricing.
pub async fn list_tiers() -> Json<Vec<TierInfo>> {
    Json(vec![
        tier_limits("free").expect("built-in free tier must exist"),
        tier_limits("pro").expect("built-in pro tier must exist"),
        tier_limits("enterprise").expect("built-in enterprise tier must exist"),
    ])
}

#[derive(Debug, Deserialize)]
pub struct UpgradeRequest {
    pub tier: String,
}

#[derive(Debug, Serialize)]
pub struct InvoiceResult {
    pub invoice_id: String,
    pub checkout_url: Option<String>,
    pub amount_sats: u64,
}

/// POST /billing/upgrade -- generate BTCPay invoice for tier upgrade.
pub async fn upgrade_tier(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<UpgradeRequest>,
) -> Result<(StatusCode, Json<InvoiceResult>), (StatusCode, Json<serde_json::Value>)> {
    let price = tier_price_sats(&body.tier).ok_or((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "invalid tier"})),
    ))?;

    if price == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "already on free tier, nothing to pay"})),
        ));
    }

    let btcpay = crate::billing::btcpay::BtcPayClient::new(
        &state.btcpay_url,
        &state.btcpay_api_key,
        "default", // store_id from config
    );

    let invoice = btcpay
        .create_invoice(
            price,
            &auth.org_id.to_string(),
            &body.tier,
            &format!("Enclava {} tier upgrade", body.tier),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    // Record pending payment
    let payment_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payments (
            id, org_id, amount_sats, btcpay_invoice_id,
            requested_tier, expected_amount_sats, purpose
         )
         VALUES ($1, $2, $3, $4, $5, $6, 'tier_upgrade')",
    )
    .bind(payment_id)
    .bind(auth.org_id)
    .bind(price as i64)
    .bind(&invoice.id)
    .bind(&body.tier)
    .bind(price as i64)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    // Audit
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, user_id, action, detail) VALUES ($1, $2, 'billing.upgrade', $3)",
    )
    .bind(auth.org_id)
    .bind(auth.user_id)
    .bind(serde_json::json!({"tier": &body.tier, "amount_sats": price, "invoice_id": &invoice.id}))
    .execute(&state.db)
    .await;

    Ok((
        StatusCode::CREATED,
        Json(InvoiceResult {
            invoice_id: invoice.id,
            checkout_url: invoice.checkout_link,
            amount_sats: price,
        }),
    ))
}

#[derive(Debug, Serialize)]
pub struct SubscriptionStatusResponse {
    pub tier: String,
    pub status: String,
    pub period_end: Option<chrono::DateTime<chrono::Utc>>,
    pub grace_period_ends: Option<chrono::DateTime<chrono::Utc>>,
}

/// GET /billing/status -- current subscription status.
pub async fn subscription_status(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<SubscriptionStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let org: crate::models::Organization =
        sqlx::query_as("SELECT * FROM organizations WHERE id = $1")
            .bind(auth.org_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;

    let sub: Option<Subscription> = sqlx::query_as(
        "SELECT * FROM subscriptions WHERE org_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(auth.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    match sub {
        Some(s) => {
            let grace_end = if s.status == crate::models::SubStatus::GracePeriod {
                Some(s.current_period_end + chrono::Duration::days(7))
            } else {
                None
            };

            Ok(Json(SubscriptionStatusResponse {
                tier: format!("{:?}", s.tier).to_lowercase(),
                status: format!("{:?}", s.status).to_lowercase(),
                period_end: Some(s.current_period_end),
                grace_period_ends: grace_end,
            }))
        }
        None => Ok(Json(SubscriptionStatusResponse {
            tier: format!("{:?}", org.tier).to_lowercase(),
            status: "active".to_string(),
            period_end: None,
            grace_period_ends: None,
        })),
    }
}

/// POST /billing/renew -- generate renewal invoice.
pub async fn renew_subscription(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<InvoiceResult>), (StatusCode, Json<serde_json::Value>)> {
    let org: crate::models::Organization =
        sqlx::query_as("SELECT * FROM organizations WHERE id = $1")
            .bind(auth.org_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "database error"})),
                )
            })?;

    let tier_str = format!("{:?}", org.tier).to_lowercase();
    let price = tier_price_sats(&tier_str).ok_or((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "cannot renew free tier"})),
    ))?;

    if price == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "free tier does not require renewal"})),
        ));
    }

    let btcpay = crate::billing::btcpay::BtcPayClient::new(
        &state.btcpay_url,
        &state.btcpay_api_key,
        "default",
    );

    let invoice = btcpay
        .create_invoice(
            price,
            &auth.org_id.to_string(),
            &tier_str,
            &format!("Enclava {} tier renewal", tier_str),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    let payment_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO payments (
            id, org_id, amount_sats, btcpay_invoice_id,
            requested_tier, expected_amount_sats, purpose
         )
         VALUES ($1, $2, $3, $4, $5, $6, 'subscription_renewal')",
    )
    .bind(payment_id)
    .bind(auth.org_id)
    .bind(price as i64)
    .bind(&invoice.id)
    .bind(&tier_str)
    .bind(price as i64)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(InvoiceResult {
            invoice_id: invoice.id,
            checkout_url: invoice.checkout_link,
            amount_sats: price,
        }),
    ))
}

/// POST /billing/webhook -- BTCPay webhook handler (unauthenticated, signature-verified).
pub async fn btcpay_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, StatusCode> {
    // Verify BTCPay HMAC signature (BILL-02 / Phase 0 item G).
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    if state.btcpay_webhook_secret.is_empty() {
        // Defence in depth: env_gates already refuses to start with an empty
        // secret, but bail early here in case state is built directly (tests).
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let sig_header = headers
        .get("BTCPay-Sig")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let expected_sig_hex = sig_header
        .strip_prefix("sha256=")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let expected_sig = hex::decode(expected_sig_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut mac = HmacSha256::new_from_slice(state.btcpay_webhook_secret.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    mac.update(&body);
    // Constant-time MAC compare via the underlying CtOutput.
    if mac.verify_slice(&expected_sig).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let payload: crate::billing::btcpay::WebhookPayload =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Replay protection: reject duplicates by event_id (which BTCPay
    // increments per delivery). delivery_id, when present, is recorded for
    // operator forensics.
    let delivery_id = headers
        .get("BTCPay-Delivery")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let event_id = format!("{}:{}", payload.invoice_id, payload.event_type);
    let inserted = sqlx::query(
        "INSERT INTO processed_webhooks (delivery_id, event_id) VALUES ($1, $2)
         ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(&delivery_id)
    .bind(&event_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if inserted.rows_affected() == 0 {
        tracing::info!(event_id = %event_id, "btcpay webhook replay ignored");
        return Ok(StatusCode::OK);
    }

    if payload.event_type == "InvoiceSettled" || payload.event_type == "InvoicePaymentSettled" {
        let btcpay = crate::billing::btcpay::BtcPayClient::new(
            &state.btcpay_url,
            &state.btcpay_api_key,
            "default",
        );
        let invoice = btcpay
            .get_invoice(&payload.invoice_id)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        if !invoice_status_is_settled(&invoice.status) {
            tracing::warn!(
                invoice_id = %payload.invoice_id,
                status = %invoice.status,
                "settlement webhook did not match server-side invoice status"
            );
            return Ok(StatusCode::OK);
        }

        let payment: Option<(Uuid, i64, Option<String>, Option<i64>)> = sqlx::query_as(
            "SELECT org_id, amount_sats, requested_tier, expected_amount_sats
                 FROM payments
                 WHERE btcpay_invoice_id = $1 AND status = 'pending'",
        )
        .bind(&payload.invoice_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if let Some((org_id, amount_sats, requested_tier, expected_amount_sats)) = payment {
            let expected = expected_amount_sats.unwrap_or(amount_sats);
            if !invoice_amount_matches(&invoice.amount, expected) {
                tracing::warn!(
                    invoice_id = %payload.invoice_id,
                    expected_amount_sats = expected,
                    invoice_amount = ?invoice.amount,
                    "settled invoice amount did not match server-side payment intent"
                );
                return Ok(StatusCode::OK);
            }

            let Some(tier) = requested_tier.filter(|tier| tier_price_sats(tier).is_some()) else {
                tracing::warn!(
                    invoice_id = %payload.invoice_id,
                    "payment missing valid server-side requested_tier; refusing tier update"
                );
                return Ok(StatusCode::OK);
            };

            sqlx::query(
                "UPDATE payments
                 SET status = 'confirmed', confirmed_at = now()
                 WHERE btcpay_invoice_id = $1 AND status = 'pending'",
            )
            .bind(&payload.invoice_id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            sqlx::query(
                "UPDATE organizations SET tier = $1::tier_enum, updated_at = now() WHERE id = $2",
            )
            .bind(&tier)
            .bind(org_id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let sub_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO subscriptions (id, org_id, tier, status, current_period_end)
                 VALUES ($1, $2, $3::tier_enum, 'active', now() + interval '30 days')",
            )
            .bind(sub_id)
            .bind(org_id)
            .bind(&tier)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            let _ = sqlx::query(
                "UPDATE payments SET subscription_id = $1 WHERE btcpay_invoice_id = $2",
            )
            .bind(sub_id)
            .bind(&payload.invoice_id)
            .execute(&state.db)
            .await;
        }
    }

    Ok(StatusCode::OK)
}

fn invoice_status_is_settled(status: &str) -> bool {
    matches!(
        status.to_ascii_lowercase().as_str(),
        "settled" | "complete" | "completed"
    )
}

fn invoice_amount_matches(invoice_amount: &Option<String>, expected_sats: i64) -> bool {
    invoice_amount
        .as_deref()
        .and_then(|amount| amount.parse::<i64>().ok())
        .is_some_and(|amount| amount == expected_sats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settled_status_check_is_strict() {
        assert!(invoice_status_is_settled("Settled"));
        assert!(invoice_status_is_settled("complete"));
        assert!(!invoice_status_is_settled("processing"));
        assert!(!invoice_status_is_settled("invalid"));
    }

    #[test]
    fn invoice_amount_must_match_intent() {
        assert!(invoice_amount_matches(&Some("1000".to_string()), 1000));
        assert!(!invoice_amount_matches(&Some("999".to_string()), 1000));
        assert!(!invoice_amount_matches(&Some("1000.0".to_string()), 1000));
        assert!(!invoice_amount_matches(&None, 1000));
    }
}
