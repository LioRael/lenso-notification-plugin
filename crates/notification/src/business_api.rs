use crate::repository::{
    AttemptRecord, DeliveryDetail, DeliverySummary, PostgresNotificationRepository, ReceiptRecord,
    RetryRecord,
};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use lenso::host::http::{
    ApiErrorResponse, ApiOpenApiRouter, AppContext, AppError, ErrorCode, ErrorResponse,
    HttpRequestContext, JsonBody, OpenApiRouter, json, routes,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const NOTIFICATION_CONTRACT_DIGEST: &str =
    "sha256:ebbbec96b0657a1158850b1fddbee702367387dfb7f610c9c1ab15d4200089f5";
pub const LIST_DELIVERIES_OPERATION: &str = "notification/http/GET:/deliveries";
pub const GET_DELIVERY_OPERATION: &str = "notification/http/GET:/deliveries/{id}";
pub const RETRY_DELIVERY_OPERATION: &str = "notification/http/POST:/deliveries/{id}/retry";

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
pub struct DeliveryListQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeliverySummaryResponse {
    pub id: String,
    pub recipient_mask: String,
    pub template_id: String,
    pub template_version: String,
    pub locale: String,
    pub status: String,
    pub revision: i64,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub redacted_preview: String,
    pub content_digest: String,
    pub correlation_id: String,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub final_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub retry_now_eligible: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryPageResponse {
    pub records: Vec<DeliverySummaryResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AttemptResponse {
    pub id: String,
    pub sequence: i32,
    pub function_run_id: String,
    pub status: String,
    pub provider: Option<String>,
    pub remote_receipt_id: Option<String>,
    pub failure_code: Option<String>,
    pub failure_classification: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReceiptResponse {
    pub id: String,
    pub attempt_id: String,
    pub kind: String,
    pub source: String,
    pub remote_id: String,
    pub digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetryResponseRecord {
    pub id: String,
    pub kind: String,
    pub requested_by: Option<String>,
    pub source_revision: i64,
    pub decision: String,
    pub reason: Option<String>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryDetailResponse {
    #[serde(flatten)]
    pub delivery: DeliverySummaryResponse,
    pub attempts: Vec<AttemptResponse>,
    pub receipts: Vec<ReceiptResponse>,
    pub retry_requests: Vec<RetryResponseRecord>,
    pub open_in_story_correlation_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RetryDeliveryRequest {
    pub revision: i64,
    pub idempotency_key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetryDeliveryResponse {
    pub delivery_id: String,
    pub revision: i64,
    pub status: String,
    pub scheduled_at: DateTime<Utc>,
    pub idempotent_replay: bool,
}

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(list_deliveries))
        .routes(routes!(get_delivery))
        .routes(routes!(retry_delivery))
}

#[utoipa::path(
    get,
    path = "/v1/notification/console/deliveries",
    operation_id = "notification_console_list_deliveries",
    tag = "notification-console",
    params(
        ("limit" = Option<i64>, Query, minimum = 1, maximum = 200),
        ("cursor" = Option<String>, Query),
        ("status" = Option<String>, Query)
    ),
    responses(
        (status = 200, body = DeliveryPageResponse, content_type = "application/json"),
        (status = 400, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn list_deliveries(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Query(query): Query<DeliveryListQuery>,
) -> Result<Json<DeliveryPageResponse>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        LIST_DELIVERIES_OPERATION,
        crate::module::NOTIFICATION_DELIVERIES_READ,
        &ctx,
        &request_ctx,
    )?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(api_error(
            ErrorCode::Validation,
            "limit must be between 1 and 200",
            &request_ctx,
        ));
    }
    validate_status(query.status.as_deref(), &request_ctx)?;
    let rows = PostgresNotificationRepository::new(ctx)
        .list_deliveries(limit + 1, query.cursor.as_deref(), query.status.as_deref())
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let has_more = i64::try_from(rows.len()).is_ok_and(|count| count > limit);
    let records = rows
        .into_iter()
        .take(usize::try_from(limit).unwrap_or_default())
        .map(summary_response)
        .collect::<Vec<_>>();
    let next_cursor = has_more
        .then(|| records.last().map(|record| record.id.clone()))
        .flatten();
    Ok(json(DeliveryPageResponse {
        records,
        next_cursor,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/notification/console/deliveries/{delivery_id}",
    operation_id = "notification_console_get_delivery",
    tag = "notification-console",
    params(("delivery_id" = String, Path)),
    responses(
        (status = 200, body = DeliveryDetailResponse, content_type = "application/json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 404, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn get_delivery(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Path(delivery_id): Path<String>,
) -> Result<Json<DeliveryDetailResponse>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        GET_DELIVERY_OPERATION,
        crate::module::NOTIFICATION_DELIVERIES_READ,
        &ctx,
        &request_ctx,
    )?;
    require_resource_id(&delivery_id, &request_ctx)?;
    let detail = PostgresNotificationRepository::new(ctx)
        .get_delivery(&delivery_id)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?
        .ok_or_else(|| {
            api_error(
                ErrorCode::NotFound,
                "Notification delivery was not found",
                &request_ctx,
            )
        })?;
    Ok(json(detail_response(detail)))
}

#[utoipa::path(
    post,
    path = "/v1/notification/console/deliveries/{delivery_id}/retry",
    operation_id = "notification_console_retry_delivery",
    tag = "notification-console",
    params(("delivery_id" = String, Path)),
    request_body = RetryDeliveryRequest,
    responses(
        (status = 200, body = RetryDeliveryResponse, content_type = "application/json"),
        (status = 400, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 404, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 409, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn retry_delivery(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Path(delivery_id): Path<String>,
    JsonBody(input): JsonBody<RetryDeliveryRequest>,
) -> Result<Json<RetryDeliveryResponse>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        RETRY_DELIVERY_OPERATION,
        crate::module::NOTIFICATION_DELIVERIES_RETRY,
        &ctx,
        &request_ctx,
    )?;
    require_resource_id(&delivery_id, &request_ctx)?;
    if input.revision <= 0 || input.idempotency_key.trim().is_empty() {
        return Err(api_error(
            ErrorCode::Validation,
            "revision and idempotency_key are required",
            &request_ctx,
        ));
    }
    let requested_by = header(&headers, "x-lenso-console-delegated-actor")
        .unwrap_or("unknown")
        .chars()
        .take(240)
        .collect::<String>();
    let result = PostgresNotificationRepository::new(ctx.clone())
        .request_manual_retry(
            &delivery_id,
            input.revision,
            &input.idempotency_key,
            &requested_by,
            ctx.clock.now(),
        )
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    Ok(json(RetryDeliveryResponse {
        delivery_id: result.delivery_id,
        revision: result.revision,
        status: result.status,
        scheduled_at: result.scheduled_at,
        idempotent_replay: result.idempotent_replay,
    }))
}

fn validate_surface_request(
    headers: &HeaderMap,
    operation: &str,
    capability: &str,
    ctx: &AppContext,
    request_ctx: &lenso::host::http::RequestContext,
) -> Result<(), ApiErrorResponse> {
    let deadline =
        header(headers, "x-lenso-deadline-unix-ms").and_then(|value| value.parse::<i64>().ok());
    let valid = header(headers, "x-lenso-console-contract-digest")
        == Some(NOTIFICATION_CONTRACT_DIGEST)
        && header(headers, "x-lenso-console-operation-id") == Some(operation)
        && header(headers, "x-lenso-console-capability") == Some(capability)
        && header(headers, "x-lenso-console-delegated-actor").is_some_and(non_empty)
        && header(headers, "x-lenso-console-service-id").is_some_and(non_empty)
        && header(headers, "x-lenso-console-delegated-authority").is_some_and(valid_digest)
        && deadline.is_some_and(|value| value > ctx.clock.now().timestamp_millis());
    if !valid {
        return Err(api_error(
            ErrorCode::Forbidden,
            "Notification Business API request is not bound to an accepted Console Surface operation",
            request_ctx,
        ));
    }
    Ok(())
}

fn summary_response(value: DeliverySummary) -> DeliverySummaryResponse {
    let retry_now_eligible =
        value.status == "retry_scheduled" && value.attempt_count < value.max_attempts;
    DeliverySummaryResponse {
        id: value.id,
        recipient_mask: value.recipient_mask,
        template_id: value.template_id,
        template_version: value.template_version,
        locale: value.locale,
        status: value.status,
        revision: value.revision,
        attempt_count: value.attempt_count,
        max_attempts: value.max_attempts,
        redacted_preview: value.redacted_preview,
        content_digest: value.content_digest,
        correlation_id: value.correlation_id,
        next_attempt_at: value.next_attempt_at,
        final_reason: value.final_reason,
        created_at: value.created_at,
        updated_at: value.updated_at,
        retry_now_eligible,
    }
}

fn detail_response(value: DeliveryDetail) -> DeliveryDetailResponse {
    let correlation_id = value.delivery.correlation_id.clone();
    DeliveryDetailResponse {
        delivery: summary_response(value.delivery),
        attempts: value.attempts.into_iter().map(attempt_response).collect(),
        receipts: value.receipts.into_iter().map(receipt_response).collect(),
        retry_requests: value
            .retry_requests
            .into_iter()
            .map(retry_record_response)
            .collect(),
        open_in_story_correlation_id: correlation_id,
    }
}

fn attempt_response(value: AttemptRecord) -> AttemptResponse {
    AttemptResponse {
        id: value.id,
        sequence: value.sequence,
        function_run_id: value.function_run_id,
        status: value.status,
        provider: value.provider,
        remote_receipt_id: value.remote_receipt_id,
        failure_code: value.failure_code,
        failure_classification: value.failure_classification,
        started_at: value.started_at,
        completed_at: value.completed_at,
    }
}

fn receipt_response(value: ReceiptRecord) -> ReceiptResponse {
    ReceiptResponse {
        id: value.id,
        attempt_id: value.attempt_id,
        kind: value.kind,
        source: value.source,
        remote_id: value.remote_id,
        digest: value.digest,
        observed_at: value.observed_at,
    }
}

fn retry_record_response(value: RetryRecord) -> RetryResponseRecord {
    RetryResponseRecord {
        id: value.id,
        kind: value.kind,
        requested_by: value.requested_by,
        source_revision: value.source_revision,
        decision: value.decision,
        reason: value.reason,
        scheduled_at: value.scheduled_at,
        created_at: value.created_at,
    }
}

fn validate_status(
    status: Option<&str>,
    request_ctx: &lenso::host::http::RequestContext,
) -> Result<(), ApiErrorResponse> {
    if status.is_some_and(|value| {
        !matches!(
            value,
            "queued"
                | "attempting"
                | "accepted"
                | "retry_scheduled"
                | "delivered"
                | "failed"
                | "delivery_unknown"
        )
    }) {
        return Err(api_error(
            ErrorCode::Validation,
            "status is not a Notification delivery status",
            request_ctx,
        ));
    }
    Ok(())
}

fn require_resource_id(
    value: &str,
    request_ctx: &lenso::host::http::RequestContext,
) -> Result<(), ApiErrorResponse> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    {
        return Err(api_error(
            ErrorCode::Validation,
            "delivery_id contains an unsafe path character",
            request_ctx,
        ));
    }
    Ok(())
}

fn api_error(
    code: ErrorCode,
    message: impl Into<String>,
    request_ctx: &lenso::host::http::RequestContext,
) -> ApiErrorResponse {
    ApiErrorResponse::with_context(AppError::new(code, message), request_ctx)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_response_shape_has_no_sensitive_body_fields() {
        let encoded = serde_json::to_string(&DeliverySummaryResponse {
            id: "ntf_dlv_1".to_owned(),
            recipient_mask: "a***@example.com".to_owned(),
            template_id: "organization-invitation".to_owned(),
            template_version: "v1".to_owned(),
            locale: "en".to_owned(),
            status: "queued".to_owned(),
            revision: 1,
            attempt_count: 0,
            max_attempts: 4,
            redacted_preview: "Join with [link redacted]".to_owned(),
            content_digest: format!("sha256:{}", "0".repeat(64)),
            correlation_id: "corr_1".to_owned(),
            next_attempt_at: None,
            final_reason: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            retry_now_eligible: false,
        })
        .expect("serialized");
        for forbidden in ["ciphertext", "subject", "html", "invitation_url", "token"] {
            assert!(!encoded.contains(forbidden), "leaked field {forbidden}");
        }
    }
}
