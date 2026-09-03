//! Agent-facing Tools over an explicitly bound Notification Admin capability.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_notification_admin::{
    self as notification_admin, GetDeliveryRequest, ListDeliveriesRequest, RetryDeliveryRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const LIST_DELIVERIES_TOOL: &str = "notification_admin_list_deliveries";
pub const GET_DELIVERY_TOOL: &str = "notification_admin_get_delivery";
pub const RETRY_DELIVERY_TOOL: &str = "notification_admin_retry_delivery";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct NotificationAdminAgentToolsPlugin {
    admin: Port<notification_admin::AdminClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl NotificationAdminAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        match request.name.as_str() {
            LIST_DELIVERIES_TOOL => {
                let arguments = decode::<ListDeliveriesRequest>(&request)?;
                match self
                    .admin
                    .list_deliveries_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(LIST_DELIVERIES_TOOL, &response),
                    Err(notification_admin::AdminListDeliveriesInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_list_deliveries_error(&error)))
                    }
                    Err(notification_admin::AdminListDeliveriesInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            GET_DELIVERY_TOOL => {
                let arguments = decode::<GetDeliveryRequest>(&request)?;
                match self
                    .admin
                    .get_delivery_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(GET_DELIVERY_TOOL, &response),
                    Err(notification_admin::AdminGetDeliveryInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_get_delivery_error(&error)))
                    }
                    Err(notification_admin::AdminGetDeliveryInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            RETRY_DELIVERY_TOOL => {
                let arguments = decode::<RetryDeliveryRequest>(&request)?;
                match self
                    .admin
                    .retry_delivery_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(RETRY_DELIVERY_TOOL, &response),
                    Err(notification_admin::AdminRetryDeliveryInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_retry_delivery_error(&error)))
                    }
                    Err(notification_admin::AdminRetryDeliveryInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            LIST_DELIVERIES_TOOL,
            "List bounded redacted Notification delivery records, optionally filtered by exact status.",
            include_str!(
                "../../lenso-capability-notification-admin/schemas/list-deliveries-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            GET_DELIVERY_TOOL,
            "Get one redacted Notification delivery with its bounded attempts, receipts, retry decisions, and revision.",
            include_str!(
                "../../lenso-capability-notification-admin/schemas/get-delivery-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            RETRY_DELIVERY_TOOL,
            "Request one revision-checked, idempotent manual retry when the Notification provider still considers the delivery eligible.",
            include_str!(
                "../../lenso-capability-notification-admin/schemas/retry-delivery-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Notification Admin Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Notification Admin Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("Notification Admin Tool could not serialize its response: {error}"),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Notification Admin Tool metadata must be valid JSON"),
    })
}

fn map_list_deliveries_error(error: &notification_admin::ListDeliveriesError) -> ExecuteError {
    match error {
        notification_admin::ListDeliveriesError::InvalidFilter => ExecuteError::InvalidArguments,
        notification_admin::ListDeliveriesError::Unauthorized => ExecuteError::PermissionDenied,
        notification_admin::ListDeliveriesError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn map_get_delivery_error(error: &notification_admin::GetDeliveryError) -> ExecuteError {
    match error {
        notification_admin::GetDeliveryError::DeliveryNotFound => ExecuteError::NotFound,
        notification_admin::GetDeliveryError::EvidenceOverflow => rejected("evidence_overflow"),
        notification_admin::GetDeliveryError::InvalidRequest => ExecuteError::InvalidArguments,
        notification_admin::GetDeliveryError::Unauthorized => ExecuteError::PermissionDenied,
        notification_admin::GetDeliveryError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn map_retry_delivery_error(error: &notification_admin::RetryDeliveryError) -> ExecuteError {
    match error {
        notification_admin::RetryDeliveryError::DeliveryNotFound => ExecuteError::NotFound,
        notification_admin::RetryDeliveryError::InvalidRequest => ExecuteError::InvalidArguments,
        notification_admin::RetryDeliveryError::Unauthorized => ExecuteError::PermissionDenied,
        notification_admin::RetryDeliveryError::IdempotencyConflict => {
            rejected("idempotency_conflict")
        }
        notification_admin::RetryDeliveryError::RetryNotAllowed => rejected("retry_not_allowed"),
        notification_admin::RetryDeliveryError::StaleRevision => rejected("stale_revision"),
        notification_admin::RetryDeliveryError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Notification administration rejected the requested operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Notification Admin Tool error metadata must be valid JSON"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_is_a_stateless_admin_adapter() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.notification.admin.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.notification.admin@1");
    }

    #[test]
    fn catalog_has_two_reads_and_one_explicit_mutation() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 3);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            2
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            1
        );
    }

    #[test]
    fn requests_and_domain_failures_preserve_contract_semantics() {
        let list = decode::<ListDeliveriesRequest>(&request(
            LIST_DELIVERIES_TOOL,
            r#"{"limit":50,"status":"failed"}"#,
        ))
        .unwrap();
        assert_eq!(list.limit, Some(50));
        assert!(
            decode::<ListDeliveriesRequest>(&request(
                LIST_DELIVERIES_TOOL,
                r#"{"limit":50,"status":"failure"}"#,
            ))
            .is_err()
        );
        assert_eq!(
            map_get_delivery_error(&notification_admin::GetDeliveryError::DeliveryNotFound),
            ExecuteError::NotFound
        );
        assert_eq!(
            map_retry_delivery_error(&notification_admin::RetryDeliveryError::Unauthorized),
            ExecuteError::PermissionDenied
        );
        assert!(matches!(
            map_retry_delivery_error(&notification_admin::RetryDeliveryError::RetryNotAllowed),
            ExecuteError::ExecutionFailed { .. }
        ));
    }
}
