use crate::business_api;
use crate::events::NotificationEventHandler;
use crate::migrations::NOTIFICATION_MIGRATIONS;
use crate::runtime::{DISPATCH_DUE_FUNCTION, DISPATCH_QUEUE, DispatchDueDeliveries};
use lenso::console::{
    ConsoleNavigation, ConsoleNavigationGroup, ConsoleSurface, ConsoleSurfacePresentation,
    ConsoleWorkspaceRef,
};
use lenso::host::http::{LinkedBinding, LinkedHttpContribution, ModuleHttpMethod, ModuleHttpRoute};
use lenso::host::runtime::{
    AppContext, FunctionDefinition, Module, RetryPolicy, RuntimeDescriptor,
};
use lenso::host::{HostLinkedModule, ModuleManifest};
use lenso::{
    EventHandlerDeclaration, EventSurface, ModuleConfigActivation, ModuleConfigContract,
    ModuleConfigField, ModuleConfigFieldType, ModuleConfigMutability, ModuleConfigScope,
    ModuleMigrationActivation, ModuleMigrationDeclaration, ModuleRequirement,
    RuntimeFunctionDeclaration, RuntimeRetryPolicyDeclaration, RuntimeSurface,
    ScheduledFunctionDeclaration,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub const MODULE_ID: &str = "lenso/notification";
pub const MODULE_NAME: &str = "notification";
pub const NOTIFICATION_DELIVERIES_READ: &str = "notification.deliveries.read";
pub const NOTIFICATION_DELIVERIES_RETRY: &str = "notification.deliveries.retry";

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_ID)
        .summary("Transactional notification intents, delivery attempts, receipts, and final state")
        .capabilities(vec![
            NOTIFICATION_DELIVERIES_READ.to_owned(),
            NOTIFICATION_DELIVERIES_RETRY.to_owned(),
        ])
        .requires(vec![ModuleRequirement {
            module_id: "lenso/email-provider".to_owned(),
            version_requirement: "*".to_owned(),
            capabilities: vec!["email.dispatch".to_owned()],
            optional: false,
        }])
        .config(ModuleConfigContract {
            fields: vec![ModuleConfigField {
                key: "snapshot_protection_key".to_owned(),
                field_type: ModuleConfigFieldType::String,
                required: true,
                scope: ModuleConfigScope::Environment,
                sensitive: true,
                secret_reference: true,
                mutability: ModuleConfigMutability::Static,
                activation: ModuleConfigActivation::Restart,
                read_capability: None,
                write_capability: None,
                default: None,
                validation: None,
            }],
        })
        .migrations(vec![ModuleMigrationDeclaration {
            migration_id: "notification/0001_create_notification_schema".to_owned(),
            order: 1,
            store: "postgres".to_owned(),
            destructive: false,
            reversible: false,
            activation: ModuleMigrationActivation::BeforeActivation,
        }])
        .http_routes(http_routes())
        .runtime(RuntimeSurface {
            functions: vec![RuntimeFunctionDeclaration {
                name: DISPATCH_DUE_FUNCTION.to_owned(),
                version: 1,
                queue: DISPATCH_QUEUE.to_owned(),
                input_schema: Some(
                    "contracts/runtime/notification.dispatch-due.v1.schema.json".to_owned(),
                ),
                retry_policy: Some(RuntimeRetryPolicyDeclaration {
                    max_attempts: 3,
                    initial_delay_ms: 5_000,
                }),
                operation: None,
            }],
            schedules: vec![ScheduledFunctionDeclaration {
                name: "notification-dispatch-due".to_owned(),
                function_name: DISPATCH_DUE_FUNCTION.to_owned(),
                cron: "* * * * *".to_owned(),
                input: json!({ "limit": 25 }),
            }],
            workflows: Vec::new(),
        })
        .events(EventSurface {
            handlers: vec![
                event_handler(
                    "notification.apply-email-dispatch-observation.v1",
                    crate::contracts::EMAIL_DISPATCH_OBSERVED_EVENT,
                ),
                event_handler(
                    "notification.apply-email-receipt.v1",
                    crate::contracts::EMAIL_RECEIPT_OBSERVED_EVENT,
                ),
                event_handler(
                    "notification.apply-runtime-terminal.v1",
                    crate::contracts::RUNTIME_FUNCTION_TERMINAL_EVENT,
                ),
                event_handler(
                    "notification.apply-invitation-accepted.v1",
                    crate::contracts::ORGANIZATION_INVITATION_ACCEPTED_EVENT,
                ),
                event_handler(
                    "notification.apply-invitation-revoked.v1",
                    crate::contracts::ORGANIZATION_INVITATION_REVOKED_EVENT,
                ),
            ],
        })
        .console(vec![ConsoleSurface {
            name: "deliveries".to_owned(),
            label: "Deliveries".to_owned(),
            route: "/notifications/deliveries".to_owned(),
            presentation: ConsoleSurfacePresentation::Esm {
                entry: "index.js".to_owned(),
            },
            icon: Some("activity".to_owned()),
            required_capabilities: vec![NOTIFICATION_DELIVERIES_READ.to_owned()],
            navigation: Some(ConsoleNavigation {
                workspace: ConsoleWorkspaceRef {
                    id: "notifications".to_owned(),
                    label: "Notifications".to_owned(),
                    icon: Some("workflow".to_owned()),
                },
                group: Some(ConsoleNavigationGroup {
                    id: "transactional".to_owned(),
                    label: "Transactional".to_owned(),
                    icon: Some("activity".to_owned()),
                    order: Some(10),
                }),
                order: Some(10),
            }),
        }])
        .build()
}

pub fn module(app: &AppContext) -> Module {
    Module::linked(manifest(), binding(app))
}

pub fn linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(MODULE_NAME, manifest, module, NOTIFICATION_MIGRATIONS)
        .with_http_binding(http_binding)
}

fn binding(app: &AppContext) -> LinkedBinding {
    LinkedBinding::builder()
        .http(http_contribution())
        .event_handlers(vec![
            Arc::new(NotificationEventHandler::dispatch_observed(app.clone())),
            Arc::new(NotificationEventHandler::receipt_observed(app.clone())),
            Arc::new(NotificationEventHandler::runtime_terminal(app.clone())),
            Arc::new(NotificationEventHandler::invitation_accepted(app.clone())),
            Arc::new(NotificationEventHandler::invitation_revoked(app.clone())),
        ])
        .runtime(RuntimeDescriptor {
            module: MODULE_NAME,
            functions: vec![FunctionDefinition {
                name: DISPATCH_DUE_FUNCTION.to_owned(),
                version: 1,
                queue: DISPATCH_QUEUE.to_owned(),
                retry_policy: RetryPolicy::fixed(3, Duration::from_secs(5)),
                handler: Arc::new(DispatchDueDeliveries::new(app.clone())),
            }],
            ..RuntimeDescriptor::default()
        })
        .build()
}

fn http_binding() -> LinkedBinding {
    LinkedBinding::builder().http(http_contribution()).build()
}

fn http_contribution() -> LinkedHttpContribution {
    LinkedHttpContribution {
        public_prefixes: &["/v1/notification/console"],
        merge: merge_http,
    }
}

fn merge_http(base: lenso::host::http::ApiOpenApiRouter) -> lenso::host::http::ApiOpenApiRouter {
    base.merge(business_api::router())
}

fn http_routes() -> Vec<ModuleHttpRoute> {
    vec![
        route(
            ModuleHttpMethod::Get,
            "/v1/notification/console/deliveries",
            NOTIFICATION_DELIVERIES_READ,
            "List notification deliveries",
        ),
        route(
            ModuleHttpMethod::Get,
            "/v1/notification/console/deliveries/{delivery_id}",
            NOTIFICATION_DELIVERIES_READ,
            "Get notification delivery",
        ),
        route(
            ModuleHttpMethod::Post,
            "/v1/notification/console/deliveries/{delivery_id}/retry",
            NOTIFICATION_DELIVERIES_RETRY,
            "Retry notification delivery",
        ),
    ]
}

fn route(
    method: ModuleHttpMethod,
    path: &str,
    capability: &str,
    display_name: &str,
) -> ModuleHttpRoute {
    ModuleHttpRoute {
        method,
        path: path.to_owned(),
        capability: Some(capability.to_owned()),
        display_name: Some(display_name.to_owned()),
        story_title: Some(display_name.to_owned()),
        operation: None,
    }
}

fn event_handler(name: &str, event_name: &str) -> EventHandlerDeclaration {
    EventHandlerDeclaration {
        name: name.to_owned(),
        event_name: event_name.to_owned(),
        operation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_declares_only_implemented_surfaces() {
        let manifest = manifest();
        let errors = lenso::lint_module_manifest(&manifest)
            .into_iter()
            .filter(|lint| matches!(lint.severity, lenso::ModuleManifestLintSeverity::Error))
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "manifest errors: {errors:#?}");
        assert_eq!(manifest.console[0].route, "/notifications/deliveries");
        assert_eq!(manifest.runtime.expect("runtime").functions.len(), 1);
        assert_eq!(manifest.events.expect("events").handlers.len(), 5);
    }
}
