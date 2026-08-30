use std::{cell::RefCell, fmt, rc::Rc, time::Duration as StdDuration};

use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use lenso::prelude::*;
use lenso_capability_email_dispatch as email;
use lenso_capability_email_dispatch::{
    DispatchRequest, DispatchResponseOutcome, EmailDispatchInvocationError,
};
use lenso_capability_notification_admin as admin;
use lenso_capability_notification_delivery as delivery;
use lenso_capability_notification_template as notification_template;
use lenso_capability_notification_transactional as transactional;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::contracts::{
    DispatchOutcome, EMAIL_DISPATCH_OBSERVED_EVENT, EMAIL_RECEIPT_OBSERVED_EVENT,
    EmailDispatchObserved, EmailReceiptObserved, ORGANIZATION_INVITATION_ACCEPTED_EVENT,
    ORGANIZATION_INVITATION_EXPIRED_EVENT, ORGANIZATION_INVITATION_REVOKED_EVENT,
    OrganizationInvitationLifecycle, ReceiptKind, RemoteReceiptSummary, SanitizedFailure,
};
use crate::domain::MAX_SAFE_WIRE_INTEGER;
use crate::error::{ErrorCode, NotificationError};
use crate::events::{NotificationEventApplier, ObservationEnvelope};
use crate::migrations::schema_plan;
use crate::operator::verify_managed_catalog;
use crate::public::{
    AccessRequestNotificationEvent, AccessRequestNotificationTemplateV1, AccessRequestRoleV1,
    AccessRequestScopeV1, CreateAccessRequestNotificationIntent, CreateTransactionalEmailIntent,
    EmailRecipient, IntentSource, OrganizationInvitationTemplateV1, RenderedTemplate,
    access_request_template_id, create_access_request_notification_in_tx,
    create_transactional_email_intent_in_tx, find_access_request_notification_replay,
    find_transactional_email_intent_replay,
};
use crate::repository::{
    ADMIN_ATTEMPT_LIMIT, ADMIN_RECEIPT_LIMIT, ADMIN_RETRY_REQUEST_LIMIT, AttemptRecord,
    DeliveryDetail, DeliverySummary, PostgresNotificationRepository, ReceiptRecord, RetryRecord,
    RetryResult,
};
use crate::runtime::{DispatchWork, claim_one_due};
use crate::snapshot::AeadSnapshotProtector;

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationConfig {
    schema: String,
    database_url_secret: String,
    snapshot_key_secret: String,
    transactional_callers: Vec<String>,
    dispatch_callers: Vec<String>,
    receipt_callers: Vec<String>,
    admin_callers: Vec<String>,
}

impl NotificationConfig {
    pub fn new(
        database_url_secret: impl Into<String>,
        snapshot_key_secret: impl Into<String>,
        transactional_callers: Vec<String>,
        dispatch_callers: Vec<String>,
        receipt_callers: Vec<String>,
        admin_callers: Vec<String>,
    ) -> Result<Self, NotificationConfigError> {
        let config = Self {
            schema: "notification".to_owned(),
            database_url_secret: database_url_secret.into(),
            snapshot_key_secret: snapshot_key_secret.into(),
            transactional_callers,
            dispatch_callers,
            receipt_callers,
            admin_callers,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), NotificationConfigError> {
        if self.schema != "notification" {
            return Err(NotificationConfigError::InvalidSchema);
        }
        if !valid_secret_reference(&self.database_url_secret)
            || !valid_secret_reference(&self.snapshot_key_secret)
            || self.database_url_secret == self.snapshot_key_secret
        {
            return Err(NotificationConfigError::InvalidSecretReference);
        }
        for callers in [
            &self.transactional_callers,
            &self.dispatch_callers,
            &self.receipt_callers,
            &self.admin_callers,
        ] {
            if callers.is_empty()
                || callers.len() > 64
                || callers.iter().any(|caller| !valid_instance(caller))
                || callers
                    .iter()
                    .enumerate()
                    .any(|(index, caller)| callers[..index].contains(caller))
            {
                return Err(NotificationConfigError::InvalidCallers);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NotificationConfigError {
    #[error("the legacy Notification schema identity must remain `notification`")]
    InvalidSchema,
    #[error("database and snapshot keys require distinct valid secret references")]
    InvalidSecretReference,
    #[error("each authority role requires unique valid caller Instance keys")]
    InvalidCallers,
}

fn validate_config(config: &NotificationConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct NotificationPlugin {
    #[config]
    config: NotificationConfig,
    secrets: Port<lenso_capability_secrets::SecretsClient>,
    email: Port<email::EmailDispatchClient>,
    templates: Port<notification_template::NotificationTemplateClient>,
    state: Rc<RefCell<Option<PreparedNotification>>>,
}

#[derive(Clone)]
struct PreparedNotification {
    postgres: OwnedPostgres,
    protector: AeadSnapshotProtector,
    email_provider_instance: String,
}

impl fmt::Debug for PreparedNotification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedNotification")
            .field("schema", &self.postgres.schema())
            .field("email_provider_instance", &self.email_provider_instance)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for NotificationPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotificationPlugin")
            .field("prepared", &self.state.borrow().is_some())
            .field(
                "transactional_caller_count",
                &self.config.transactional_callers.len(),
            )
            .field("dispatch_caller_count", &self.config.dispatch_callers.len())
            .field("receipt_caller_count", &self.config.receipt_callers.len())
            .field("admin_caller_count", &self.config.admin_callers.len())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(transactional::Transactional, delivery::Delivery, admin::Admin)]
impl NotificationPlugin {
    async fn create_organization_invitation(
        &self,
        context: Ctx,
        request: transactional::CreateOrganizationInvitationRequest,
    ) -> PluginResult<
        transactional::CreateOrganizationInvitationResponse,
        transactional::CreateOrganizationInvitationError,
    > {
        let Some(caller) =
            authorized_caller(&context, &self.config.transactional_callers).map(str::to_owned)
        else {
            return Err(PluginError::domain(
                transactional::CreateOrganizationInvitationError::Unauthorized,
            ));
        };
        let now = Utc::now();
        if !valid_create_request(&request, now) {
            return Err(PluginError::domain(
                transactional::CreateOrganizationInvitationError::InvalidIntent,
            ));
        }
        let expires_at = parse_time(&request.template.expires_at).map_err(|_| {
            PluginError::domain(transactional::CreateOrganizationInvitationError::InvalidIntent)
        })?;
        let locale = match request.recipient.locale {
            transactional::CreateOrganizationInvitationRequestRecipientLocale::En => "en",
            transactional::CreateOrganizationInvitationRequestRecipientLocale::EnUS => "en-US",
        };
        let intent = CreateTransactionalEmailIntent {
            source: intent_source(caller, request.source),
            recipient: EmailRecipient {
                address: request.recipient.address,
                display_name: request.recipient.display_name,
                locale: locale.to_owned(),
            },
            template: OrganizationInvitationTemplateV1 {
                organization_id: request.template.organization_id,
                organization_name: request.template.organization_name,
                invitation_id: request.template.invitation_id,
                invitation_url: request.template.invitation_url,
                inviter_display_name: request.template.inviter_display_name,
                role_name: request.template.role_name,
                expires_at,
            },
            idempotency_key: request.idempotency_key,
            correlation_id: request.correlation_id,
            causation_id: request.causation_id,
            requested_by: request.requested_by,
        };
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        if let Some(receipt) =
            find_transactional_email_intent_replay(prepared.postgres.pool(), &intent, now)
                .await
                .map_err(map_create_error)?
        {
            return Ok(transactional::CreateOrganizationInvitationResponse {
                delivery_id: receipt.delivery_id,
                idempotent_replay: true,
                intent_id: receipt.intent_id,
                status: transactional::CreateOrganizationInvitationResponseStatus::Queued,
            });
        }
        let rendered = self
            .render_organization_invitation(context, &intent)
            .await
            .map_err(PluginError::runtime)?;
        let mut transaction = prepared
            .postgres
            .pool()
            .begin()
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?;
        let receipt = create_transactional_email_intent_in_tx(
            &mut transaction,
            &intent,
            &rendered,
            now,
            &prepared.protector,
        )
        .await
        .map_err(map_create_error)?;
        transaction
            .commit()
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?;
        Ok(transactional::CreateOrganizationInvitationResponse {
            delivery_id: receipt.delivery_id,
            idempotent_replay: receipt.idempotent_replay,
            intent_id: receipt.intent_id,
            status: transactional::CreateOrganizationInvitationResponseStatus::Queued,
        })
    }

    async fn create_access_request_notification(
        &self,
        context: Ctx,
        request: transactional::CreateAccessRequestNotificationRequest,
    ) -> PluginResult<
        transactional::CreateAccessRequestNotificationResponse,
        transactional::CreateAccessRequestNotificationError,
    > {
        let Some(caller) =
            authorized_caller(&context, &self.config.transactional_callers).map(str::to_owned)
        else {
            return Err(PluginError::domain(
                transactional::CreateAccessRequestNotificationError::Unauthorized,
            ));
        };
        let now = Utc::now();
        if !valid_access_request_notification_request(&request, now) {
            return Err(PluginError::domain(
                transactional::CreateAccessRequestNotificationError::InvalidIntent,
            ));
        }
        let event = match request.event {
            transactional::CreateAccessRequestNotificationRequestEvent::Submitted => {
                AccessRequestNotificationEvent::Submitted
            }
            transactional::CreateAccessRequestNotificationRequestEvent::Approved => {
                AccessRequestNotificationEvent::Approved
            }
            transactional::CreateAccessRequestNotificationRequestEvent::Denied => {
                AccessRequestNotificationEvent::Denied
            }
            transactional::CreateAccessRequestNotificationRequestEvent::Expiring => {
                AccessRequestNotificationEvent::Expiring
            }
        };
        let expires_at = request
            .expires_at
            .as_deref()
            .map(parse_time)
            .transpose()
            .map_err(|_| {
                PluginError::domain(
                    transactional::CreateAccessRequestNotificationError::InvalidIntent,
                )
            })?;
        let locale = match request.recipient.locale {
            transactional::CreateAccessRequestNotificationRequestRecipientLocale::En => "en",
            transactional::CreateAccessRequestNotificationRequestRecipientLocale::EnUS => "en-US",
        };
        let intent = CreateAccessRequestNotificationIntent {
            source: IntentSource {
                module_id: caller,
                entity_type: "access_request".to_owned(),
                entity_id: request.request_id.clone(),
            },
            recipient: EmailRecipient {
                address: request.recipient.address,
                display_name: request.recipient.display_name,
                locale: locale.to_owned(),
            },
            template: AccessRequestNotificationTemplateV1 {
                request_id: request.request_id,
                organization_id: request.organization_id,
                event,
                role: AccessRequestRoleV1 {
                    role_id: request.role.role_id,
                    display_name: request.role.display_name,
                },
                scope: AccessRequestScopeV1 {
                    kind: request.scope.kind,
                    id: request.scope.id,
                    display_name: request.scope.display_name,
                },
                expires_at,
            },
            idempotency_key: request.idempotency_key,
            correlation_id: request.correlation_id,
            causation_id: request.causation_id,
            requested_by: request.requested_by,
        };
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        if let Some(receipt) =
            find_access_request_notification_replay(prepared.postgres.pool(), &intent, now)
                .await
                .map_err(map_access_request_create_error)?
        {
            return Ok(transactional::CreateAccessRequestNotificationResponse {
                delivery_id: receipt.delivery_id,
                idempotent_replay: true,
                intent_id: receipt.intent_id,
                status: transactional::CreateAccessRequestNotificationResponseStatus::Queued,
            });
        }
        let rendered = self
            .render_access_request_notification(context, &intent)
            .await
            .map_err(PluginError::runtime)?;
        let mut transaction = prepared
            .postgres
            .pool()
            .begin()
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?;
        let receipt = create_access_request_notification_in_tx(
            &mut transaction,
            &intent,
            &rendered,
            now,
            &prepared.protector,
        )
        .await
        .map_err(map_access_request_create_error)?;
        transaction
            .commit()
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?;
        Ok(transactional::CreateAccessRequestNotificationResponse {
            delivery_id: receipt.delivery_id,
            idempotent_replay: receipt.idempotent_replay,
            intent_id: receipt.intent_id,
            status: transactional::CreateAccessRequestNotificationResponseStatus::Queued,
        })
    }

    async fn observe_invitation_lifecycle(
        &self,
        context: Ctx,
        request: transactional::ObserveInvitationLifecycleRequest,
    ) -> PluginResult<
        transactional::ObserveInvitationLifecycleResponse,
        transactional::ObserveInvitationLifecycleError,
    > {
        let Some(caller) =
            authorized_caller(&context, &self.config.transactional_callers).map(str::to_owned)
        else {
            return Err(PluginError::domain(
                transactional::ObserveInvitationLifecycleError::Unauthorized,
            ));
        };
        if !valid_lifecycle_request(&request) {
            return Err(PluginError::domain(
                transactional::ObserveInvitationLifecycleError::InvalidObservation,
            ));
        }
        let observed_at = parse_time(&request.observed_at).map_err(|_| {
            PluginError::domain(transactional::ObserveInvitationLifecycleError::InvalidObservation)
        })?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let event_name = match request.lifecycle {
            transactional::ObserveInvitationLifecycleRequestLifecycle::Accepted => {
                ORGANIZATION_INVITATION_ACCEPTED_EVENT
            }
            transactional::ObserveInvitationLifecycleRequestLifecycle::Expired => {
                ORGANIZATION_INVITATION_EXPIRED_EVENT
            }
            transactional::ObserveInvitationLifecycleRequestLifecycle::Revoked => {
                ORGANIZATION_INVITATION_REVOKED_EVENT
            }
        };
        let payload = OrganizationInvitationLifecycle {
            invitation_id: request.invitation_id.clone(),
            organization_id: request.organization_id,
            observed_at,
        };
        apply_observation(
            prepared.postgres.pool(),
            ObservationEnvelope {
                id: request.observation_id,
                event_name: event_name.to_owned(),
                event_version: 1,
                source_module: caller,
                aggregate_id: request.invitation_id,
                occurred_at: observed_at,
                payload: serde_json::to_value(payload)
                    .map_err(|error| PluginError::runtime(runtime(error)))?,
            },
        )
        .await
        .map_err(map_lifecycle_error)?;
        Ok(transactional::ObserveInvitationLifecycleResponse { recorded: true })
    }

    async fn dispatch_due(
        &self,
        context: Ctx,
        _request: delivery::DispatchDueRequest,
    ) -> PluginResult<delivery::DispatchDueResponse, delivery::DispatchDueError> {
        if !authorized(&context, &self.config.dispatch_callers) {
            return Err(PluginError::domain(
                delivery::DispatchDueError::Unauthorized,
            ));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let now = Utc::now();
        let Some(work) = claim_one_due(prepared.postgres.pool(), &prepared.protector, now)
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?
        else {
            return Err(PluginError::domain(
                delivery::DispatchDueError::NoDeliveryDue,
            ));
        };
        let dispatch = dispatch_request(&work);
        let response = match self.email.dispatch(dispatch).await {
            Ok(response) => response,
            Err(EmailDispatchInvocationError::Domain(email::DispatchError::InvalidDispatch)) => {
                let observed = permanent_rejection(
                    &work,
                    &prepared.email_provider_instance,
                    "email_invalid_dispatch",
                    now,
                );
                apply_dispatch(prepared.postgres.pool(), &work, &observed)
                    .await
                    .map_err(|error| PluginError::runtime(runtime(error)))?;
                return Err(PluginError::domain(
                    delivery::DispatchDueError::DispatchRejected,
                ));
            }
            Err(EmailDispatchInvocationError::Domain(email::DispatchError::UnsupportedMessage)) => {
                let observed = permanent_rejection(
                    &work,
                    &prepared.email_provider_instance,
                    "email_unsupported_message",
                    now,
                );
                apply_dispatch(prepared.postgres.pool(), &work, &observed)
                    .await
                    .map_err(|error| PluginError::runtime(runtime(error)))?;
                return Err(PluginError::domain(
                    delivery::DispatchDueError::DispatchRejected,
                ));
            }
            Err(EmailDispatchInvocationError::Domain(email::DispatchError::Unknown(_))) => {
                let observed = unknown_dispatch(
                    &work,
                    &prepared.email_provider_instance,
                    now,
                    "email_dispatch_unknown_domain_error",
                );
                apply_dispatch(prepared.postgres.pool(), &work, &observed)
                    .await
                    .map_err(|error| PluginError::runtime(runtime(error)))?;
                return Err(PluginError::runtime(email_protocol_violation()));
            }
            Err(EmailDispatchInvocationError::Runtime(error)) => {
                let observed = unknown_dispatch(
                    &work,
                    &prepared.email_provider_instance,
                    now,
                    "email_dispatch_runtime_failure",
                );
                apply_dispatch(prepared.postgres.pool(), &work, &observed)
                    .await
                    .map_err(|storage| PluginError::runtime(runtime(storage)))?;
                return Err(PluginError::runtime(error));
            }
        };
        let observed =
            match dispatch_observation(&work, &prepared.email_provider_instance, response) {
                Ok(observed) => observed,
                Err(error) => {
                    let observed = unknown_dispatch(
                        &work,
                        &prepared.email_provider_instance,
                        now,
                        "email_dispatch_protocol_failure",
                    );
                    apply_dispatch(prepared.postgres.pool(), &work, &observed)
                        .await
                        .map_err(|storage| PluginError::runtime(runtime(storage)))?;
                    return Err(PluginError::runtime(error));
                }
            };
        apply_dispatch(prepared.postgres.pool(), &work, &observed)
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?;
        let detail = PostgresNotificationRepository::from_pool(prepared.postgres.pool().clone())
            .get_delivery(&work.claim.delivery_id)
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?
            .ok_or_else(|| PluginError::runtime(runtime("claimed delivery disappeared")))?;
        let next_attempt_at = detail
            .delivery
            .next_attempt_at
            .map(format_time)
            .transpose()
            .map_err(PluginError::runtime)?;
        let observed_at = format_time(observed.observed_at).map_err(PluginError::runtime)?;
        Ok(delivery::DispatchDueResponse {
            attempt_id: work.claim.attempt_id,
            delivery_id: work.claim.delivery_id,
            next_attempt_at,
            observed_at,
            run_id: work.claim.run_id,
            status: delivery_status(&detail.delivery.status).map_err(PluginError::runtime)?,
        })
    }

    async fn observe_receipt(
        &self,
        context: Ctx,
        request: delivery::ObserveReceiptRequest,
    ) -> PluginResult<delivery::ObserveReceiptResponse, delivery::ObserveReceiptError> {
        let Some(caller) =
            authorized_caller(&context, &self.config.receipt_callers).map(str::to_owned)
        else {
            return Err(PluginError::domain(
                delivery::ObserveReceiptError::Unauthorized,
            ));
        };
        if !valid_receipt_request(&request) {
            return Err(PluginError::domain(
                delivery::ObserveReceiptError::InvalidReceipt,
            ));
        }
        let observed_at = parse_time(&request.observed_at)
            .map_err(|_| PluginError::domain(delivery::ObserveReceiptError::InvalidReceipt))?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let kind = match request.kind {
            delivery::ObserveReceiptRequestKind::Delivered => ReceiptKind::Delivered,
            delivery::ObserveReceiptRequestKind::Bounced => ReceiptKind::Bounced,
            delivery::ObserveReceiptRequestKind::Rejected => ReceiptKind::Rejected,
        };
        let aggregate_id = request.delivery_id.clone();
        let payload = receipt_observation(caller.clone(), &request, kind, observed_at);
        apply_observation(
            prepared.postgres.pool(),
            ObservationEnvelope {
                id: request.observation_id,
                event_name: EMAIL_RECEIPT_OBSERVED_EVENT.to_owned(),
                event_version: 1,
                source_module: caller,
                aggregate_id,
                occurred_at: observed_at,
                payload: serde_json::to_value(payload)
                    .map_err(|error| PluginError::runtime(runtime(error)))?,
            },
        )
        .await
        .map_err(map_receipt_error)?;
        Ok(delivery::ObserveReceiptResponse { recorded: true })
    }

    async fn list_deliveries(
        &self,
        context: Ctx,
        request: admin::ListDeliveriesRequest,
    ) -> PluginResult<admin::ListDeliveriesResponse, admin::ListDeliveriesError> {
        if !authorized(&context, &self.config.admin_callers) {
            return Err(PluginError::domain(
                admin::ListDeliveriesError::Unauthorized,
            ));
        }
        if !valid_list_request(&request) {
            return Err(PluginError::domain(
                admin::ListDeliveriesError::InvalidFilter,
            ));
        }
        let limit = request.limit.unwrap_or(100);
        let status = request.status.as_ref().map(admin_status);
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let rows = PostgresNotificationRepository::from_pool(prepared.postgres.pool().clone())
            .list_deliveries(limit + 1, request.cursor.as_deref(), status)
            .await
            .map_err(|error| PluginError::runtime(runtime(error)))?;
        let has_more = i64::try_from(rows.len()).is_ok_and(|count| count > limit);
        let records = rows
            .into_iter()
            .take(usize::try_from(limit).unwrap_or_default())
            .map(admin_delivery)
            .collect::<Result<Vec<_>, _>>()
            .map_err(PluginError::runtime)?;
        let next_cursor = has_more
            .then(|| records.last().map(|record| record.id.clone()))
            .flatten();
        Ok(admin::ListDeliveriesResponse {
            next_cursor,
            records,
        })
    }

    async fn get_delivery(
        &self,
        context: Ctx,
        request: admin::GetDeliveryRequest,
    ) -> PluginResult<admin::GetDeliveryResponse, admin::GetDeliveryError> {
        if !authorized(&context, &self.config.admin_callers) {
            return Err(PluginError::domain(admin::GetDeliveryError::Unauthorized));
        }
        if !required_bounded(&request.delivery_id, 1, 160) {
            return Err(PluginError::domain(admin::GetDeliveryError::InvalidRequest));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let detail = PostgresNotificationRepository::from_pool(prepared.postgres.pool().clone())
            .get_delivery(&request.delivery_id)
            .await
            .map_err(map_get_error)?
            .ok_or_else(|| PluginError::domain(admin::GetDeliveryError::DeliveryNotFound))?;
        admin_detail(detail).map_err(PluginError::runtime)
    }

    async fn retry_delivery(
        &self,
        context: Ctx,
        request: admin::RetryDeliveryRequest,
    ) -> PluginResult<admin::RetryDeliveryResponse, admin::RetryDeliveryError> {
        let Some(caller) =
            authorized_caller(&context, &self.config.admin_callers).map(str::to_owned)
        else {
            return Err(PluginError::domain(admin::RetryDeliveryError::Unauthorized));
        };
        if !valid_retry_request(&request) {
            return Err(PluginError::domain(
                admin::RetryDeliveryError::InvalidRequest,
            ));
        }
        if request.revision == MAX_SAFE_WIRE_INTEGER {
            return Err(PluginError::domain(
                admin::RetryDeliveryError::RetryNotAllowed,
            ));
        }
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let result = PostgresNotificationRepository::from_pool(prepared.postgres.pool().clone())
            .request_manual_retry(
                &request.delivery_id,
                request.revision,
                &request.idempotency_key,
                &caller,
                Utc::now(),
            )
            .await
            .map_err(map_retry_error)?;
        admin_retry(result).map_err(PluginError::runtime)
    }
}

impl NotificationPlugin {
    fn prepared(&self) -> Result<PreparedNotification, RuntimeFailure> {
        self.state
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Notification Plugin is not prepared".to_owned(),
            })
    }

    async fn render_organization_invitation(
        &self,
        context: Ctx,
        intent: &CreateTransactionalEmailIntent,
    ) -> Result<RenderedTemplate, RuntimeFailure> {
        self.templates
            .render_with_context(context, organization_invitation_render_request(intent))
            .await
            .map(rendered_template)
            .map_err(map_template_render_error)
    }

    async fn render_access_request_notification(
        &self,
        context: Ctx,
        intent: &CreateAccessRequestNotificationIntent,
    ) -> Result<RenderedTemplate, RuntimeFailure> {
        self.templates
            .render_with_context(context, access_request_render_request(intent))
            .await
            .map(rendered_template)
            .map_err(map_template_render_error)
    }
}

fn organization_invitation_render_request(
    intent: &CreateTransactionalEmailIntent,
) -> notification_template::RenderRequest {
    notification_template::RenderRequest {
        template_id: crate::public::ORGANIZATION_INVITATION_TEMPLATE_ID.to_owned(),
        version: Some(crate::public::ORGANIZATION_INVITATION_TEMPLATE_VERSION.to_owned()),
        locale: intent.recipient.locale.clone(),
        variables: render_variables([
            (
                "expires_at",
                format_template_time(intent.template.expires_at),
            ),
            ("invitation_url", intent.template.invitation_url.clone()),
            (
                "inviter_display_name",
                trimmed_optional(intent.template.inviter_display_name.as_deref()),
            ),
            ("locale", intent.recipient.locale.clone()),
            (
                "organization_name",
                intent.template.organization_name.trim().to_owned(),
            ),
            (
                "recipient_display_name",
                trimmed_optional(intent.recipient.display_name.as_deref()),
            ),
            (
                "role_name",
                trimmed_optional(intent.template.role_name.as_deref()),
            ),
        ]),
    }
}

fn access_request_render_request(
    intent: &CreateAccessRequestNotificationIntent,
) -> notification_template::RenderRequest {
    let role = intent
        .template
        .role
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&intent.template.role.role_id)
        .to_owned();
    let scope = intent
        .template
        .scope
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&intent.template.scope.id)
        .to_owned();
    let mut variables = vec![
        render_variable("locale", intent.recipient.locale.clone()),
        render_variable("organization_id", intent.template.organization_id.clone()),
        render_variable(
            "recipient_display_name",
            trimmed_optional(intent.recipient.display_name.as_deref()),
        ),
        render_variable("request_id", intent.template.request_id.clone()),
        render_variable("role", role),
        render_variable("scope", scope),
        render_variable("scope_kind", intent.template.scope.kind.clone()),
    ];
    if intent.template.event != AccessRequestNotificationEvent::Denied {
        variables.push(render_variable(
            "expires_at",
            intent
                .template
                .expires_at
                .map(format_template_time)
                .unwrap_or_default(),
        ));
    }
    variables.sort_by(|left, right| left.name.cmp(&right.name));
    notification_template::RenderRequest {
        template_id: access_request_template_id(intent.template.event).to_owned(),
        version: Some(crate::public::ACCESS_REQUEST_TEMPLATE_VERSION.to_owned()),
        locale: intent.recipient.locale.clone(),
        variables,
    }
}

fn render_variables<const N: usize>(
    variables: [(&str, String); N],
) -> Vec<notification_template::RenderRequestVariablesItem> {
    variables
        .into_iter()
        .map(|(name, value)| render_variable(name, value))
        .collect()
}

fn render_variable(name: &str, value: String) -> notification_template::RenderRequestVariablesItem {
    notification_template::RenderRequestVariablesItem {
        name: name.to_owned(),
        value,
    }
}

fn trimmed_optional(value: Option<&str>) -> String {
    value.map(str::trim).unwrap_or_default().to_owned()
}

fn format_template_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn rendered_template(response: notification_template::RenderResponse) -> RenderedTemplate {
    RenderedTemplate {
        template_id: response.template_id,
        template_version: response.version,
        requested_locale: response.requested_locale,
        resolved_locale: response.resolved_locale,
        fallback_used: response.fallback_used,
        renderer_identity: response.renderer_identity,
        template_digest: response.template_digest,
        content_digest: response.content_digest,
        subject: response.subject,
        text: response.text,
        html: response.html,
    }
}

fn map_template_render_error(
    error: notification_template::NotificationTemplateRenderInvocationError,
) -> RuntimeFailure {
    match error {
        notification_template::NotificationTemplateRenderInvocationError::Runtime(error) => error,
        notification_template::NotificationTemplateRenderInvocationError::Domain(
            notification_template::RenderError::NotFound,
        ) => RuntimeFailure::PluginFailure {
            detail: "required Notification Template version is unavailable".to_owned(),
        },
        notification_template::NotificationTemplateRenderInvocationError::Domain(
            notification_template::RenderError::Unauthorized,
        ) => RuntimeFailure::PluginFailure {
            detail:
                "Notification is not authorized to render through its configured Template Provider"
                    .to_owned(),
        },
        notification_template::NotificationTemplateRenderInvocationError::Domain(_) => {
            RuntimeFailure::ProtocolViolation {
                capability: notification_template::CAPABILITY_ID,
            }
        }
    }
}

fn authorized(context: &Ctx, allowed: &[String]) -> bool {
    authorized_caller(context, allowed).is_some()
}

fn authorized_caller<'a>(context: &'a Ctx, allowed: &[String]) -> Option<&'a str> {
    context
        .caller_instance()
        .filter(|caller| allowed.iter().any(|allowed| allowed == caller))
}

fn required_bounded(value: &str, minimum: usize, maximum: usize) -> bool {
    let length = value.chars().count();
    !value.trim().is_empty() && (minimum..=maximum).contains(&length)
}

fn optional_bounded(value: Option<&str>, maximum: usize) -> bool {
    value.is_none_or(|value| value.chars().count() <= maximum)
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_create_request(
    request: &transactional::CreateOrganizationInvitationRequest,
    now: DateTime<Utc>,
) -> bool {
    required_bounded(&request.source.entity_type, 1, 160)
        && request.source.entity_type == "organization_invitation"
        && required_bounded(&request.source.entity_id, 1, 240)
        && required_bounded(&request.recipient.address, 3, 320)
        && request.recipient.address.contains('@')
        && optional_bounded(request.recipient.display_name.as_deref(), 240)
        && required_bounded(&request.template.organization_id, 1, 240)
        && required_bounded(&request.template.organization_name, 1, 240)
        && required_bounded(&request.template.invitation_id, 1, 240)
        && request.source.entity_id == request.template.invitation_id
        && required_bounded(&request.template.invitation_url, 1, 4_096)
        && (request.template.invitation_url.starts_with("https://")
            || request
                .template
                .invitation_url
                .starts_with("http://localhost"))
        && optional_bounded(request.template.inviter_display_name.as_deref(), 240)
        && optional_bounded(request.template.role_name.as_deref(), 160)
        && valid_time(&request.template.expires_at)
        && parse_time(&request.template.expires_at).is_ok_and(|expires_at| expires_at > now)
        && required_bounded(&request.idempotency_key, 1, 240)
        && required_bounded(&request.correlation_id, 1, 240)
        && optional_bounded(request.causation_id.as_deref(), 240)
        && optional_bounded(request.requested_by.as_deref(), 240)
}

fn valid_access_request_notification_request(
    request: &transactional::CreateAccessRequestNotificationRequest,
    now: DateTime<Utc>,
) -> bool {
    let event = match &request.event {
        transactional::CreateAccessRequestNotificationRequestEvent::Submitted => "submitted",
        transactional::CreateAccessRequestNotificationRequestEvent::Approved => "approved",
        transactional::CreateAccessRequestNotificationRequestEvent::Denied => "denied",
        transactional::CreateAccessRequestNotificationRequestEvent::Expiring => "expiring",
    };
    let expected_idempotency_key = format!("access-request:{}:{event}", request.request_id);
    let expiry = request
        .expires_at
        .as_deref()
        .and_then(|value| parse_time(value).ok());
    let expiry_valid = match &request.event {
        transactional::CreateAccessRequestNotificationRequestEvent::Expiring => {
            expiry.is_some_and(|value| value > now)
        }
        transactional::CreateAccessRequestNotificationRequestEvent::Denied => {
            request.expires_at.is_none()
        }
        _ => request.expires_at.is_none() || expiry.is_some_and(|value| value > now),
    };
    required_bounded(&request.request_id, 1, 160)
        && required_bounded(&request.organization_id, 1, 240)
        && required_bounded(&request.recipient.address, 3, 320)
        && request.recipient.address.contains('@')
        && optional_bounded(request.recipient.display_name.as_deref(), 240)
        && required_bounded(&request.role.role_id, 1, 160)
        && optional_bounded(request.role.display_name.as_deref(), 160)
        && required_bounded(&request.scope.kind, 1, 160)
        && required_bounded(&request.scope.id, 1, 240)
        && optional_bounded(request.scope.display_name.as_deref(), 240)
        && request.expires_at.as_deref().is_none_or(valid_time)
        && expiry_valid
        && request.idempotency_key == expected_idempotency_key
        && required_bounded(&request.correlation_id, 1, 240)
        && optional_bounded(request.causation_id.as_deref(), 240)
        && optional_bounded(request.requested_by.as_deref(), 240)
}

fn valid_lifecycle_request(request: &transactional::ObserveInvitationLifecycleRequest) -> bool {
    required_bounded(&request.observation_id, 1, 240)
        && required_bounded(&request.organization_id, 1, 240)
        && required_bounded(&request.invitation_id, 1, 240)
        && valid_time(&request.observed_at)
}

fn valid_receipt_request(request: &delivery::ObserveReceiptRequest) -> bool {
    required_bounded(&request.observation_id, 1, 240)
        && required_bounded(&request.delivery_id, 1, 160)
        && required_bounded(&request.attempt_id, 1, 160)
        && required_bounded(&request.run_id, 1, 160)
        && valid_time(&request.observed_at)
        && required_bounded(&request.remote_id, 1, 320)
        && valid_digest(&request.digest)
}

fn valid_list_request(request: &admin::ListDeliveriesRequest) -> bool {
    request.limit.is_none_or(|limit| (1..=200).contains(&limit))
        && request
            .cursor
            .as_deref()
            .is_none_or(|cursor| required_bounded(cursor, 1, 160))
}

fn valid_retry_request(request: &admin::RetryDeliveryRequest) -> bool {
    required_bounded(&request.delivery_id, 1, 160)
        && (1..=MAX_SAFE_WIRE_INTEGER).contains(&request.revision)
        && required_bounded(&request.idempotency_key, 1, 240)
}

fn intent_source(
    caller: String,
    source: transactional::CreateOrganizationInvitationRequestSource,
) -> IntentSource {
    IntentSource {
        module_id: caller,
        entity_type: source.entity_type,
        entity_id: source.entity_id,
    }
}

fn receipt_observation(
    caller: String,
    request: &delivery::ObserveReceiptRequest,
    kind: ReceiptKind,
    observed_at: DateTime<Utc>,
) -> EmailReceiptObserved {
    EmailReceiptObserved {
        delivery_id: request.delivery_id.clone(),
        attempt_id: request.attempt_id.clone(),
        function_run_id: request.run_id.clone(),
        kind,
        source: caller,
        observed_at,
        remote_id: request.remote_id.clone(),
        digest: request.digest.clone(),
    }
}

impl Lifecycle for NotificationPlugin {
    async fn prepare(&self, context: PrepareContext) -> Result<(), RuntimeFailure> {
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let email_providers = email::EmailDispatchClient::many_from_dependencies(&dependencies)?;
        let [email_provider] = email_providers.as_slice() else {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Notification requires exactly one lenso.email-dispatch@1 Provider"
                    .to_owned(),
            });
        };
        let email_provider_instance = email_provider.provider_instance().to_owned();
        let secrets = lenso_capability_secrets::SecretsClient::from_dependencies(&dependencies)?;
        let database_context =
            dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation.clone())?;
        let database_url =
            resolve_secret(&secrets, database_context, &self.config.database_url_secret).await?;
        let snapshot_context =
            dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
        let snapshot_key =
            resolve_secret(&secrets, snapshot_context, &self.config.snapshot_key_secret).await?;
        let protector = AeadSnapshotProtector::from_base64_key(
            &snapshot_key,
            self.config.snapshot_key_secret.clone(),
        )
        .map_err(runtime)?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(runtime)?;
        if let Err(error) = verify_managed_catalog(postgres.pool()).await {
            postgres.pool().close().await;
            return Err(runtime(error));
        }
        self.state.replace(Some(PreparedNotification {
            postgres,
            protector,
            email_provider_instance,
        }));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.state.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

fn dispatch_request(work: &DispatchWork) -> DispatchRequest {
    work.request.clone()
}

fn dispatch_observation(
    work: &DispatchWork,
    email_provider_instance: &str,
    response: email::DispatchResponse,
) -> Result<EmailDispatchObserved, RuntimeFailure> {
    if !valid_dispatch_response(&response, email_provider_instance) {
        return Err(email_protocol_violation());
    }
    let observed_at = parse_time(&response.observed_at).map_err(|_| email_protocol_violation())?;
    let failure = response
        .failure
        .map(|failure| {
            Ok(SanitizedFailure {
                code: failure.code,
                classification: failure.classification,
                retry_after_ms: failure
                    .retry_after_ms
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| email_protocol_violation())?,
            })
        })
        .transpose()?;
    Ok(EmailDispatchObserved {
        delivery_id: work.claim.delivery_id.clone(),
        attempt_id: work.claim.attempt_id.clone(),
        function_run_id: work.claim.run_id.clone(),
        outcome: match response.outcome {
            DispatchResponseOutcome::Accepted => DispatchOutcome::Accepted,
            DispatchResponseOutcome::TemporaryFailure => DispatchOutcome::TemporaryFailure,
            DispatchResponseOutcome::PermanentFailure => DispatchOutcome::PermanentFailure,
            DispatchResponseOutcome::DeliveryUnknown => DispatchOutcome::DeliveryUnknown,
        },
        provider: email_provider_instance.to_owned(),
        observed_at,
        remote_receipt: response.remote_receipt.map(|receipt| RemoteReceiptSummary {
            remote_id: receipt.remote_id,
            source: email_provider_instance.to_owned(),
            digest: receipt.digest,
        }),
        failure,
    })
}

fn valid_dispatch_response(
    response: &email::DispatchResponse,
    email_provider_instance: &str,
) -> bool {
    if response.provider != email_provider_instance || !valid_time(&response.observed_at) {
        return false;
    }
    let remote_receipt_valid = response.remote_receipt.as_ref().is_none_or(|receipt| {
        required_bounded(&receipt.remote_id, 1, 320)
            && receipt.source == email_provider_instance
            && valid_digest(&receipt.digest)
    });
    if !remote_receipt_valid {
        return false;
    }
    match &response.outcome {
        DispatchResponseOutcome::Accepted => response.failure.is_none(),
        DispatchResponseOutcome::TemporaryFailure => {
            response.remote_receipt.is_none()
                && response.failure.as_ref().is_some_and(|failure| {
                    valid_dispatch_failure(failure, "temporary_failure")
                        && failure
                            .retry_after_ms
                            .is_none_or(|delay| (0..=86_400_000).contains(&delay))
                })
        }
        DispatchResponseOutcome::PermanentFailure => {
            response.remote_receipt.is_none()
                && response.failure.as_ref().is_some_and(|failure| {
                    valid_dispatch_failure(failure, "permanent_failure")
                        && failure.retry_after_ms.is_none()
                })
        }
        DispatchResponseOutcome::DeliveryUnknown => {
            response.remote_receipt.is_none()
                && response.failure.as_ref().is_some_and(|failure| {
                    valid_dispatch_failure(failure, "delivery_unknown")
                        && failure.retry_after_ms.is_none()
                })
        }
    }
}

fn valid_dispatch_failure(failure: &email::DispatchResponseFailure, classification: &str) -> bool {
    required_bounded(&failure.code, 1, 160)
        && required_bounded(&failure.classification, 1, 160)
        && failure.classification == classification
}

fn email_protocol_violation() -> RuntimeFailure {
    RuntimeFailure::ProtocolViolation {
        capability: email::CAPABILITY_ID,
    }
}

fn permanent_rejection(
    work: &DispatchWork,
    email_provider_instance: &str,
    code: &str,
    observed_at: DateTime<Utc>,
) -> EmailDispatchObserved {
    EmailDispatchObserved {
        delivery_id: work.claim.delivery_id.clone(),
        attempt_id: work.claim.attempt_id.clone(),
        function_run_id: work.claim.run_id.clone(),
        outcome: DispatchOutcome::PermanentFailure,
        provider: email_provider_instance.to_owned(),
        observed_at,
        remote_receipt: None,
        failure: Some(SanitizedFailure {
            code: code.to_owned(),
            classification: "permanent_failure".to_owned(),
            retry_after_ms: None,
        }),
    }
}

fn unknown_dispatch(
    work: &DispatchWork,
    email_provider_instance: &str,
    observed_at: DateTime<Utc>,
    code: &str,
) -> EmailDispatchObserved {
    EmailDispatchObserved {
        delivery_id: work.claim.delivery_id.clone(),
        attempt_id: work.claim.attempt_id.clone(),
        function_run_id: work.claim.run_id.clone(),
        outcome: DispatchOutcome::DeliveryUnknown,
        provider: email_provider_instance.to_owned(),
        observed_at,
        remote_receipt: None,
        failure: Some(SanitizedFailure {
            code: code.to_owned(),
            classification: "delivery_unknown".to_owned(),
            retry_after_ms: None,
        }),
    }
}

async fn apply_dispatch(
    pool: &sqlx::PgPool,
    work: &DispatchWork,
    observed: &EmailDispatchObserved,
) -> Result<(), NotificationError> {
    apply_observation(
        pool,
        ObservationEnvelope {
            id: format!("dispatch-observation:{}", work.claim.attempt_id),
            event_name: EMAIL_DISPATCH_OBSERVED_EVENT.to_owned(),
            event_version: 1,
            source_module: observed.provider.clone(),
            aggregate_id: work.claim.delivery_id.clone(),
            occurred_at: observed.observed_at,
            payload: serde_json::to_value(observed).map_err(|error| {
                NotificationError::new(
                    ErrorCode::Internal,
                    "Notification dispatch observation encoding failed",
                )
                .with_source(error)
            })?,
        },
    )
    .await
}

async fn apply_observation(
    pool: &sqlx::PgPool,
    envelope: ObservationEnvelope,
) -> Result<(), NotificationError> {
    NotificationEventApplier::new(pool.clone())
        .apply(&envelope)
        .await
}

fn delivery_status(status: &str) -> Result<delivery::DispatchDueResponseStatus, RuntimeFailure> {
    match status {
        "accepted" => Ok(delivery::DispatchDueResponseStatus::Accepted),
        "retry_scheduled" => Ok(delivery::DispatchDueResponseStatus::RetryScheduled),
        "failed" => Ok(delivery::DispatchDueResponseStatus::Failed),
        "delivery_unknown" => Ok(delivery::DispatchDueResponseStatus::DeliveryUnknown),
        other => Err(runtime(format!(
            "stored delivery status `{other}` is invalid after dispatch"
        ))),
    }
}

fn admin_detail(value: DeliveryDetail) -> Result<admin::GetDeliveryResponse, RuntimeFailure> {
    if value.attempts.len() > ADMIN_ATTEMPT_LIMIT
        || value.receipts.len() > ADMIN_RECEIPT_LIMIT
        || value.retry_requests.len() > ADMIN_RETRY_REQUEST_LIMIT
    {
        return Err(invalid_admin_projection());
    }
    let correlation_id = value.delivery.correlation_id.clone();
    Ok(admin::GetDeliveryResponse {
        attempts: value
            .attempts
            .into_iter()
            .map(admin_attempt)
            .collect::<Result<Vec<_>, _>>()?,
        delivery: admin_delivery(value.delivery)?,
        open_in_story_correlation_id: correlation_id,
        receipts: value
            .receipts
            .into_iter()
            .map(admin_receipt)
            .collect::<Result<Vec<_>, _>>()?,
        retry_requests: value
            .retry_requests
            .into_iter()
            .map(admin_retry_record)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn admin_delivery(value: DeliverySummary) -> Result<admin::Delivery, RuntimeFailure> {
    if !required_bounded(&value.id, 1, 160)
        || !required_bounded(&value.recipient_mask, 3, 320)
        || !required_bounded(&value.template_id, 1, 160)
        || !required_bounded(&value.template_version, 1, 80)
        || !required_bounded(&value.locale, 2, 32)
        || !(1..=MAX_SAFE_WIRE_INTEGER).contains(&value.revision)
        || !(0..=10).contains(&value.attempt_count)
        || !(1..=10).contains(&value.max_attempts)
        || value.attempt_count > value.max_attempts
        || value.redacted_preview.chars().count() > 160
        || !valid_digest(&value.content_digest)
        || !required_bounded(&value.correlation_id, 1, 240)
        || !optional_bounded(value.final_reason.as_deref(), 160)
    {
        return Err(invalid_admin_projection());
    }
    let status = match value.status.as_str() {
        "queued" => admin::DeliveryStatus::Queued,
        "attempting" => admin::DeliveryStatus::Attempting,
        "accepted" => admin::DeliveryStatus::Accepted,
        "retry_scheduled" => admin::DeliveryStatus::RetryScheduled,
        "delivered" => admin::DeliveryStatus::Delivered,
        "failed" => admin::DeliveryStatus::Failed,
        "delivery_unknown" => admin::DeliveryStatus::DeliveryUnknown,
        other => {
            let _ = other;
            return Err(invalid_admin_projection());
        }
    };
    Ok(admin::Delivery {
        attempt_count: i64::from(value.attempt_count),
        content_digest: value.content_digest,
        correlation_id: value.correlation_id,
        created_at: format_time(value.created_at)?,
        final_reason: value.final_reason,
        id: value.id,
        locale: value.locale,
        max_attempts: i64::from(value.max_attempts),
        next_attempt_at: value.next_attempt_at.map(format_time).transpose()?,
        recipient_mask: value.recipient_mask,
        redacted_preview: value.redacted_preview,
        retry_now_eligible: value.status == "retry_scheduled"
            && value.attempt_count < value.max_attempts,
        revision: value.revision,
        status,
        template_id: value.template_id,
        template_version: value.template_version,
        updated_at: format_time(value.updated_at)?,
    })
}

fn admin_attempt(value: AttemptRecord) -> Result<admin::Attempt, RuntimeFailure> {
    if !required_bounded(&value.id, 1, 160)
        || !(1..=10).contains(&value.sequence)
        || !required_bounded(&value.function_run_id, 1, 160)
        || !optional_bounded(value.provider.as_deref(), 160)
        || !optional_bounded(value.remote_receipt_id.as_deref(), 320)
        || !optional_bounded(value.failure_code.as_deref(), 160)
        || !optional_bounded(value.failure_classification.as_deref(), 160)
    {
        return Err(invalid_admin_projection());
    }
    let status = match value.status.as_str() {
        "dispatching" => admin::AttemptStatus::Dispatching,
        "accepted" => admin::AttemptStatus::Accepted,
        "temporary_failure" => admin::AttemptStatus::TemporaryFailure,
        "permanent_failure" => admin::AttemptStatus::PermanentFailure,
        "delivery_unknown" => admin::AttemptStatus::DeliveryUnknown,
        _ => return Err(invalid_admin_projection()),
    };
    Ok(admin::Attempt {
        completed_at: value.completed_at.map(format_time).transpose()?,
        failure_classification: value.failure_classification,
        failure_code: value.failure_code,
        id: value.id,
        provider: value.provider,
        remote_receipt_id: value.remote_receipt_id,
        run_id: value.function_run_id,
        sequence: i64::from(value.sequence),
        started_at: format_time(value.started_at)?,
        status,
    })
}

fn admin_receipt(value: ReceiptRecord) -> Result<admin::Receipt, RuntimeFailure> {
    if !required_bounded(&value.id, 1, 160)
        || !required_bounded(&value.attempt_id, 1, 160)
        || !required_bounded(&value.source, 1, 160)
        || !required_bounded(&value.remote_id, 1, 320)
        || !valid_digest(&value.digest)
    {
        return Err(invalid_admin_projection());
    }
    let kind = match value.kind.as_str() {
        "accepted" => admin::ReceiptKind::Accepted,
        "delivered" => admin::ReceiptKind::Delivered,
        "bounced" => admin::ReceiptKind::Bounced,
        "rejected" => admin::ReceiptKind::Rejected,
        _ => return Err(invalid_admin_projection()),
    };
    Ok(admin::Receipt {
        attempt_id: value.attempt_id,
        digest: value.digest,
        id: value.id,
        kind,
        observed_at: format_time(value.observed_at)?,
        remote_id: value.remote_id,
        source: value.source,
    })
}

fn admin_retry_record(value: RetryRecord) -> Result<admin::RetryRecord, RuntimeFailure> {
    if !required_bounded(&value.id, 1, 160)
        || !optional_bounded(value.requested_by.as_deref(), 240)
        || !(1..=MAX_SAFE_WIRE_INTEGER).contains(&value.source_revision)
        || !optional_bounded(value.reason.as_deref(), 160)
    {
        return Err(invalid_admin_projection());
    }
    let kind = match value.kind.as_str() {
        "automatic" => admin::RetryRecordKind::Automatic,
        "manual" => admin::RetryRecordKind::Manual,
        _ => return Err(invalid_admin_projection()),
    };
    let decision = match value.decision.as_str() {
        "scheduled" => admin::RetryRecordDecision::Scheduled,
        "rejected" => admin::RetryRecordDecision::Rejected,
        _ => return Err(invalid_admin_projection()),
    };
    Ok(admin::RetryRecord {
        created_at: format_time(value.created_at)?,
        decision,
        id: value.id,
        kind,
        reason: value.reason,
        requested_by: value.requested_by,
        scheduled_at: value.scheduled_at.map(format_time).transpose()?,
        source_revision: value.source_revision,
    })
}

fn admin_retry(value: RetryResult) -> Result<admin::RetryDeliveryResponse, RuntimeFailure> {
    if !required_bounded(&value.delivery_id, 1, 160)
        || !(1..=MAX_SAFE_WIRE_INTEGER).contains(&value.revision)
        || value.status != "retry_scheduled"
    {
        return Err(invalid_admin_projection());
    }
    Ok(admin::RetryDeliveryResponse {
        delivery_id: value.delivery_id,
        idempotent_replay: value.idempotent_replay,
        revision: value.revision,
        scheduled_at: format_time(value.scheduled_at)?,
        status: admin::RetryDeliveryResponseStatus::RetryScheduled,
    })
}

fn invalid_admin_projection() -> RuntimeFailure {
    runtime("stored Notification Admin projection violates its bounded Capability Contract")
}

fn admin_status(status: &admin::DeliveryStatus) -> &'static str {
    match status {
        admin::DeliveryStatus::Queued => "queued",
        admin::DeliveryStatus::Attempting => "attempting",
        admin::DeliveryStatus::Accepted => "accepted",
        admin::DeliveryStatus::RetryScheduled => "retry_scheduled",
        admin::DeliveryStatus::Delivered => "delivered",
        admin::DeliveryStatus::Failed => "failed",
        admin::DeliveryStatus::DeliveryUnknown => "delivery_unknown",
    }
}

fn map_create_error(
    error: NotificationError,
) -> PluginError<transactional::CreateOrganizationInvitationError> {
    match error.code {
        ErrorCode::Validation => {
            PluginError::domain(transactional::CreateOrganizationInvitationError::InvalidIntent)
        }
        ErrorCode::Conflict => PluginError::domain(
            transactional::CreateOrganizationInvitationError::IdempotencyConflict,
        ),
        ErrorCode::NotFound | ErrorCode::EvidenceOverflow | ErrorCode::Internal => {
            PluginError::runtime(runtime(error))
        }
    }
}

fn map_access_request_create_error(
    error: NotificationError,
) -> PluginError<transactional::CreateAccessRequestNotificationError> {
    match error.code {
        ErrorCode::Validation => {
            PluginError::domain(transactional::CreateAccessRequestNotificationError::InvalidIntent)
        }
        ErrorCode::Conflict => PluginError::domain(
            transactional::CreateAccessRequestNotificationError::IdempotencyConflict,
        ),
        ErrorCode::NotFound | ErrorCode::EvidenceOverflow | ErrorCode::Internal => {
            PluginError::runtime(runtime(error))
        }
    }
}

fn map_lifecycle_error(
    error: NotificationError,
) -> PluginError<transactional::ObserveInvitationLifecycleError> {
    match error.code {
        ErrorCode::Validation => {
            PluginError::domain(transactional::ObserveInvitationLifecycleError::InvalidObservation)
        }
        ErrorCode::Conflict => {
            PluginError::domain(transactional::ObserveInvitationLifecycleError::ObservationConflict)
        }
        ErrorCode::NotFound | ErrorCode::EvidenceOverflow | ErrorCode::Internal => {
            PluginError::runtime(runtime(error))
        }
    }
}

fn map_receipt_error(error: NotificationError) -> PluginError<delivery::ObserveReceiptError> {
    match error.code {
        ErrorCode::Validation => PluginError::domain(delivery::ObserveReceiptError::InvalidReceipt),
        ErrorCode::NotFound => PluginError::domain(delivery::ObserveReceiptError::DeliveryNotFound),
        ErrorCode::Conflict => PluginError::domain(delivery::ObserveReceiptError::ReceiptConflict),
        ErrorCode::EvidenceOverflow | ErrorCode::Internal => PluginError::runtime(runtime(error)),
    }
}

fn map_get_error(error: NotificationError) -> PluginError<admin::GetDeliveryError> {
    match error.code {
        ErrorCode::EvidenceOverflow => {
            PluginError::domain(admin::GetDeliveryError::EvidenceOverflow)
        }
        ErrorCode::Validation | ErrorCode::NotFound | ErrorCode::Conflict | ErrorCode::Internal => {
            PluginError::runtime(runtime(error))
        }
    }
}

fn map_retry_error(error: NotificationError) -> PluginError<admin::RetryDeliveryError> {
    match error.code {
        ErrorCode::NotFound => PluginError::domain(admin::RetryDeliveryError::DeliveryNotFound),
        ErrorCode::Conflict if error.message().contains("revision is stale") => {
            PluginError::domain(admin::RetryDeliveryError::StaleRevision)
        }
        ErrorCode::Conflict if error.message().contains("not eligible") => {
            PluginError::domain(admin::RetryDeliveryError::RetryNotAllowed)
        }
        ErrorCode::Conflict => PluginError::domain(admin::RetryDeliveryError::IdempotencyConflict),
        ErrorCode::Validation | ErrorCode::EvidenceOverflow | ErrorCode::Internal => {
            PluginError::runtime(runtime(error))
        }
    }
}

async fn resolve_secret(
    secrets: &lenso_capability_secrets::SecretsClient,
    context: Ctx,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

fn valid_secret_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn valid_instance(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|value| value.with_timezone(&Utc))
}

fn valid_time(value: &str) -> bool {
    required_bounded(value, 1, 64) && parse_time(value).is_ok()
}

pub(crate) fn format_time(value: DateTime<Utc>) -> Result<String, RuntimeFailure> {
    if !(0..=9_999).contains(&value.year()) {
        return Err(runtime(
            "stored Notification timestamp is outside the RFC 3339 four-digit year range",
        ));
    }
    let formatted = value.to_rfc3339_opts(SecondsFormat::Millis, true);
    if !valid_time(&formatted) {
        return Err(runtime(
            "stored Notification timestamp violates its bounded Capability Contract",
        ));
    }
    Ok(formatted)
}

fn runtime(error: impl fmt::Display) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc, time::Duration};

    use lenso_app_plan::{
        AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
        PluginInstancePlan, ResolvedAppPlan,
    };
    use lenso_kernel::{
        ActivateContext, CancellationToken, DeterministicDriver, InvocationContext, Kernel,
        NativeRequestEndpoint, NativeRequestFuture, PluginFuture, PluginLifecycle, RuntimeFailure,
        ShutdownOutcome,
    };
    use lenso_native_adapter::{
        NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
    };

    use super::*;
    use crate::domain::DeliveryStatus as StoredDeliveryStatus;

    const CONSUMER_PACKAGE_ID: &str = "test.notification-consumer";
    const FIXTURE_PROVIDER_PACKAGE_ID: &str = "test.notification-transactional-provider";
    const EMPTY_PACKAGE_ID: &str = "test.without-notification";
    const SECRETS_PACKAGE_ID: &str = "test.notification-secrets";
    const EMAIL_PACKAGE_ID: &str = "test.notification-email-dispatch";
    const TEMPLATE_PACKAGE_ID: &str = "test.notification-template";

    #[derive(Clone, Copy, Debug)]
    enum FixtureOutcome {
        Success,
        Domain,
        Runtime,
    }

    type InvocationResult = Result<
        transactional::CreateOrganizationInvitationResponse,
        transactional::TransactionalCreateOrganizationInvitationInvocationError,
    >;

    #[derive(Clone, Debug)]
    struct FixtureTransactionalProvider {
        outcome: FixtureOutcome,
    }

    impl transactional::TransactionalProvider for FixtureTransactionalProvider {
        fn create_access_request_notification(
            &self,
            _context: InvocationContext,
            _request: transactional::CreateAccessRequestNotificationRequest,
        ) -> NativeRequestFuture<transactional::TransactionalCreateAccessRequestNotification>
        {
            Box::pin(std::future::ready(Ok(Ok(
                transactional::CreateAccessRequestNotificationResponse {
                    delivery_id: "ntf_dlv_access_fixture".to_owned(),
                    idempotent_replay: false,
                    intent_id: "ntf_int_access_fixture".to_owned(),
                    status: transactional::CreateAccessRequestNotificationResponseStatus::Queued,
                },
            ))))
        }

        fn create_organization_invitation(
            &self,
            _context: InvocationContext,
            _request: transactional::CreateOrganizationInvitationRequest,
        ) -> NativeRequestFuture<transactional::TransactionalCreateOrganizationInvitation> {
            let result = match self.outcome {
                FixtureOutcome::Success => {
                    Ok(Ok(transactional::CreateOrganizationInvitationResponse {
                        delivery_id: "ntf_dlv_fixture".to_owned(),
                        idempotent_replay: false,
                        intent_id: "ntf_int_fixture".to_owned(),
                        status: transactional::CreateOrganizationInvitationResponseStatus::Queued,
                    }))
                }
                FixtureOutcome::Domain => Ok(Err(
                    transactional::CreateOrganizationInvitationError::Unauthorized,
                )),
                FixtureOutcome::Runtime => Err(RuntimeFailure::PluginFailure {
                    detail: "fixture notification storage unavailable".to_owned(),
                }),
            };
            Box::pin(std::future::ready(result))
        }

        fn observe_invitation_lifecycle(
            &self,
            _context: InvocationContext,
            _request: transactional::ObserveInvitationLifecycleRequest,
        ) -> NativeRequestFuture<transactional::TransactionalObserveInvitationLifecycle> {
            Box::pin(std::future::ready(Ok(Ok(
                transactional::ObserveInvitationLifecycleResponse { recorded: true },
            ))))
        }
    }

    #[derive(Clone, Debug)]
    struct FixtureProviderFactory {
        outcome: FixtureOutcome,
    }

    impl NativePluginFactory for FixtureProviderFactory {
        fn package_id(&self) -> &'static str {
            FIXTURE_PROVIDER_PACKAGE_ID
        }

        fn instantiate(
            &self,
            _context: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            let endpoint = Rc::new(transactional::TransactionalEndpoint::new(
                FixtureTransactionalProvider {
                    outcome: self.outcome,
                },
            )) as Rc<dyn NativeRequestEndpoint>;
            Ok(NativePluginInstance::new(vec![endpoint]))
        }
    }

    #[derive(Clone, Debug)]
    struct ConsumerFactory {
        observed: Rc<RefCell<Option<InvocationResult>>>,
    }

    impl NativePluginFactory for ConsumerFactory {
        fn package_id(&self) -> &'static str {
            CONSUMER_PACKAGE_ID
        }

        fn instantiate(
            &self,
            _context: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            Ok(NativePluginInstance::with_lifecycle(
                Vec::new(),
                ConsumerLifecycle {
                    observed: self.observed.clone(),
                },
            ))
        }
    }

    #[derive(Clone, Debug)]
    struct ConsumerLifecycle {
        observed: Rc<RefCell<Option<InvocationResult>>>,
    }

    impl PluginLifecycle for ConsumerLifecycle {
        fn activate(&self, context: ActivateContext) -> PluginFuture {
            let client =
                transactional::TransactionalClient::from_dependencies(context.dependencies());
            let observed = self.observed.clone();
            Box::pin(async move {
                let client = client?;
                observed.replace(Some(
                    client
                        .create_organization_invitation(generated_request())
                        .await,
                ));
                Ok(())
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct EmptyFactory(&'static str);

    impl NativePluginFactory for EmptyFactory {
        fn package_id(&self) -> &'static str {
            self.0
        }

        fn instantiate(
            &self,
            _context: NativePluginFactoryContext<'_>,
        ) -> Result<NativePluginInstance, RuntimeFailure> {
            Ok(NativePluginInstance::default())
        }
    }

    #[test]
    fn generated_descriptor_declares_business_roles_and_exact_dependencies() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON)
            .expect("generated Plugin descriptor must be JSON");
        assert_eq!(PACKAGE_ID, "lenso.notification");
        assert_eq!(descriptor["plugin_id"], PACKAGE_ID);
        assert_eq!(descriptor["root_slot"], "notifications");
        let provided = descriptor["provided_capabilities"]
            .as_array()
            .expect("provided capabilities")
            .iter()
            .map(|entry| entry["capability_id"].as_str().expect("capability id"))
            .collect::<Vec<_>>();
        assert_eq!(
            provided,
            vec![
                transactional::CAPABILITY_ID,
                delivery::CAPABILITY_ID,
                admin::CAPABILITY_ID,
            ]
        );
        let required = descriptor["required_capabilities"]
            .as_array()
            .expect("required capabilities")
            .iter()
            .map(|entry| entry["capability_id"].as_str().expect("capability id"))
            .collect::<Vec<_>>();
        assert_eq!(
            required,
            vec![
                lenso_capability_secrets::CAPABILITY_ID,
                email::CAPABILITY_ID,
                notification_template::CAPABILITY_ID,
            ]
        );
        let linked = NativePluginRegistry::new()
            .with_linked_factories()
            .factories()
            .filter(|factory| factory.package_id() == PACKAGE_ID)
            .count();
        assert_eq!(linked, 1);
    }

    #[test]
    fn template_requests_are_exact_versioned_and_event_typed() {
        let expires_at = parse_time("2026-09-01T00:00:00Z").expect("timestamp");
        let invitation = CreateTransactionalEmailIntent {
            source: IntentSource {
                module_id: "organization-blue".to_owned(),
                entity_type: "organization_invitation".to_owned(),
                entity_id: "invite_1".to_owned(),
            },
            recipient: EmailRecipient {
                address: "member@example.com".to_owned(),
                display_name: Some(" Member ".to_owned()),
                locale: "en-US".to_owned(),
            },
            template: OrganizationInvitationTemplateV1 {
                organization_id: "org_1".to_owned(),
                organization_name: " Acme ".to_owned(),
                invitation_id: "invite_1".to_owned(),
                invitation_url: "https://example.test/invite".to_owned(),
                inviter_display_name: None,
                role_name: Some(" Member ".to_owned()),
                expires_at,
            },
            idempotency_key: "organization-invitation:invite_1".to_owned(),
            correlation_id: "corr_1".to_owned(),
            causation_id: None,
            requested_by: None,
        };
        let request = organization_invitation_render_request(&invitation);
        assert_eq!(request.template_id, "organization-invitation");
        assert_eq!(request.version.as_deref(), Some("v1"));
        assert_eq!(request.locale, "en-US");
        let variables = request
            .variables
            .into_iter()
            .map(|item| (item.name, item.value))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(variables.len(), 7);
        assert_eq!(variables["organization_name"], "Acme");
        assert_eq!(variables["recipient_display_name"], "Member");
        assert_eq!(variables["inviter_display_name"], "");
        assert_eq!(variables["expires_at"], "2026-09-01T00:00:00Z");

        let mut access = CreateAccessRequestNotificationIntent {
            source: IntentSource {
                module_id: "access-request-blue".to_owned(),
                entity_type: "access_request".to_owned(),
                entity_id: "ar_1".to_owned(),
            },
            recipient: EmailRecipient {
                address: "member@example.com".to_owned(),
                display_name: None,
                locale: "en".to_owned(),
            },
            template: AccessRequestNotificationTemplateV1 {
                request_id: "ar_1".to_owned(),
                organization_id: "org_1".to_owned(),
                event: AccessRequestNotificationEvent::Submitted,
                role: AccessRequestRoleV1 {
                    role_id: "role_member".to_owned(),
                    display_name: None,
                },
                scope: AccessRequestScopeV1 {
                    kind: "organization".to_owned(),
                    id: "org_1".to_owned(),
                    display_name: None,
                },
                expires_at: Some(expires_at),
            },
            idempotency_key: "access-request:ar_1:submitted".to_owned(),
            correlation_id: "corr_2".to_owned(),
            causation_id: None,
            requested_by: None,
        };
        let submitted = access_request_render_request(&access);
        assert_eq!(submitted.template_id, "access-request-submitted");
        assert!(
            submitted
                .variables
                .iter()
                .any(|item| item.name == "expires_at")
        );

        access.template.event = AccessRequestNotificationEvent::Denied;
        access.template.expires_at = None;
        let denied = access_request_render_request(&access);
        assert_eq!(denied.template_id, "access-request-denied");
        assert!(
            denied
                .variables
                .iter()
                .all(|item| item.name != "expires_at")
        );
    }

    #[test]
    fn template_render_failures_preserve_runtime_and_fail_closed_on_domain_results() {
        let runtime = RuntimeFailure::Unavailable {
            capability: notification_template::CAPABILITY_ID,
        };
        assert!(matches!(
            map_template_render_error(
                notification_template::NotificationTemplateRenderInvocationError::Runtime(runtime)
            ),
            RuntimeFailure::Unavailable { capability }
                if capability == notification_template::CAPABILITY_ID
        ));
        assert!(matches!(
            map_template_render_error(
                notification_template::NotificationTemplateRenderInvocationError::Domain(
                    notification_template::RenderError::NotFound,
                )
            ),
            RuntimeFailure::PluginFailure { .. }
        ));
        assert!(matches!(
            map_template_render_error(
                notification_template::NotificationTemplateRenderInvocationError::Domain(
                    notification_template::RenderError::UnexpectedVariable,
                )
            ),
            RuntimeFailure::ProtocolViolation { capability }
                if capability == notification_template::CAPABILITY_ID
        ));
    }

    #[test]
    fn generated_client_provider_and_plan_preserve_success_domain_and_runtime_lanes() {
        let success = run_generated_fixture(FixtureOutcome::Success);
        assert!(matches!(
            success,
            Ok(transactional::CreateOrganizationInvitationResponse {
                status: transactional::CreateOrganizationInvitationResponseStatus::Queued,
                ..
            })
        ));
        let domain = run_generated_fixture(FixtureOutcome::Domain);
        assert!(matches!(
            domain,
            Err(
                transactional::TransactionalCreateOrganizationInvitationInvocationError::Domain(
                    transactional::CreateOrganizationInvitationError::Unauthorized
                )
            )
        ));
        let runtime = run_generated_fixture(FixtureOutcome::Runtime);
        assert!(matches!(
            runtime,
            Err(
                transactional::TransactionalCreateOrganizationInvitationInvocationError::Runtime(
                    RuntimeFailure::PluginFailure { detail }
                )
            ) if detail == "fixture notification storage unavailable"
        ));
    }

    #[test]
    fn caller_identity_is_derived_and_cannot_be_spoofed_by_payload() {
        let request = generated_request();
        let source = intent_source("organization-blue".to_owned(), request.source);
        assert_eq!(source.module_id, "organization-blue");

        let transactional_schema: serde_json::Value =
            serde_json::from_str(transactional::CREATE_ORGANIZATION_INVITATION_REQUEST_SCHEMA_JSON)
                .expect("transactional request schema");
        assert!(
            transactional_schema["properties"]["source"]["properties"]
                .get("plugin_id")
                .is_none()
        );

        let receipt_request = delivery::ObserveReceiptRequest {
            attempt_id: "attempt".to_owned(),
            delivery_id: "delivery".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            kind: delivery::ObserveReceiptRequestKind::Delivered,
            observation_id: "observation".to_owned(),
            observed_at: "2026-08-30T00:00:00Z".to_owned(),
            remote_id: "remote".to_owned(),
            run_id: "run".to_owned(),
        };
        let receipt = receipt_observation(
            "email-provider-blue".to_owned(),
            &receipt_request,
            ReceiptKind::Delivered,
            Utc::now(),
        );
        assert_eq!(receipt.source, "email-provider-blue");
        let delivery_schema: serde_json::Value =
            serde_json::from_str(delivery::OBSERVE_RECEIPT_REQUEST_SCHEMA_JSON)
                .expect("receipt request schema");
        assert!(delivery_schema["properties"].get("source").is_none());
    }

    #[test]
    fn observation_authorities_are_disjoint_per_operation() {
        let plugin = unprepared_plugin();
        assert!(matches!(
            futures::executor::block_on(plugin.dispatch_due(
                caller_context("email-provider-blue"),
                delivery::DispatchDueRequest {},
            )),
            Err(PluginError::Domain(
                delivery::DispatchDueError::Unauthorized
            ))
        ));

        let request = delivery::ObserveReceiptRequest {
            attempt_id: "attempt".to_owned(),
            delivery_id: "delivery".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            kind: delivery::ObserveReceiptRequestKind::Delivered,
            observation_id: "observation".to_owned(),
            observed_at: "2026-08-30T00:00:00Z".to_owned(),
            remote_id: "remote".to_owned(),
            run_id: "run".to_owned(),
        };
        assert!(matches!(
            futures::executor::block_on(
                plugin.observe_receipt(caller_context("notification-worker-blue"), request,)
            ),
            Err(PluginError::Domain(
                delivery::ObserveReceiptError::Unauthorized
            ))
        ));

        let lifecycle = transactional::ObserveInvitationLifecycleRequest {
            invitation_id: "invite".to_owned(),
            lifecycle: transactional::ObserveInvitationLifecycleRequestLifecycle::Revoked,
            observation_id: "observation".to_owned(),
            observed_at: "2026-08-30T00:00:00Z".to_owned(),
            organization_id: "organization".to_owned(),
        };
        assert!(matches!(
            futures::executor::block_on(plugin.observe_invitation_lifecycle(
                caller_context("notification-worker-blue"),
                lifecycle,
            )),
            Err(PluginError::Domain(
                transactional::ObserveInvitationLifecycleError::Unauthorized
            ))
        ));
    }

    #[test]
    fn native_typed_requests_revalidate_every_bound_before_state_or_dependencies() {
        let now = parse_time("2026-08-30T00:00:00Z").expect("fixed validation time");
        for request in invalid_create_requests() {
            assert!(!valid_create_request(&request, now));
            assert!(matches!(
                futures::executor::block_on(
                    unprepared_plugin().create_organization_invitation(
                        caller_context("organization-blue"),
                        request,
                    )
                ),
                Err(PluginError::Domain(
                    transactional::CreateOrganizationInvitationError::InvalidIntent
                ))
            ));
        }

        let mut invalid_access_request = generated_access_request();
        invalid_access_request.idempotency_key = "caller-selected".to_owned();
        assert!(!valid_access_request_notification_request(
            &invalid_access_request,
            now
        ));
        assert!(matches!(
            futures::executor::block_on(unprepared_plugin().create_access_request_notification(
                caller_context("organization-blue"),
                invalid_access_request,
            )),
            Err(PluginError::Domain(
                transactional::CreateAccessRequestNotificationError::InvalidIntent
            ))
        ));

        let lifecycle = transactional::ObserveInvitationLifecycleRequest {
            invitation_id: "invite".to_owned(),
            lifecycle: transactional::ObserveInvitationLifecycleRequestLifecycle::Revoked,
            observation_id: "observation".to_owned(),
            observed_at: "2026-08-30T00:00:00Z".to_owned(),
            organization_id: "organization".to_owned(),
        };
        assert!(valid_lifecycle_request(&lifecycle));
        for request in [
            transactional::ObserveInvitationLifecycleRequest {
                observation_id: "x".repeat(241),
                ..lifecycle.clone()
            },
            transactional::ObserveInvitationLifecycleRequest {
                organization_id: "x".repeat(241),
                ..lifecycle.clone()
            },
            transactional::ObserveInvitationLifecycleRequest {
                invitation_id: "x".repeat(241),
                ..lifecycle.clone()
            },
            transactional::ObserveInvitationLifecycleRequest {
                observed_at: "not-a-time".to_owned(),
                ..lifecycle
            },
        ] {
            assert!(!valid_lifecycle_request(&request));
            assert!(matches!(
                futures::executor::block_on(
                    unprepared_plugin().observe_invitation_lifecycle(
                        caller_context("organization-blue"),
                        request,
                    )
                ),
                Err(PluginError::Domain(
                    transactional::ObserveInvitationLifecycleError::InvalidObservation
                ))
            ));
        }

        let receipt = delivery::ObserveReceiptRequest {
            attempt_id: "attempt".to_owned(),
            delivery_id: "delivery".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            kind: delivery::ObserveReceiptRequestKind::Delivered,
            observation_id: "observation".to_owned(),
            observed_at: "2026-08-30T00:00:00Z".to_owned(),
            remote_id: "remote".to_owned(),
            run_id: "run".to_owned(),
        };
        assert!(valid_receipt_request(&receipt));
        for request in [
            delivery::ObserveReceiptRequest {
                observation_id: "x".repeat(241),
                ..receipt.clone()
            },
            delivery::ObserveReceiptRequest {
                delivery_id: "x".repeat(161),
                ..receipt.clone()
            },
            delivery::ObserveReceiptRequest {
                attempt_id: "x".repeat(161),
                ..receipt.clone()
            },
            delivery::ObserveReceiptRequest {
                run_id: "x".repeat(161),
                ..receipt.clone()
            },
            delivery::ObserveReceiptRequest {
                observed_at: "not-a-time".to_owned(),
                ..receipt.clone()
            },
            delivery::ObserveReceiptRequest {
                remote_id: "x".repeat(321),
                ..receipt.clone()
            },
            delivery::ObserveReceiptRequest {
                digest: "sha256:not-a-digest".to_owned(),
                ..receipt
            },
        ] {
            assert!(!valid_receipt_request(&request));
            assert!(matches!(
                futures::executor::block_on(
                    unprepared_plugin()
                        .observe_receipt(caller_context("email-provider-blue"), request,)
                ),
                Err(PluginError::Domain(
                    delivery::ObserveReceiptError::InvalidReceipt
                ))
            ));
        }

        for request in [
            admin::ListDeliveriesRequest {
                cursor: None,
                limit: Some(0),
                status: None,
            },
            admin::ListDeliveriesRequest {
                cursor: None,
                limit: Some(201),
                status: None,
            },
            admin::ListDeliveriesRequest {
                cursor: Some("x".repeat(161)),
                limit: None,
                status: None,
            },
            admin::ListDeliveriesRequest {
                cursor: Some(String::new()),
                limit: None,
                status: None,
            },
        ] {
            assert!(!valid_list_request(&request));
            assert!(matches!(
                futures::executor::block_on(
                    unprepared_plugin().list_deliveries(caller_context("console-blue"), request,)
                ),
                Err(PluginError::Domain(
                    admin::ListDeliveriesError::InvalidFilter
                ))
            ));
        }

        for delivery_id in [String::new(), "x".repeat(161)] {
            assert!(!required_bounded(&delivery_id, 1, 160));
            assert!(matches!(
                futures::executor::block_on(unprepared_plugin().get_delivery(
                    caller_context("console-blue"),
                    admin::GetDeliveryRequest { delivery_id },
                )),
                Err(PluginError::Domain(admin::GetDeliveryError::InvalidRequest))
            ));
        }

        for request in [
            admin::RetryDeliveryRequest {
                delivery_id: "x".repeat(161),
                idempotency_key: "retry".to_owned(),
                revision: 1,
            },
            admin::RetryDeliveryRequest {
                delivery_id: "delivery".to_owned(),
                idempotency_key: "x".repeat(241),
                revision: 1,
            },
            admin::RetryDeliveryRequest {
                delivery_id: "delivery".to_owned(),
                idempotency_key: "retry".to_owned(),
                revision: 0,
            },
            admin::RetryDeliveryRequest {
                delivery_id: "delivery".to_owned(),
                idempotency_key: "retry".to_owned(),
                revision: MAX_SAFE_WIRE_INTEGER + 1,
            },
        ] {
            assert!(!valid_retry_request(&request));
            assert!(matches!(
                futures::executor::block_on(
                    unprepared_plugin().retry_delivery(caller_context("console-blue"), request,)
                ),
                Err(PluginError::Domain(
                    admin::RetryDeliveryError::InvalidRequest
                ))
            ));
        }

        let maximum_revision = admin::RetryDeliveryRequest {
            delivery_id: "delivery".to_owned(),
            idempotency_key: "retry".to_owned(),
            revision: MAX_SAFE_WIRE_INTEGER,
        };
        assert!(valid_retry_request(&maximum_revision));
        assert!(matches!(
            futures::executor::block_on(
                unprepared_plugin()
                    .retry_delivery(caller_context("console-blue"), maximum_revision,)
            ),
            Err(PluginError::Domain(
                admin::RetryDeliveryError::RetryNotAllowed
            ))
        ));
    }

    #[test]
    fn native_admin_outputs_reject_unbounded_or_nonportable_storage_values() {
        let now = Utc::now();
        let summary = DeliverySummary {
            id: "delivery".to_owned(),
            recipient_mask: "a***@example.test".to_owned(),
            template_id: "organization-invitation".to_owned(),
            template_version: "v1".to_owned(),
            locale: "en".to_owned(),
            status: "queued".to_owned(),
            revision: 1,
            attempt_count: 0,
            max_attempts: 4,
            redacted_preview: "Invitation".to_owned(),
            content_digest: format!("sha256:{}", "a".repeat(64)),
            correlation_id: "story".to_owned(),
            next_attempt_at: Some(now),
            final_reason: None,
            created_at: now,
            updated_at: now,
        };
        assert!(admin_delivery(summary.clone()).is_ok());
        assert!(
            admin_delivery(DeliverySummary {
                revision: MAX_SAFE_WIRE_INTEGER + 1,
                ..summary.clone()
            })
            .is_err()
        );
        assert!(
            admin_delivery(DeliverySummary {
                id: "x".repeat(161),
                ..summary.clone()
            })
            .is_err()
        );

        let attempt = AttemptRecord {
            id: "attempt".to_owned(),
            sequence: 1,
            function_run_id: "run".to_owned(),
            status: "dispatching".to_owned(),
            provider: None,
            remote_receipt_id: None,
            failure_code: None,
            failure_classification: None,
            started_at: now,
            completed_at: None,
        };
        assert!(admin_attempt(attempt.clone()).is_ok());
        assert!(
            admin_attempt(AttemptRecord {
                function_run_id: "x".repeat(161),
                ..attempt.clone()
            })
            .is_err()
        );

        let detail = DeliveryDetail {
            delivery: summary,
            attempts: vec![attempt; ADMIN_ATTEMPT_LIMIT + 1],
            receipts: Vec::new(),
            retry_requests: Vec::new(),
        };
        assert!(admin_detail(detail).is_err());

        let mapped = map_get_error(NotificationError::new(
            ErrorCode::EvidenceOverflow,
            "bounded evidence overflow fixture",
        ));
        assert!(matches!(
            mapped,
            PluginError::Domain(admin::GetDeliveryError::EvidenceOverflow)
        ));

        assert!(
            admin_retry(RetryResult {
                delivery_id: "delivery".to_owned(),
                revision: MAX_SAFE_WIRE_INTEGER + 1,
                status: "retry_scheduled".to_owned(),
                scheduled_at: now,
                idempotent_replay: false,
            })
            .is_err()
        );
    }

    #[test]
    fn native_email_response_validation_rejects_invalid_bounds_and_cross_fields() {
        let work = dispatch_work();
        let email_provider_instance = "email-provider-blue";
        let accepted = email::DispatchResponse {
            failure: None,
            observed_at: "2026-08-30T00:00:00Z".to_owned(),
            outcome: DispatchResponseOutcome::Accepted,
            provider: "email-provider-blue".to_owned(),
            remote_receipt: Some(email::DispatchResponseRemoteReceipt {
                digest: format!("sha256:{}", "a".repeat(64)),
                remote_id: "remote".to_owned(),
                source: "email-provider-blue".to_owned(),
            }),
        };
        let accepted_observation =
            dispatch_observation(&work, email_provider_instance, accepted.clone())
                .expect("bound Provider response is valid");
        assert_eq!(accepted_observation.provider, email_provider_instance);
        assert_eq!(
            accepted_observation
                .remote_receipt
                .expect("accepted receipt")
                .source,
            email_provider_instance
        );

        let temporary = email::DispatchResponse {
            failure: Some(email::DispatchResponseFailure {
                classification: "temporary_failure".to_owned(),
                code: "rate_limited".to_owned(),
                retry_after_ms: Some(1_000),
            }),
            observed_at: "2026-08-30T00:00:00Z".to_owned(),
            outcome: DispatchResponseOutcome::TemporaryFailure,
            provider: "email-provider-blue".to_owned(),
            remote_receipt: None,
        };
        assert!(dispatch_observation(&work, email_provider_instance, temporary.clone()).is_ok());

        let invalid = [
            email::DispatchResponse {
                provider: String::new(),
                ..accepted.clone()
            },
            email::DispatchResponse {
                provider: "different-provider".to_owned(),
                ..accepted.clone()
            },
            email::DispatchResponse {
                observed_at: "not-a-time".to_owned(),
                ..accepted.clone()
            },
            email::DispatchResponse {
                observed_at: format!("2026-08-30T00:00:00.{}Z", "1".repeat(50)),
                ..accepted.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    classification: "permanent_failure".to_owned(),
                    code: "should-not-exist".to_owned(),
                    retry_after_ms: None,
                }),
                ..accepted.clone()
            },
            email::DispatchResponse {
                outcome: DispatchResponseOutcome::PermanentFailure,
                remote_receipt: None,
                failure: None,
                ..accepted.clone()
            },
            email::DispatchResponse {
                outcome: DispatchResponseOutcome::DeliveryUnknown,
                remote_receipt: None,
                failure: None,
                ..accepted.clone()
            },
            email::DispatchResponse {
                remote_receipt: Some(email::DispatchResponseRemoteReceipt {
                    remote_id: String::new(),
                    ..accepted.remote_receipt.clone().expect("accepted receipt")
                }),
                ..accepted.clone()
            },
            email::DispatchResponse {
                remote_receipt: Some(email::DispatchResponseRemoteReceipt {
                    remote_id: "x".repeat(321),
                    ..accepted.remote_receipt.clone().expect("accepted receipt")
                }),
                ..accepted.clone()
            },
            email::DispatchResponse {
                remote_receipt: Some(email::DispatchResponseRemoteReceipt {
                    source: "different-provider".to_owned(),
                    ..accepted.remote_receipt.clone().expect("accepted receipt")
                }),
                ..accepted.clone()
            },
            email::DispatchResponse {
                remote_receipt: Some(email::DispatchResponseRemoteReceipt {
                    digest: "sha256:not-a-digest".to_owned(),
                    ..accepted.remote_receipt.clone().expect("accepted receipt")
                }),
                ..accepted.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    retry_after_ms: Some(-1),
                    ..temporary.failure.clone().expect("temporary failure")
                }),
                ..temporary.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    retry_after_ms: Some(86_400_001),
                    ..temporary.failure.clone().expect("temporary failure")
                }),
                ..temporary.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    code: String::new(),
                    ..temporary.failure.clone().expect("temporary failure")
                }),
                ..temporary.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    code: "x".repeat(161),
                    ..temporary.failure.clone().expect("temporary failure")
                }),
                ..temporary.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    classification: String::new(),
                    ..temporary.failure.clone().expect("temporary failure")
                }),
                ..temporary.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    classification: "x".repeat(161),
                    ..temporary.failure.clone().expect("temporary failure")
                }),
                ..temporary.clone()
            },
            email::DispatchResponse {
                failure: Some(email::DispatchResponseFailure {
                    classification: "permanent_failure".to_owned(),
                    ..temporary.failure.clone().expect("temporary failure")
                }),
                ..temporary.clone()
            },
            email::DispatchResponse {
                remote_receipt: accepted.remote_receipt,
                ..temporary
            },
        ];
        for response in invalid {
            assert!(matches!(
                dispatch_observation(&work, email_provider_instance, response),
                Err(RuntimeFailure::ProtocolViolation {
                    capability: email::CAPABILITY_ID
                })
            ));
        }
    }

    #[test]
    fn linked_factory_rejects_invalid_configuration_before_startup() {
        let driver = DeterministicDriver::new();
        let error = driver
            .run(Kernel::start_native(
                invalid_actual_plan(),
                driver.clone(),
                NativePluginRegistry::new()
                    .with_linked_factories()
                    .with_factory(EmptyFactory(SECRETS_PACKAGE_ID))
                    .with_factory(EmptyFactory(EMAIL_PACKAGE_ID))
                    .with_factory(EmptyFactory(TEMPLATE_PACKAGE_ID)),
            ))
            .expect_err("invalid Notification authority must reject startup");
        assert!(matches!(error, RuntimeFailure::InvalidResolvedPlan { .. }));
    }

    #[test]
    fn removing_notification_selection_removes_runtime_behavior() {
        let plan = AppComposition::new(
            vec![PluginInstancePlan::new("empty", EMPTY_PACKAGE_ID)],
            Vec::new(),
        )
        .resolve()
        .expect("App without Notification must resolve");
        let driver = DeterministicDriver::new();
        let app = driver
            .run(Kernel::start_native(
                plan,
                driver.clone(),
                NativePluginRegistry::new()
                    .with_linked_factories()
                    .with_factory(EmptyFactory(EMPTY_PACKAGE_ID)),
            ))
            .expect("unselected Notification Plugin must be inert");
        assert_eq!(
            driver.run(app.shutdown(Duration::from_secs(1))),
            ShutdownOutcome::Clean
        );
    }

    #[test]
    fn configuration_rejects_ambient_or_ambiguous_authority() {
        let config = NotificationConfig::new(
            "notification/database",
            "notification/snapshot-key",
            vec!["organization".to_owned()],
            vec!["notification-worker".to_owned()],
            vec!["email-provider".to_owned()],
            vec!["notification-console-http".to_owned()],
        )
        .expect("valid config");
        assert_eq!(config.schema, "notification");

        let mut duplicate_secret = config.clone();
        duplicate_secret.snapshot_key_secret = duplicate_secret.database_url_secret.clone();
        assert_eq!(
            duplicate_secret.validate(),
            Err(NotificationConfigError::InvalidSecretReference)
        );

        let mut ambient = config;
        ambient.admin_callers.clear();
        assert_eq!(
            ambient.validate(),
            Err(NotificationConfigError::InvalidCallers)
        );
    }

    #[test]
    fn removing_notification_needs_no_kernel_branch() {
        let remaining = lenso_app_plan::AppComposition::new(
            vec![lenso_app_plan::PluginInstancePlan::new(
                "organization",
                "test.organization",
            )],
            vec![],
        )
        .resolve()
        .expect("App without Notification should resolve");
        assert_eq!(remaining.plugin_instances().len(), 1);
        assert!(remaining.capability_bindings().is_empty());
    }

    #[test]
    fn unknown_dispatch_is_terminal_and_redaction_safe() {
        let work = DispatchWork {
            claim: crate::runtime::DispatchClaim {
                delivery_id: "delivery".to_owned(),
                attempt_id: "attempt".to_owned(),
                run_id: "run".to_owned(),
            },
            request: DispatchRequest {
                delivery_id: "delivery".to_owned(),
                attempt_id: "attempt".to_owned(),
                run_id: "run".to_owned(),
                idempotency_key: "attempt".to_owned(),
                recipient: email::DispatchRequestRecipient {
                    address: "member@example.com".to_owned(),
                },
                message: email::DispatchRequestMessage {
                    template_id: "organization-invitation".to_owned(),
                    template_version: "v1".to_owned(),
                    locale: "en".to_owned(),
                    subject: "secret".to_owned(),
                    text: "secret".to_owned(),
                    html: "secret".to_owned(),
                    content_digest: format!("sha256:{}", "a".repeat(64)),
                },
                correlation_id: "correlation".to_owned(),
            },
        };
        let observation =
            unknown_dispatch(&work, "email-provider-blue", Utc::now(), "runtime_failure");
        assert_eq!(observation.outcome, DispatchOutcome::DeliveryUnknown);
        assert!(observation.failure.is_some());
        assert!(!format!("{observation:?}").contains("member@example.com"));
    }

    #[test]
    fn stored_delivery_unknown_never_maps_to_a_retry_state() {
        assert_eq!(
            delivery_status("delivery_unknown").unwrap(),
            delivery::DispatchDueResponseStatus::DeliveryUnknown
        );
        assert!(crate::domain::can_transition(
            StoredDeliveryStatus::Attempting,
            StoredDeliveryStatus::DeliveryUnknown
        ));
        assert!(!crate::domain::can_transition(
            StoredDeliveryStatus::DeliveryUnknown,
            StoredDeliveryStatus::RetryScheduled
        ));
    }

    fn run_generated_fixture(outcome: FixtureOutcome) -> InvocationResult {
        let observed = Rc::new(RefCell::new(None));
        let driver = DeterministicDriver::new();
        let app = driver
            .run(Kernel::start_native(
                generated_fixture_plan(),
                driver.clone(),
                NativePluginRegistry::new()
                    .with_factory(FixtureProviderFactory { outcome })
                    .with_factory(ConsumerFactory {
                        observed: observed.clone(),
                    }),
            ))
            .expect("generated Notification fixture must start");
        let outcome = observed
            .borrow_mut()
            .take()
            .expect("generated Client consumer must observe an invocation");
        assert_eq!(
            driver.run(app.shutdown(Duration::from_secs(1))),
            ShutdownOutcome::Clean
        );
        outcome
    }

    fn generated_fixture_plan() -> ResolvedAppPlan {
        let consumer = PluginInstancePlan::new("consumer", CONSUMER_PACKAGE_ID).with_requirement(
            CapabilityRequirementPlan::one(
                transactional::CAPABILITY_ID,
                transactional::DESCRIPTOR_VERSION,
            ),
        );
        let provider = PluginInstancePlan::new("notification", FIXTURE_PROVIDER_PACKAGE_ID)
            .with_capability(CapabilityEndpointPlan::new(
                transactional::CAPABILITY_ID,
                transactional::DESCRIPTOR_VERSION,
                [
                    transactional::CREATE_ACCESS_REQUEST_NOTIFICATION_OPERATION,
                    transactional::CREATE_ORGANIZATION_INVITATION_OPERATION,
                    transactional::OBSERVE_INVITATION_LIFECYCLE_OPERATION,
                ],
            ));
        AppComposition::new(
            vec![consumer, provider],
            vec![CapabilityBinding::new(
                "consumer",
                transactional::CAPABILITY_ID,
                transactional::DESCRIPTOR_VERSION,
                "notification",
            )],
        )
        .resolve()
        .expect("generated Client/Provider Composition must resolve")
    }

    fn invalid_actual_plan() -> ResolvedAppPlan {
        let invalid = NotificationConfig {
            schema: "notification".to_owned(),
            database_url_secret: "notification/database".to_owned(),
            snapshot_key_secret: "notification/snapshot-key".to_owned(),
            transactional_callers: Vec::new(),
            dispatch_callers: vec!["worker".to_owned()],
            receipt_callers: vec!["email-provider".to_owned()],
            admin_callers: vec!["admin".to_owned()],
        };
        let notification = PluginInstancePlan::new("notification", PACKAGE_ID)
            .with_configuration(serde_json::to_string(&invalid).expect("serialize invalid config"))
            .with_requirement(CapabilityRequirementPlan::one(
                lenso_capability_secrets::CAPABILITY_ID,
                lenso_capability_secrets::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                email::CAPABILITY_ID,
                email::DESCRIPTOR_VERSION,
            ))
            .with_requirement(CapabilityRequirementPlan::one(
                notification_template::CAPABILITY_ID,
                notification_template::DESCRIPTOR_VERSION,
            ));
        let secrets = PluginInstancePlan::new("secrets", SECRETS_PACKAGE_ID).with_capability(
            CapabilityEndpointPlan::new(
                lenso_capability_secrets::CAPABILITY_ID,
                lenso_capability_secrets::DESCRIPTOR_VERSION,
                [lenso_capability_secrets::RESOLVE_OPERATION],
            ),
        );
        let email_provider = PluginInstancePlan::new("email", EMAIL_PACKAGE_ID).with_capability(
            CapabilityEndpointPlan::new(
                email::CAPABILITY_ID,
                email::DESCRIPTOR_VERSION,
                [email::DISPATCH_OPERATION],
            ),
        );
        let template_provider = PluginInstancePlan::new("templates", TEMPLATE_PACKAGE_ID)
            .with_capability(CapabilityEndpointPlan::new(
                notification_template::CAPABILITY_ID,
                notification_template::DESCRIPTOR_VERSION,
                [notification_template::RENDER_OPERATION],
            ));
        AppComposition::new(
            vec![notification, secrets, email_provider, template_provider],
            vec![
                CapabilityBinding::new(
                    "notification",
                    lenso_capability_secrets::CAPABILITY_ID,
                    lenso_capability_secrets::DESCRIPTOR_VERSION,
                    "secrets",
                ),
                CapabilityBinding::new(
                    "notification",
                    email::CAPABILITY_ID,
                    email::DESCRIPTOR_VERSION,
                    "email",
                ),
                CapabilityBinding::new(
                    "notification",
                    notification_template::CAPABILITY_ID,
                    notification_template::DESCRIPTOR_VERSION,
                    "templates",
                ),
            ],
        )
        .resolve()
        .expect("invalid configuration should pass structural Plan resolution")
    }

    fn caller_context(caller: &str) -> InvocationContext {
        InvocationContext::new(1, None, CancellationToken::new())
            .with_caller_instance(caller.to_owned())
    }

    fn unprepared_plugin() -> NotificationPlugin {
        NotificationPlugin {
            config: NotificationConfig::new(
                "notification/database",
                "notification/snapshot-key",
                vec!["organization-blue".to_owned()],
                vec!["notification-worker-blue".to_owned()],
                vec!["email-provider-blue".to_owned()],
                vec!["console-blue".to_owned()],
            )
            .expect("valid unprepared test Plugin"),
            secrets: Port::new(),
            email: Port::new(),
            templates: Port::new(),
            state: Rc::new(RefCell::new(None)),
        }
    }

    fn invalid_create_requests() -> Vec<transactional::CreateOrganizationInvitationRequest> {
        let base = generated_request();
        vec![
            transactional::CreateOrganizationInvitationRequest {
                source: transactional::CreateOrganizationInvitationRequestSource {
                    entity_type: "x".repeat(161),
                    ..base.source.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                source: transactional::CreateOrganizationInvitationRequestSource {
                    entity_id: "x".repeat(241),
                    ..base.source.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                recipient: transactional::CreateOrganizationInvitationRequestRecipient {
                    address: format!("a@{}", "x".repeat(319)),
                    ..base.recipient.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                recipient: transactional::CreateOrganizationInvitationRequestRecipient {
                    display_name: Some("x".repeat(241)),
                    ..base.recipient.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                template: transactional::CreateOrganizationInvitationRequestTemplate {
                    organization_id: "x".repeat(241),
                    ..base.template.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                template: transactional::CreateOrganizationInvitationRequestTemplate {
                    organization_name: "x".repeat(241),
                    ..base.template.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                template: transactional::CreateOrganizationInvitationRequestTemplate {
                    invitation_id: "x".repeat(241),
                    ..base.template.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                template: transactional::CreateOrganizationInvitationRequestTemplate {
                    invitation_url: format!("https://{}", "x".repeat(4_089)),
                    ..base.template.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                template: transactional::CreateOrganizationInvitationRequestTemplate {
                    inviter_display_name: Some("x".repeat(241)),
                    ..base.template.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                template: transactional::CreateOrganizationInvitationRequestTemplate {
                    role_name: Some("x".repeat(161)),
                    ..base.template.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                template: transactional::CreateOrganizationInvitationRequestTemplate {
                    expires_at: "not-a-time".to_owned(),
                    ..base.template.clone()
                },
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                idempotency_key: "x".repeat(241),
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                correlation_id: "x".repeat(241),
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                causation_id: Some("x".repeat(241)),
                ..base.clone()
            },
            transactional::CreateOrganizationInvitationRequest {
                requested_by: Some("x".repeat(241)),
                ..base
            },
        ]
    }

    fn dispatch_work() -> DispatchWork {
        DispatchWork {
            claim: crate::runtime::DispatchClaim {
                delivery_id: "delivery".to_owned(),
                attempt_id: "attempt".to_owned(),
                run_id: "run".to_owned(),
            },
            request: DispatchRequest {
                delivery_id: "delivery".to_owned(),
                attempt_id: "attempt".to_owned(),
                run_id: "run".to_owned(),
                idempotency_key: "attempt".to_owned(),
                recipient: email::DispatchRequestRecipient {
                    address: "member@example.com".to_owned(),
                },
                message: email::DispatchRequestMessage {
                    template_id: "organization-invitation".to_owned(),
                    template_version: "v1".to_owned(),
                    locale: "en".to_owned(),
                    subject: "secret".to_owned(),
                    text: "secret".to_owned(),
                    html: "secret".to_owned(),
                    content_digest: format!("sha256:{}", "a".repeat(64)),
                },
                correlation_id: "correlation".to_owned(),
            },
        }
    }

    fn generated_request() -> transactional::CreateOrganizationInvitationRequest {
        transactional::CreateOrganizationInvitationRequest {
            causation_id: Some("obs_invitation_fixture".to_owned()),
            correlation_id: "corr_notification_fixture".to_owned(),
            idempotency_key: "organization-invitation:fixture".to_owned(),
            recipient: transactional::CreateOrganizationInvitationRequestRecipient {
                address: "member@example.com".to_owned(),
                display_name: Some("Member".to_owned()),
                locale: transactional::CreateOrganizationInvitationRequestRecipientLocale::En,
            },
            requested_by: Some("usr_fixture".to_owned()),
            source: transactional::CreateOrganizationInvitationRequestSource {
                entity_id: "invite_fixture".to_owned(),
                entity_type: "organization_invitation".to_owned(),
            },
            template: transactional::CreateOrganizationInvitationRequestTemplate {
                expires_at: "2026-09-01T00:00:00Z".to_owned(),
                invitation_id: "invite_fixture".to_owned(),
                invitation_url: "https://example.test/invitations/secret".to_owned(),
                inviter_display_name: Some("Operator".to_owned()),
                organization_id: "org_fixture".to_owned(),
                organization_name: "Fixture Organization".to_owned(),
                role_name: Some("Member".to_owned()),
            },
        }
    }

    fn generated_access_request() -> transactional::CreateAccessRequestNotificationRequest {
        transactional::CreateAccessRequestNotificationRequest {
            causation_id: Some("access_request_fixture:submitted".to_owned()),
            correlation_id: "corr_access_request_fixture".to_owned(),
            event: transactional::CreateAccessRequestNotificationRequestEvent::Submitted,
            expires_at: Some("2026-09-01T00:00:00Z".to_owned()),
            idempotency_key: "access-request:ar_fixture:submitted".to_owned(),
            organization_id: "org_fixture".to_owned(),
            recipient: transactional::CreateAccessRequestNotificationRequestRecipient {
                address: "requester@example.com".to_owned(),
                display_name: Some("Requester".to_owned()),
                locale: transactional::CreateAccessRequestNotificationRequestRecipientLocale::En,
            },
            request_id: "ar_fixture".to_owned(),
            requested_by: Some("subject_fixture".to_owned()),
            role: transactional::CreateAccessRequestNotificationRequestRole {
                display_name: Some("Member".to_owned()),
                role_id: "role_member".to_owned(),
            },
            scope: transactional::CreateAccessRequestNotificationRequestScope {
                display_name: Some("Fixture Organization".to_owned()),
                id: "org_fixture".to_owned(),
                kind: "organization".to_owned(),
            },
        }
    }
}
