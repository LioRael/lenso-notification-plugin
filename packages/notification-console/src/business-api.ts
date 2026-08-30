import type { ConsoleClient, SurfaceOperationRequestContext } from "@lenso/console-module-api";
import contract from "./notification-business-api.v1.json";

export const NOTIFICATION_CONTRACT_DIGEST = "sha256:2408bb3ab10ae5c3eaddd237ee6f2cb3e07b44fbc5f4f70273b4265cf1d2beb2" as const;
export const NOTIFICATION_OPERATION_IDS = {
  getDelivery: "notification/http/GET:/deliveries/{id}",
  listDeliveries: "notification/http/GET:/deliveries",
  retryDelivery: "notification/http/POST:/deliveries/{id}/retry"
} as const;

export type DeliveryStatus = "queued" | "attempting" | "accepted" | "retry_scheduled" | "delivered" | "failed" | "delivery_unknown";
export interface DeliveryRecord {
  readonly id: string; readonly recipient_mask: string; readonly template_id: string; readonly template_version: string;
  readonly locale: string; readonly status: DeliveryStatus; readonly revision: number; readonly attempt_count: number;
  readonly max_attempts: number; readonly redacted_preview: string; readonly content_digest: string;
  readonly correlation_id: string; readonly next_attempt_at: string | null; readonly final_reason: string | null;
  readonly created_at: string; readonly updated_at: string; readonly retry_now_eligible: boolean;
}
export interface AttemptRecord { readonly id: string; readonly sequence: number; readonly function_run_id: string; readonly status: string; readonly provider: string | null; readonly remote_receipt_id: string | null; readonly failure_code: string | null; readonly failure_classification: string | null; readonly started_at: string; readonly completed_at: string | null; }
export interface ReceiptRecord { readonly id: string; readonly attempt_id: string; readonly kind: string; readonly source: string; readonly remote_id: string; readonly digest: string; readonly observed_at: string; }
export interface RetryRecord { readonly id: string; readonly kind: string; readonly requested_by: string | null; readonly source_revision: number; readonly decision: string; readonly reason: string | null; readonly scheduled_at: string | null; readonly created_at: string; }
export interface DeliveryDetail extends DeliveryRecord { readonly attempts: readonly AttemptRecord[]; readonly receipts: readonly ReceiptRecord[]; readonly retry_requests: readonly RetryRecord[]; readonly open_in_story_correlation_id: string; }
export interface DeliveryPage { readonly records: readonly DeliveryRecord[]; readonly next_cursor: string | null; }
export interface RetryResult { readonly delivery_id: string; readonly revision: number; readonly status: DeliveryStatus; readonly scheduled_at: string; readonly idempotent_replay: boolean; }
export interface NotificationRequestOptions { readonly deadlineUnixMs?: number; readonly idempotencyKey?: string; readonly story?: SurfaceOperationRequestContext["story"]; }

const context = (options?: NotificationRequestOptions): SurfaceOperationRequestContext => ({
  deadlineUnixMs: options?.deadlineUnixMs ?? Date.now() + 10_000,
  ...(options?.idempotencyKey ? { idempotencyKey: options.idempotencyKey } : {}),
  ...(options?.story ? { story: options.story } : {})
});

export const createNotificationBusinessApi = (client: ConsoleClient) => {
  const invoke = async <Input, Output>(operationId: string, input: Input, options?: NotificationRequestOptions): Promise<Output> => {
    const response = await client.surfaceApi.invoke<Input, Output>({
      context: client.managedServiceContext,
      contractDigest: NOTIFICATION_CONTRACT_DIGEST,
      input,
      moduleId: client.identity.moduleId,
      moduleReleaseDigest: client.identity.moduleReleaseDigest,
      operationId,
      protocol: "lenso.console-surface-gateway.v1",
      requestContext: context(options),
      uiArtifactDigest: client.identity.uiArtifactDigest
    });
    return response.output;
  };
  return {
    getDelivery: (id: string, options?: NotificationRequestOptions) => invoke<{ id: string }, DeliveryDetail>(NOTIFICATION_OPERATION_IDS.getDelivery, { id }, options),
    listDeliveries: (input: { limit?: number; cursor?: string; status?: DeliveryStatus } = {}, options?: NotificationRequestOptions) => invoke<typeof input, DeliveryPage>(NOTIFICATION_OPERATION_IDS.listDeliveries, input, options),
    retryDelivery: (id: string, revision: number, idempotencyKey: string, options?: NotificationRequestOptions) => invoke(NOTIFICATION_OPERATION_IDS.retryDelivery, { id, revision, idempotency_key: idempotencyKey }, { ...options, idempotencyKey }) as Promise<RetryResult>
  };
};

export const notificationBusinessApiContract = contract;
