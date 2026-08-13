import {
  Button,
  ConsolePage,
  DataGrid,
  DataRow,
  FilterSelect,
  InlineStatus,
  Inspector,
  KeyValueList,
  PaneHeader,
  SplitView,
  StateView,
  SurfaceRoot,
  TableHeader,
  Tabs,
  pageStyles,
  useConsoleClient,
  type SemanticTone
} from "@lenso/console-ui";
import * as stylex from "@stylexjs/stylex";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  createNotificationBusinessApi,
  type DeliveryDetail,
  type DeliveryRecord,
  type DeliveryStatus
} from "./business-api";

const READ_CAPABILITY = "notification.deliveries.read";
const RETRY_CAPABILITY = "notification.deliveries.retry";
type InspectorTab = "snapshot" | "attempts" | "receipts";

const styles = stylex.create({
  feedback: {
    color: "var(--lenso-token-toneErrorForeground, #ff8589)",
    fontFamily: 'var(--lenso-token-fontCode, "Roboto Mono", monospace)',
    fontSize: 10,
    lineHeight: "14px",
    margin: 0,
    overflowWrap: "anywhere"
  },
  filters: { flexWrap: "wrap" },
  lines: { display: "grid", gap: 6 },
  mono: { fontFamily: 'var(--lenso-token-fontCode, "Roboto Mono", monospace)', overflowWrap: "anywhere" },
  state: { backgroundColor: "var(--lenso-token-canvas, #000000)" },
  tabs: { marginBlockStart: 2 }
});

export function NotificationDeliveriesPage() {
  const client = useConsoleClient();
  const api = useMemo(() => createNotificationBusinessApi(client), [client]);
  const [status, setStatus] = useState<DeliveryStatus | "all">("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const load = useCallback(
    () => api.listDeliveries({ limit: 200, ...(status === "all" ? {} : { status }) }),
    [api, status]
  );
  const deliveries = useAsyncQuery(load);
  const records = deliveries.data?.records ?? [];
  const selected = records.find((record) => record.id === selectedId) ?? records[0] ?? null;
  const loadDetail = useCallback(
    () => selected ? api.getDelivery(selected.id) : Promise.resolve<DeliveryDetail | null>(null),
    [api, selected]
  );
  const detail = useAsyncQuery(loadDetail);
  const refresh = useCallback(() => {
    deliveries.refetch();
    detail.refetch();
  }, [deliveries.refetch, detail.refetch]);

  if (!client.capabilities.has(READ_CAPABILITY)) {
    return (
      <SurfaceRoot moduleId="lenso/notification" surfaceId="deliveries">
        <PageState title="Delivery access denied" description="This operator cannot read Notification delivery records." />
      </SurfaceRoot>
    );
  }

  return (
    <SurfaceRoot moduleId="lenso/notification" surfaceId="deliveries">
      <ConsolePage data-page="notification-deliveries-page">
        <ConsolePage.Header>
          <ConsolePage.Heading>
            <ConsolePage.Title>Deliveries</ConsolePage.Title>
            <ConsolePage.Description>
              Transactional email intent, attempt, and receipt evidence. Acceptance remains distinct from delivery.
            </ConsolePage.Description>
          </ConsolePage.Heading>
          <ConsolePage.Actions>Notification business ledger · sensitive content redacted</ConsolePage.Actions>
        </ConsolePage.Header>
        <ConsolePage.Body>
          <div {...stylex.props(pageStyles.pageFilters, styles.filters)}>
            <FilterSelect
              aria-label="Delivery status"
              icon={<span aria-hidden="true">⌄</span>}
              onChange={(event) => setStatus(event.currentTarget.value as DeliveryStatus | "all")}
              value={status}
            >
              <option value="all">Any status</option>
              <option value="queued">Queued</option>
              <option value="attempting">Attempting</option>
              <option value="accepted">Accepted</option>
              <option value="retry_scheduled">Retry scheduled</option>
              <option value="delivered">Delivered</option>
              <option value="failed">Failed</option>
              <option value="delivery_unknown">Delivery unknown</option>
            </FilterSelect>
          </div>
          {deliveries.isPending && records.length === 0 ? (
            <PageState title="Loading deliveries" description="Reading Notification records from the selected Managed Service." />
          ) : deliveries.isError ? (
            <PageState title="Deliveries could not be loaded" description={errorMessage(deliveries.error)} />
          ) : records.length === 0 ? (
            <PageState title="No deliveries" description="No transactional deliveries match this status." />
          ) : (
            <SplitView inspectorWidth={400}>
              <SplitView.Main>
                <PaneHeader meta={`${records.length} records`} title="Delivery ledger" />
                <DataGrid>
                  <TableHeader columns={["Recipient", "Template", "Updated", "Status"]} />
                  {records.map((record) => (
                    <DataRow
                      cells={[
                        `${record.template_id}@${record.template_version}`,
                        formatTimestamp(record.updated_at),
                        <InlineStatus key={`${record.id}-status`} tone={statusTone(record.status)}>{statusLabel(record.status)}</InlineStatus>
                      ]}
                      interactive
                      key={record.id}
                      onActivate={() => setSelectedId(record.id)}
                      primary={record.recipient_mask}
                      secondary={`${record.attempt_count}/${record.max_attempts} attempts`}
                      selected={selected?.id === record.id}
                    />
                  ))}
                </DataGrid>
              </SplitView.Main>
              <SplitView.Inspector>
                {detail.isPending && !detail.data ? (
                  <PageState title="Loading delivery" description="Reading attempt and receipt evidence." />
                ) : detail.isError ? (
                  <PageState title="Delivery detail unavailable" description={errorMessage(detail.error)} />
                ) : detail.data ? (
                  <DeliveryInspector
                    canRetry={client.capabilities.has(RETRY_CAPABILITY)}
                    delivery={detail.data}
                    navigate={client.navigate}
                    onRefresh={refresh}
                    retry={(id, revision, key) => api.retryDelivery(id, revision, key)}
                  />
                ) : (
                  <PageState title="No delivery selected" description="Choose a delivery to inspect its evidence." />
                )}
              </SplitView.Inspector>
            </SplitView>
          )}
        </ConsolePage.Body>
      </ConsolePage>
    </SurfaceRoot>
  );
}

function DeliveryInspector({
  canRetry,
  delivery,
  navigate,
  onRefresh,
  retry
}: {
  canRetry: boolean;
  delivery: DeliveryDetail;
  navigate: (path: string) => void;
  onRefresh: () => void;
  retry: (id: string, revision: number, key: string) => Promise<unknown>;
}) {
  const [tab, setTab] = useState<InspectorTab>("snapshot");
  const executeRetry = useCallback(
    () => retry(delivery.id, delivery.revision, `console-retry:${delivery.id}:${delivery.revision}`),
    [delivery.id, delivery.revision, retry]
  );
  const mutation = useAsyncMutation(executeRetry, onRefresh);
  const eligible = canRetry && delivery.retry_now_eligible;
  return (
    <Inspector
      status={<InlineStatus tone={statusTone(delivery.status)}>{statusLabel(delivery.status)}</InlineStatus>}
      subtitle={`${delivery.template_id}@${delivery.template_version} · ${delivery.recipient_mask}`}
      title={delivery.id}
    >
      <Tabs density="inspector" stylex={styles.tabs}>
        <Tabs.List>
          {(["snapshot", "attempts", "receipts"] as const).map((item) => (
            <Tabs.Tab key={item} onClick={() => setTab(item)} selected={tab === item}>{titleCase(item)}</Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel>
          {tab === "snapshot" ? (
            <>
              <Inspector.Section title="Rendered snapshot">
                <KeyValueList>
                  <KeyValueList.Row label="Preview" value={delivery.redacted_preview} />
                  <KeyValueList.Row label="Digest" value={delivery.content_digest} />
                  <KeyValueList.Row label="Locale" value={delivery.locale} />
                </KeyValueList>
              </Inspector.Section>
              <Inspector.Section title="Lifecycle">
                <KeyValueList>
                  <KeyValueList.Row label="Revision" value={String(delivery.revision)} />
                  <KeyValueList.Row label="Attempts" value={`${delivery.attempt_count}/${delivery.max_attempts}`} />
                  <KeyValueList.Row label="Next attempt" value={formatTimestamp(delivery.next_attempt_at)} />
                  <KeyValueList.Row label="Final reason" value={delivery.final_reason ?? "—"} />
                </KeyValueList>
              </Inspector.Section>
            </>
          ) : tab === "attempts" ? (
            <Inspector.Section title="Business attempts">
              <InspectorLines items={delivery.attempts.length === 0 ? ["No attempt has been claimed."] : delivery.attempts.map((attempt) => `#${attempt.sequence} · ${attempt.status} · ${attempt.provider ?? "provider pending"} · ${attempt.function_run_id}`)} />
            </Inspector.Section>
          ) : (
            <>
              <Inspector.Section title="Remote receipts">
                <InspectorLines items={delivery.receipts.length === 0 ? ["No authoritative receipt recorded."] : delivery.receipts.map((receipt) => `${receipt.kind} · ${receipt.source} · ${receipt.remote_id} · ${formatTimestamp(receipt.observed_at)}`)} />
              </Inspector.Section>
              <Inspector.Section title="Retry decisions">
                <InspectorLines items={delivery.retry_requests.length === 0 ? ["No retry decision recorded."] : delivery.retry_requests.map((request) => `${request.kind} · ${request.decision} · ${request.reason ?? "—"}`)} />
              </Inspector.Section>
            </>
          )}
        </Tabs.Panel>
      </Tabs>
      <Inspector.Actions>
        <Button onClick={() => navigate(`/runtime/stories?story=${encodeURIComponent(delivery.open_in_story_correlation_id)}`)} variant="secondary">Open in Story</Button>
        <Button disabled={!eligible || mutation.isPending} onClick={mutation.mutate} variant="primary">
          {mutation.isPending ? "Scheduling…" : "Retry now"}
        </Button>
        {!canRetry ? "This operator cannot retry deliveries." : !delivery.retry_now_eligible ? "Only retry-scheduled deliveries can be accelerated; terminal and unknown deliveries stay closed." : null}
        {mutation.isError ? <p {...stylex.props(styles.feedback)}>{errorMessage(mutation.error)}</p> : null}
      </Inspector.Actions>
    </Inspector>
  );
}

function InspectorLines({ items }: { items: readonly ReactNode[] }) {
  return <div {...stylex.props(styles.lines, styles.mono)}>{items.map((item, index) => <span key={index}>{item}</span>)}</div>;
}

function PageState({ title, description }: { title: string; description: ReactNode }) {
  return <StateView description={description} stylex={styles.state} title={title} />;
}

interface QueryState<T> { readonly data?: T; readonly error: unknown; readonly isError: boolean; readonly isPending: boolean; readonly refetch: () => void; }
function useAsyncQuery<T>(load: () => Promise<T>): QueryState<T> {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<Omit<QueryState<T>, "refetch">>({ error: null, isError: false, isPending: true });
  useEffect(() => {
    let active = true;
    setState((current) => ({ ...current, error: null, isError: false, isPending: true }));
    void load().then((data) => { if (active) setState({ data, error: null, isError: false, isPending: false }); }).catch((error: unknown) => { if (active) setState({ error, isError: true, isPending: false }); });
    return () => { active = false; };
  }, [load, revision]);
  const refetch = useCallback(() => setRevision((value) => value + 1), []);
  return { ...state, refetch };
}

function useAsyncMutation(execute: () => Promise<unknown>, onSuccess: () => void) {
  const [state, setState] = useState({ error: null as unknown, isError: false, isPending: false });
  const mutate = useCallback(() => {
    setState({ error: null, isError: false, isPending: true });
    void execute().then(() => { setState({ error: null, isError: false, isPending: false }); onSuccess(); }).catch((error: unknown) => setState({ error, isError: true, isPending: false }));
  }, [execute, onSuccess]);
  return { ...state, mutate };
}

function statusTone(status: DeliveryStatus): SemanticTone {
  if (status === "delivered") return "success";
  if (status === "failed" || status === "delivery_unknown") return "danger";
  if (status === "accepted" || status === "retry_scheduled") return "warning";
  return "neutral";
}
const statusLabel = (status: string) => status.split("_").map(titleCase).join(" ");
const titleCase = (value: string) => `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
const formatTimestamp = (value: string | null) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "—";
const errorMessage = (error: unknown) => error instanceof Error ? error.message : "The selected Managed Service is unavailable.";
