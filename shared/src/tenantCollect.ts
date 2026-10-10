// ============================================================================
// Collect a whole client's configurations — the bulk "collect now"
// ============================================================================
//
// One gesture re-reads every collectable router of ONE tenant through the
// same door as the device page's "Collect now" and the scheduled drift pass
// (`collectAndStore`: identity asserted, no-secrets gate, `/export terse
// show-sensitive=no` over the router's own SSH transport). It writes
// configuration SNAPSHOTS in ObliWAN and nothing to a router.
//
// The progress lives in the server process: the snapshots are durable, and
// the audit trail records the start and the end with the counts. A restart
// mid-run loses the progress view, not what was collected.

export const TENANT_COLLECT_OUTCOMES = ['created', 'unchanged', 'failed', 'skipped'] as const;
export type TenantCollectOutcome = (typeof TENANT_COLLECT_OUTCOMES)[number];

export interface TenantCollectResult {
  deviceId: number;
  deviceName: string;
  outcome: TenantCollectOutcome;
  /** created / unchanged: null. failed: the collector's error code
   *  (TIMEOUT, AUTH_FAILED, sensitive_material…). skipped: why the router was
   *  not dialled (ppp_down, health_down, circuit_open, in_flight…). */
  reason: string | null;
  /** The collector's English sentence, when it failed. */
  message: string | null;
}

export interface TenantCollectState {
  tenantId: number;
  running: boolean;
  startedAt: string;
  finishedAt: string | null;
  startedBy: number | null;
  /** Routers this run will look at (the cap applied). */
  total: number;
  /** Routers already looked at (dialled or skipped). */
  done: number;
  /** Routers beyond the per-run cap, left for a next run. */
  deferred: number;
  results: TenantCollectResult[];
}
