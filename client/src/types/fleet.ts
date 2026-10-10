// ObliWAN client — inventory DTOs.
//
// These are the shapes the client expects on the wire for the fleet routes.
// They deliberately live in the client and NOT in @obliwan/shared: `shared/`
// is a contract package, and inventing entities there would create a
// conflict on a contract file. When it is consolidated, these interfaces should move to `shared/src/inventory.ts`
// verbatim and be re-exported from here.
//
// Section 8.2 is load-bearing in every shape below: NO secret ever crosses
// this boundary. A transport exposes `hasSecret` / `hasPrivateKey` booleans,
// never the material itself, and `lastError` is the redacted message.

import type {
  DeviceBrand,
  DeviceFamily,
  DeviceRole,
  DeviceStatus,
  TransportKind,
  DiscoveryState,
  CircuitState,
  ReachabilityVerdict,
  RouterOsDeviceMode,
  DeviceHealthCheckView,
  DeviceHealthSummary,
  SiteUplinkKind,
  ObjectAccess,
} from '@obliwan/shared';

// ── Sites ───────────────────────────────────────────────────────────────────

/** Opaque to the client — the change scheduler owns the semantics.
 *  We render it, we never interpret it beyond display. */
export interface MaintenanceWindow {
  /** 0 = Sunday … 6 = Saturday, as stored by the scheduler. */
  days?: number[];
  /** 'HH:MM' local to `tz`. */
  start?: string;
  end?: string;
  tz?: string;
}

export interface Site {
  id: number;
  uuid: string;
  tenantId: number;
  /** The caller's level on this site (migration 087). Absent on a socket
   *  payload (the stores merge, so the list's value survives) and on an older server. */
  access?: ObjectAccess;
  /** God view only: the owning workspace's name (GodViewTenantTag). */
  tenantName?: string | null;
  code: string;
  name: string;
  address: string | null;
  contact: string | null;
  timezone: string;
  maintenanceWindow: MaintenanceWindow | null;
  /** The declared access link (migration 076): null = not declared, ObliWAN
   *  infers it. Absent on an older server: treat as null. */
  uplinkKind?: SiteUplinkKind | null;
  /** The last declaration ("automatic" included): when, and by which user id. */
  uplinkKindSetAt?: string | null;
  uplinkKindSetBy?: number | null;
  /** « Opérateur du lien fixe » (migration 095): null = not declared (the
   *  provider is inferred). Absent on an older server: treat as null. */
  fixedProvider?: string | null;
  createdAt: string;
  updatedAt: string;
  /** Server-side rollup when the list endpoint provides it. */
  deviceCount?: number;
  /** List endpoint, SIM_READ only: the site's SIM lines (its own and its
   *  routers', each once) — what the 4G lines page lists for `?siteId=`.
   *  Absent = not provided, never 0. */
  simCount?: number;
}

export interface SiteInput {
  code: string;
  name: string;
  address?: string | null;
  contact?: string | null;
  timezone?: string;
  maintenanceWindow?: MaintenanceWindow | null;
  uplinkKind?: SiteUplinkKind | null;
  fixedProvider?: string | null;
}

// ── Presence & reachability ─────────────────────────────────────────────────

/**
 * The client-side view of "is this box on the tunnel right now".
 *
 * `up: null` is a THIRD value: nothing has been observed yet. Folding it into
 * `false` is exactly how a green fleet turns red on a page load, so the UI
 * renders it as "unknown", never as "down".
 */
export interface DevicePresence {
  up: boolean | null;
  /** `null` = no reachability verdict has ever been recorded for this device. Rendered
   *  as UNREACHABLE ("we cannot see"), never as an outage. */
  verdict: ReachabilityVerdict | null;
  at: string | null;
  tunnelIp?: string | null;
  callerIp?: string | null;
}

// ── Devices ─────────────────────────────────────────────────────────────────

/**
 * One read of RouterOS `/system/device-mode` (7.13+).
 *
 * `null` in `Device.deviceMode` means nobody ever asked — the state of the whole
 * fleet before the first probe, and of every non-MikroTik device forever.
 * `mode: null` INSIDE the object means we asked and the menu did not answer.
 * The two must stay apart: the second one is not "ungated, therefore armable".
 *
 * `deadmanReadiness()` in `@obliwan/shared` is the only place allowed to turn
 * these three fields into a verdict — the server and this page read the same
 * function so they cannot disagree about which routers can carry a dead-man.
 */
export interface DeviceModeInfo {
  mode: RouterOsDeviceMode | null;
  schedulerAllowed: boolean | null;
  fetchAllowed: boolean | null;
  observedAt: string;
}

export interface Device {
  id: number;
  uuid: string;
  tenantId: number;
  /** The caller's level on this device (migration 087). Absent on a socket
   *  payload (the stores merge, so the list's value survives) and on an older server. */
  access?: ObjectAccess;
  /** God view only: the owning workspace's name (GodViewTenantTag). */
  tenantName?: string | null;
  siteId: number | null;
  siteName?: string | null;
  groupId: number | null;
  groupName?: string | null;
  name: string;
  brand: DeviceBrand;
  family: DeviceFamily;
  model: string | null;
  serial: string | null;
  osVersion: string | null;
  role: DeviceRole;
  concentratorId: number | null;
  concentratorName?: string | null;
  pppUsername: string | null;
  systemIdentity: string | null;
  tunnelIp: string | null;
  wanPublicIp: string | null;
  sourceIpHint: string | null;
  status: DeviceStatus;
  isManaged: boolean;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
  /** `null` until something has actually read the menu on this unit. */
  deviceMode: DeviceModeInfo | null;
  /** Learning mode (migration 089): set while ObliWAN learns this router —
   *  template pushes are refused meanwhile. Absent from an older server. */
  learning?: { since: string; byUserId: number | null } | null;
  /** Present when the list endpoint joins the last verdict. */
  presence?: DevicePresence | null;
  /** The permanent health check, compact. Present on the list only. */
  healthSummary?: DeviceHealthSummary;
}

export interface DeviceInput {
  name: string;
  brand: DeviceBrand;
  family: DeviceFamily;
  role: DeviceRole;
  siteId?: number | null;
  groupId?: number | null;
  model?: string | null;
  serial?: string | null;
  osVersion?: string | null;
  concentratorId?: number | null;
  pppUsername?: string | null;
  systemIdentity?: string | null;
  tunnelIp?: string | null;
  wanPublicIp?: string | null;
  sourceIpHint?: string | null;
  status?: DeviceStatus;
  isManaged?: boolean;
  notes?: string | null;
}

/** One channel. Ciphertext stays server-side; only its presence is reported. */
export interface DeviceTransport {
  id: number;
  deviceId: number;
  transport: TransportKind;
  enabled: boolean;
  priority: number;
  host: string | null;
  port: number | null;
  username: string | null;
  /** Section 8.2 — the vault holds the material, the UI only learns it exists. */
  hasSecret: boolean;
  hasPrivateKey: boolean;
  keyVersion: number;
  useTls: boolean;
  tlsFingerprintSha256: string | null;
  /** The certificate a handshake was refused on against the pin, recorded by
   *  the server (migration 069), and since when. Null when no refusal stands.
   *  Optional so an older server's answer still type-checks. */
  tlsPresentedSha256?: string | null;
  tlsPresentedAt?: string | null;
  params: Record<string, unknown>;
  lastOkAt: string | null;
  /** Already redacted server-side. */
  lastError: string | null;
}

export interface DeviceTransportInput {
  transport: TransportKind;
  enabled?: boolean;
  priority?: number;
  host?: string | null;
  port?: number | null;
  username?: string | null;
  /** Write-only. Sent once; no read of the devices API returns it (the one
   *  way back is the audited reveal, `secrets.api.ts`). */
  secret?: string | null;
  privateKey?: string | null;
  useTls?: boolean;
  params?: Record<string, unknown>;
}

export type ConnState = 'ok' | 'degraded' | 'down' | 'unknown';

export interface DeviceHealth {
  deviceId: number;
  transport: TransportKind;
  connState: ConnState;
  circuitState: CircuitState;
  consecutiveFailures: number;
  backoffMs: number;
  nextRetryAt: string | null;
  lastRttMs: number | null;
  lastOkAt: string | null;
  lastFailureAt: string | null;
  lastError: string | null;
  enabled: boolean;
}

/** `GET /api/devices/:id`. Every joined block is optional: the server agent
 *  may ship them incrementally, and a missing block must degrade to an honest
 *  "not available", never to a crash or to invented data. */
export interface DeviceDetail extends Device {
  transports?: DeviceTransport[];
  /** Per-transport circuit breakers — NOT the permanent check below. */
  health?: DeviceHealth[];
  /** The permanent health check, with the settings that apply to it now. */
  healthCheck?: DeviceHealthCheckView | null;
}

export interface TransportTestResult {
  transport: TransportKind;
  ok: boolean;
  rttMs?: number | null;
  /** Redacted message. */
  error?: string | null;
}

/**
 * What a successful probe taught the server about the box.
 *
 * `filled` is only ever columns that were EMPTY. `conflicts` are columns whose
 * stored value the box contradicted — never written, because overwriting them
 * would make ObliWAN rewrite its own records to match whatever answered at that
 * address, and the binding check would then pass forever.
 */
export interface LearnedFacts {
  filled: Record<string, string>;
  conflicts: Array<{ field: string; stored: string; observed: string }>;
}

export interface TestConnectionResponse {
  deviceId: number;
  results: TransportTestResult[];
  learned?: LearnedFacts | null;
  /**
   * Set when the test REACHED the box and the identity read then failed.
   *
   * Distinct from `learned: null`, which means "nothing changed". This one
   * means the fields on screen are still `—` for a reason the server knows and
   * the operator otherwise cannot: an empty identity card with no explanation,
   * on a device that just answered, is the shape of a product that is silently
   * broken. The message is already redacted by the driver layer.
   */
  learnError?: string | null;
}

// ── Why the channel failed ──────────────────────────────────────────────────

/** `refused` is the interesting one: the host sent a packet saying no, which
 *  proves it exists and is routed. `timeout` proves nothing at all. */
export type DiagnosticPortState = 'open' | 'refused' | 'reset' | 'unreachable' | 'timeout';

export interface DiagnosticPort {
  port: number;
  /** What this port means on this brand, so the operator need not know. */
  service: string;
  state: DiagnosticPortState;
  ms: number;
}

export interface DiagnosticStep {
  step: 'dns' | 'route' | 'tcp' | 'icmp' | 'traceroute';
  label: string;
  /** `unknown` means the tool was missing or refused — NOT that it found
   *  nothing. Blurring the two sends an operator to the wrong place. */
  outcome: 'ok' | 'fail' | 'unknown' | 'skipped';
  detail: string;
  ms: number | null;
}

export interface DeviceDiagnosis {
  deviceId: number;
  target: { host: string; port: number | null; transport: string };
  ports: DiagnosticPort[];
  steps: DiagnosticStep[];
  /** The synthesised sentence. This is what the operator reads first. */
  verdict: string;
  hostAnswered: boolean;
}

// ── PPP presence history ────────────────────────────────────────────────────

export interface PppSession {
  id: number;
  concentratorId: number;
  deviceId: number | null;
  deviceName?: string | null;
  pppUsername: string;
  tunnelIp: string | null;
  callerIp: string | null;
  startedAt: string;
  /** null = still open. */
  endedAt: string | null;
  durationSeconds: number | null;
  disconnectReason: string | null;
}

// ── Discovery quarantine ────────────────────────────────────────────────────

export interface Discovery {
  id: number;
  uuid: string;
  /** God view only: the bound device's workspace, else the concentrator's. */
  tenantId?: number;
  tenantName?: string | null;
  concentratorId: number;
  concentratorName?: string | null;
  pppUsername: string;
  remoteAddress: string | null;
  callerIp: string | null;
  profile: string | null;
  pppComment: string | null;
  raw: Record<string, unknown>;
  state: DiscoveryState;
  boundDeviceId: number | null;
  boundDeviceName?: string | null;
  reviewedBy: number | null;
  reviewedByName?: string | null;
  reviewedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

/**
 * Binding a discovery is a security act: it decides whose router
 * receives whose configuration.
 *
 * RECONCILED WITH THE SERVER. This used to carry `tenantId`,
 * `confirmPppUsername` and `confirmedIdentity`, none of which the server reads:
 *
 *  - the TENANT is the session's, resolved by `requireTenant`. A tenant sent in
 *    a body is a tenant the caller chose, and the whole point of the tenant-scoping work
 *    was that nothing tenant-scoped is ever taken from a request body. The bind
 *    dialog therefore states the workspace tenant instead of offering a choice
 *    the server would ignore — an ignored control is worse than no control,
 *    because the operator believes it did something.
 *  - `confirmPppUsername` / `confirmedIdentity` stay CLIENT-SIDE guard rails.
 *    They gate the submit button; they were never an authorisation, and
 *    shipping them made them look like one.
 *
 * `brand` is absent by design: the server derives it from `family`
 * (`FAMILY_BRAND`), and accepting both invites a request where the two
 * disagree and every driver lookup afterwards resolves to the wrong dialect.
 */
export interface DiscoveryBindInput {
  /** Attach to an existing device… */
  deviceId?: number;
  /** …or create one. Exactly one of the two — the server refuses both/neither. */
  device?: {
    name: string;
    family: DeviceFamily;
    role: DeviceRole;
    siteId?: number | null;
    groupId?: number | null;
  };
}

/** `pending` puts the row back in the review queue; `ignored` files it as "not
 *  ours". There is no `bound` here: binding is a different, heavier gesture. */
export interface DiscoveryStateInput {
  state: 'pending' | 'ignored';
}
