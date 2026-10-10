// ============================================================================
// ObliWAN — autoConfirm.service : the closed loop of a bench-prepared router
// ============================================================================
//
// A router prepared at the bench lands as a `pending` device
// (`bench/compile.service.ts`). Until now it stayed there until a human
// approved it, and nothing checked that the box had applied what it was
// given. For a batch of forty, that was forty confirmations by hand, none of
// them better informed than a click.
//
// ┌─ THE DESIGN DECISION, AND THE ONLY THING IT AUTHORISES ──────────────────┐
// │ The default — a human confirms a pending device — is overridden for THIS  │
// │ path only, by explicit design: a device that passes plan conformity at    │
// │ the config level confirms itself.                                         │
// │ The exact conditions are listed where the identity rule is documented     │
// │ (`deviceBinding.service.ts`, header box), and enforced here, in order:    │
// │  1. CANDIDATE   `pending`; latest `bench_provisionings` row compiled by a  │
// │                 station that is `approved` NOW; outcome `applied` or not  │
// │                 yet reported — a bench-reported `failed` is a human's.    │
// │  2. SERIAL      the bench READ a serial off this box: the compile's own   │
// │                 audit entry (`bench.compiled`, same transaction as the    │
// │                 provisioning row) carries it, and the device row still    │
// │                 holds that very serial. `ppp_username` and               │
// │                 `system_identity` are IMPOSED by the compiled file, so any│
// │                 box that ran it carries them; the serial is the one       │
// │                 attribute that tells the physical box apart, and a serial │
// │                 the box reported about itself afterwards (learned by      │
// │                 `assertTargetBinding`) is the box defining its own test.  │
// │                 Checked BEFORE anything is dialled.                       │
// │                 Its API channel must be TLS: a cleartext one (a file      │
// │                 compiled before api-ssl) is an anomaly, never dialled.    │
// │  3. PRESENCE    its PPP session is open on its concentrator.              │
// │  3b. CHANNEL    the check's FIRST session pins the api-ssl certificate it │
// │                 is shown when none is pinned (trust on first use), or     │
// │                 refuses one other than the pin, before any login. Every   │
// │                 later session, the assertion's included, must present     │
// │                 the pinned certificate. A pin this check wrote is         │
// │                 released when (4) contradicts or does not complete the    │
// │                 identity: the box that showed it is not shown to be this  │
// │                 device.                                                   │
// │  4. IDENTITY    `assertTargetBinding()` on a fresh connection with the    │
// │                 device's own vaulted credential, and ALL THREE of         │
// │                 ppp_username / system_identity / serial must MATCH. A     │
// │                 contradiction quarantines (the assertion's own path).     │
// │  5. MARKER      the box carries the compile's success script for THAT     │
// │                 file's tag. Its failure script is a non-conformity; its   │
// │                 absence means the file may still be running → retry.     │
// │  6. PLAN        configuration collected through `collectAndStore` (the    │
// │                 frozen export) against the desired state of the          │
// │                 SAME revision, SAME allocation, SAME box facts → the      │
// │                 planner's own `buildPlanOps` → ZERO operations, AND every │
// │                 claimed kind compared in both directions — by the diff   │
// │                 engine, or by the two stated read-backs below. A kind    │
// │                 that could not be compared completely is NOT conformity: │
// │                 it is an anomaly, and a human confirms.                   │
// │ Conformant → `confirmBenchDeviceByConformity()`: status `active` only,   │
// │ audited, `is_managed` untouched, and only if — in the SAME statement —   │
// │ the device is still pending with the identity just proved, the file     │
// │ judged is still its LATEST bench file and its station still approved.   │
// │ Anything else leaves the device `pending` and says why. NEVER on an     │
// │ empty or failed collection. Off switch: BENCH_AUTO_CONFIRM_ENABLED=false.│
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHERE THE DESIRED STATE COMES FROM, AND WHY NOT `renderRevisionForDevice`┐
// │ The fleet path (`template/render.service.ts`) renders a revision for a    │
// │ DEVICE from stored variables. A bench revision declares `computed` and    │
// │ `bench` variables, which are never stored (`RENDER_TIME_LEVELS`): that     │
// │ path refuses it for want of them. The bench's own path —                   │
// │ `renderForSite()` in 'redacted' mode — is the renderer that produced the  │
// │ file, and it is the one reused here, with:                                │
// │  - the revision `bench_provisionings.revision_id` names;                 │
// │  - the computed values `previewForSite()` returns for the COMMITTED      │
// │    allocation — the same `computedValues()` the compile read through     │
// │    `computedForSite()`, read-only (nothing is allocated here);            │
// │  - the box facts: model and RouterOS version from the device row (the     │
// │    bench wrote them there), board and Wi-Fi stack read off the box on    │
// │    the asserted session, exactly as the bench reads them;                 │
// │  - the secrets as PLACEHOLDERS — a redacted render never holds one, so a │
// │    stand-in for a computed or bench secret changes nothing in the text.  │
// │ The text then becomes an NCM document through the SAME steps            │
// │ `renderRevisionForDevice` applies to a body (`claimedKindsOf`, the        │
// │ normaliser with the device's ruleset and defaults, `restrictCoverage`,   │
// │ `NcmDocumentAuthored`) — composed from the exported pieces, because that │
// │ file exposes no "text → desired document" function of its own.          │
// │ Whether the re-render reproduces the compiled text is CHECKED, not        │
// │ assumed: its digest is compared with `redacted_sha256`, and the answer   │
// │ (true / false / unknowable) is recorded as `render_matches_compile`.     │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ HOW "BOTH DIRECTIONS" IS REACHED, AND WHERE IT IS NOT ──────────────────┐
// │ The diff engine (N3) emits `missing` only when the OBSERVED side is      │
// │ complete and `extra` only when the DESIRED side is. Left as it is, a     │
// │ bench template never gets either for most kinds — and an empty plan then │
// │ says nothing about a hand-added accept rule or a service left open.      │
// │ (g) DESIRED SIDE. The normaliser marks every kind `partial` when ONE line│
// │     of the text is not configuration. Two kinds of line are removed      │
// │     before normalising, and only these: the tail's DHCP-client release   │
// │     (the line `splitRendered` forces to the end of the file — an ACTION, │
// │     it writes nothing), and single-line `:log` / `:delay` / `:put` with  │
// │     no embedded command. Any other line the model cannot read stops the  │
// │     check (anomaly `not_comparable`): what the box holds beyond the plan │
// │     could not be compared. `interface` and `service` are partial on ANY  │
// │     text — a statement about what /export omits — and the template      │
// │     render is the whole of what the template asks of them, so the        │
// │     desired side of those two is taken as complete: anything the box     │
// │     shows for them that the plan does not is a difference.               │
// │ (h) OBSERVED SIDE. For every claimed kind but `interface` and `service`  │
// │     the export must be complete (it is, unless a line of it could not be │
// │     parsed — then anomaly). For those two, /export omits what is at its  │
// │     factory value, so `missing` is established another way:              │
// │      - SERVICES the plan names and the export omits are read off the box │
// │        (`/ip/service/print`, `/snmp/print`, on the asserted session),    │
// │        turned into records by the SAME normaliser and compared by the    │
// │        diff engine like any other record. A community the plan names and │
// │        the export omits is absent (an added object is always exported). │
// │      - INTERFACES the plan names and the export omits: if the plan gives │
// │        one anything modelled (comment, disabled, mtu, address, list,     │
// │        parent…) or creates it (bridge, vlan, l2tp…), the box would have  │
// │        exported it — absence is a difference. A physical interface the   │
// │        plan names with nothing modelled is "present at factory or       │
// │        absent", which /export cannot tell: recorded, not compared.      │
// │ Any other kind-level limitation the engine declares (weak keys, partial │
// │ order analysis, version skew) stops the check (anomaly).                │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHAT IS NOT COMPARED, EACH FOR A STATED REASON ─────────────────────────┐
// │ (a) VALUES TYPED AT THE BENCH. Never stored (a SIM PIN, an APN…), so the │
// │     desired state cannot know them. The revision is rendered once per    │
// │     bench key with that key VARIED (two stand-ins) and, when optional,   │
// │     ABSENT; every resource whose record moves with a key is excluded,    │
// │     from BOTH documents, and named with the keys that feed it. A kind   │
// │     the template claims only for some bench values is excluded whole.    │
// │ (b) THE OBLIWAN ACCESS BLOCK. Written by the compiler AFTER the template │
// │     (`accessLines()`). ONE record is set aside whole: the `obliwan`      │
// │     account. Its password is unreadable by construction, how a          │
// │     real `/export` spells its group's policy back is unobserved, and     │
// │     this check logs in with it, over the API, from the management range  │
// │     its `address` allows. Every other record the blocks write is         │
// │     COMPARED, the blocks' value standing for the template's in the       │
// │     fields they write and in no other (`withBlockEffects`); a record the │
// │     template does not write starts from its factory reading:             │
// │      - `api-ssl`: enabled, port 8729, its addresses the management range │
// │        ALONE, its certificate `obliwan-api` — the block overwrites them, │
// │        whatever the template said (`apiSslExpectedState`, shared/src/    │
// │        managementAccess.ts, the one source of those lines and of this    │
// │        expectation). The certificates themselves (`obliwan-ca`,          │
// │        `obliwan-api`) are NOT compared: the NCM does not model           │
// │        `/certificate`, (d). What stands for them is the service's        │
// │        `certificate` name here, and the fingerprint this check pins on   │
// │        its first session (3b) — the RouterOS pool pins the same way for  │
// │        a device it reaches first. A box's certificate is therefore       │
// │        trusted on first contact, by design: the first                    │
// │        session can authenticate nothing, and an on-path party answering  │
// │        it would be pinned. The plain `api` service                       │
// │        is NOT the block's: it is compared as the template left it, like  │
// │        any other record;                                                 │
// │      - `ssh`: enabled, port 22, its addresses plus every management      │
// │        prefix. The NCM reads an empty list and `0.0.0.0/0` alike as      │
// │        `any`, and the block does not: it appends to `0.0.0.0/0` (still   │
// │        everything) and writes the range alone over an empty list. So     │
// │        the template's TEXT decides (`templateSshOpensAll`): an ssh it    │
// │        opens to all EXPLICITLY must still be open; any other `any` ssh — │
// │        not written, or written with no `address=` — must be on the       │
// │        management range alone, and one open to all is a difference;     │
// │      - `/snmp`, when the compile wrote the SNMP block: enabled. The      │
// │        compile's manifest says whether it did (the block is a section of │
// │        its own); only for a file compiled before split files, which has  │
// │        none, does the setting below decide, as it resolves NOW;          │
// │      - the POLLED community, named after the community of the credential │
// │        SNMP_AUTO_TARGET_CREDENTIAL names NOW (the compile records that   │
// │        it wrote the block, not which name). The template writes it: the │
// │        block KEPT it, its addresses plus every management prefix (an     │
// │        empty list stays empty, as the block leaves it). The template     │
// │        does not: the block ADDED it, as its own `add` line reads         │
// │        (the management range, comment `obliwan:access`).                │
// │     Anything else on those records (another address, a comment, the      │
// │     community's `security`) is a difference, and so is any community    │
// │     the plan does not have — one commented `obliwan:access` included:    │
// │     that comment is anyone's to write, the template's and a hand's. A    │
// │     community's read/write access is NOT compared: the normaliser does  │
// │     not model it, (d). The management range is read as the compile      │
// │     reads it (`readManagementRange`), but NOW: a range changed since the │
// │     compile shows as differences, never as conformity, and with no valid │
// │     range a template that claims `service` is not compared (anomaly).    │
// │ (c) RECORDS THAT CARRY A SECRET PLACEHOLDER on the desired side. The      │
// │     box holds the plaintext, the desired side cannot without reading     │
// │     it. Excluded only when the box has the record under the SAME key; a │
// │     placeholder in a key, or a secret-bearing record the box does not   │
// │     show under its key, stops the check — pairing it would need the     │
// │     secret, and reporting its counterpart would print it.               │
// │ (d) SECTIONS AND PROPERTIES THE NCM DOES NOT MODEL (`/system identity`,  │
// │     `/certificate`, `/interface lte apn`, an L2TP client's               │
// │     `connect-to`…) and kinds the template does not claim — the planner   │
// │     never compares them either                                           │
// │     (N3, N5). Identity is proved by (4); the tunnel by the session      │
// │     being up on ITS concentrator (3).                                   │
// │ (e) WHAT THE PRODUCT ALREADY CALLS NOISE, on both sides alike: state,   │
// │     counters, defaults and every layer-1..3 rule of the device's ruleset │
// │     (the same `loadNormalizationRules` / `loadDefaults` for both), and   │
// │     inert moves, which `semanticDiff` never emits as findings. Layer-4   │
// │     `suppress_finding` rules are NOT applied: they decide what a drift   │
// │     SCREEN shows, they can only hide a difference, and the plan — what a │
// │     push would execute — does not apply them either.                     │
// │ (f) PHYSICAL INTERFACES the plan names with nothing modelled — (h).      │
// │ Everything excluded is written on the check row (`excluded`).            │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ A FIRST NON-CONFORMITY IS LOOKED AT TWICE ──────────────────────────────┐
// │ The file ends with the DHCP-client release that starts the operator's    │
// │ DHCP scripts, and a first contact can land while they still run. A first │
// │ automatic look that finds differences schedules ONE more look after      │
// │ `SETTLE_MS` (reason `settling`, differences shown); the second verdict   │
// │ stands. A box that reports its own failure, and "Re-check now", are     │
// │ judged at once.                                                          │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHAT IS REASONED, NOT OBSERVED ─────────────────────────────────────────┐
// │ No real box has been through this. The harness proves the logic against  │
// │ a fake RouterOS API, a fake SSH server and an export written as RouterOS │
// │ writes one (a service at its factory value is ABSENT from it). Whether a │
// │ real `/export` of a freshly prepared box normalises to an empty plan     │
// │ against its template render is the "< 3 noise findings" question,        │
// │ never measured: if it does not, the boxes come out `non_conformant` with │
// │ the differences listed and stay pending — the failure is a human         │
// │ confirmation, never a wrong one. The `/ip/service/print` and             │
// │ `/snmp/print` read-backs are unobserved on hardware too.                 │
// └──────────────────────────────────────────────────────────────────────────┘
//
// LEADERSHIP: the session-up listener and the sweep act only on the
// leader. "Re-check now" runs in the request, like "Collect now"; the row
// claim below makes every path idempotent against every other.

import crypto from 'crypto';
import type { Knex } from 'knex';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import pLimit from 'p-limit';
import {
  ANY_SELECTOR,
  API_SSL_PORT,
  API_SSL_SERVICE,
  addressAtom,
  apiSslExpectedState,
  NcmDocumentAuthored,
  type ApiSslExpectedState,
  RESOURCE_KIND_TO_COLLECTION,
  SETTINGS_KEYS,
  SOCKET_EVENTS,
  coverageOf,
  localUserKey,
  normalizeSelector,
  ROUTEROS_SERVICE_CONNECTION_PROPS,
  routerOsConfiguredServiceRows,
  routerOsServiceRowNamed,
  serviceKey,
  upgradeNcm,
  type DeviceFamily,
  type NcmDiffFinding,
  type NcmDocument,
  type NcmInterface,
  type NcmResourceKind,
  type NcmService,
  type PlanOp,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { liveAlertService } from '../liveAlert.service';
import { decrypt } from '../secretVault.service';
import { settingsService } from '../settings.service';
import {
  createRouterOsConnection,
  RouterOsFingerprintError,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import {
  collectAndStore,
  loadDefaults,
  loadNormalizationRules,
  type NormalizeContextInput,
  type NormalizeFn,
} from '../config/collect.service';
import { normalizeRouterOsExport } from '../config/normalize.service';
import { parseExport } from '../drivers/mikrotik/parse';
import { SERVICE_NAME_MAP } from '../drivers/mikrotik/quirks';
import { renderForSite, SiteRenderError, type BoxFacts } from '../template/siteRender.service';
import { claimedKindsOf, restrictCoverage } from '../template/render.service';
import { SECRET_PLACEHOLDER_RE } from '../template/variableResolver.service';
import { buildPlanOps } from '../plan/planner.service';
import { AllocationError, PPP_PASSWORD_ALPHABET, PPP_PASSWORD_LENGTH, previewForSite } from '../allocation';
import { MANAGEMENT_RANGE_KEY, benchDeclarationsOf, readManagementRange, type BenchVariableDecl } from '../bench/planning.service';
import { OBLIWAN_ACCOUNT, TAIL_MARKER } from '../bench/compile.service';
import { emitToTenantAudience } from './scopedEmit';
import { onPppSessionUp, type PppSessionUpEvent } from './pppPresence.service';
import {
  BindingAssertionError,
  confirmBenchDeviceByConformity,
  withAssertedDevice,
  type AttributeCheck,
  type BindingAssertion,
} from './deviceBinding.service';
import { getDevice } from './device.service';
import { toDeviceDto } from './dto';
import { usableCredentialTenants } from '../snmp/credential.service';

// ============================================================================
// Constants
// ============================================================================

const T = 'bench_conformity_checks';

export const AUTO_CONFIRM_METHOD = 'auto_conformity';
/** Live event on the tenant room. Not (yet) in `SOCKET_EVENTS`, which lives in
 *  `shared/` — named in the same `wan:device:*` family so it can move there. */
export const AUTO_CONFIRM_EVENT = 'wan:device:conformity';
/** The installation-wide off switch. Anything but `false` leaves the operator's
 *  decision in force; `false` disarms the listener and the sweep and refuses
 *  "Re-check now". Read at call time, so a test can flip it. */
export const AUTO_CONFIRM_ENV = 'BENCH_AUTO_CONFIRM_ENABLED';

/** The leader's correction pass, for the session-up events it missed. */
export const SWEEP_INTERVAL_MS = 3 * 60_000;
/** A session comes up while the run-after-reset file is still running (the
 *  tunnel is configured in the body, the success marker written at the end),
 *  so the first look waits a little. */
export const FIRST_CONTACT_DELAY_MS = 45_000;
/** A first automatic look that found differences looks once more after this
 *  (header, "a first non-conformity is looked at twice"). */
export const SETTLE_MS = 10 * 60_000;
/** Attempts that dialled the box (a session that is down costs none). */
export const MAX_ATTEMPTS = 8;
/** ...or this long after the first attempt, whichever comes first. */
export const GIVE_UP_AFTER_MS = 6 * 3600_000;
/** Wait after the Nth failed attempt (the last value repeats). */
export const BACKOFF_MS: readonly number[] = [60_000, 2 * 60_000, 5 * 60_000, 10 * 60_000, 20 * 60_000, 40 * 60_000, 60 * 60_000];
/** A claim older than this is presumed to belong to a dead process. */
const CLAIM_LEASE_SEC = 15 * 60;
const SWEEP_BATCH = 50;
const SWEEP_CONCURRENCY = 4;
/** Recorded differences are capped; the count is not. */
const MAX_DIFFERENCES_STORED = 200;
/** Collection failures a retry cannot change (`DriverErrorCode`). */
const FINAL_COLLECT_CODES: ReadonlySet<string> = new Set([
  'NO_TRANSPORT', 'NOT_IMPLEMENTED', 'UNSUPPORTED', 'PERMISSION_DENIED', 'TLS_PINNING_FAILED',
]);
/** The two kinds whose `missing` this file establishes itself (header, (h)). */
const READ_BACK_KINDS: ReadonlySet<NcmResourceKind> = new Set(['interface', 'service']);
/** Interface types that exist only because something ADDED them — always in
 *  an `/export` when they exist. */
const CREATED_INTERFACE_TYPES: ReadonlySet<string> = new Set(['bridge', 'vlan', 'bond', 'pppoe', 'l2tp', 'wireguard', 'gre']);

/** The compile's success / failure scripts — `assembleCompiledFile()` writes
 *  `obliwan-provision-ok-<tag>` / `obliwan-provision-failed-<tag>` (its
 *  `PROVISION_PREFIX` is private). The harness compiles a real file and checks
 *  these two names are in it, so the two spellings cannot drift silently. */
export const PROVISION_OK_SCRIPT = (tag: string): string => `obliwan-provision-ok-${tag}`;
export const PROVISION_FAILED_SCRIPT = (tag: string): string => `obliwan-provision-failed-${tag}`;
/** The ssh port the access block writes (`/ip service set $oSsh
 *  disabled=no port=22 …`; compile.service's `SSH_PORT` is private). The
 *  harness compiles a real file and checks its ssh line carries this port. */
export const ACCESS_BLOCK_SSH_PORT = 22;
// The api-ssl port, addresses and certificate the access block writes are
// not restated here: both sides read them from shared/src/managementAccess.ts
// (`apiSslAccessLines` writes them, `apiSslExpectedState` says them).
/** The community names the compile writes into a router unescaped
 *  (compile.service's private `COMMUNITY_RE`): it refuses to compile any
 *  other, so no other can be the one its SNMP block wrote. */
const BLOCK_COMMUNITY_RE = /^[A-Za-z0-9._-]{1,32}$/;
/** How the compile's manifest names the SNMP block's own section file
 *  (`<runner>-snmp.rsc`, `sectionFile()` in bench/splitFile.ts). The harness
 *  checks a real compile's manifest: present with a community, absent without. */
export const SNMP_SECTION_FILE_SUFFIX = '-snmp.rsc';

export type ConformityState = 'waiting' | 'conformant' | 'non_conformant' | 'anomaly' | 'superseded';

export type ConformityReasonCode =
  | 'session_down'
  | 'unreachable'
  | 'marker_absent'
  | 'collect_failed'
  | 'collection_empty'
  | 'settling'
  | 'conformant'
  | 'plan_not_empty'
  | 'provisioning_failed'
  | 'provisioning_replaced'
  | 'identity_mismatch'
  | 'identity_incomplete'
  | 'station_not_approved'
  | 'bench_failed'
  | 'allocation_changed'
  | 'revision_gone'
  | 'render_refused'
  | 'bench_value_unsimulable'
  | 'wifi_stack_unknown'
  | 'nothing_compared'
  | 'not_comparable'
  | 'collect_refused'
  | 'gave_up'
  | 'status_changed'
  | 'internal';

// ============================================================================
// Seams — the harness replaces them
// ============================================================================

export interface AutoConfirmDeps {
  isLeader: () => boolean;
  /** The off switch (`BENCH_AUTO_CONFIRM_ENABLED`). */
  enabled: () => boolean;
  /** `collectAndStore` — the one door (identity asserted again inside). */
  collect: (deviceId: number, tenantId: number) => Promise<{ snapshotId: string }>;
  firstContactDelayMs: number;
  settleMs: number;
  connectTimeoutMs: number;
}

const defaultDeps: AutoConfirmDeps = {
  isLeader: () => leaderElection.isLeader(),
  enabled: () => (process.env[AUTO_CONFIRM_ENV] ?? 'true').trim().toLowerCase() !== 'false',
  collect: async (deviceId, tenantId) => {
    const r = await collectAndStore(deviceId, tenantId, { source: 'ssh' });
    return { snapshotId: r.snapshot.snapshotId };
  },
  firstContactDelayMs: FIRST_CONTACT_DELAY_MS,
  settleMs: SETTLE_MS,
  connectTimeoutMs: 10_000,
};
let deps: AutoConfirmDeps = { ...defaultDeps };

export function setAutoConfirmDeps(partial: Partial<AutoConfirmDeps>): void {
  deps = { ...deps, ...partial };
}
export function resetAutoConfirmDeps(): void {
  deps = { ...defaultDeps };
}
export function autoConfirmEnabled(): boolean {
  return deps.enabled();
}

// ============================================================================
// Shapes
// ============================================================================

export interface ConformityDifference {
  /** The plan op that would have been needed (`create`, `update`, `delete`,
   *  `move`, `blocked`…), or `provisioning` for the box's own failure marker. */
  op: string;
  resource: string;
  semKey: string;
  fields: string[];
  /** Field values, masked where the field speaks of a secret. */
  values: Array<{ field: string; intent: string; actual: string }>;
  reason: string;
}

export interface ConformityExcluded {
  /** The access and SNMP blocks' records, (b). Without `fields`: set aside
   *  whole (the `obliwan` account only). With `fields`: a record the blocks
   *  write, compared like any other except that these fields carry the
   *  blocks' value, not the template's (for one the template does not write,
   *  the rest is its factory reading, or the SNMP block's own `add`). */
  accessBlock: Array<{ resource: string; semKey: string; fields?: string[] }>;
  benchFed: Array<{ resource: string; semKey: string; benchKeys: string[] }>;
  benchFedKinds: Array<{ resource: string; benchKeys: string[] }>;
  secretBearing: Array<{ resource: string; semKey: string; secrets: string[] }>;
  unmodelledSections: string[];
  notClaimedKinds: string[];
  /** Lines of the render removed before normalising, (g): never configuration. */
  nonConfigLines: Array<{ line: number; what: string }>;
  /** Physical interfaces the plan names with nothing modelled, (f). */
  factoryInterfaces: string[];
  /** Services the export omits, compared against the box's own read, (h). */
  readOnBox: string[];
  /** The kinds whose `missing` the diff engine declines, and how it was
   *  established instead (header, (h)). Any other limitation stops the check. */
  limitations: Array<{
    resource: string;
    reason: string;
    missingCompared: boolean;
    /** `missing` was established by this file's read-back, not the engine. */
    missingReadOnBox: boolean;
    extraCompared: boolean;
    desiredCoverage: string;
    observedCoverage: string;
  }>;
}

export interface ConformityView {
  deviceId: number;
  deviceStatus: string;
  /** False when the installation switched the feature off. */
  enabled: boolean;
  /** False for a device that no bench compiled — the panel says so. */
  applicable: boolean;
  notApplicableReason: 'not_bench' | 'bench_failed' | null;
  /** False when the caller may not read configuration (CONFIG_READ): the
   *  differences then carry their kind and operation only. Set by the route. */
  configDetail: boolean;
  provisioning: {
    id: string; tag: string; outcome: string; compiledAt: string; revisionId: string | null;
    stationId: number; stationApproved: boolean;
  } | null;
  sessionUp: boolean;
  /** null = no check row yet: never contacted since the compile. */
  state: ConformityState | null;
  reasonCode: string | null;
  reason: string | null;
  attempts: number;
  firstAttemptAt: string | null;
  lastAttemptAt: string | null;
  /** When the next attempt is due — null while `waitingForTunnel`: no
   *  attempt is made then, whatever the stored backoff says. */
  nextAttemptAt: string | null;
  /**
   * The check is still to be decided and the box's PPP session is DOWN. Every
   * trigger needs the tunnel: the sweep only takes devices whose session
   * is open, a scheduled attempt with the session down stops at step 3 without
   * consuming an attempt, and the session-up event brings the next attempt to
   * `firstContactDelayMs` after the tunnel returns. So the honest next step is
   * "when the tunnel is back", not the stored `next_attempt_at` — which, once
   * passed, read as "next attempt" at a date already gone.
   */
  waitingForTunnel: boolean;
  lastError: string | null;
  confirmedAt: string | null;
  decidedAt: string | null;
  method: string | null;
  snapshotId: string | null;
  renderMatchesCompile: boolean | null;
  differenceCount: number | null;
  differences: ConformityDifference[];
  excluded: ConformityExcluded | null;
  planSummary: Record<string, unknown> | null;
  maxAttempts: number;
}

/** A step that could not reach a verdict. `retry` is transient; `anomaly`
 *  needs a human. */
class CheckStop extends Error {
  constructor(
    readonly kind: 'retry' | 'anomaly' | 'not_contacted' | 'superseded',
    readonly code: ConformityReasonCode,
    message: string,
  ) {
    super(message);
    this.name = 'CheckStop';
  }
}

interface CheckRow {
  id: string;
  tenant_id: number;
  device_id: number;
  provisioning_id: string;
  state: ConformityState;
  reason_code: string | null;
  reason: string | null;
  attempts: number;
  first_attempt_at: Date | null;
  last_attempt_at: Date | null;
  next_attempt_at: Date | null;
  claim_token: string | null;
  claimed_at: Date | null;
  last_error: string | null;
  revision_id: string | null;
  snapshot_id: string | null;
  observed_ncm_hash: string | null;
  render_matches_compile: boolean | null;
  difference_count: number | null;
  differences: unknown;
  excluded: unknown;
  plan_summary: unknown;
  method: string | null;
  confirmed_at: Date | null;
  decided_at: Date | null;
}

interface DeviceFacts {
  id: number;
  tenant_id: number;
  site_id: number | null;
  group_id: number | null;
  name: string;
  brand: string;
  family: DeviceFamily | null;
  status: string;
  model: string | null;
  os_version: string | null;
  serial: string | null;
  system_identity: string | null;
  ppp_username: string | null;
  concentrator_id: number | null;
  tunnel_ip: string | null;
}

interface ProvisioningFacts {
  id: string;
  tenant_id: number;
  site_id: number;
  device_id: number;
  station_id: number;
  revision_id: string | null;
  tag: string;
  redacted_sha256: string;
  outcome: string;
  compiled_at: Date;
  station_status: string | null;
  /** The compile's manifest of split files (`bench_provisionings.files`):
   *  name, role, digest, size. null for a file compiled before split files. */
  files: unknown;
}

// ============================================================================
// Reads
// ============================================================================

async function loadDeviceFacts(tenantId: number, deviceId: number): Promise<DeviceFacts | null> {
  const row = (await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first(
      'id', 'tenant_id', 'site_id', 'group_id', 'name', 'brand', 'family', 'status', 'model', 'os_version',
      'serial', 'system_identity', 'ppp_username', 'concentrator_id',
      db.raw('host(tunnel_ip) as tunnel_ip'),
    )) as DeviceFacts | undefined;
  return row
    ? {
      ...row,
      id: Number(row.id),
      tenant_id: Number(row.tenant_id),
      group_id: row.group_id === null || row.group_id === undefined ? null : Number(row.group_id),
    }
    : null;
}

/** The device's LATEST compile — a re-prepared box is judged on its newest
 *  file, and an older file's check row stays as history. */
async function loadLatestProvisioning(tenantId: number, deviceId: number): Promise<ProvisioningFacts | null> {
  const row = (await db('bench_provisionings as b')
    .leftJoin('bench_stations as s', 's.id', 'b.station_id')
    .where({ 'b.device_id': deviceId, 'b.tenant_id': tenantId })
    .orderBy('b.compiled_at', 'desc')
    .orderBy('b.id', 'desc')
    .first(
      'b.id as id', 'b.tenant_id as tenant_id', 'b.site_id as site_id', 'b.device_id as device_id',
      'b.station_id as station_id', 'b.revision_id as revision_id', 'b.tag as tag',
      'b.redacted_sha256 as redacted_sha256', 'b.outcome as outcome', 'b.compiled_at as compiled_at',
      'b.files as files', 's.status as station_status',
    )) as ProvisioningFacts | undefined;
  if (!row) return null;
  return {
    ...row,
    id: String(row.id),
    revision_id: row.revision_id === null ? null : String(row.revision_id),
    station_id: Number(row.station_id),
    tenant_id: Number(row.tenant_id),
    device_id: Number(row.device_id),
  };
}

async function loadRow(provisioningId: string): Promise<CheckRow | null> {
  const row = (await db(T).where({ provisioning_id: provisioningId }).first()) as CheckRow | undefined;
  return row ? { ...row, id: String(row.id), provisioning_id: String(row.provisioning_id) } : null;
}

/** A device whose PPP session is down is never dialled. */
async function isSessionUp(d: DeviceFacts): Promise<boolean> {
  if (!d.ppp_username || d.concentrator_id === null) return false;
  const open = await db('ppp_sessions')
    .where({ concentrator_id: d.concentrator_id, ppp_username: d.ppp_username })
    .whereNull('ended_at')
    .first('id');
  return Boolean(open);
}

/**
 * What the bench READ off the box as its serial, for THIS file: the
 * `bench.compiled` audit entry the compile appends in the same transaction as
 * the `bench_provisionings` row, under the station's own actor id. The ledger
 * is append-only and hash-chained (migration 019), which is why it is the
 * source and not the device row: `devices.serial` is filled afterwards by
 * `assertTargetBinding`'s learning when the bench left it blank — i.e. by the
 * box itself. `found: false` = no such entry (never true for a compile of
 * this build); `serial: null` = the bench's routerboard read failed.
 */
async function loadBenchRecordedSerial(prov: ProvisioningFacts): Promise<{ found: boolean; serial: string | null }> {
  const row = (await db('audit_log')
    .where({
      tenant_id: prov.tenant_id,
      action: 'bench.compiled',
      entity_type: 'device',
      entity_id: String(prov.device_id),
      actor_id: `bench-station:${prov.station_id}`,
    })
    .whereRaw("after->>'tag' = ?", [prov.tag])
    .orderBy('id', 'desc')
    .first(db.raw("after->>'boxSerial' as serial"))) as { serial: string | null } | undefined;
  if (!row) return { found: false, serial: null };
  return { found: true, serial: row.serial ?? null };
}

/** What the compile's SNMP block did, as far as it can be known now (file
 *  header, exclusion (b)). */
export interface SnmpBlockFacts {
  /** The compile wrote the SNMP block, which ends `/snmp set enabled=yes`
   *  in every branch. */
  ran: boolean;
  /** semKey of the community that block added or kept, or null (block not
   *  written, or no v1/v2c credential resolves now). It holds the
   *  community's NAME, a secret: never logged, stored or shown unmasked. */
  communityKey: string | null;
}

/** What `snmpBlockFacts` read, with the community's plaintext name: kept in
 *  `judge`/`compare` memory to rebuild the block's `add` line, NEVER logged,
 *  stored or shown (everything that leaves goes through `maskCommunity`). */
interface SnmpBlockRead extends SnmpBlockFacts {
  communityName: string | null;
}

/** The community of the v1/v2c credential SNMP_AUTO_TARGET_CREDENTIAL names
 *  for this device NOW, as compile.service reads it (same setting, same
 *  credential rules, the same name pattern: the compile refuses any other);
 *  null when none resolves. */
async function polledCommunity(device: DeviceFacts): Promise<string | null> {
  const resolved = await settingsService.resolveForDevice(device.tenant_id, device.id, device.group_id);
  const id = Number(resolved[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL]?.value ?? 0);
  if (!Number.isSafeInteger(id) || id <= 0) return null;
  const cred = (await db('snmp_credentials')
    .where({ id })
    .whereIn('tenant_id', usableCredentialTenants(device.tenant_id))
    .first('version', 'community_enc')) as { version: string; community_enc: string | null } | undefined;
  if (!cred || (cred.version !== 'v1' && cred.version !== 'v2c') || !cred.community_enc) return null;
  let community: string;
  try {
    community = decrypt(cred.community_enc);
  } catch (err) {
    // Unreadable: no community is recognised as the block's, so a widened
    // one shows as a difference — a human confirms, never a wrong one.
    logger.warn({ deviceId: device.id, credentialId: id, err: err instanceof Error ? err.name : 'error' },
      'auto-confirm: the polled SNMP credential could not be decrypted');
    return null;
  }
  return BLOCK_COMMUNITY_RE.test(community) ? community : null;
}

/** Whether the compile wrote the SNMP block. When the compile left a
 *  manifest, the manifest alone says so (the block is a section file of its
 *  own): no comment on the box, which anyone can write, overrides it. A file
 *  compiled before split files has none, and the setting as it resolves now
 *  decides, as it did before. The community is the setting's as it resolves
 *  now: the compile does not record which name it wrote. */
async function snmpBlockFacts(device: DeviceFacts, prov: ProvisioningFacts): Promise<SnmpBlockRead> {
  const community = await polledCommunity(device);
  const ran = Array.isArray(prov.files)
    ? (prov.files as Array<{ name?: unknown } | null>).some(
      (f) => typeof f?.name === 'string' && f.name.endsWith(SNMP_SECTION_FILE_SUFFIX))
    : community !== null;
  const recognised = ran && community !== null;
  return {
    ran,
    communityKey: recognised ? serviceKey('other', `snmp-community:${community}`) : null,
    communityName: recognised ? community : null,
  };
}

// ============================================================================
// Pure helpers — exported for the harness
// ============================================================================

/** Stable JSON: keys sorted at every level, so two equal records compare equal
 *  whatever order a builder assigned their fields in. */
export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableJson(obj[k])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

type AnyRecord = { semKey: string; kind: NcmResourceKind; managedBy?: string; managedSlug?: string | null };

function recordsOf(doc: NcmDocument): AnyRecord[] {
  const out: AnyRecord[] = [];
  for (const [kind, collection] of Object.entries(RESOURCE_KIND_TO_COLLECTION) as Array<[NcmResourceKind, string]>) {
    const list = (doc.resources as unknown as Record<string, AnyRecord[] | undefined>)[collection] ?? [];
    for (const r of list) out.push({ ...r, kind });
  }
  return out;
}

function recordMap(doc: NcmDocument): Map<string, { kind: NcmResourceKind; json: string }> {
  const m = new Map<string, { kind: NcmResourceKind; json: string }>();
  for (const r of recordsOf(doc)) m.set(r.semKey, { kind: r.kind, json: stableJson(r) });
  return m;
}

function listOf<R>(doc: NcmDocument, kind: NcmResourceKind): R[] {
  return ((doc.resources as unknown as Record<string, R[] | undefined>)[RESOURCE_KIND_TO_COLLECTION[kind]] ?? []);
}

function withList<R>(doc: NcmDocument, kind: NcmResourceKind, list: R[]): NcmDocument {
  return {
    ...doc,
    resources: { ...(doc.resources as unknown as Record<string, unknown>), [RESOURCE_KIND_TO_COLLECTION[kind]]: list } as unknown as NcmDocument['resources'],
  };
}

/** The same document without the records whose semKey is in `drop`. Order is
 *  kept: removing a record from an ordered chain on BOTH sides leaves the
 *  relative order of the others untouched. */
export function withoutRecords(doc: NcmDocument, drop: ReadonlySet<string>): NcmDocument {
  if (drop.size === 0) return doc;
  const resources = { ...(doc.resources as unknown as Record<string, unknown>) };
  for (const collection of Object.values(RESOURCE_KIND_TO_COLLECTION)) {
    const list = resources[collection];
    if (Array.isArray(list)) {
      resources[collection] = (list as AnyRecord[]).filter((r) => !drop.has(r.semKey));
    }
  }
  return { ...doc, resources: resources as unknown as NcmDocument['resources'] };
}

/**
 * The one record the ObliWAN access block writes that is set aside WHOLE
 * (file header, exclusion (b)): the `obliwan` account. Every other record
 * the blocks write — `api-ssl`, `ssh`, `/snmp`, the polled community, added
 * or kept — is compared, through `withBlockEffects`. A record's comment
 * (`obliwan:access`) excuses nothing: the template, or a hand, can write it
 * on any record of any kind.
 */
export function accessBlockKeys(): Map<string, NcmResourceKind> {
  return new Map<string, NcmResourceKind>([[localUserKey(OBLIWAN_ACCOUNT), 'localUser']]);
}

/** A record the blocks write, and the fields they write on it. */
export interface BlockAdjusted {
  resource: NcmResourceKind;
  semKey: string;
  fields: string[];
  /** The template does not write this record: the desired one is the
   *  blocks' alone (a factory reading with their fields, or the SNMP
   *  block's own `add`). Not counted as something the template asked. */
  injected: boolean;
}

/** The records `BlockEffectsInput.factory` builds when the template does not
 *  write them: `ssh`, `api-ssl` and `/snmp` at their factory reading, and the
 *  polled `community` as the SNMP block's `add` line writes it. */
export type BlockFactoryRecord = 'ssh' | 'api-ssl' | 'snmp' | 'community';

export interface BlockEffectsInput {
  /** The management prefixes as the normaliser spells a selector atom
   *  (`managementAtoms`). Never empty: the caller stops the check first. */
  mgmtAtoms: ReadonlySet<string>;
  snmp: SnmpBlockFacts;
  /** The template's TEXT opens ssh to all explicitly (`templateSshOpensAll`):
   *  the only `any` ssh the access block leaves open. */
  sshOpensAll: boolean;
  /** What the access block leaves on api-ssl (`apiSslExpectedState` of the
   *  management range): its state, port and certificate are read from here;
   *  its addresses from `mgmtAtoms`, the same range as the normaliser spells
   *  it. */
  apiSsl: ApiSslExpectedState;
  /** The normaliser's reading, with the device's own context, of
   *  `/ip service set ssh disabled=no`, `/ip service set api-ssl disabled=no`,
   *  `/snmp set enabled=no`, or of the SNMP block's `/snmp community add` of
   *  the polled community. Asked for only when the template does not write
   *  that record. */
  factory: (record: BlockFactoryRecord) => NcmService;
  /** Keys already set aside (bench-fed, secret-bearing, access block). */
  skip: ReadonlySet<string>;
}

/** `/ip service set $oSsh disabled=no port=22 address=…` (`$oSsh`: the
 *  configured ssh row, a connection entry of that name skipped).
 *  `disabled` and `enabled` are both read off RouterOS's one `disabled`
 *  property. */
const SSH_BLOCK_FIELDS = ['allowedFrom', 'disabled', 'enabled', 'port'];
/** `/ip service set $oasSvc disabled=no port=8729 address=…
 *  certificate="obliwan-api"` on the configured api-ssl row
 *  (`apiSslAccessLines`). */
const API_SSL_BLOCK_FIELDS = ['allowedFrom', 'certificate', 'disabled', 'enabled', 'port'];
/** `/snmp set enabled=yes`. */
const SNMP_BLOCK_FIELDS = ['enabled'];
/** `/snmp community set $obliwanSnmp addresses=…` (a KEPT community). */
const COMMUNITY_BLOCK_FIELDS = ['allowedFrom'];
/** `/snmp community add name=… addresses=… read-access=yes write-access=no
 *  comment="obliwan:access"` (an ADDED community): the modelled fields the
 *  line writes; the access flags are not modelled, (d). */
const COMMUNITY_ADD_FIELDS = ['allowedFrom', 'comment'];

function isAnySelector(s: readonly string[]): boolean {
  return s.includes('any');
}

/**
 * Whether the template's rendered text opens ssh to all EXPLICITLY: the last
 * `/ip service` line naming ssh that writes `address=` writes a non-empty
 * list the normaliser reads as everything (`0.0.0.0/0`, `::/0`). The access
 * block appends to such a list, which stays everything; over an EMPTY list —
 * the factory's, `address=""`, or none written — it writes the management
 * range alone. The NCM reads both as `any`, so only the text tells them
 * apart. Lines are matched as the normaliser matches them (`name=`,
 * `[ find name=… ]`, or the bare name).
 */
export function templateSshOpensAll(text: string): boolean {
  let last: string | null = null;
  for (const e of parseExport(text).entries) {
    if (e.sectionPath !== '/ip/service' || !Object.prototype.hasOwnProperty.call(e.props, 'address')) continue;
    const name = (e.props.name ?? e.find?.['name'] ?? e.positional[0] ?? '').toLowerCase();
    if (name === 'ssh') last = e.props.address;
  }
  if (last === null) return false;
  const atoms = last.split(',').map((s) => s.trim()).filter(Boolean);
  return atoms.length > 0 && isAnySelector(normalizeSelector(atoms.map((a) => addressAtom(a))));
}

/**
 * The desired document as the FILE leaves the box (file header, (b)): the
 * template's records, with what the access block writes on `api-ssl` (as
 * `i.apiSsl` states it) and `ssh` and what the SNMP block writes on `/snmp`
 * and on the polled community, in
 * those fields and in no other. A record the template does not write starts
 * from its factory reading (the community, from the block's own `add`);
 * every other record is returned as it was. The value expected is decided
 * from the template and the blocks ALONE, never from what the box shows,
 * except where `/export` omits a port at the very value the block writes.
 * Only `service` is touched, and only when the template claims it: an
 * unclaimed kind is not compared at all. The fields are listed in `adjusted`.
 */
export function withBlockEffects(
  desired: NcmDocument,
  observed: NcmDocument,
  claimed: ReadonlySet<NcmResourceKind>,
  i: BlockEffectsInput,
): { desired: NcmDocument; adjusted: BlockAdjusted[] } {
  if (!claimed.has('service')) return { desired, adjusted: [] };
  const sshKey = serviceKey('ssh', null);
  const apiSslKey = serviceKey(API_SSL_SERVICE, null);
  const snmpKey = serviceKey('snmp', null);
  const onBox = new Map(listOf<NcmService>(observed, 'service').map((r) => [r.semKey, r]));
  const adjusted: BlockAdjusted[] = [];
  // `/export` omits a port at its factory value, and the port the block
  // writes on ssh (22) and on api-ssl (8729, its default per the RouterOS
  // manual, "Services") IS that value: a port the export leaves unwritten is
  // the block's, any port it writes must be the block's.
  const portOf = (key: string, port: number): number | null => {
    const o = onBox.get(key);
    return o && o.port !== null ? port : null;
  };

  const ssh = (r: NcmService, injected: boolean): NcmService => {
    let allowedFrom: NcmService['allowedFrom'];
    if (!isAnySelector(r.allowedFrom)) {
      allowedFrom = normalizeSelector([...r.allowedFrom, ...i.mgmtAtoms]);
    } else if (!injected && i.sshOpensAll) {
      // `0.0.0.0/0` plus the prefixes is still everything.
      allowedFrom = ANY_SELECTOR;
    } else {
      // An empty list — the factory's, or the template's — becomes the
      // management range alone.
      allowedFrom = normalizeSelector([...i.mgmtAtoms]);
    }
    adjusted.push({ resource: 'service', semKey: sshKey, fields: SSH_BLOCK_FIELDS, injected });
    return { ...r, enabled: true, disabled: false, port: portOf(sshKey, ACCESS_BLOCK_SSH_PORT), allowedFrom };
  };
  // api-ssl: state, port, addresses and certificate are the block's,
  // whatever the template said; the addresses are the management range
  // ALONE (the line writes `address=`, it does not append). The plain `api`
  // record is not touched: the block never writes it.
  const apiSsl = (r: NcmService, injected: boolean): NcmService => {
    adjusted.push({ resource: 'service', semKey: apiSslKey, fields: API_SSL_BLOCK_FIELDS, injected });
    return {
      ...r, enabled: i.apiSsl.enabled, disabled: !i.apiSsl.enabled, port: portOf(apiSslKey, i.apiSsl.port),
      allowedFrom: normalizeSelector([...i.mgmtAtoms]), certificate: i.apiSsl.certificate,
    };
  };
  const snmp = (r: NcmService, injected: boolean): NcmService => {
    adjusted.push({ resource: 'service', semKey: snmpKey, fields: SNMP_BLOCK_FIELDS, injected });
    return { ...r, enabled: true };
  };
  const community = (r: NcmService): NcmService => {
    adjusted.push({ resource: 'service', semKey: r.semKey, fields: COMMUNITY_BLOCK_FIELDS, injected: false });
    // An empty list is left as it is; `0.0.0.0/0` plus the prefixes is still
    // everything. Otherwise the prefixes the list lacked are appended.
    return isAnySelector(r.allowedFrom) ? r : { ...r, allowedFrom: normalizeSelector([...r.allowedFrom, ...i.mgmtAtoms]) };
  };
  const communityKey = i.snmp.ran ? i.snmp.communityKey : null;

  const list = listOf<NcmService>(desired, 'service').map((r) => {
    if (i.skip.has(r.semKey)) return r;
    if (r.semKey === sshKey) return ssh(r, false);
    if (r.semKey === apiSslKey) return apiSsl(r, false);
    if (i.snmp.ran && r.semKey === snmpKey) return snmp(r, false);
    if (communityKey !== null && r.semKey === communityKey && isCommunity(r)) return community(r);
    return r;
  });
  const lacks = (key: string): boolean => !i.skip.has(key) && !list.some((r) => r.semKey === key);
  if (lacks(apiSslKey)) list.push(apiSsl(i.factory('api-ssl'), true));
  if (lacks(sshKey)) list.push(ssh(i.factory('ssh'), true));
  if (i.snmp.ran && lacks(snmpKey)) list.push(snmp(i.factory('snmp'), true));
  if (communityKey !== null && lacks(communityKey)) {
    const added = i.factory('community');
    adjusted.push({ resource: 'service', semKey: added.semKey, fields: COMMUNITY_ADD_FIELDS, injected: true });
    list.push(added);
  }
  return { desired: withList(desired, 'service', list), adjusted };
}

/** Keys of the secret placeholders a record carries (`__OBLIWAN_SECRET_X__`). */
export function placeholdersIn(json: string): string[] {
  const re = new RegExp(SECRET_PLACEHOLDER_RE.source, 'g');
  const out = new Set<string>();
  for (const m of json.matchAll(re)) out.add(m[0].replace(/^__OBLIWAN_SECRET_/, '').replace(/__$/, ''));
  return [...out].sort();
}

/** An SNMP community's NAME is its secret, and the normaliser puts it in the
 *  semKey and in `rawName` (`snmp-community:<name>`). Nothing of it leaves
 *  this file: every semKey, value and sentence stored or shown goes through
 *  this mask. */
export function maskCommunity(text: string): string {
  return text.replace(/(snmp-community:)[^\s"',}\]]*/gi, '$1***');
}

const SECRETISH_FIELD = /(secret|password|passwd|psk|fingerprint|community|private-?key|pin)\b/i;

function shown(field: string, value: unknown): string {
  if (SECRETISH_FIELD.test(field)) return '***';
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? null);
  if (new RegExp(SECRET_PLACEHOLDER_RE.source).test(text)) return '***';
  const masked = maskCommunity(text);
  return masked.length > 120 ? `${masked.slice(0, 117)}...` : masked;
}

/** Plan ops → the differences a human reads. No secret: the NCM holds none,
 *  secret-named fields are masked, community names too, and the planner's
 *  sentence is cut. */
export function differencesOf(ops: readonly PlanOp[], findings: readonly NcmDiffFinding[]): ConformityDifference[] {
  const bySemKey = new Map(findings.map((f) => [f.semKey, f]));
  return ops.map((op) => {
    const f = bySemKey.get(op.semKey);
    return {
      op: op.kind,
      resource: op.resource,
      semKey: maskCommunity(op.semKey),
      fields: op.fields.slice(0, 20),
      values: (f?.fieldDiffs ?? []).slice(0, 20).map((d) => ({
        field: d.field,
        intent: shown(d.field, d.intent),
        actual: shown(d.field, d.actual),
      })),
      reason: maskCommunity((op.reason ?? '').slice(0, 300)),
    };
  });
}

/** Wait before the next attempt, after `attempts` failed ones. */
export function backoffAfter(attempts: number): number {
  const i = Math.max(0, Math.min(attempts - 1, BACKOFF_MS.length - 1));
  return BACKOFF_MS[i];
}

/** All three identity attributes MATCHED — the general rule's "one match and
 *  no contradiction" is not enough to confirm without a human. */
export function identityFullyMatched(checks: readonly AttributeCheck[]): boolean {
  return (['ppp_username', 'system_identity', 'serial'] as const).every(
    (a) => checks.find((c) => c.attribute === a)?.outcome === 'match',
  );
}

/** `compareIdentity`'s own normalisation: trimmed, case-folded, blank = none. */
function idNorm(v: string | null | undefined): string | null {
  const s = v?.trim();
  return s ? s.toLowerCase() : null;
}

/**
 * Condition 2 of the header, decided before anything is dialled: why the
 * device's serial cannot carry an automatic confirmation, or null when it
 * can. `bench` is what `loadBenchRecordedSerial` found; `recorded` the
 * device row's serial now.
 */
export function benchSerialProblem(
  bench: { found: boolean; serial: string | null },
  recorded: string | null,
): string | null {
  if (!bench.found) {
    return "the bench's own record of this compile (audit entry 'bench.compiled' for this file) was not found, "
      + 'so what the bench read off the box cannot be established; a human confirms this device';
  }
  const b = idNorm(bench.serial);
  if (b === null) {
    return 'the bench recorded no serial for this box (its routerboard read failed). The PPP login and the '
      + 'system identity are written by the compiled file itself, so any box that ran the file carries them; '
      + 'the serial is the one attribute that tells the physical box apart, and one the box reported about '
      + 'itself later proves nothing. A human confirms this device';
  }
  if (idNorm(recorded) !== b) {
    return `the device's recorded serial is no longer the one the bench read (${bench.serial}): only a serial `
      + 'an approved station read off the box may carry an automatic confirmation; a human confirms this device';
  }
  return null;
}

// ── Desired text ────────────────────────────────────────────────────────────

/** The single-line release forms of the template's tail (`splitRendered`
 *  forces a release to be its last line). */
const DHCP_RELEASE_DO_RE = /^:do\s*\{\s*\/ip\s+dhcp-client\s+release(?:\s+\[\s*find[^\]{}]*\]|\s+[A-Za-z0-9_.-]+)?\s*\}\s*on-error=\{\s*\}$/;
const DHCP_RELEASE_RE = /^\/ip\s+dhcp-client\s+release(?:\s+\[\s*find[^\]{}]*\]|\s+[A-Za-z0-9_.-]+)?$/;
/** `:log`, `:delay` and `:put` with no embedded command, block or variable:
 *  a runtime effect, never a configuration one. */
const SCRIPT_NOOP_RE = /^:(?:log\s+(?:debug|info|warning|error)\b|delay\b|put\b)[^[\]{};$]*$/;

/**
 * Header, (g): the render without the lines that are not configuration and
 * that the normaliser would otherwise count as a parse gap on every kind. The
 * removed lines become blank, so line numbers stay those of the render.
 */
export function prepareDesiredText(text: string): { text: string; stripped: Array<{ line: number; what: string }> } {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  const tailAt = lines.findIndex((l) => l.trim() === TAIL_MARKER);
  const stripped: Array<{ line: number; what: string }> = [];
  const out = lines.map((raw, i) => {
    const l = raw.trim();
    if (tailAt >= 0 && i > tailAt && (DHCP_RELEASE_DO_RE.test(l) || DHCP_RELEASE_RE.test(l))) {
      stripped.push({ line: i + 1, what: 'dhcp-client release (template tail)' });
      return '';
    }
    if (SCRIPT_NOOP_RE.test(l)) {
      stripped.push({ line: i + 1, what: l.split(/\s+/)[0] });
      return '';
    }
    return raw;
  });
  return { text: out.join('\n'), stripped };
}

// ── Interfaces and services the export omits ────────────────────────────────

/** The modelled fields of an interface that differ from what a factory
 *  interface carries — any one of them makes `/export` list the interface. */
export function nonFactoryInterfaceFields(r: NcmInterface): string[] {
  const out: string[] = [];
  if (r.comment !== null && r.comment !== undefined) out.push('comment');
  if (r.disabled) out.push('disabled');
  if (r.mtu !== null && r.mtu !== undefined) out.push('mtu');
  if (r.alias !== null && r.alias !== undefined) out.push('alias');
  if (r.parent !== null && r.parent !== undefined) out.push('parent');
  if (r.addresses.length > 0) out.push('addresses');
  if (r.lists.length > 0) out.push('lists');
  if (r.zone !== null && r.zone !== undefined) out.push('zone');
  return out;
}

function isCommunity(r: NcmService): boolean {
  return r.service === 'other' && (r.rawName ?? '').toLowerCase().startsWith('snmp-community:');
}

const ROS_SERVICE_NAME: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(SERVICE_NAME_MAP).map(([ros, ncm]) => [ncm, ros]),
);

function apiBool(v: string | undefined): boolean | null {
  const s = v?.trim().toLowerCase();
  if (s === 'true' || s === 'yes') return true;
  if (s === 'false' || s === 'no') return false;
  return null;
}

/**
 * A desired `/ip/service` or `/snmp` record the export omits, as an export
 * line built from the box's own print. Only the properties the DESIRED record
 * sets are written (an unwritten port stays unwritten on both sides); the
 * state of the service and its address restriction always are. null = the
 * box's answer could not be read safely.
 */
export function serviceLineFromBox(
  r: NcmService,
  ipServices: ReadonlyArray<Record<string, string>> | null,
  snmp: Record<string, string> | null,
): { line: string | null; missing: boolean } {
  if (r.semKey === serviceKey('snmp', null)) {
    const enabled = apiBool(snmp?.enabled);
    if (!snmp || enabled === null) return { line: null, missing: false };
    let line = `/snmp set enabled=${enabled ? 'yes' : 'no'}`;
    if (r.version !== null) {
      const v = (snmp['trap-version'] ?? '').trim();
      if (!/^[123]$/.test(v)) return { line: null, missing: false };
      line += ` trap-version=${v}`;
    }
    return { line, missing: false };
  }
  const ros = (r.service === 'other' ? (r.rawName ?? '') : ROS_SERVICE_NAME[r.service] ?? '').trim().toLowerCase();
  if (!/^[a-z0-9-]{1,32}$/.test(ros) || ipServices === null) return { line: null, missing: false };
  // The CONFIGURED row: a connection entry of that name (RouterOS 7.24.5 lists
  // one per open session — this check's own api-ssl session among them) is no
  // service, and two configured rows are no reading
  // (shared/src/routerOsService.ts).
  const pick = routerOsServiceRowNamed(ipServices, ros);
  if (pick.kind === 'absent') return { line: null, missing: true };
  if (pick.kind === 'ambiguous') return { line: null, missing: false };
  const row = pick.row;
  const disabled = apiBool(row.disabled);
  if (disabled === null) return { line: null, missing: false };
  const parts = [`/ip service set ${ros} disabled=${disabled ? 'yes' : 'no'}`];
  if (r.port !== null) {
    const port = (row.port ?? '').trim();
    if (!/^\d{1,5}$/.test(port)) return { line: null, missing: false };
    parts.push(`port=${port}`);
  }
  const address = (row['available-from'] ?? row.address ?? '').trim();
  if (address !== '') {
    if (!/^[0-9A-Fa-f.:,/]+$/.test(address)) return { line: null, missing: false };
    parts.push(`address=${address}`);
  }
  if (r.certificate !== null) {
    const cert = (row.certificate ?? '').trim();
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(cert)) return { line: null, missing: false };
    parts.push(`certificate=${cert}`);
  }
  return { line: parts.join(' '), missing: false };
}

// ── Bench stand-ins ─────────────────────────────────────────────────────────

const standInAjv = new Ajv({ allErrors: false, strict: false, coerceTypes: false, useDefaults: false });
addFormats(standInAjv);
for (const keyword of ['x-obliwan-secret', 'x-obliwan-level', 'x-obliwan-label']) {
  standInAjv.addKeyword({ keyword });
}

/**
 * Two DIFFERENT values the declaration accepts, when it has two; one when it
 * has only one; none when no candidate fits. Stand-ins are never shown and
 * never reach a box: they only make a render possible so the resources a
 * bench value feeds can be found by varying it (header, exclusion (a)).
 */
export function benchStandIns(decl: BenchVariableDecl, prop: Record<string, unknown> | undefined): unknown[] {
  const p = prop ?? {};
  const candidates: unknown[] = [];
  if (Array.isArray(p.enum)) candidates.push(...(p.enum as unknown[]));
  if ('default' in p) candidates.push(p.default);
  const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  if (decl.type === 'boolean') candidates.push(true, false);
  else if (decl.type === 'integer' || decl.type === 'number') {
    const lo = num(p.minimum);
    const hi = num(p.maximum);
    for (const v of [lo, hi, lo !== null ? lo + 1 : null, 1, 2, 0, 7, 1234, 4321]) if (v !== null) candidates.push(v);
    if (decl.type === 'number') candidates.push(1.5, 2.5);
  } else {
    const min = num(p.minLength) ?? 0;
    candidates.push(
      '0000', '1234', '00000000', '12345678',
      '192.0.2.10', '198.51.100.20', '192.0.2.0/24', '198.51.100.0/24',
      'standin-a', 'standin-b', 'standina', 'standinb', 'a', 'b',
      'a'.repeat(Math.max(1, min)), 'b'.repeat(Math.max(1, min)),
      'standin-a.example', 'standin-b.example',
    );
  }
  let validate: ValidateFunction | null = null;
  try {
    validate = standInAjv.compile(p);
  } catch {
    validate = null;
  }
  const out: unknown[] = [];
  const seen = new Set<string>();
  for (const c of candidates) {
    const key = JSON.stringify(c);
    if (seen.has(key)) continue;
    seen.add(key);
    if (validate && !validate(c)) continue;
    out.push(c);
    if (out.length === 2) break;
  }
  return out;
}

function pppPasswordStandIn(): string {
  let s = '';
  for (let i = 0; i < PPP_PASSWORD_LENGTH; i++) s += PPP_PASSWORD_ALPHABET[i % PPP_PASSWORD_ALPHABET.length];
  return s;
}

// ============================================================================
// The box, on the asserted session
// ============================================================================

interface BoxReadout {
  assertion: BindingAssertion;
  board: string | null;
  wifiStack: 'wifi' | 'wireless' | null;
  okMarker: boolean;
  failedMarker: boolean;
  /** `/ip/service/print`, its CONFIGURED rows only (connection entries
   *  dropped) — null when the menu answered `!trap`. */
  ipServices: Array<Record<string, string>> | null;
  /** `/snmp/print`, first row — null when the menu answered `!trap`. */
  snmp: Record<string, string> | null;
}

async function openApiSession(deviceId: number, label: string): Promise<RouterOsConnection> {
  const t = (await db('device_transports as t')
    .join('devices as d', 'd.id', 't.device_id')
    .where({ 't.device_id': deviceId, 't.transport': 'routeros_api' })
    .first(
      't.host as host', 't.port as port', 't.username as username', 't.secret_enc as secret_enc',
      't.use_tls as use_tls', 't.tls_fingerprint_sha256 as fp', 't.enabled as enabled',
      db.raw('host(d.tunnel_ip) as tunnel_ip'),
    )) as {
      host: string | null; port: number | null; username: string | null; secret_enc: string | null;
      use_tls: boolean | null; fp: string | null; enabled: boolean; tunnel_ip: string | null;
    } | undefined;
  const host = t?.host ?? t?.tunnel_ip ?? null;
  if (!t || !t.enabled || !host || !t.username || !t.secret_enc) {
    throw new CheckStop('anomaly', 'collect_refused', 'the device has no usable RouterOS API channel');
  }
  return createRouterOsConnection({
    host,
    port: t.port ?? undefined,
    tls: t.use_tls === true,
    username: t.username,
    // Decrypted for this one call, never logged, never kept.
    password: decrypt(t.secret_enc),
    expectedFingerprint: t.fp,
    connectTimeoutMs: deps.connectTimeoutMs,
    label,
  });
}

/**
 * Step 2's channel guard, before anything is dialled: the API channel must be
 * TLS. A cleartext one is what a bench file compiled BEFORE the management
 * API moved to api-ssl left (plain api on 8728, its row without TLS): logging
 * in over it would carry the account's password in the clear across the
 * unencrypted L2TP leg, and the box could not be conformant anyway — that
 * file enabled the plain api, which is now compared as the template left it,
 * and no api-ssl. So it is an anomaly that names its cause and the way out,
 * not a generic difference on every such box. A channel that is absent or
 * disabled is left to the steps that dial, which already refuse it.
 */
async function assertTlsApiChannel(deviceId: number): Promise<void> {
  const row = (await db('device_transports')
    .where({ device_id: deviceId, transport: 'routeros_api' })
    .first('use_tls', 'port', 'enabled')) as { use_tls: boolean | null; port: number | null; enabled: boolean } | undefined;
  if (!row || !row.enabled || row.use_tls === true) return;
  throw new CheckStop('anomaly', 'collect_refused',
    `the device's RouterOS API channel is plain api (port ${row.port ?? 'default'}, no TLS), as bench files compiled before the move to api-ssl `
      + 'wrote it: the check does not log in over a cleartext API across the unencrypted L2TP link, and such a file left the plain api '
      + `enabled and no api-ssl. Prepare the box again at the bench: the new file sets up api-ssl on ${API_SSL_PORT} and the channel with it`);
}

/**
 * Step 3b — the check's FIRST session, before the identity assertion: the
 * trust-on-first-use of the api-ssl certificate (by design: ObliWAN
 * pins the fingerprint on first contact). The compile writes the channel with
 * no pin (the certificate is made on the box when the file runs), so for a
 * bench box this session is the first contact.
 *  - No pin yet: the certificate this session is shown is pinned (the
 *    RouterOS pool's own rule: `WHERE tls_fingerprint_sha256 IS NULL`), and
 *    every later session of the check — `assertTargetBinding`, the read-back,
 *    the collection's own assertion — reads the row and must present it.
 *    Returns the fingerprint THIS call wrote, so the caller can release it if
 *    the identity is then contradicted (judge). Null when another writer
 *    pinned first: the sessions that follow enforce that pin instead.
 *  - A pin already: this session must present it. Another certificate is
 *    refused at the handshake, before any login, and is an anomaly — an
 *    interception, or a certificate made again on the box: a human decides.
 * What this cannot do is authenticate the first session itself: the account
 * logs in over a channel nobody has vouched for yet, exactly as the pool's
 * first dial does. That is trust on first use, as decided, and it is said in
 * the file header.
 */
async function pinOrVerifyApiCertificate(device: DeviceFacts): Promise<string | null> {
  const row = (await db('device_transports')
    .where({ device_id: device.id, transport: 'routeros_api' })
    .first('use_tls', 'tls_fingerprint_sha256', 'enabled')) as
    { use_tls: boolean | null; tls_fingerprint_sha256: string | null; enabled: boolean } | undefined;
  // Nothing to pin on a channel without TLS (step 2 refused a cleartext one);
  // an absent or disabled channel is refused by the assertion, as before.
  if (!row || !row.enabled || row.use_tls !== true) return null;
  let conn: RouterOsConnection;
  try {
    conn = await openApiSession(device.id, `conformity-pin:${device.name}`);
  } catch (err) {
    if (err instanceof RouterOsFingerprintError) {
      throw new CheckStop('anomaly', 'collect_refused',
        'the box presented a TLS certificate other than the one pinned for this device, and the session was refused before any login: '
          + 'either the session was intercepted, or the certificate was made again on the box. A human decides; nothing was read or confirmed');
    }
    throw err;
  }
  const seen = conn.fingerprint;
  conn.close();
  if (row.tls_fingerprint_sha256 !== null) return null;
  if (!seen) throw new CheckStop('retry', 'unreachable', 'the TLS session reported no certificate fingerprint to pin');
  const n = await db('device_transports')
    .where({ device_id: device.id, transport: 'routeros_api' })
    .whereNull('tls_fingerprint_sha256')
    .update({ tls_fingerprint_sha256: seen, updated_at: db.fn.now() });
  if (n === 0) return null;
  logger.info({ deviceId: device.id, fingerprint: seen }, 'Pinned the bench box\'s api-ssl certificate on the conformity check\'s first contact');
  return seen;
}

/** Undo `pinOrVerifyApiCertificate`'s write — only that write, only while
 *  the row still holds it. */
async function releasePin(deviceId: number, fingerprint: string | null): Promise<void> {
  if (fingerprint === null) return;
  try {
    const n = await db('device_transports')
      .where({ device_id: deviceId, transport: 'routeros_api', tls_fingerprint_sha256: fingerprint })
      .update({ tls_fingerprint_sha256: null, updated_at: db.fn.now() });
    if (n > 0) logger.info({ deviceId, fingerprint }, 'Released the api-ssl pin: the box that showed it was not shown to be this device');
  } catch (err) {
    logger.warn({ err, deviceId }, 'Could not release the api-ssl pin written by this check');
  }
}

/** `!trap` = "no such menu here" — an answer, not a failure. */
async function rowsOrNull(conn: RouterOsConnection, words: string[]): Promise<Record<string, string>[] | null> {
  try {
    return await conn.query(words);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
}

/**
 * Identity first, through the one sanctioned door (`withAssertedDevice`: a
 * fresh socket, a mismatch quarantines), then — only when all three
 * attributes matched — the facts the render needs, the compile's markers and
 * the two service menus of (h), on a second fresh session opened with the
 * same vaulted credential. Read only: nothing is written to the box.
 */
async function readAssertedBox(device: DeviceFacts, tag: string): Promise<BoxReadout> {
  return withAssertedDevice(
    device.id,
    async (assertion) => {
      const empty: BoxReadout = {
        assertion, board: null, wifiStack: null, okMarker: false, failedMarker: false, ipServices: null, snmp: null,
      };
      if (!identityFullyMatched(assertion.checks)) return empty;
      const conn = await openApiSession(device.id, `conformity:${device.name}`);
      try {
        const resource = await rowsOrNull(conn, ['/system/resource/print']);
        const board = resource?.[0]?.['board-name']?.trim() || null;
        // The bench's own probe (`readBoxExtras`): `wifi` first, then `wireless`.
        let wifiStack: BoxReadout['wifiStack'] = null;
        if ((await rowsOrNull(conn, ['/interface/wifi/print', '=.proplist=name'])) !== null) wifiStack = 'wifi';
        else if ((await rowsOrNull(conn, ['/interface/wireless/print', '=.proplist=name'])) !== null) wifiStack = 'wireless';
        const scripts = (await rowsOrNull(conn, ['/system/script/print', '=.proplist=name'])) ?? [];
        const names = new Set(scripts.map((s) => (s.name ?? '').trim()));
        // `available-from` is the allowed-address list on recent RouterOS 7
        // (7.24.5), `address` before: ask for both, an unknown name is
        // simply absent from the reply. `dynamic`, `local`, `remote`: what
        // tells a CONNECTION entry — this very api-ssl session is one on
        // 7.24.5 — from the service of the same name; those rows are dropped
        // here (shared/src/routerOsService.ts).
        const servicePrint = await rowsOrNull(conn, [
          '/ip/service/print',
          `=.proplist=name,disabled,port,address,available-from,certificate,${ROUTEROS_SERVICE_CONNECTION_PROPS.join(',')}`,
        ]);
        const ipServices = servicePrint === null ? null : routerOsConfiguredServiceRows(servicePrint);
        const snmpRows = await rowsOrNull(conn, ['/snmp/print', '=.proplist=enabled,trap-version']);
        return {
          assertion,
          board,
          wifiStack,
          okMarker: names.has(PROVISION_OK_SCRIPT(tag)),
          failedMarker: names.has(PROVISION_FAILED_SCRIPT(tag)),
          ipServices,
          snmp: snmpRows?.[0] ?? null,
        };
      } finally {
        conn.close();
      }
    },
    { quarantineOnMismatch: true, connectTimeoutMs: deps.connectTimeoutMs },
  );
}

// ============================================================================
// The desired state
// ============================================================================

interface NormKit {
  family: DeviceFamily;
  rules: Awaited<ReturnType<typeof loadNormalizationRules>>;
  defaults: Map<string, string>;
}

async function normKitFor(device: DeviceFacts): Promise<NormKit> {
  const family = (device.family ?? 'mikrotik_routeros7') as DeviceFamily;
  const [rules, defaults] = await Promise.all([
    loadNormalizationRules(device.id, device.tenant_id, family),
    loadDefaults(family, device.os_version),
  ]);
  return { family, rules, defaults };
}

function ctxOf(device: DeviceFacts, kit: NormKit, via: 'ssh' | 'routeros_api', previous: NcmDocument | null): NormalizeContextInput {
  return {
    deviceId: device.id,
    tenantId: device.tenant_id,
    family: kit.family,
    // The device's version, as `renderRevisionForDevice` passes it: the
    // desired and observed documents normalised by the same ruleset.
    osVersion: device.os_version,
    rules: kit.rules,
    defaults: kit.defaults,
    via,
    // The design case 2: desired ordinals paired against the observed document.
    previous,
  };
}

interface DesiredResult {
  desired: NcmDocument;
  claimed: Set<NcmResourceKind>;
  unmodelledSections: string[];
  nonConfigLines: Array<{ line: number; what: string }>;
  benchFed: Map<string, { kind: NcmResourceKind; keys: Set<string> }>;
  benchFedKinds: Map<NcmResourceKind, Set<string>>;
  renderMatchesCompile: boolean | null;
  variants: number;
  /** `templateSshOpensAll` of the base render's text (header, (b)). */
  sshOpensAll: boolean;
}

const normalize: NormalizeFn = normalizeRouterOsExport as unknown as NormalizeFn;

function textToDesired(
  text: string,
  sectionSeverity: unknown,
  device: DeviceFacts,
  kit: NormKit,
  previous: NcmDocument,
): { doc: NcmDocument; claims: ReturnType<typeof claimedKindsOf> } {
  const claims = claimedKindsOf(text, sectionSeverity);
  const out = normalize(text, ctxOf(device, kit, 'ssh', previous));
  const doc = NcmDocumentAuthored.parse({
    ...out.ncm,
    coverage: restrictCoverage(out.ncm.coverage, claims.kinds),
  }) as NcmDocument;
  return { doc, claims };
}

async function desiredForBench(
  device: DeviceFacts,
  prov: ProvisioningFacts,
  box: BoxReadout,
  observed: NcmDocument,
  kit: NormKit,
): Promise<DesiredResult> {
  if (prov.revision_id === null) {
    throw new CheckStop('anomaly', 'revision_gone', 'the template revision this box was compiled from no longer exists');
  }
  const rev = (await db('template_revisions')
    .where({ id: prov.revision_id })
    .first('var_schema', 'section_severity')) as { var_schema: unknown; section_severity: unknown } | undefined;
  if (!rev) throw new CheckStop('anomaly', 'revision_gone', `template revision #${prov.revision_id} no longer exists`);
  if (box.wifiStack === null) {
    throw new CheckStop('anomaly', 'wifi_stack_unknown', 'the box answers neither /interface/wifi nor /interface/wireless');
  }

  // ── The allocation, read-only — what `computedForSite` gave the compile ──
  let preview: Awaited<ReturnType<typeof previewForSite>>;
  try {
    preview = await previewForSite(device.tenant_id, prov.site_id);
  } catch (err) {
    if (err instanceof AllocationError) {
      throw new CheckStop('anomaly', 'allocation_changed', `the site's allocation cannot be read: ${err.message}`);
    }
    throw err;
  }
  if (!preview.committed) {
    throw new CheckStop('anomaly', 'allocation_changed', 'the site no longer has a committed allocation');
  }
  if (
    preview.ppp_username !== device.ppp_username ||
    preview.system_identity !== device.system_identity ||
    preview.concentrator_id !== device.concentrator_id
  ) {
    throw new CheckStop(
      'anomaly',
      'allocation_changed',
      "the site's allocation (PPP login, system identity or concentrator) no longer matches this device",
    );
  }

  const schema = (rev.var_schema ?? {}) as { properties?: Record<string, Record<string, unknown>> };
  const props = schema.properties ?? {};
  const computed: Record<string, unknown> = { ...preview.values };
  // Rendered as a PLACEHOLDER in 'redacted' mode: the stand-in's text never
  // reaches the output (and the compile declared it computed only if secret).
  if (props.ppp_password?.['x-obliwan-level'] === 'computed') computed.ppp_password = pppPasswordStandIn();

  const boxFacts: BoxFacts = { wifi_stack: box.wifiStack };
  if (box.board !== null) boxFacts.board = box.board;
  if (device.model !== null) boxFacts.model = device.model;
  if (device.os_version !== null) boxFacts.ros_version = device.os_version;

  // ── Variants: base, then each bench key varied / absent ──────────────────
  const decls = benchDeclarationsOf(schema);
  const base: Record<string, unknown> = {};
  const second = new Map<string, unknown>();
  for (const d of decls) {
    const values = benchStandIns(d, props[d.key]);
    if (values.length === 0) {
      if (d.secret) {
        // A secret is never validated at render time and never reaches the
        // text: any stand-in renders the same placeholder.
        base[d.key] = 'standin';
        continue;
      }
      if (!d.required) continue;
      throw new CheckStop(
        'anomaly',
        'bench_value_unsimulable',
        `no stand-in satisfies the declaration of the bench value "${d.key}", so the template cannot be re-rendered without it`,
      );
    }
    base[d.key] = values[0];
    if (!d.secret && values.length > 1) second.set(d.key, values[1]);
  }
  const variants: Array<{ key: string | null; bench: Record<string, unknown> }> = [{ key: null, bench: base }];
  for (const d of decls) {
    if (second.has(d.key)) variants.push({ key: d.key, bench: { ...base, [d.key]: second.get(d.key) } });
    if (!d.required && d.key in base) {
      const without = { ...base };
      delete without[d.key];
      variants.push({ key: d.key, bench: without });
    }
  }

  const rendered: Array<{
    key: string | null; doc: NcmDocument; claims: ReturnType<typeof claimedKindsOf>; sha: string;
    prepared: ReturnType<typeof prepareDesiredText>;
  }> = [];
  for (const v of variants) {
    let r: Awaited<ReturnType<typeof renderForSite>>;
    try {
      r = await renderForSite({
        tenantId: device.tenant_id,
        siteId: prov.site_id,
        revisionId: Number(prov.revision_id),
        computed,
        bench: v.bench,
        box: boxFacts,
        mode: 'redacted',
      });
    } catch (err) {
      if (err instanceof SiteRenderError) {
        throw new CheckStop('anomaly', 'render_refused', `the template cannot be re-rendered for this box: ${err.message}`);
      }
      throw err;
    }
    // (g): every variant is prepared the same way, so a bench key cannot
    // appear to move a record merely because a stripped line moved.
    const prepared = prepareDesiredText(r.redacted);
    const { doc, claims } = textToDesired(prepared.text, rev.section_severity, device, kit, observed);
    rendered.push({ key: v.key, doc, claims, sha: r.redactedSha256, prepared });
  }

  // ── (g): what is left must be configuration, all of it ──────────────────
  const baseR = rendered[0];
  const gap = parseExport(baseR.prepared.text).unparsed;
  if (gap.length > 0) {
    const first = gap[0].text.split(/\s+/)[0].slice(0, 24);
    throw new CheckStop(
      'anomaly',
      'not_comparable',
      `the template's render holds ${gap.length} line(s) the configuration model cannot read (first near line ` +
        `${gap[0].line}, starting "${first}"): what the box holds beyond the plan cannot be compared, so an empty ` +
        'plan would not mean conformity',
    );
  }

  // ── What moves with a bench key ──────────────────────────────────────────
  const baseMap = recordMap(baseR.doc);
  const benchFed = new Map<string, { kind: NcmResourceKind; keys: Set<string> }>();
  const benchFedKinds = new Map<NcmResourceKind, Set<string>>();
  const mark = (semKey: string, kind: NcmResourceKind, key: string): void => {
    const e = benchFed.get(semKey) ?? { kind, keys: new Set<string>() };
    e.keys.add(key);
    benchFed.set(semKey, e);
  };
  for (const v of rendered.slice(1)) {
    const key = v.key as string;
    const m = recordMap(v.doc);
    for (const [semKey, rec] of baseMap) {
      const other = m.get(semKey);
      if (!other || other.json !== rec.json) mark(semKey, rec.kind, key);
    }
    for (const [semKey, rec] of m) if (!baseMap.has(semKey)) mark(semKey, rec.kind, key);
    const a = baseR.claims.kinds;
    const b = v.claims.kinds;
    for (const kind of new Set([...a, ...b])) {
      if (a.has(kind) !== b.has(kind)) {
        const s = benchFedKinds.get(kind) ?? new Set<string>();
        s.add(key);
        benchFedKinds.set(kind, s);
      }
    }
  }

  // ── Does the re-render reproduce the compiled text? ─────────────────────
  // Exhaustive only when no clear bench value exists (its text is unknown)
  // and at most one optional key (every presence combination was rendered).
  const matched = rendered.some((r) => r.sha === prov.redacted_sha256);
  const clearKeys = decls.filter((d) => !d.secret);
  const optional = decls.filter((d) => !d.required);
  const exhaustive = clearKeys.length === 0 && optional.length <= 1;
  const renderMatchesCompile = matched ? true : exhaustive ? false : null;

  const claimed = new Set([...baseR.claims.kinds].filter((k) => !benchFedKinds.has(k)));
  return {
    desired: baseR.doc,
    claimed,
    unmodelledSections: baseR.claims.unclaimedSections,
    nonConfigLines: baseR.prepared.stripped,
    benchFed,
    benchFedKinds,
    renderMatchesCompile,
    variants: rendered.length,
    // EVERY variant: a bench value could turn `0.0.0.0/0` into no address
    // without moving the record (the NCM reads both as `any`). Then the box
    // must be on the management range alone, and one the bench value left
    // open is a difference — a human confirms, never a wrong one.
    sshOpensAll: rendered.every((r) => templateSshOpensAll(r.prepared.text)),
  };
}

/** The management prefixes as the normaliser spells a selector atom — what
 *  the access block writes on api-ssl and appends to ssh, and the SNMP block
 *  appends to a community it keeps. */
function managementAtoms(device: DeviceFacts, kit: NormKit, prefixes: readonly string[]): Set<string> {
  if (prefixes.length === 0) return new Set();
  const doc = normalize(
    `/snmp community add name=obliwan-management-probe addresses=${prefixes.join(',')}`,
    ctxOf(device, kit, 'routeros_api', null),
  ).ncm;
  const rec = listOf<NcmService>(doc, 'service')[0];
  return new Set((rec?.allowedFrom ?? []).filter((a) => a !== 'any'));
}

/** One service record as the normaliser reads `line` for this device — the
 *  factory state `withBlockEffects` starts from. `label` names the line in
 *  the refusal instead of the line itself when the line holds a secret. */
function serviceRecordOf(device: DeviceFacts, kit: NormKit, line: string, semKey: string, label = `"${line}"`): NcmService {
  const rec = listOf<NcmService>(normalize(line, ctxOf(device, kit, 'routeros_api', null)).ncm, 'service')
    .find((r) => r.semKey === semKey);
  if (!rec) throw new CheckStop('anomaly', 'not_comparable', `the normaliser does not model ${label}`);
  return rec;
}

// ============================================================================
// The comparison
// ============================================================================

interface Comparison {
  ops: PlanOp[];
  differences: ConformityDifference[];
  excluded: ConformityExcluded;
  summary: Record<string, unknown>;
}

interface CompareInput {
  device: DeviceFacts;
  d: DesiredResult;
  observedRaw: NcmDocument;
  snapshotId: string;
  box: BoxReadout;
  kit: NormKit;
  /** Never empty when the template claims `service` (`judge` stops the
   *  check first); only read then. */
  mgmtAtoms: ReadonlySet<string>;
  /** The same range as `readManagementRange` spells it — what the compile
   *  wrote into the SNMP block's `add` line. */
  mgmtPrefixes: readonly string[];
  snmp: SnmpBlockRead;
}

function compare(i: CompareInput): Comparison {
  const { device, d, observedRaw, snapshotId, box, kit } = i;
  const observedKeys = new Set(recordsOf(observedRaw).map((r) => r.semKey));
  // (b) the one record of the access block set aside whole (the `obliwan`
  // account) — before anything else is judged.
  const access = accessBlockKeys();

  // (c) records carrying a secret placeholder on the desired side (a record
  // already set aside as bench-fed or as the access block's is not judged).
  const secretBearing = new Map<string, { kind: NcmResourceKind; secrets: string[] }>();
  for (const [semKey, rec] of recordMap(d.desired)) {
    const keys = placeholdersIn(rec.json);
    if (keys.length === 0 || d.benchFed.has(semKey) || access.has(semKey)) continue;
    if (new RegExp(SECRET_PLACEHOLDER_RE.source).test(semKey)) {
      throw new CheckStop('anomaly', 'not_comparable',
        `a secret sits in the identity of a ${rec.kind} record of the plan: it cannot be paired with the box without reading the secret`);
    }
    if (!observedKeys.has(semKey)) {
      throw new CheckStop('anomaly', 'not_comparable',
        `a ${rec.kind} record of the plan carries a secret and the box shows nothing under the same key: either the box ` +
          'lacks it or the secret feeds its identity, and telling which needs the secret');
    }
    secretBearing.set(semKey, { kind: rec.kind, secrets: keys });
  }

  const drop = new Set<string>([...d.benchFed.keys(), ...secretBearing.keys(), ...access.keys()]);
  let observed = withoutRecords(observedRaw, drop);
  // (b) the other records the blocks write (api-ssl, ssh, /snmp, the polled
  // community): the template's, with what the blocks write on them, and
  // nothing more excused. The plain `api` is not among them: compared as the
  // template left it.
  const { communityName } = i.snmp;
  const effects = withBlockEffects(withoutRecords(d.desired, drop), observed, d.claimed, {
    mgmtAtoms: i.mgmtAtoms,
    snmp: { ran: i.snmp.ran, communityKey: i.snmp.communityKey },
    sshOpensAll: d.sshOpensAll,
    apiSsl: apiSslExpectedState(i.mgmtPrefixes),
    factory: (record) => {
      switch (record) {
        case 'ssh': return serviceRecordOf(device, kit, '/ip service set ssh disabled=no', serviceKey('ssh', null));
        case 'api-ssl': return serviceRecordOf(device, kit, `/ip service set ${API_SSL_SERVICE} disabled=no`, serviceKey(API_SSL_SERVICE, null));
        case 'snmp': return serviceRecordOf(device, kit, '/snmp set enabled=no', serviceKey('snmp', null));
        case 'community':
          // Only asked for when `communityKey` is set, which `snmpBlockFacts`
          // sets only together with the name. The SNMP block's own line,
          // which holds the name: the refusal names the line, not its text.
          if (communityName === null) throw new CheckStop('anomaly', 'not_comparable', 'the polled SNMP community could not be read');
          return serviceRecordOf(device, kit,
            `/snmp community add name="${communityName}" addresses="${i.mgmtPrefixes.join(',')}" read-access=yes write-access=no comment="obliwan:access"`,
            serviceKey('other', `snmp-community:${communityName}`),
            'the SNMP block\'s `/snmp community add` line');
      }
    },
    skip: drop,
  });
  // What the TEMPLATE asks of the box: neither a record the blocks injected
  // (the template is silent on it) nor `api-ssl`, whose state, port,
  // addresses and certificate the block overwrites whatever the template
  // said. The `nothing_compared` guard counts these, so a box is never
  // confirmed on the blocks' records alone.
  const blockOnly = new Set([
    ...effects.adjusted.filter((a) => a.injected).map((a) => a.semKey),
    serviceKey(API_SSL_SERVICE, null),
  ]);
  let desired = effects.desired;
  // A kind the template claims only for some bench values is not compared at
  // all: its coverage is withdrawn on the desired side, as `restrictCoverage`
  // withdraws any kind the template does not claim.
  if (d.benchFedKinds.size > 0) desired = { ...desired, coverage: restrictCoverage(desired.coverage, d.claimed) };
  // (g): `interface` and `service` are partial on ANY text — a statement about
  // what /export omits. The render is the whole of what the template asks of
  // them, so their desired side is complete: `extra` is compared.
  const coverage = { ...(desired.coverage as unknown as Record<string, { state: string; reason: string | null }>) };
  for (const kind of READ_BACK_KINDS) {
    const c = coverage[kind];
    if (c && d.claimed.has(kind) && c.state === 'partial') coverage[kind] = { ...c, state: 'complete', reason: null };
  }
  desired = { ...desired, coverage: coverage as unknown as NcmDocument['coverage'] };

  const desiredRecords = recordsOf(desired).length;
  const templateRecords = recordsOf(desired).filter((r) => !blockOnly.has(r.semKey)).length;
  if (templateRecords === 0) {
    throw new CheckStop('anomaly', 'nothing_compared',
      'once the access block\'s records, the values typed at the bench and the secret-bearing records are set aside, the plan holds no record of the template\'s to compare');
  }

  const supplementary: ConformityDifference[] = [];
  const observedNow = new Set(recordsOf(observed).map((r) => r.semKey));

  // (h) services the export omits: the box's own read, through the normaliser.
  const readOnBox: string[] = [];
  const unreadable: string[] = [];
  const lines: Array<{ semKey: string; line: string }> = [];
  if (d.claimed.has('service')) {
    for (const r of listOf<NcmService>(desired, 'service')) {
      if (observedNow.has(r.semKey)) continue;
      if (isCommunity(r)) {
        supplementary.push({
          op: 'create', resource: 'service', semKey: maskCommunity(r.semKey), fields: [], values: [],
          reason: 'An SNMP community the plan adds is absent from the box (an added community is always exported).',
        });
        continue;
      }
      const res = serviceLineFromBox(r, box.ipServices, box.snmp);
      if (res.missing) {
        supplementary.push({
          op: 'create', resource: 'service', semKey: r.semKey, fields: [], values: [],
          reason: `The box has no service named after ${r.semKey}.`,
        });
      } else if (res.line === null) {
        unreadable.push(r.semKey);
      } else {
        lines.push({ semKey: r.semKey, line: res.line });
      }
    }
  }
  if (unreadable.length > 0) {
    throw new CheckStop('anomaly', 'not_comparable',
      `the box's own state of ${unreadable.join(', ')} (absent from its export, i.e. at its factory value) could not be read`);
  }
  if (lines.length > 0) {
    const fromBox = listOf<NcmService>(
      normalize(lines.map((l) => l.line).join('\n'), ctxOf(device, kit, 'routeros_api', null)).ncm,
      'service',
    );
    const bySemKey = new Map(fromBox.map((r) => [r.semKey, r]));
    const injected: NcmService[] = [];
    for (const l of lines) {
      const rec = bySemKey.get(l.semKey);
      if (!rec) {
        throw new CheckStop('anomaly', 'not_comparable', `the box's own state of ${l.semKey} could not be modelled`);
      }
      injected.push(rec);
      readOnBox.push(l.semKey);
    }
    observed = withList(observed, 'service', [...listOf<NcmService>(observed, 'service'), ...injected]);
  }

  // (h) interfaces the export omits.
  const factoryInterfaces: string[] = [];
  if (d.claimed.has('interface')) {
    for (const r of listOf<NcmInterface>(desired, 'interface')) {
      if (observedNow.has(r.semKey)) continue;
      const fields = nonFactoryInterfaceFields(r);
      if (fields.length > 0) {
        supplementary.push({
          op: 'create', resource: 'interface', semKey: r.semKey, fields,
          values: fields.map((f) => ({
            field: f,
            intent: shown(f, (r as unknown as Record<string, unknown>)[f]),
            actual: '—',
          })),
          reason: `The plan gives ${r.name} ${fields.join(', ')}; /export lists every interface that carries any of them, and the box's does not list it.`,
        });
      } else if (CREATED_INTERFACE_TYPES.has(r.type)) {
        supplementary.push({
          op: 'create', resource: 'interface', semKey: r.semKey, fields: [], values: [],
          reason: `The plan creates ${r.type} ${r.name}; an added interface is always exported, and the box's export does not list it.`,
        });
      } else {
        factoryInterfaces.push(r.name);
      }
    }
  }

  const planned = buildPlanOps({
    desired,
    observed,
    claimedKinds: [...d.claimed],
    deviceId: device.id,
    tunnelIp: device.tunnel_ip,
  });

  // Every kind-level limitation the engine declares stops the check, except
  // the one (h) establishes another way: `missing` on interface and service.
  const suppressed = planned.diff.suppressed.filter((s) => d.claimed.has(s.resource));
  const blocking = suppressed.filter((s) => !(READ_BACK_KINDS.has(s.resource) && s.reason === 'coverage_incomplete'));
  if (blocking.length > 0) {
    throw new CheckStop('anomaly', 'not_comparable',
      `the diff engine could not compare ${blocking.map((b) => `${b.resource} (${b.reason})`).join(', ')} completely, ` +
        'so an empty plan would not mean conformity');
  }

  const present = (doc: NcmDocument): Set<string> => new Set(recordsOf(doc).map((r) => r.semKey));
  const inDesired = present(d.desired);
  const excluded: ConformityExcluded = {
    accessBlock: [
      ...[...access].filter(([k]) => inDesired.has(k) || observedKeys.has(k))
        .map(([semKey, kind]): ConformityExcluded['accessBlock'][number] => ({ resource: kind, semKey })),
      ...effects.adjusted.map((a) => ({ resource: a.resource, semKey: a.semKey, fields: [...a.fields] })),
    ].map((x) => ({ ...x, semKey: maskCommunity(x.semKey) })),
    benchFed: [...d.benchFed].map(([semKey, e]) => ({ resource: e.kind, semKey: maskCommunity(semKey), benchKeys: [...e.keys].sort() })),
    benchFedKinds: [...d.benchFedKinds].map(([kind, keys]) => ({ resource: kind, benchKeys: [...keys].sort() })),
    secretBearing: [...secretBearing].map(([semKey, e]) => ({ resource: e.kind, semKey: maskCommunity(semKey), secrets: e.secrets })),
    unmodelledSections: d.unmodelledSections,
    notClaimedKinds: (Object.keys(RESOURCE_KIND_TO_COLLECTION) as NcmResourceKind[]).filter((k) => !d.claimed.has(k)),
    nonConfigLines: d.nonConfigLines,
    factoryInterfaces,
    readOnBox: readOnBox.map(maskCommunity),
    limitations: [...new Set(suppressed.map((s) => s.resource))].map((kind) => ({
      resource: kind,
      reason: 'coverage_incomplete',
      missingCompared: true,
      missingReadOnBox: true,
      extraCompared: true,
      desiredCoverage: coverageOf(desired.coverage, kind).state,
      observedCoverage: coverageOf(observed.coverage, kind).state,
    })),
  };

  // The planner states each limitation as a KIND-LEVEL `blocked` op (`semKey`
  // `suppressed:<kind>`): what remains of them here are the two (h) covers,
  // recorded above. Every OTHER op, a record-level `blocked` included (a
  // deletion the planner refuses is still something on the box the plan does
  // not have), is a difference.
  const notices = planned.ops.filter((op) => op.kind === 'blocked' && op.semKey === `suppressed:${op.resource}`);
  const ops = planned.ops.filter((op) => !notices.includes(op));
  const differences = [...differencesOf(ops, planned.diff.findings), ...supplementary];

  const byKind: Record<string, number> = {};
  for (const op of ops) byKind[op.kind] = (byKind[op.kind] ?? 0) + 1;
  const summary = {
    opCount: ops.length,
    readBackDifferenceCount: supplementary.length,
    kindNoticeCount: notices.length,
    opsByKind: byKind,
    claimedKinds: [...d.claimed].sort(),
    desiredRecords,
    /** Of those, the ones the template asks (the guard above). */
    templateRecords,
    observedRecords: recordsOf(observed).length,
    inertMoveCount: planned.diff.inertMoveCount,
    outOfScopeCount: planned.diff.outOfScopeCount,
    renderVariants: d.variants,
    snapshotId,
  };
  return { ops, differences, excluded, summary };
}

/** What the audit entry carries about the comparison: counts and kind names,
 *  never a semKey (a community's key holds its secret name). */
function auditSummaryOf(cmp: Comparison, renderMatchesCompile: boolean | null): Record<string, unknown> {
  const ex = cmp.excluded;
  return {
    ...cmp.summary,
    renderMatchesCompile,
    notCompared: {
      accessBlock: ex.accessBlock.filter((a) => !a.fields).length,
      benchFed: ex.benchFed.length,
      benchFedKinds: ex.benchFedKinds.map((b) => b.resource),
      secretBearing: ex.secretBearing.length,
      unmodelledSections: ex.unmodelledSections.length,
      notClaimedKinds: ex.notClaimedKinds,
      factoryInterfaces: ex.factoryInterfaces.length,
      nonConfigLines: ex.nonConfigLines.length,
    },
    /** Records the blocks write and this check compares, with the blocks'
     *  value in the fields they write (header, (b)). */
    blockAdjusted: ex.accessBlock.filter((a) => a.fields).length,
    readOnBox: ex.readOnBox.length,
  };
}

// ============================================================================
// One check
// ============================================================================

export type CheckTrigger = 'event' | 'sweep' | 'manual';

export interface CheckResult {
  ran: boolean;
  /** What happened, in one word, for a log line or a toast. */
  outcome: 'confirmed' | 'non_conformant' | 'anomaly' | 'retry' | 'not_contacted' | 'superseded' | 'skipped';
  message: string;
  view: ConformityView | null;
}

/** In this process: one check per device at a time. Across processes, the
 *  row claim. */
const inFlight = new Map<number, Promise<CheckResult>>();

function isCandidateOutcome(outcome: string): boolean {
  return outcome === 'applied' || outcome === 'compiled';
}

/** `now() + secs` on the DATABASE clock — the one every `<= now()` below is
 *  judged on. The database may run on another host than this process. */
function dbIn(secs: number): Knex.Raw {
  return db.raw('now() + make_interval(secs => ?)', [Math.max(0, secs)]);
}

/** Create the row for the device's latest compile if it has none. Never
 *  touches a row in a final state. */
async function ensureRow(prov: ProvisioningFacts, dueInSecs: number | null): Promise<void> {
  await db(T)
    .insert({
      tenant_id: prov.tenant_id,
      device_id: prov.device_id,
      provisioning_id: prov.id,
      state: 'waiting',
      revision_id: prov.revision_id,
      next_attempt_at: dueInSecs === null ? null : dbIn(dueInSecs),
    })
    .onConflict('provisioning_id')
    .ignore();
}

async function claim(rowId: string, manual: boolean): Promise<string | null> {
  const token = crypto.randomUUID();
  const q = db(T)
    .where({ id: rowId, state: 'waiting' })
    .andWhere((w) => {
      void w.whereNull('claimed_at').orWhereRaw('claimed_at < now() - make_interval(secs => ?)', [CLAIM_LEASE_SEC]);
    });
  if (!manual) {
    q.andWhere((w) => {
      void w.whereNull('next_attempt_at').orWhere('next_attempt_at', '<=', db.fn.now());
    });
  }
  const n = await q.update({ claim_token: token, claimed_at: db.fn.now(), updated_at: db.fn.now() });
  return n === 1 ? token : null;
}

async function release(rowId: string, token: string, columns: Record<string, unknown>): Promise<boolean> {
  const n = await db(T)
    .where({ id: rowId, claim_token: token })
    .update({ ...columns, claim_token: null, claimed_at: null, updated_at: db.fn.now() });
  return n === 1;
}

/**
 * Run the check for one device. Idempotent: a device that is not a candidate,
 * a row already claimed elsewhere, or a row not yet due is reported and left
 * alone. `manual` (the "Re-check now" button) re-opens a `non_conformant` or
 * `anomaly` row of a device still `pending`, and ignores the backoff.
 */
export async function checkDevice(
  tenantId: number,
  deviceId: number,
  trigger: CheckTrigger,
): Promise<CheckResult> {
  const running = inFlight.get(deviceId);
  if (running) {
    if (trigger !== 'manual') return running;
    await running.catch(() => undefined);
  }
  const p = runCheck(tenantId, deviceId, trigger).finally(() => {
    if (inFlight.get(deviceId) === p) inFlight.delete(deviceId);
  });
  inFlight.set(deviceId, p);
  return p;
}

/** Harness only: `runCheck` WITHOUT this process's per-device serialisation,
 *  so two calls contest the database claim the way two processes would. */
export function runCheckUnserialisedForTests(tenantId: number, deviceId: number, trigger: CheckTrigger): Promise<CheckResult> {
  return runCheck(tenantId, deviceId, trigger);
}

async function runCheck(tenantId: number, deviceId: number, trigger: CheckTrigger): Promise<CheckResult> {
  const manual = trigger === 'manual';
  const skip = async (message: string): Promise<CheckResult> => ({
    ran: false, outcome: 'skipped', message, view: await conformityView(tenantId, deviceId),
  });
  if (!deps.enabled()) {
    return skip(`the automatic conformity check is switched off on this installation (${AUTO_CONFIRM_ENV}=false)`);
  }
  const device = await loadDeviceFacts(tenantId, deviceId);
  if (!device) return { ran: false, outcome: 'skipped', message: 'device not found', view: null };
  const prov = await loadLatestProvisioning(tenantId, deviceId);
  if (!prov) return skip('this device was not prepared at the bench');
  if (!isCandidateOutcome(prov.outcome)) {
    return skip('the bench reported this preparation as failed: a human confirms it');
  }

  let row = await loadRow(prov.id);
  if (device.status !== 'pending') {
    if (row && row.state === 'waiting' && row.claim_token === null) {
      await db(T).where({ id: row.id, state: 'waiting' }).whereNull('claim_token').update({
        state: 'superseded', reason_code: 'status_changed',
        reason: `the device became '${device.status}' before a verdict was reached`,
        decided_at: db.fn.now(), next_attempt_at: null, updated_at: db.fn.now(),
      });
    }
    return skip(`the device is '${device.status}', not pending`);
  }

  if (!row) {
    await ensureRow(prov, null);
    row = await loadRow(prov.id);
    if (!row) return skip('the check row could not be created');
  }
  // A human asking again re-opens anything but a confirmation (a conformant
  // row's device is no longer pending, and was turned away above). Every
  // condition is judged again from the start: re-opening decides nothing.
  const reopenable = ['non_conformant', 'anomaly', 'superseded', 'waiting'];
  if (manual && reopenable.includes(row.state)) {
    await db(T).where({ id: row.id }).whereIn('state', reopenable).whereNull('claim_token').update({
      state: 'waiting', reason_code: null, reason: null, decided_at: null, attempts: 0,
      first_attempt_at: null, next_attempt_at: null, last_error: null,
      differences: null, difference_count: null, snapshot_id: null, observed_ncm_hash: null,
      render_matches_compile: null, excluded: null, plan_summary: null, updated_at: db.fn.now(),
    });
  }
  const token = await claim(row.id, manual);
  if (!token) return skip('already being checked, not due yet, or already decided');
  // Read under the claim: a waiting row that already counts differences was
  // looked at once and is now being looked at the second time (settling).
  const prior = (await db(T).where({ id: row.id }).first('difference_count')) as { difference_count: number | null } | undefined;

  let outcome: CheckResult['outcome'] = 'retry';
  let message = '';
  try {
    const result = await judge(device, prov, row.id, token, {
      trigger,
      priorDifferenceCount: prior?.difference_count ?? null,
    });
    outcome = result.outcome;
    message = result.message;
  } catch (err) {
    // `judge` records every outcome it reaches; this is the bug path. The
    // claim is released as a retry so the lease does not have to expire.
    logger.error({ err, deviceId }, 'Automatic conformity check failed unexpectedly');
    message = err instanceof Error ? err.message : String(err);
    await settleRetry(device, row.id, token, 'internal', message).catch(() => undefined);
    outcome = 'retry';
  }
  const view = await conformityView(tenantId, deviceId);
  emitToTenantAudience(tenantId, AUTO_CONFIRM_EVENT, { deviceId, state: view?.state ?? null, reasonCode: view?.reasonCode ?? null }, { deviceId });
  return { ran: true, outcome, message, view };
}

/** The ordered steps of the file header. Records its own outcome. */
async function judge(
  device: DeviceFacts,
  prov: ProvisioningFacts,
  rowId: string,
  token: string,
  ctx: { trigger: CheckTrigger; priorDifferenceCount: number | null },
): Promise<{ outcome: CheckResult['outcome']; message: string }> {
  try {
    // 1. Candidate, as of NOW.
    if (prov.station_status !== 'approved') {
      throw new CheckStop('anomaly', 'station_not_approved',
        `the bench station that compiled this file is '${prov.station_status ?? 'unknown'}', not approved`);
    }
    // 2. The serial the bench read — before anything is dialled.
    const bench = await loadBenchRecordedSerial(prov);
    const serialProblem = benchSerialProblem(bench, device.serial);
    if (serialProblem) throw new CheckStop('anomaly', 'identity_incomplete', serialProblem);
    // … and the API channel must be TLS — still before anything is dialled.
    await assertTlsApiChannel(device.id);
    // 3. Presence. Not an attempt: nothing was dialled.
    if (!(await isSessionUp(device))) {
      throw new CheckStop('not_contacted', 'session_down', 'the PPP session is down: the box has not come up through its tunnel');
    }
    await db(T).where({ id: rowId, claim_token: token }).update({
      attempts: db.raw('attempts + 1'),
      last_attempt_at: db.fn.now(),
      first_attempt_at: db.raw('COALESCE(first_attempt_at, now())'),
      revision_id: prov.revision_id,
    });

    // 3b + 4 + 5. The certificate (pinned or verified), identity, box facts,
    // markers. A pin written here is released when the identity is then
    // CONTRADICTED or NOT COMPLETE — the box that showed the certificate is
    // not shown to be this device — and kept when the check merely could not
    // finish (unreachable, marker absent): nothing then speaks against it.
    let pinnedHere: string | null = null;
    let box: BoxReadout;
    try {
      pinnedHere = await pinOrVerifyApiCertificate(device);
      box = await readAssertedBox(device, prov.tag);
    } catch (err) {
      if (err instanceof CheckStop) throw err;
      if (err instanceof BindingAssertionError) {
        if (err.assertion.mismatched > 0) {
          await releasePin(device.id, pinnedHere);
          throw new CheckStop('anomaly', 'identity_mismatch',
            `${err.assertion.reason}; the device was quarantined`);
        }
        throw new CheckStop('retry', 'unreachable', err.assertion.reason);
      }
      throw new CheckStop('retry', 'unreachable', err instanceof Error ? err.message : String(err));
    }
    const serialCheck = box.assertion.checks.find((c) => c.attribute === 'serial');
    if (!identityFullyMatched(box.assertion.checks) || idNorm(serialCheck?.observed) !== idNorm(bench.serial)) {
      await releasePin(device.id, pinnedHere);
      const detail = box.assertion.checks.map((c) => `${c.attribute}: ${c.outcome}`).join(', ');
      throw new CheckStop('anomaly', 'identity_incomplete',
        `the identity was not proved on all three attributes against what the bench recorded (${detail}); a human confirms this device`);
    }
    if (!box.okMarker && !box.failedMarker) {
      throw new CheckStop('retry', 'marker_absent',
        `the box does not (yet) carry the success marker of file ${prov.tag}: the file may still be running`);
    }

    // 6. The collection — the one door, the frozen redacted export.
    let snapshotId: string;
    try {
      snapshotId = (await deps.collect(device.id, device.tenant_id)).snapshotId;
    } catch (err) {
      if (err instanceof BindingAssertionError && err.assertion.mismatched > 0) {
        throw new CheckStop('anomaly', 'identity_mismatch', `${err.assertion.reason}; the device was quarantined`);
      }
      // A refusal that a retry cannot change — no channel, no collector for
      // the family, a pin mismatch, an export that would carry secrets
      // — needs a human now; anything else is retried, then given up on.
      const code = (err as { code?: string }).code ?? '';
      const name = err instanceof Error ? err.name : '';
      if (
        FINAL_COLLECT_CODES.has(code) ||
        name === 'NoNormalizerError' || name === 'SensitiveMaterialError' || name === 'ExportDialectRefusal'
      ) {
        throw new CheckStop('anomaly', 'collect_refused', err instanceof Error ? err.message : String(err));
      }
      throw new CheckStop('retry', 'collect_failed', err instanceof Error ? err.message : String(err));
    }
    const snap = (await db('config_snapshots')
      .where({ id: snapshotId, device_id: device.id })
      .first('ncm', 'ncm_hash')) as { ncm: unknown; ncm_hash: string } | undefined;
    if (!snap) throw new CheckStop('retry', 'collect_failed', `snapshot #${snapshotId} is not this device's`);
    const observed = upgradeNcm(snap.ncm);
    if (recordsOf(observed).length === 0) {
      throw new CheckStop('retry', 'collection_empty', 'the collected configuration holds no modelled record at all');
    }

    // The desired state of the same revision, and the plan between them.
    const kit = await normKitFor(device);
    const d = await desiredForBench(device, prov, box, observed, kit);
    if (d.claimed.size === 0) {
      throw new CheckStop('anomaly', 'nothing_compared',
        'the template writes no section the NCM models (or only sections fed by bench values): there is nothing to compare');
    }
    for (const kind of d.claimed) {
      const c = coverageOf(observed.coverage, kind);
      if (c.state === 'failed') {
        throw new CheckStop('retry', 'collect_failed', `the collection of ${kind} failed`);
      }
      if (c.state === 'unsupported') {
        throw new CheckStop('anomaly', 'not_comparable', `the collection cannot read ${kind}, which the template writes`);
      }
      // (h): every kind but the two read back must be complete on the box's
      // side, or `missing` is not compared for it.
      if (c.state !== 'complete' && !READ_BACK_KINDS.has(kind)) {
        throw new CheckStop('anomaly', 'not_comparable',
          `what the box holds of ${kind} cannot be established completely from its export: ${c.reason ?? c.state}`);
      }
    }
    // The range the compile wrote, read the way the compile reads it.
    // Without it, what the blocks wrote on api-ssl, ssh and the polled community
    // cannot be told from a hand edit: no verdict either way. Only the
    // `service` kind needs it; a template that does not claim it has none of
    // those records compared.
    const range = await readManagementRange();
    const mgmtPrefixes = range.ok ? range.prefixes : [];
    const mgmtAtoms = managementAtoms(device, kit, mgmtPrefixes);
    if (d.claimed.has('service') && mgmtAtoms.size === 0) {
      throw new CheckStop('anomaly', 'not_comparable',
        `the management range (instance variable ${MANAGEMENT_RANGE_KEY}) is unset, invalid or stored as a secret, so ` +
          'what the access block wrote on the services cannot be told from a hand edit');
    }
    const cmp = compare({
      device,
      d,
      observedRaw: observed,
      snapshotId,
      box,
      kit,
      mgmtAtoms,
      mgmtPrefixes,
      snmp: await snmpBlockFacts(device, prov),
    });

    const differences = [...cmp.differences];
    if (box.failedMarker) {
      differences.unshift({
        op: 'provisioning',
        resource: 'provisioning',
        semKey: PROVISION_FAILED_SCRIPT(prov.tag),
        fields: [],
        values: [],
        reason: 'The box reports that its preparation file stopped on an error (failure marker present).',
      });
    }
    const common = {
      snapshot_id: snapshotId,
      observed_ncm_hash: snap.ncm_hash,
      render_matches_compile: d.renderMatchesCompile,
      excluded: JSON.stringify(cmp.excluded),
      plan_summary: JSON.stringify(cmp.summary),
      last_error: null,
      next_attempt_at: null,
    };

    if (differences.length > 0) {
      const stored = JSON.stringify(differences.slice(0, MAX_DIFFERENCES_STORED));
      // A first automatic look: once more after the settling delay.
      if (!box.failedMarker && ctx.trigger !== 'manual' && ctx.priorDifferenceCount === null) {
        const reason = `${differences.length} difference(s) with the plan of revision ${prov.revision_id} on a first look; ` +
          `looking again in ${Math.round(deps.settleMs / 60_000)} min in case the box was still settling.`;
        await release(rowId, token, {
          ...common,
          reason_code: 'settling',
          reason,
          difference_count: differences.length,
          differences: stored,
          next_attempt_at: dbIn(deps.settleMs / 1000),
        });
        return { outcome: 'retry', message: reason };
      }
      const reason = box.failedMarker
        ? `The box reports its preparation failed; ${differences.length - 1} difference(s) with the plan.`
        : `${differences.length} difference(s) between the box and the plan of revision ${prov.revision_id}.`;
      await release(rowId, token, {
        ...common,
        state: 'non_conformant',
        reason_code: box.failedMarker ? 'provisioning_failed' : 'plan_not_empty',
        reason,
        difference_count: differences.length,
        differences: stored,
        decided_at: db.fn.now(),
      });
      await raiseAlert(device, rowId, 'non_conformant', reason);
      return { outcome: 'non_conformant', message: reason };
    }

    // ── CONFORMANT: the one narrow door, one transaction ───────────────────
    const statement = `auto-confirmed by conformity check: revision ${prov.revision_id}, snapshot ${snapshotId}, plan empty`;
    const confirmed = await db.transaction(async (trx) => {
      const ok = await confirmBenchDeviceByConformity(trx, {
        tenantId: device.tenant_id,
        deviceId: device.id,
        recorded: {
          pppUsername: device.ppp_username as string,
          systemIdentity: device.system_identity as string,
          serial: device.serial as string,
        },
        provisioningId: Number(prov.id),
        provisioningTag: prov.tag,
        revisionId: prov.revision_id,
        snapshotId,
        observedNcmHash: snap.ncm_hash,
        summary: auditSummaryOf(cmp, d.renderMatchesCompile),
      });
      if (!ok) return false;
      const n = await trx(T)
        .where({ id: rowId, claim_token: token })
        .update({
          ...common, state: 'conformant', reason_code: 'conformant', reason: statement,
          difference_count: 0, differences: JSON.stringify([]), method: AUTO_CONFIRM_METHOD,
          confirmed_at: trx.fn.now(), decided_at: trx.fn.now(),
          claim_token: null, claimed_at: null, updated_at: trx.fn.now(),
        });
      if (n !== 1) throw new Error('the conformity check lost its claim before recording the verdict');
      return true;
    });
    if (!confirmed) {
      // The conditional update matched nothing: say which condition moved.
      const latest = await loadLatestProvisioning(device.tenant_id, device.id);
      if (latest && latest.id !== prov.id) {
        throw new CheckStop('superseded', 'provisioning_replaced',
          `a newer bench file (${latest.tag}) was compiled for this device while file ${prov.tag} was being checked: the newer one is the one to judge`);
      }
      if (latest && latest.station_status !== 'approved') {
        throw new CheckStop('anomaly', 'station_not_approved',
          `the bench station that compiled this file became '${latest.station_status ?? 'unknown'}' while it was being checked`);
      }
      if (latest && !isCandidateOutcome(latest.outcome)) {
        throw new CheckStop('superseded', 'bench_failed', 'the bench reported this preparation as failed while it was being checked');
      }
      throw new CheckStop('superseded', 'status_changed',
        'the device stopped being pending (or its identity was edited) while it was being checked');
    }
    const row = await getDevice(device.tenant_id, device.id);
    if (row) emitToTenantAudience(device.tenant_id, SOCKET_EVENTS.DEVICE_UPDATED, { device: toDeviceDto(row) }, { deviceId: device.id });
    return { outcome: 'confirmed', message: statement };
  } catch (err) {
    if (!(err instanceof CheckStop)) throw err;
    const message = maskCommunity(err.message);
    switch (err.kind) {
      case 'not_contacted':
        // Nothing was dialled: no attempt consumed, no retry scheduled — the
        // next session-up event (or the sweep, which only takes devices
        // whose session is up) brings it back.
        await release(rowId, token, { reason_code: err.code, reason: message, next_attempt_at: null });
        return { outcome: 'not_contacted', message };
      case 'retry':
        return settleRetry(device, rowId, token, err.code, message);
      case 'superseded':
        await release(rowId, token, {
          state: 'superseded', reason_code: err.code, reason: message, next_attempt_at: null, decided_at: db.fn.now(),
        });
        return { outcome: 'superseded', message };
      case 'anomaly':
      default:
        await release(rowId, token, {
          state: 'anomaly', reason_code: err.code, reason: message,
          next_attempt_at: null, decided_at: db.fn.now(),
        });
        await raiseAlert(device, rowId, 'anomaly', message);
        return { outcome: 'anomaly', message };
    }
  }
}

/** A transient failure: retry with backoff, or give up into an anomaly. */
async function settleRetry(
  device: DeviceFacts,
  rowId: string,
  token: string,
  code: ConformityReasonCode,
  message: string,
): Promise<{ outcome: CheckResult['outcome']; message: string }> {
  const row = (await db(T)
    .where({ id: rowId })
    .first(
      'attempts',
      db.raw('COALESCE(EXTRACT(EPOCH FROM (now() - first_attempt_at)), 0) * 1000 AS since_ms'),
    )) as { attempts: number; since_ms: string | number } | undefined;
  const attempts = Number(row?.attempts ?? 0);
  const since = Number(row?.since_ms ?? 0);
  const error = message.slice(0, 2000);
  if (attempts >= MAX_ATTEMPTS || since >= GIVE_UP_AFTER_MS) {
    const reason =
      `Gave up after ${attempts} attempt(s) over ${Math.round(since / 60_000)} min. Last failure (${code}): ${error}`;
    await release(rowId, token, {
      state: 'anomaly', reason_code: 'gave_up', reason: reason.slice(0, 2000), last_error: error,
      next_attempt_at: null, decided_at: db.fn.now(),
    });
    await raiseAlert(device, rowId, 'anomaly', reason);
    return { outcome: 'anomaly', message: reason };
  }
  const wait = backoffAfter(Math.max(1, attempts));
  await release(rowId, token, {
    reason_code: code,
    reason: message.slice(0, 2000),
    last_error: error,
    next_attempt_at: dbIn(wait / 1000),
  });
  return { outcome: 'retry', message };
}

/** Non-conformity and anomaly go through the existing live-alert pipeline.
 *  One unread alert per check row and verdict kind: a repeat while the first
 *  is unread adds nothing (`stableKey` dedup). */
async function raiseAlert(device: DeviceFacts, rowId: string, kind: 'non_conformant' | 'anomaly', reason: string): Promise<void> {
  try {
    await liveAlertService.add(device.tenant_id, {
      severity: 'warning',
      title: kind === 'non_conformant'
        ? `${device.name}: not confirmed automatically — configuration differs from the plan`
        : `${device.name}: automatic confirmation needs a human`,
      message: maskCommunity(reason).slice(0, 1000),
      navigateTo: `/devices/${device.id}`,
      deviceId: device.id,
      stableKey: `bench-conformity:${rowId}:${kind}`,
    });
  } catch (err) {
    logger.warn({ err, deviceId: device.id }, 'Conformity alert could not be raised');
  }
}

// ============================================================================
// The view
// ============================================================================

const iso = (d: Date | string | null | undefined): string | null => (d ? new Date(d).toISOString() : null);

function jsonOf<V>(v: unknown, fallback: V): V {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'string') {
    try { return JSON.parse(v) as V; } catch { return fallback; }
  }
  return v as V;
}

export async function conformityView(tenantId: number, deviceId: number): Promise<ConformityView | null> {
  const device = await loadDeviceFacts(tenantId, deviceId);
  if (!device) return null;
  const prov = await loadLatestProvisioning(tenantId, deviceId);
  const row = prov ? await loadRow(prov.id) : null;
  const sessionUp = await isSessionUp(device);
  const applicable = Boolean(prov && isCandidateOutcome(prov.outcome));
  const undecided = row === null || row.state === 'waiting';
  const waitingForTunnel =
    applicable && deps.enabled() && device.status === 'pending' && undecided && !sessionUp;
  return {
    deviceId,
    deviceStatus: device.status,
    enabled: deps.enabled(),
    applicable,
    notApplicableReason: !prov ? 'not_bench' : !isCandidateOutcome(prov.outcome) ? 'bench_failed' : null,
    configDetail: true,
    provisioning: prov
      ? {
        id: prov.id, tag: prov.tag, outcome: prov.outcome, compiledAt: iso(prov.compiled_at) as string,
        revisionId: prov.revision_id, stationId: prov.station_id, stationApproved: prov.station_status === 'approved',
      }
      : null,
    sessionUp,
    state: row?.state ?? null,
    reasonCode: row?.reason_code ?? null,
    reason: row?.reason ?? null,
    attempts: Number(row?.attempts ?? 0),
    firstAttemptAt: iso(row?.first_attempt_at),
    lastAttemptAt: iso(row?.last_attempt_at),
    nextAttemptAt: waitingForTunnel ? null : iso(row?.next_attempt_at),
    waitingForTunnel,
    lastError: row?.last_error ?? null,
    confirmedAt: iso(row?.confirmed_at),
    decidedAt: iso(row?.decided_at),
    method: row?.method ?? null,
    snapshotId: row?.snapshot_id === null || row?.snapshot_id === undefined ? null : String(row.snapshot_id),
    renderMatchesCompile: row?.render_matches_compile ?? null,
    differenceCount: row?.difference_count ?? null,
    differences: jsonOf<ConformityDifference[]>(row?.differences, []),
    excluded: jsonOf<ConformityExcluded | null>(row?.excluded, null),
    planSummary: jsonOf<Record<string, unknown> | null>(row?.plan_summary, null),
    maxAttempts: MAX_ATTEMPTS,
  };
}

/**
 * The view for a caller who may read devices but not configuration
 * (CONFIG_READ is distinct from DEVICE_READ so configuration can be withheld):
 * the verdict, its reason and the kind and operation of each difference stay;
 * semantic keys, field values, the exclusion list and the snapshot go.
 */
export function withoutConfigDetail(view: ConformityView): ConformityView {
  return {
    ...view,
    configDetail: false,
    snapshotId: null,
    differences: view.differences.map((d) => ({ op: d.op, resource: d.resource, semKey: '', fields: [], values: [], reason: '' })),
    excluded: null,
    planSummary: null,
  };
}

/**
 * For the Sites list: the latest check of each site's bench devices that
 * ended in a state a human must look at. Tenant-scoped.
 */
export async function conformityAnomaliesBySite(
  tenantId: number,
  siteIds: readonly number[],
): Promise<Map<number, Array<{ deviceId: number; state: ConformityState; reasonCode: string | null; differenceCount: number | null }>>> {
  const out = new Map<number, Array<{ deviceId: number; state: ConformityState; reasonCode: string | null; differenceCount: number | null }>>();
  if (siteIds.length === 0) return out;
  const rows = (await db(`${T} as c`)
    .join('bench_provisionings as b', 'b.id', 'c.provisioning_id')
    .join('devices as d', function joinDevice(this: Knex.JoinClause) {
      this.on('d.id', '=', 'c.device_id').andOn('d.tenant_id', '=', 'c.tenant_id');
    })
    .where('c.tenant_id', tenantId)
    .whereIn('b.site_id', siteIds as number[])
    .whereIn('c.state', ['non_conformant', 'anomaly'])
    .where('d.status', 'pending')
    .whereRaw('b.id = (SELECT b2.id FROM bench_provisionings b2 WHERE b2.device_id = c.device_id ORDER BY b2.compiled_at DESC, b2.id DESC LIMIT 1)')
    .select('b.site_id', 'c.device_id', 'c.state', 'c.reason_code', 'c.difference_count')) as Array<{
      site_id: number; device_id: number; state: ConformityState; reason_code: string | null; difference_count: number | null;
    }>;
  for (const r of rows) {
    const list = out.get(Number(r.site_id)) ?? [];
    list.push({ deviceId: Number(r.device_id), state: r.state, reasonCode: r.reason_code, differenceCount: r.difference_count });
    out.set(Number(r.site_id), list);
  }
  return out;
}

// ============================================================================
// Triggers — leader only
// ============================================================================

const scheduled = new Map<number, { timer: NodeJS.Timeout; done: Promise<void> }>();
let stopping = false;

/**
 * The session-up listener (registered by `startAutoConfirmRuntime`). A NEW
 * session for a candidate schedules a check after `firstContactDelayMs`.
 */
export async function handleSessionUp(event: PppSessionUpEvent): Promise<void> {
  if (stopping || !deps.enabled() || !deps.isLeader()) return;
  const device = await loadDeviceFacts(event.tenantId, event.deviceId);
  if (!device || device.status !== 'pending') return;
  const prov = await loadLatestProvisioning(event.tenantId, event.deviceId);
  if (!prov || !isCandidateOutcome(prov.outcome)) return;
  const delaySecs = deps.firstContactDelayMs / 1000;
  await ensureRow(prov, delaySecs);
  // A box that comes back while waiting on a long backoff is looked at again
  // soon: a new session is new evidence.
  await db(T)
    .where({ provisioning_id: prov.id, state: 'waiting' })
    .andWhere((w) => {
      void w.whereNull('next_attempt_at').orWhere('next_attempt_at', '>', dbIn(delaySecs));
    })
    .update({ next_attempt_at: dbIn(delaySecs), updated_at: db.fn.now() });
  schedule(event.tenantId, event.deviceId, deps.firstContactDelayMs);
}

function schedule(tenantId: number, deviceId: number, delayMs: number): void {
  if (scheduled.has(deviceId)) return;
  let resolveDone: () => void = () => undefined;
  const done = new Promise<void>((r) => { resolveDone = r; });
  const timer = setTimeout(() => {
    void (async () => {
      try {
        if (!stopping && deps.isLeader()) await checkDevice(tenantId, deviceId, 'event');
      } catch (err) {
        logger.warn({ err, deviceId }, 'Scheduled conformity check failed');
      } finally {
        scheduled.delete(deviceId);
        resolveDone();
      }
    })();
  }, Math.max(0, delayMs));
  timer.unref?.();
  scheduled.set(deviceId, { timer, done });
}

export interface SweepSummary { skipped: 'not_leader' | 'disabled' | null; candidates: number; ran: number }

/**
 * The correction pass: every candidate whose session is up and whose check is
 * due, including those whose session-up event was missed (a restart, a lost
 * `listen`). Leader only.
 */
export async function sweepAutoConfirm(): Promise<SweepSummary> {
  if (!deps.enabled()) return { skipped: 'disabled', candidates: 0, ran: 0 };
  if (stopping || !deps.isLeader()) return { skipped: 'not_leader', candidates: 0, ran: 0 };
  const rows = (await db('devices as d')
    .joinRaw(
      'JOIN LATERAL (SELECT b.id, b.outcome FROM bench_provisionings b WHERE b.device_id = d.id ' +
        'ORDER BY b.compiled_at DESC, b.id DESC LIMIT 1) lp ON true',
    )
    .leftJoin(`${T} as c`, 'c.provisioning_id', 'lp.id')
    .where('d.status', 'pending')
    .whereIn('lp.outcome', ['applied', 'compiled'])
    .whereExists(function openSession(this: Knex.QueryBuilder) {
      void this.select(db.raw('1')).from('ppp_sessions as s')
        .whereRaw('s.ppp_username = d.ppp_username')
        .whereRaw('s.concentrator_id = d.concentrator_id')
        .whereNull('s.ended_at');
    })
    .andWhere((w) => {
      void w.whereNull('c.id').orWhere((c) => {
        void c.where('c.state', 'waiting')
          .andWhere((n) => { void n.whereNull('c.next_attempt_at').orWhere('c.next_attempt_at', '<=', db.fn.now()); })
          .andWhere((n) => {
            void n.whereNull('c.claimed_at').orWhereRaw('c.claimed_at < now() - make_interval(secs => ?)', [CLAIM_LEASE_SEC]);
          });
      });
    })
    .orderBy('d.id')
    .limit(SWEEP_BATCH)
    .select('d.id as device_id', 'd.tenant_id as tenant_id')) as Array<{ device_id: number; tenant_id: number }>;

  const limit = pLimit(SWEEP_CONCURRENCY);
  let ran = 0;
  await Promise.all(rows.map((r) => limit(async () => {
    if (stopping || !deps.isLeader()) return;
    try {
      const res = await checkDevice(Number(r.tenant_id), Number(r.device_id), 'sweep');
      if (res.ran) ran++;
    } catch (err) {
      logger.warn({ err, deviceId: r.device_id }, 'Conformity sweep: one device failed');
    }
  })));
  return { skipped: null, candidates: rows.length, ran };
}

/** Session-up events still being looked up (before `schedule`). */
const pendingEvents = new Set<Promise<void>>();

function trackEvent(event: PppSessionUpEvent): Promise<void> {
  const p = handleSessionUp(event)
    .catch((err) => logger.warn({ err, deviceId: event.deviceId }, 'Conformity session-up handling failed'))
    .finally(() => { pendingEvents.delete(p); });
  pendingEvents.add(p);
  return p;
}

/** Wait for every event, scheduled and running check. For shutdown and the
 *  harness. */
export async function flushAutoConfirm(): Promise<void> {
  while (pendingEvents.size > 0 || scheduled.size > 0 || inFlight.size > 0) {
    await Promise.allSettled([
      ...pendingEvents,
      ...[...scheduled.values()].map((s) => s.done),
      ...inFlight.values(),
    ]);
  }
}

// ============================================================================
// Runtime
// ============================================================================

let unsubscribeLeader: (() => void) | null = null;
let unsubscribePresence: (() => void) | null = null;
let sweepTimer: NodeJS.Timeout | null = null;
let sweeping: Promise<unknown> | null = null;

function startSweep(): void {
  if (sweepTimer) return;
  const tick = (): void => {
    if (sweeping) return;
    sweeping = sweepAutoConfirm()
      .catch((err) => logger.warn({ err }, 'Conformity sweep failed'))
      .finally(() => { sweeping = null; });
  };
  sweepTimer = setInterval(tick, SWEEP_INTERVAL_MS);
  sweepTimer.unref?.();
  tick();
}

function stopSweep(): void {
  if (sweepTimer) clearInterval(sweepTimer);
  sweepTimer = null;
  for (const s of scheduled.values()) clearTimeout(s.timer);
  scheduled.clear();
}

/** Wire the listener and the sweep to leadership. Idempotent. Not armed at
 *  all when the installation switched the feature off. */
export function startAutoConfirmRuntime(): void {
  if (unsubscribeLeader) return;
  if (!deps.enabled()) {
    logger.warn(`Automatic conformity check of bench devices is OFF (${AUTO_CONFIRM_ENV}=false): every bench device waits for a human`);
    return;
  }
  stopping = false;
  unsubscribePresence = onPppSessionUp((event) => trackEvent(event));
  unsubscribeLeader = leaderElection.onChange((leader) => {
    if (leader) startSweep();
    else stopSweep();
  });
  logger.info('Automatic conformity check of bench devices wired to leadership');
}

export async function stopAutoConfirmRuntime(): Promise<void> {
  stopping = true;
  unsubscribeLeader?.();
  unsubscribeLeader = null;
  unsubscribePresence?.();
  unsubscribePresence = null;
  stopSweep();
  if (sweeping) await sweeping;
  await Promise.allSettled([...pendingEvents, ...inFlight.values()]);
}

/** Harness only: re-arm after a stop without the leadership wiring. */
export function resetAutoConfirmRuntimeForTests(): void {
  stopping = false;
}
