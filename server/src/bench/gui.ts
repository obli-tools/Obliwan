import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { execPath } from 'node:process';
import { loadBenchConfig, normaliseBenchUrl, type BenchConfig } from './config';
import {
  BenchStation,
  describeStation,
  stationUrlKey,
  STATION_POLL_PENDING_MS,
  STATION_POLL_UNREACHABLE_MS,
  type StationStatus,
} from './station';
import { networkInterfaces } from 'node:os';
import { spawn } from 'node:child_process';
import { BenchApi, BenchApiError, type BenchBox, type BenchCompiled, type BenchLocalCheck, type BenchPlan } from './benchApi';
import {
  discoverCandidates,
  discoverOnAddresses,
  isUnicastMac,
  macOffset,
  normalizeMac,
  type MndpCandidate,
  type MndpNeighbour,
} from './mndp';
import {
  FACTORY_ADDRESS,
  ipv4InSubnet,
  planBoxRoute,
  readBenchSlots,
  type BenchSlot,
  type SlotReading,
} from './slots';
import {
  applyFactoryProvisioning,
  COMPILED_FILE_NAME_PATTERN,
  DEVICE_MODE_ACTIVATION_MS,
  FactoryProvisioningError,
  identifyFactoryBox,
  PROVISION_TAG_PATTERN,
  PROVISIONING_STEP_LABELS,
  requestDeviceModeUpdate,
  sha256Hex,
  SIM_RETRY_MS,
  SIM_WAIT_BUDGET_MS,
  type CompiledProvisioningFile,
  type DialFn,
  type FactoryBoxIdentification,
  type ProvisioningStep,
  type SftpUploadFn,
  type SimCardReading,
  type SimReadReport,
  type SimWaitFor,
} from './routerosApply';
import {
  ALWAYS_NEEDED,
  blockedFeatures,
  deviceModeExplanation,
  featureList,
  featuresUsedBy,
  featureVerdict,
} from './deviceModeGate';
import { BoxWaitError, frenchDuration, waitForBox } from './boxWait';
import { RouterOsUpgradeError, upgradeRouterOs, type DownloadFn } from './routerosUpgrade';
import { sftpUploadOverSsh } from './sftp';
import { applyUpdate, checkForUpdate, currentVersion, type UpdateCheck } from './selfUpdate';
import { appendHistory, defaultHistoryFile, todaysHistory, type HistoryEntry } from './history';
import { PAGE } from './ui';
import {
  claimInstance,
  flashWindow,
  instanceLockPath,
  logError,
  openAppWindow,
  showMessageBox,
  WindowWatch,
  type InstanceLock,
  type WindowMode,
} from './window';

// Moved to slots.ts with the bench links; still importable from here.
export { boxesAnnouncing, ipv4InSubnet } from './slots';

/**
 * ObliWAN bench — the application: a gated local server and its window.
 *
 * ┌─ NOTHING BEFORE THE AUTHORISATION ───────────────────────────────────────┐
 * │ The old form read any router on the LAN with a family, a port and a     │
 * │ factory account, before the workstation was authorised by anyone. Now   │
 * │ the order is fixed and enforced HERE, in this process, not merely hidden │
 * │ in the page:                                                            │
 * │   1. no ObliWAN address known → the only screen asks for it;            │
 * │   2. the workstation registers (station.ts) and, until an administrator │
 * │      approves it, the only screen says so, with the name and the code;  │
 * │   3. revoked → a blocking screen.                                       │
 * │ Every router-facing route (find, device-mode, upgrade, prepare) re-asks │
 * │ the platform                                                            │
 * │ (`GET /api/bench/stations/me`) right before it touches a router and     │
 * │ answers 403 without dialling unless the answer is `approved`. Tenants,  │
 * │ sites and plan are refused here on the LAST KNOWN state. Compile is     │
 * │ reached only through prepare, i.e. after that live check. Result is     │
 * │ not checked here at all: it reports a run that was allowed, and if the  │
 * │ station was revoked meanwhile the platform refuses it. The platform     │
 * │ refuses all five itself anyway (`requireApprovedBenchStation`). The     │
 * │ address may be changed only when it is not the administrator's          │
 * │ (`urlEditable`).                                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE CLERK'S PATH, AND WHAT EACH STEP PROVES ────────────────────────────┐
 * │ find:    a MAC (any notation) and the factory password. MNDP says where │
 * │          to dial (`discoverCandidates`), the advanced address is the    │
 * │          fallback, and `identifyFactoryBox` REFUSES unless the typed MAC │
 * │          is one of the box's own. Two boxes announcing the bench address │
 * │          stop the search before any dial; a box NOT in its factory state │
 * │          (renamed, another account than admin, an IP address added, or  │
 * │          those three unreadable — `factoryStateFindings`) is refused —  │
 * │          nothing destructive is offered for it. It also reads           │
 * │          model, serial, version, Wi-Fi stack, device-mode and packages.  │
 * │ plan:    the server's plan for the chosen site and this box. When       │
 * │          nothing fits ONLY because RouterOS is too old, the plan offers  │
 * │          the upgrade (`routerosUpgrade.ts`), after which it is asked    │
 * │          again. Each candidate's device-mode needs are compared with the │
 * │          box's reading HERE, before anything is committed; a denial     │
 * │          opens the device-mode wizard (request, button press, reboot,   │
 * │          MAC proof again, mode read again).                             │
 * │ prepare: the box is proven still there first (a read-only MAC proof:   │
 * │          the compile commits an allocation and a concentrator account), │
 * │          then the server compiles the run-after-reset file (or a runner │
 * │          and its body); the bench refuses it unless every SHA-256 is the │
 * │          announced and its menus are allowed by the box's device-mode   │
 * │          (a refusal here keeps the box and offers the wizard), uploads  │
 * │          it as it is and resets the box (`applyFactoryProvisioning`,    │
 * │          which takes the MAC proof again on its own session), waits for │
 * │          the box to announce its NEW name over MNDP (the local check),  │
 * │          and reports the outcome to the platform. A site that already   │
 * │          has a router (the plan's `replaces`) is prepared only once the │
 * │          operator ticked its replacement: the page sends that device's  │
 * │          id, checked here against the card's plan, and the compile      │
 * │          carries it (`confirmReplaceDeviceId`).                         │
 * │ The factory password, the bench variables (a SIM PIN) and the compiled │
 * │ file stay in this process: the page is never sent any of them back.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE DEVICE-MODE TEST OVERRIDE ──────────────────────────────────────────┐
 * │ A bench driven through a remote-desktop tool has nobody to press RESET. │
 * │ Under "Options avancées" the operator may continue despite a device-    │
 * │ mode denial, after TYPING a confirmation phrase this process checks.    │
 * │ The compile then declares `deviceModeOverride`, the server must echo    │
 * │ `testOverride` (or nothing is uploaded), the result carries it, and the  │
 * │ summary says TEST in red. It changes no check of the box's identity.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ LONG OPERATIONS OUTLIVE THEIR REQUEST AND THEIR WINDOW ─────────────────┐
 * │ An upgrade, the wizard and a preparation each run for minutes. The page │
 * │ tags each one (`x-bench-op`) and its outcome is kept here (`GET         │
 * │ /api/outcome`): a request that breaks, or a window reopened meanwhile,  │
 * │ reads the outcome back instead of losing it. The page also sends them   │
 * │ DETACHED (`x-bench-async`): answered within `answerWithinMs`, else with │
 * │ 202 and read back by short polls — a browser opens about six            │
 * │ connections per host, and five held for minutes (five cards) plus the   │
 * │ event stream would leave none for the board, the progress or a click.  │
 * │ A request without that header is held to its end, as it always was.    │
 * │ Closing the window does not end the process while one runs (`runGui`): │
 * │ the window comes back once, and the process leaves only after the       │
 * │ operation.                                                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SEVERAL ROUTERS AT ONCE: CARDS ON BENCH LINKS ──────────────────────────┐
 * │ Each router in progress is a CARD: its own box, plan, operation,        │
 * │ progress and outcome (`Card`). There is no global session: every       │
 * │ router-facing route acts on the card the request names (`?card=` or     │
 * │ `x-bench-card`; none = the first card, which is the single-router path  │
 * │ the page and the harnesses always used). The gate is asked again for    │
 * │ every such request, whichever card it is for.                           │
 * │ Each box sits on its own bench link (slots.ts): MNDP says which link    │
 * │ heard the typed MAC, and every connection to that box leaves FROM that  │
 * │ link's address (`Box.localAddress`). The technician never declares a   │
 * │ link. Refused, with the card that holds it named: a MAC another card    │
 * │ holds (or the same box under another of its MACs), a site another card │
 * │ holds, a link another card's box is on.                                 │
 * │ A hold on a link is judged on what MNDP hears NOW, not only on where a  │
 * │ card's box was found: an idle card's box heard on another link is moved │
 * │ there (cables swapped), and an idle card whose box is not heard on its │
 * │ link while another box is holds nothing; when a search then proves     │
 * │ another box on that link, the idle card is told its router is gone.   │
 * │ A card's link going DOWN is watched (`sampleLinks`): during a write it  │
 * │ is an unplugged box (red, « la préparation recommencera »); during a   │
 * │ reboot it turns red only past `unplugAfterMs`, and the wait is          │
 * │ lengthened by the time the link spent down, so that a box plugged in   │
 * │ again on its port is still waited for (« la préparation reprendra »).  │
 * │ Once red, the card offers « Abandonner » (`/api/cards/abandon`): the   │
 * │ wait ends at its next attempt instead of up to `maxUnplugPauseMs`      │
 * │ later. Only an adapter cabled straight to the box sees a cable pulled  │
 * │ (slots.ts); behind a VLAN switch the link never goes down.              │
 * │ A card that starts needing the technician — a press, an outcome, an    │
 * │ error — bumps `attention`: the page beeps, and the window flashes in   │
 * │ the taskbar (`flashWindow`).                                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

const DEFAULT_BENCH_ADDRESS = FACTORY_ADDRESS;
const DEFAULT_ACCOUNT = 'admin';
const DEFAULT_API_PORT = 8728;
const APPROVED_RECHECK_MS = 60_000;
const BODY_LIMIT = 64 * 1024;
const NOT_APPROVED = 'Ce poste n\'est pas autorisé par ObliWAN : aucun routeur ne peut être lu ni préparé.';
/** What the operator types to continue despite a device-mode denial (test). */
export const OVERRIDE_PHRASE = 'CONTINUER EN TEST';
/** The name every RouterOS box carries out of the factory. */
const FACTORY_IDENTITY = 'MikroTik';

/** Every wait of the application, injectable for the harnesses. */
export interface BenchTiming {
  /** The RouterOS upgrade's reboot (download included for the fallback). */
  rebootWaitMs: number;
  /** MikroTik's device-mode activation window. */
  deviceModeWindowMs: number;
  /** How long past the window the request is kept open before it is dropped. */
  deviceModeGraceMs: number;
  /** After the window or the press: how long the box may take to come back. */
  deviceModeRebootMs: number;
  /** After the reset: how long the new name may take to be announced. */
  localCheckMs: number;
  /** Between two attempts of any of the waits above. */
  pollMs: number;
  /** How long a box's link may stay down during a REBOOT before its card
   *  says it may be unplugged (a reboot takes the link down too). */
  unplugAfterMs: number;
  /** At most this much link-down time is added to a wait's deadline. */
  maxUnplugPauseMs: number;
  /** How often the links are read and the cards' needs judged. */
  watchMs: number;
  /** A long request the page sent detached (`x-bench-async`): answered with
   *  its result if it ends this soon, else with « still running » (202). */
  answerWithinMs: number;
  /** Before the upload: how long the SIM read may wait for a modem that has
   *  just booted, and the pause between two reads (`readSimCard`). */
  simWaitMs: number;
  simRetryMs: number;
}
const DEFAULT_TIMING: BenchTiming = {
  rebootWaitMs: 8 * 60_000,
  deviceModeWindowMs: DEVICE_MODE_ACTIVATION_MS,
  deviceModeGraceMs: 30_000,
  deviceModeRebootMs: 3 * 60_000,
  localCheckMs: 7 * 60_000,
  pollMs: 5_000,
  unplugAfterMs: 150_000,
  maxUnplugPauseMs: 30 * 60_000,
  watchMs: 1_000,
  answerWithinMs: 5_000,
  simWaitMs: SIM_WAIT_BUDGET_MS,
  simRetryMs: SIM_RETRY_MS,
};
/** Router cards open at once, at most. */
const MAX_CARDS = 16;
/** Two taskbar flashes at least this far apart. */
const FLASH_GAP_MS = 3_000;
/** What the page's <title> always contains (the flash finds the window by it). */
const TITLE_PART = 'Préparation des routeurs';

export interface BenchAppHooks {
  /** A second launch asked for the window: open it again. */
  reopen?: () => void;
  /** The update installer started: the application must get out of its way. */
  exit?: () => void;
}

export interface BenchAppDeps {
  config?: BenchConfig;
  /** The station file; default `%APPDATA%\ObliWAN\bench-station.json`. */
  stationFile?: string;
  /** Where to dial for a MAC. Default: MNDP (`discoverCandidates`, 4 s). */
  discover?: (mac: string) => Promise<MndpCandidate | null>;
  /** The same search with every neighbour heard (two boxes on the bench
   *  address), on the bench links given (each neighbour tagged with the
   *  `localAddress` that heard it; none given: a wildcard listen). Default:
   *  MNDP (`discoverOnAddresses`, or `discoverCandidates` with no link);
   *  built from `discover` (no neighbours) when only that one is injected. */
  discoverAll?: (mac: string, slots: BenchSlot[]) => Promise<{ candidate: MndpCandidate | null; neighbours: MndpNeighbour[] }>;
  /** This PC's bench links and which interfaces are up. Default: `readBenchSlots()`. */
  slots?: () => SlotReading;
  /** Flash the window: a card needs the technician. Default: `flashWindow`. */
  flash?: () => void;
  dial?: DialFn;
  /** Default `sftpUploadOverSsh`; `null` turns the SFTP fallback off. */
  sftpUpload?: SftpUploadFn | null;
  /** RouterOS packages (upgrade). Default: HTTPS from download.mikrotik.com. */
  download?: DownloadFn;
  /** Default %LOCALAPPDATA%\ObliWAN\bench-cache\routeros; null: no cache. */
  packageCacheDir?: string | null;
  /** One ICMP echo to the new LAN (local check), from `source`. Default: `ping`. */
  ping?: (ip: string, source: string | null) => Promise<boolean>;
  /** This PC's IPv4 addresses. Default: `os.networkInterfaces()`. */
  localAddresses?: () => string[];
  timing?: Partial<BenchTiming>;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** Default: `checkForUpdate` against the configured URL, started at once. */
  updateCheck?: Promise<UpdateCheck> | null;
  /** The "Préparés aujourd'hui" file (history.ts); null or absent: no history
   *  (tests). `runGui` passes the real one. */
  historyFile?: string | null;
  hooks?: BenchAppHooks;
  watch?: WindowWatch;
}

interface Box {
  host: string;
  port: number;
  username: string;
  password: string;
  mac: string;
  foundVia: 'mndp' | 'address';
  /** The bench link the box was proven over: every connection to it leaves
   *  from this address (null: no link known, the OS routes). */
  localAddress: string | null;
  slot: BenchSlot | null;
  identity: FactoryBoxIdentification;
  /**
   * Device-mode features the box denies and the COMPILED file of revision
   * `revisionId` uses — set by a refusal after that compile, so that the
   * wizard asks for them too when THAT candidate is chosen again. Another
   * candidate renders another file and is not judged by this one's. The
   * plan's own needs are recomputed per candidate (`deviceModeCheck`).
   */
  blocked: { revisionId: number; features: string[]; message: string } | null;
  /**
   * What says this box was configured before (`factoryStateFindings`): empty
   * for a factory box. Not a refusal — the bench REASSIGNS routers too — but
   * the preparation, which erases it, then needs the operator's explicit
   * confirmation (`confirmWipe`), checked here and not only on the page.
   */
  previouslyConfigured: string[];
}

/**
 * What a long request ended with, kept beside the answer it sent: the page
 * tags each long request (`x-bench-op`), and when the HTTP request itself
 * breaks — a browser that gives up on a request held this long, a window
 * closed and reopened — the operation behind it did not, and its outcome is
 * read back here instead of being lost.
 */
interface OpOutcome {
  op: string;
  /** The card the operation ran on. */
  card: string;
  kind: string;
  pending: boolean;
  status: number | null;
  body: unknown;
  /** The answer went out on the request's own connection (or was read here). */
  delivered: boolean;
  finishedAt: number | null;
}
const OP_ID = /^[A-Za-z0-9_-]{8,64}$/;
/** Outcomes kept, newest last; older ones are dropped. */
const OUTCOMES_KEPT = 16;

/** What a router card runs. */
type CardOp = 'find' | 'plan' | 'prepare' | 'unlock' | 'upgrade';
/** Where a long operation is: what decides between « attendez » and
 *  « NE PAS DÉBRANCHER », and whether a link going down is an unplug. */
type CardStage = 'compile' | 'write' | 'check' | 'report' | 'reboot' | null;
/**
 * A card's colour, i.e. what the technician has to do:
 *   idle  nothing started yet          wait  the bench works: wait
 *   act   the technician must act      hold  NE PAS DÉBRANCHER
 *   ok    ready: unplug and box it     warn  finished, NOT to be shipped as is
 *   bad   an error, or unplugged
 */
export type CardTone = 'idle' | 'wait' | 'act' | 'hold' | 'ok' | 'warn' | 'bad';
const NEEDS_TECH: readonly CardTone[] = ['act', 'ok', 'warn', 'bad'];

/** What a successful preparation answered (`prepare`). */
interface PrepareSummary {
  deviceId: number | null;
  reset: string;
  concentrator: BenchCompiled['concentrator'];
  resultRecorded: boolean;
  resultError: string | null;
  site: BenchPlan['site'];
  allocation: BenchPlan['allocation'];
  localCheck: BenchLocalCheck;
  testOverride: boolean;
  upload: { files: number; method: string };
  /** The technician gave up waiting for the local check (« Abandonner »). */
  abandoned: boolean;
  /** The compile's warnings: they refused nothing and do not stop the box
   *  being shipped (a default group the platform could not apply). */
  warnings: string[];
  /** The SIM card read in the modem before the upload; null: none found. */
  sim: SimCardReading | null;
  /** Why none was read (`simNote`); null when one was. */
  simNote: string | null;
}

/** How a card's last operation ended. */
interface CardResult {
  kind: CardOp;
  ok: boolean;
  /** The refusal, as the request answered it; null on success. */
  message: string | null;
  code: string | null;
  summary: PrepareSummary | null;
  /** The box's link was cut while it was being written to. */
  unplugged: boolean;
}

/**
 * One router in progress. Everything the single-router bench kept in ONE
 * session is here, per card: the box (with the factory password), the plan,
 * the running operation and what the page draws of it.
 */
interface Card {
  id: string;
  box: Box | null;
  plan: { siteId: number; answer: BenchPlan } | null;
  generation: number;
  busy: CardOp | null;
  /** Numbers each claimed operation (the process watch reopens the window once per operation). */
  seq: number;
  progress: string | null;
  /** Times the page draws (elapsed, countdown), on this process's clock. */
  timer: null | { since?: number; deadline?: number; countdownEndsAt?: number };
  stage: CardStage;
  /** The MAC a running search is for: no other card may look for it meanwhile. */
  macClaim: string | null;
  /** The site a running plan is for, likewise. */
  siteClaim: number | null;
  /** What the board shows, kept once the box and the plan are forgotten. */
  shown: {
    mac: string | null;
    slot: BenchSlot | null;
    site: { id: number; code: string | null; name: string } | null;
    startedAt: number | null;
    endedAt: number | null;
  };
  result: CardResult | null;
  /** The box's link during the current operation (`sampleLinks`). */
  link: { downSince: number | null; downMs: number; cutInWrite: boolean };
  /** The technician gave up on an unplugged box: the running wait ends at
   *  its next attempt. Cleared when the next operation is claimed. */
  abandoned: boolean;
  /** Bumped each time the card starts needing the technician. */
  attention: number;
  lastTone: CardTone | null;
  lastBusy: CardOp | null;
}

/**
 * What says a box is NOT straight out of the factory — one French clause per
 * finding, for the refusal. A factory MikroTik holds the name `MikroTik`, the
 * single account `admin`, and no IP address but the default configuration's
 * (commented `defconf`) or a dynamic one (its DHCP client). One more address
 * is let through: the one the bench dialled, which somebody may have put by
 * hand on a model shipped without a default configuration so that the bench
 * can reach it.
 *
 * A heuristic, and only that: a box configured without touching its name,
 * its accounts or its addresses (a PPPoE client on the default LAN, say)
 * passes it, and the reset then erases it; the summary's "sera entièrement
 * effacé" stays the last warning for that case.
 */
export function factoryStateFindings(
  identity: Pick<FactoryBoxIdentification, 'systemIdentity' | 'userNames' | 'addresses'>
    & { router?: { model: string | null; board: string | null } },
  dialled: string,
): string[] {
  const out: string[] = [];
  if (identity.systemIdentity !== null && !isFactoryIdentity(identity.systemIdentity, identity.router)) {
    out.push(`il porte le nom « ${identity.systemIdentity.slice(0, 60)} »`);
  }
  const users = identity.userNames ?? [];
  if (users.includes('obliwan')) out.push('il contient déjà le compte d\'ObliWAN');
  const others = users.filter((u) => u !== 'admin' && u !== 'obliwan');
  if (others.length) {
    out.push(`il contient d'autres comptes que « admin » (${others.slice(0, 3).map((u) => `« ${u.slice(0, 30)} »`).join(', ')})`);
  }
  const added = (identity.addresses ?? []).filter((a) => !a.dynamic && a.comment !== 'defconf' && a.address.split('/')[0] !== dialled);
  if (added.length) {
    out.push(`il porte des adresses IP ajoutées après sa sortie d'usine (${added.slice(0, 3).map((a) => a.address.slice(0, 43)).join(', ')})`);
  }
  return out;
}

/**
 * A name a box can hold straight after a reset: `MikroTik`, or its own model.
 * Observed 2026-10-03 on a Chateau after `reset-configuration no-defaults=yes`
 * and an upgrade to 7.24.5: the identity came back as `D53G`, the head of its
 * RouterBOARD model code (`D53G-…`). The box's OWN model or board name says
 * nothing about a previous owner; any other name still refuses.
 */
function isFactoryIdentity(name: string, router?: { model: string | null; board: string | null }): boolean {
  const n = name.trim().toLowerCase();
  if (n === FACTORY_IDENTITY.toLowerCase()) return true;
  if (!router || n === '') return false;
  const model = (router.model ?? '').trim().toLowerCase();
  const board = (router.board ?? '').trim().toLowerCase();
  return (model !== '' && (n === model || model.startsWith(`${n}-`))) || (board !== '' && n === board);
}

/** What may go in `localCheck.mndpIdentity`: printable ASCII, 255 at most —
 *  the platform refuses the whole report otherwise (compile.service.ts
 *  `parseLocalCheck`). An identity is free UTF-8 on the wire: anything else is
 *  shown as `?`, and the comparison is made on the name as heard. */
export function wireIdentity(name: string | null): string | null {
  if (name === null) return null;
  const t = name.replace(/[^\x20-\x7e]/g, '?').trim().slice(0, 255);
  return t === '' ? null : t;
}

/** What a card says while the SIM read waits for the modem (`readSimCard`). */
export const SIM_WAIT_TEXT: Record<SimWaitFor, string> = {
  lte1: 'Lecture de la carte SIM : le modem du routeur n\'est pas encore apparu',
  card: 'Lecture de la carte SIM : le modem n\'a pas encore présenté de carte',
  answer: 'Lecture de la carte SIM : le modem ne répond pas encore',
};

/** Why no ICCID was read, in the technician's words; null when one was.
 *  Factual, never an instruction: no SIM is never a reason to hold a box. */
export function simNote(r: Omit<SimReadReport, 'sim'>): string | null {
  switch (r.outcome) {
    case 'read': return null;
    case 'no-modem': return 'ce routeur n\'a pas de modem lte1';
    case 'no-lte1': return `aucun modem lte1 n'est apparu en ${frenchDuration(r.waitedMs)} d'attente`;
    case 'no-card': return `le modem lte1 n'a présenté aucune carte en ${frenchDuration(r.waitedMs)} d'attente`;
    case 'no-answer': return `le modem n'a pas répondu en ${frenchDuration(r.waitedMs)} d'attente`;
  }
}

/** One ICMP echo, Windows `ping` (a reply carries `TTL=`; an "unreachable"
 *  relayed by a gateway exits 0 on Windows and carries none), sent FROM
 *  `source` (`-S` on Windows, `-I` elsewhere) so that it leaves by the
 *  interface holding that address rather than by whichever route wins. */
function defaultPing(ip: string, source: string | null): Promise<boolean> {
  return new Promise((resolve) => {
    const win = process.platform === 'win32';
    let out = '';
    const from = source ? (win ? ['-S', source] : ['-I', source]) : [];
    try {
      const child = spawn('ping', win ? ['-n', '1', '-w', '1500', ...from, ip] : ['-c', '1', '-W', '2', ...from, ip], { windowsHide: true });
      child.stdout?.on('data', (d: Buffer) => { out += d.toString('latin1'); });
      child.on('error', () => resolve(false));
      child.on('exit', (code) => resolve(code === 0 && /ttl=/i.test(out)));
    } catch {
      resolve(false);
    }
  });
}

function defaultLocalAddresses(): string[] {
  return Object.values(networkInterfaces()).flatMap((list) =>
    (list ?? []).filter((a) => a.family === 'IPv4' && !a.internal).map((a) => a.address));
}

type Phase = 'need-url' | 'checking' | StationStatus['state'];

class HttpError extends Error {
  constructor(readonly status: number, message: string, readonly extra: Record<string, unknown> = {}) {
    super(message);
  }
}

const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

function tokenMatches(supplied: unknown, token: string): boolean {
  if (typeof supplied !== 'string' || supplied.length !== token.length) return false;
  return timingSafeEqual(Buffer.from(supplied), Buffer.from(token));
}

const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS });
  res.end(JSON.stringify(body));
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > BODY_LIMIT) throw new HttpError(413, 'Requête trop volumineuse.');
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return {};
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    throw new HttpError(400, 'Requête illisible.');
  }
}

function positiveInt(v: unknown): number | null {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  return typeof n === 'number' && Number.isInteger(n) && n > 0 ? n : null;
}

export interface BenchApp {
  readonly server: Server;
  readonly token: string;
  readonly watch: WindowWatch;
  listen(): Promise<number>;
  url(): string;
  setWindow(mode: WindowMode, detail: string | null): void;
  /** The operation running on a router, if any (`seq` numbers each one). */
  busy(): { seq: number; kind: string } | null;
  close(): Promise<void>;
}

/** The local server, with every dependency injectable for the harnesses. */
export function createBenchApp(deps: BenchAppDeps = {}): BenchApp {
  const cfg = deps.config ?? loadBenchConfig();
  const token = randomBytes(24).toString('hex');
  const watch = deps.watch ?? new WindowWatch();
  const hooks = deps.hooks ?? {};
  // One MNDP round on the bench links at a time, shared by every card asking
  // meanwhile: its sockets hold each link's port 5678, which a second round
  // could only share by falling back to a port that hears no announcement.
  let linkRound: Promise<MndpNeighbour[]> | null = null;
  const discoverAll = deps.discoverAll
    ?? (deps.discover
      ? async (mac: string) => ({ candidate: await deps.discover!(mac), neighbours: [] as MndpNeighbour[] })
      : async (mac: string, slots: BenchSlot[]) => {
        if (slots.length === 0) {
          const r = await discoverCandidates(mac, { timeoutMs: 4_000 });
          return { candidate: r.candidates[0] ?? null, neighbours: r.discovery.neighbours };
        }
        const round = linkRound ?? (linkRound = discoverOnAddresses(
          slots.map((s) => ({ address: s.address, netmask: s.netmask })),
          { timeoutMs: 2_500 },
        ).then((d) => d.neighbours).finally(() => { linkRound = null; }));
        return { candidate: null, neighbours: await round };
      });
  // A reading that FAILED (os.networkInterfaces can throw while Windows
  // changes its adapters) is not « every link is down »: the last good one
  // stands in for it, flagged `unknown`, and the link watch skips it — or it
  // would call every busy card's box unplugged, and a write « cut ».
  let lastReading: SlotReading = { slots: [], refused: [], up: [] };
  const readSlots = (): SlotReading & { unknown?: true } => {
    try {
      lastReading = deps.slots ? deps.slots() : readBenchSlots();
      return lastReading;
    } catch {
      return { ...lastReading, unknown: true };
    }
  };
  const applyDeps = { dial: deps.dial, sftpUpload: deps.sftpUpload === undefined ? sftpUploadOverSsh : deps.sftpUpload };
  const timing: BenchTiming = { ...DEFAULT_TIMING, ...(deps.timing ?? {}) };
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const ping = deps.ping ?? defaultPing;
  const localAddresses = deps.localAddresses ?? defaultLocalAddresses;
  const updateCheck = deps.updateCheck !== undefined
    ? deps.updateCheck
    : cfg.baseUrl ? checkForUpdate(cfg.baseUrl, currentVersion()) : null;
  let updateAnswer: UpdateCheck | null = null;
  void updateCheck?.then((u) => { updateAnswer = u; }).catch(() => undefined);

  let windowMode: WindowMode | null = null;
  let windowDetail: string | null = null;

  // ── the gate ───────────────────────────────────────────────────────────────
  const gate = {
    baseUrl: null as string | null,
    source: cfg.source as BenchConfig['source'] | 'typed',
    station: null as BenchStation | null,
    api: null as BenchApi | null,
    status: null as StationStatus | null,
    checkedAt: 0,
    inFlight: null as Promise<StationStatus> | null,
  };
  const useUrl = (url: string, source: BenchConfig['source'] | 'typed'): void => {
    const key = stationUrlKey(url);
    gate.baseUrl = key;
    gate.source = source;
    gate.station = BenchStation.forUrl(key, deps.stationFile ? { file: deps.stationFile } : {});
    gate.api = new BenchApi(gate.station);
    gate.status = null;
    gate.checkedAt = 0;
  };
  if (cfg.baseUrl) {
    try {
      useUrl(cfg.baseUrl, cfg.source);
    } catch {
      /* an unusable configured URL: the address screen asks */
    }
  }

  /** `shared` joins a check already on the wire; `fresh` always asks anew (a
   *  check that left before a revocation must not authorise what follows it);
   *  `renew` draws a new token after a revocation. */
  const refresh = (mode: 'shared' | 'fresh' | 'renew' = 'shared'): Promise<StationStatus> | null => {
    const station = gate.station;
    if (!station) return null;
    if (gate.inFlight && mode === 'shared') return gate.inFlight;
    const p = (mode === 'renew' ? station.renew() : station.status()).then((s) => {
      if (gate.station === station) {
        gate.status = s;
        gate.checkedAt = Date.now();
      }
      return s;
    }).finally(() => {
      if (gate.inFlight === p) gate.inFlight = null;
    });
    gate.inFlight = p;
    return p;
  };

  const pollEvery = (s: StationStatus | null): number => {
    if (!s) return 0;
    if (s.state === 'pending') return STATION_POLL_PENDING_MS;
    if (s.state === 'approved' || s.state === 'revoked') return APPROVED_RECHECK_MS;
    return STATION_POLL_UNREACHABLE_MS;
  };
  const poller = setInterval(() => {
    if (!gate.station || gate.inFlight) return;
    if (Date.now() - gate.checkedAt >= pollEvery(gate.status)) void refresh();
  }, 1_000);
  poller.unref();
  void refresh();

  // The tool's OWN update, asked again while it runs — not only at start-up.
  // A bench left open across a release, or reopened within the 15 s its
  // process outlives its window (window.ts), never saw the new version
  // (observed 2026-10-03). Re-asked every UPDATE_RECHECK_MS, and at once
  // when the URL in use changes (typed by the operator, say). An injected
  // check (tests) is used as given and never repeated.
  const UPDATE_RECHECK_MS = 20 * 60_000;
  let updateAskedAt = deps.updateCheck !== undefined ? Infinity : Date.now();
  let updateAskedOf = deps.updateCheck !== undefined ? null : cfg.baseUrl;
  const updatePoller = setInterval(() => {
    if (deps.updateCheck !== undefined) return;
    const url = gate.baseUrl ?? cfg.baseUrl;
    if (!url) return;
    if (url === updateAskedOf && Date.now() - updateAskedAt < UPDATE_RECHECK_MS) return;
    updateAskedAt = Date.now();
    updateAskedOf = url;
    void checkForUpdate(url, currentVersion()).then((u) => { updateAnswer = u; }).catch(() => undefined);
  }, 60_000);
  updatePoller.unref();

  const phase = (): Phase => {
    if (!gate.station) return 'need-url';
    if (!gate.status) return 'checking';
    return gate.status.state;
  };

  /** For router-facing routes: ask the platform NOW, refuse unless approved. */
  const requireApprovedLive = async (): Promise<BenchApi> => {
    const s = await refresh('fresh');
    if (!s || s.state !== 'approved' || !gate.api) {
      throw new HttpError(403, `${NOT_APPROVED} ${s ? describeStation(s) : 'L\'adresse d\'ObliWAN n\'est pas connue.'}`, { gate: true });
    }
    return gate.api;
  };
  /**
   * May the address be changed from the window? Only while the station is not
   * approved, never once it is revoked, and never when the address came from
   * the installer or the environment: that address is the administrator's, and
   * if the person the gate constrains could repoint it, any server answering
   * `approved` would open every router route. A typed or remembered address is
   * the preparer's own already (deleting the station file does the same), so
   * changing it gives nothing away. With no usable address at all (need-url,
   * including an installer value that is not a URL) there is nothing to
   * protect and the address screen is the only one.
   */
  const urlEditable = (): boolean => {
    const p = phase();
    if (p === 'need-url') return true;
    return gate.source !== 'installer' && gate.source !== 'environment' && p !== 'approved' && p !== 'revoked';
  };
  /** For platform routes: the last known state (the platform checks again). */
  const requireApproved = (): BenchApi => {
    if (phase() !== 'approved' || !gate.api) throw new HttpError(403, NOT_APPROVED, { gate: true });
    return gate.api;
  };
  /** A platform refusal of THIS station changes what the window must show. */
  const platformError = (err: unknown): never => {
    if (err instanceof BenchApiError) {
      if (err.kind === 'station') void refresh();
      // 'local' is this workstation's fault, not a bad gateway: 500.
      const status = err.kind === 'station' ? 403 : err.kind === 'local' ? 500 : err.kind === 'refused' && err.status && err.status < 500 ? 422 : 502;
      // The one refusal this PC causes by its CLOCK (the device-mode reading
      // is stamped on it): say what to fix, which the platform cannot know.
      const clock = err.kind === 'refused' && /observedAt/.test(err.message)
        ? ' Vérifiez la date et l\'heure de ce poste (Paramètres Windows > Heure et langue > « Régler l\'heure automatiquement »), puis recommencez.'
        : '';
      throw new HttpError(status, `${err.message}${clock}`, { gate: err.kind === 'station' });
    }
    throw err;
  };

  // ── the cards: one per router in progress ──────────────────────────────────
  const cards = new Map<string, Card>();
  let nextCard = 1;
  /** Numbers every claimed operation, across the cards. */
  let opSeq = 0;
  const newCard = (): Card => {
    const c: Card = {
      id: String(nextCard++),
      box: null,
      plan: null,
      generation: 0,
      busy: null,
      seq: 0,
      progress: null,
      timer: null,
      stage: null,
      macClaim: null,
      siteClaim: null,
      shown: { mac: null, slot: null, site: null, startedAt: null, endedAt: null },
      result: null,
      link: { downSince: null, downMs: 0, cutInWrite: false },
      abandoned: false,
      attention: 0,
      lastTone: null,
      lastBusy: null,
    };
    cards.set(c.id, c);
    return c;
  };
  /** The card a request names nothing for: the first one (the single-router
   *  path, and the harnesses that drive it). */
  const defaultCard = (): Card => cards.values().next().value ?? newCard();
  defaultCard();
  const cardFor = (req: IncomingMessage, url: URL): Card => {
    const h = req.headers['x-bench-card'];
    const id = (typeof h === 'string' && h.trim() !== '' ? h : url.searchParams.get('card') ?? '').trim();
    if (id === '') return defaultCard();
    const c = cards.get(id);
    if (!c) throw new HttpError(404, 'Cette carte n\'existe plus (l\'application a peut-être redémarré) : fermez puis rouvrez la fenêtre.', { code: 'NO_CARD' });
    return c;
  };
  /** « la carte n°2 (Prise 12) » — how a message names another card. */
  const cardName = (c: Card): string => {
    const slot = c.box?.slot ?? c.shown.slot;
    return `la carte n°${c.id}${slot ? ` (${slot.label})` : ''}`;
  };
  const busyCards = (): Card[] => [...cards.values()].filter((c) => c.busy !== null);

  const forget = (card: Card): void => {
    card.box = null;
    card.plan = null;
    card.generation++;
  };
  const claimBusy = (card: Card, what: CardOp): void => {
    if (card.busy) throw new HttpError(409, 'Une opération est déjà en cours sur ce routeur : attendez qu\'elle se termine.');
    card.busy = what;
    card.seq = ++opSeq;
    card.stage = null;
    card.result = null;
    card.link = { downSince: null, downMs: 0, cutInWrite: false };
    card.abandoned = false;
  };
  /** A failed operation, as the board shows it until the next one. */
  const failed = (card: Card, kind: CardOp, err: unknown, unplugged = false): void => {
    card.result = {
      kind,
      ok: false,
      message: err instanceof Error ? err.message : String(err),
      code: err instanceof HttpError && typeof err.extra.code === 'string' ? err.extra.code : null,
      summary: null,
      unplugged,
    };
    card.shown.endedAt = now();
  };

  // ── the links: which card's box is where, and whether its cable is in ─────
  /** A box's own interface MACs, read at its proof. */
  const ownMacs = (b: Box): Set<string> =>
    new Set([b.mac, ...b.identity.interfaceMacs.map((m) => normalizeMac(m))].filter((m): m is string => !!m));
  /** The links on which MNDP heard one of `b`'s own interfaces this round. */
  const heardAt = (b: Box, neighbours: MndpNeighbour[]): Set<string> => {
    const own = ownMacs(b);
    return new Set(neighbours.filter((n) => n.localAddress && own.has(n.mac)).map((n) => n.localAddress!));
  };
  /**
   * Which OTHER card holds that link (its name, for the message). With no
   * link (`null`): any other card holding a box, i.e. « this PC ».
   *
   * With `neighbours` (this MNDP round), an IDLE card's hold is judged on what
   * is heard now, not on where its box was found: it holds the link while its
   * box is heard there, or while nothing at all is heard there (MNDP cannot
   * say); it does not while ANOTHER box is heard there and its own is not —
   * its box was moved or set aside (a swap of two cables left both cards
   * pointing at each other's link). A BUSY card always holds its link: its
   * box may be rebooting, and a rebooting box announces nothing.
   */
  const holderOf = (self: Card, slot: BenchSlot | null, neighbours?: MndpNeighbour[]): string | null => {
    for (const c of cards.values()) {
      if (c === self || !c.box) continue;
      if (slot === null) return cardName(c);
      if (c.box.slot?.address !== slot.address) continue;
      if (c.busy || !neighbours) return cardName(c);
      if (heardAt(c.box, neighbours).has(slot.address)) return cardName(c);
      if (!neighbours.some((n) => n.localAddress === slot.address)) return cardName(c);
    }
    return null;
  };
  /**
   * Idle cards whose box MNDP hears on ONE other link than recorded: moved
   * there (cables swapped, or a box replugged elsewhere). Heard, not proven:
   * every later connection takes the MAC proof, from that link.
   */
  const followMoves = (self: Card, neighbours: MndpNeighbour[]): void => {
    for (const c of cards.values()) {
      if (c === self || c.busy || !c.box?.slot) continue;
      const at = [...heardAt(c.box, neighbours)];
      if (at.length === 1 && at[0] !== c.box.localAddress) movedTo(c, c.box, at[0]);
    }
  };
  /**
   * `self`'s search just PROVED its box on `slot`: an idle card still
   * recorded on that link has no router there any more (one box per link,
   * and its own was not heard there while another was — or `holderOf` would
   * have refused). Its box is forgotten, and its card says so instead of
   * pointing at somebody else's.
   */
  const displacedBy = (self: Card, slot: BenchSlot): void => {
    for (const c of cards.values()) {
      if (c === self || c.busy || !c.box || c.box.slot?.address !== slot.address) continue;
      const mac = c.box.mac;
      forget(c);
      c.shown.slot = null;
      c.result = {
        kind: 'find',
        ok: false,
        message: `Le routeur ${mac} n'est plus sur la ${slot.label} : ${cardName(self)} y a trouvé un autre routeur. Rien n'a été modifié. Rebranchez-le sur une prise libre, puis relancez sa recherche — ou fermez cette carte s'il a été mis de côté.`,
        code: 'MOVED',
        summary: null,
        unplugged: false,
      };
      c.shown.endedAt = now();
    }
  };
  /** How long the card's link has been down right now (0: up). */
  const downNow = (c: Card): number => (c.link.downSince === null ? 0 : now() - c.link.downSince);
  /** What a wait adds to its deadline: the link's down time in this operation. */
  const extension = (c: Card): number => Math.min(timing.maxUnplugPauseMs, c.link.downMs + downNow(c));
  /** The card's box looks unplugged: its link went down while it was being
   *  WRITTEN to, or has stayed down longer than a reboot would keep it. */
  const unplugged = (c: Card): boolean =>
    c.busy !== null && c.box?.slot != null && c.link.downSince !== null
    && (c.stage === 'write' || downNow(c) >= timing.unplugAfterMs);
  /** Reads the links once and updates every busy card's watch. */
  const sampleLinks = (): void => {
    const reading = readSlots();
    if (reading.unknown) return; // not read: nothing is known to have changed
    for (const c of cards.values()) {
      const slot = c.busy && c.box?.slot ? c.box.slot : null;
      // Up when the OS lists the card under its name, or lists the link's
      // ADDRESS on whatever card: a USB adapter that comes back under another
      // name with the same fixed address is the same link (the dials go by
      // the address).
      const up = slot === null || reading.up.includes(slot.iface) || reading.slots.some((s) => s.address === slot.address);
      if (!up && c.link.downSince === null) c.link.downSince = now();
      if (!up && c.stage === 'write') c.link.cutInWrite = true;
      if (up && c.link.downSince !== null) {
        c.link.downMs += now() - c.link.downSince;
        c.link.downSince = null;
      }
    }
  };

  /**
   * MNDP for one MAC: the candidates (closest first) and every neighbour,
   * each tagged with the link that heard it when there are links.
   */
  const hear = async (mac: string, slots: BenchSlot[]): Promise<{ candidates: MndpCandidate[]; neighbours: MndpNeighbour[] }> => {
    const r = await discoverAll(mac, slots);
    const candidates: MndpCandidate[] = r.candidate ? [r.candidate] : [];
    for (const n of r.neighbours) {
      const d = macOffset(n.mac, mac);
      if (d === null || candidates.some((c) => c.mac === n.mac && (c.localAddress ?? null) === (n.localAddress ?? null))) continue;
      candidates.push({ ...n, macOffset: d });
    }
    candidates.sort((a, b) => a.macOffset - b.macOffset);
    return { candidates, neighbours: r.neighbours };
  };
  /**
   * Where `box` is now, for the waits and the local check: a neighbour whose
   * MAC is one of the box's OWN interfaces (read at its proof) — not merely
   * one in the typed MAC's window, which on a bench of one batch also covers
   * the next box, on its own link, with another card. With no link known,
   * the closest candidate, as the single-router bench always did.
   */
  const locate = (box: Box) => async (mac: string): Promise<MndpCandidate | null> => {
    const reading = readSlots();
    const { candidates } = await hear(mac, reading.slots);
    const own = new Set(box.identity.interfaceMacs.map((m) => normalizeMac(m)));
    const mine = candidates.find((c) => own.has(c.mac));
    if (mine) return mine;
    if (reading.slots.length === 0) return candidates[0] ?? null;
    return candidates.find((c) => c.localAddress != null && c.localAddress === box.localAddress) ?? null;
  };
  /** The box was proven again over `localAddress`: that is its link now. */
  const movedTo = (card: Card, box: Box, localAddress: string | null): void => {
    if (!localAddress || localAddress === box.localAddress) return;
    box.localAddress = localAddress;
    box.slot = readSlots().slots.find((s) => s.address === localAddress) ?? box.slot;
    card.shown.slot = box.slot;
  };

  const outcomes: OpOutcome[] = [];
  const opOf = (req: IncomingMessage): string | null => {
    const raw = req.headers['x-bench-op'];
    return typeof raw === 'string' && OP_ID.test(raw) ? raw : null;
  };
  /**
   * Runs a long route and keeps what it answered under the page's operation
   * id, then answers as any route does. The record is made BEFORE the work
   * starts, so "pending" and "never arrived" (no record) stay distinct.
   *
   * Sent DETACHED (`x-bench-async: 1`, with an operation id): answered with
   * its result if it ends within `answerWithinMs`, else at once with 202
   * `{ detached: true, op }` while it goes on; the page then reads its
   * outcome by short polls. That keeps the browser's few connections per
   * host free for the board while several routers are worked on (header).
   */
  const tracked = async (req: IncomingMessage, res: ServerResponse, card: Card, kind: string, run: () => Promise<unknown>): Promise<void> => {
    const op = opOf(req);
    let rec: OpOutcome | null = null;
    if (op) {
      const i = outcomes.findIndex((o) => o.op === op);
      if (i >= 0) outcomes.splice(i, 1);
      rec = { op, card: card.id, kind, pending: true, status: null, body: null, delivered: false, finishedAt: null };
      outcomes.push(rec);
      // Oldest first — but never one still running: its page may be reading
      // it back (a detached request has no other way to learn its end).
      while (outcomes.length > OUTCOMES_KEPT) {
        const old = outcomes.findIndex((o) => !o.pending);
        if (old < 0) break;
        outcomes.splice(old, 1);
      }
      const r = rec;
      res.once('finish', () => { if (!r.pending) r.delivered = true; });
    }
    const work = run().then(
      (body) => {
        if (rec) Object.assign(rec, { pending: false, status: 200, body, finishedAt: now() });
        return { ok: true as const, body };
      },
      (err: unknown) => {
        if (rec) {
          const status = err instanceof HttpError ? err.status : 500;
          const body = err instanceof HttpError ? { error: err.message, ...err.extra } : { error: err instanceof Error ? err.message : String(err) };
          Object.assign(rec, { pending: false, status, body, finishedAt: now() });
        }
        return { ok: false as const, err };
      },
    );
    let settled: Awaited<typeof work> | null;
    if (rec && req.headers['x-bench-async'] === '1') {
      let timer: NodeJS.Timeout | undefined;
      settled = await Promise.race([
        work,
        new Promise<null>((r) => { timer = setTimeout(() => r(null), timing.answerWithinMs); }),
      ]);
      clearTimeout(timer);
      if (settled === null) {
        const id = rec.op;
        void work.then((w) => {
          if (!w.ok && !(w.err instanceof HttpError)) {
            logError(`bench ${kind} (detached): ${w.err instanceof Error ? w.err.stack ?? w.err.message : String(w.err)}`);
          }
        });
        json(res, 202, { detached: true, op: id, card: card.id });
        return;
      }
    } else {
      settled = await work;
    }
    if (settled.ok) {
      json(res, 200, settled.body);
      return;
    }
    throw settled.err; // answered by the server's own error path, as before
  };
  const release = (card: Card): void => {
    // A link cut that is still being counted ends with the operation.
    if (card.link.downSince !== null) {
      card.link.downMs += now() - card.link.downSince;
      card.link.downSince = null;
    }
    card.busy = null;
    card.progress = null;
    card.timer = null;
    card.stage = null;
  };
  const onStep = (card: Card) => (step: ProvisioningStep): void => {
    card.progress = PROVISIONING_STEP_LABELS[step];
  };

  const benchBox = (b: Box, api: BenchApi): BenchBox => ({
    brand: 'mikrotik',
    model: b.identity.router.model,
    board: b.identity.router.board,
    serial: b.identity.router.serial,
    ros_version: b.identity.router.version,
    wifi_stack: b.identity.wifiStack,
    mac: b.mac,
    deviceMode: {
      mode: b.identity.deviceMode.answered ? b.identity.deviceMode.mode : null,
      flags: b.identity.deviceMode.answered ? { ...b.identity.deviceMode.flags } : {},
      // Stamped on this PC's clock; restated on ObliWAN's when they disagree.
      observedAt: api.onServerClock(b.identity.deviceMode.observedAt),
    },
    packages: (b.identity.packages ?? []).map((p) => p.name),
    architecture: b.identity.router.architecture,
  });
  const publicBox = (b: Box) => ({
    mac: b.mac,
    address: b.host,
    foundVia: b.foundVia,
    brand: 'MikroTik',
    model: b.identity.router.model,
    board: b.identity.router.board,
    serial: b.identity.router.serial,
    version: b.identity.router.version,
    wifiStack: b.identity.wifiStack,
    deviceMode: b.identity.deviceMode.answered ? b.identity.deviceMode.mode : null,
    blocked: b.blocked,
    previouslyConfigured: b.previouslyConfigured,
    slot: b.slot ? { label: b.slot.label, iface: b.slot.iface, address: b.slot.address } : null,
  });

  /**
   * What a candidate needs from device-mode on this box, and what the box
   * denies of it: the server's list for the rendered revision (or nothing,
   * from a server that does not send one), the features every provisioning
   * needs (`ALWAYS_NEEDED`), and whatever a compile of THIS candidate
   * already found blocked.
   */
  const deviceModeCheck = (b: Box, candidate: BenchPlan['candidates'][number] | undefined) => {
    const compiled = b.blocked && candidate && b.blocked.revisionId === candidate.revisionId ? b.blocked.features : [];
    const needed = Array.from(new Set([...(candidate?.deviceModeFeatures ?? []), ...ALWAYS_NEEDED, ...compiled]));
    const blocked = blockedFeatures(b.identity.deviceMode, needed);
    return {
      revisionId: candidate?.revisionId ?? null,
      needed,
      blocked,
      message: blocked.length ? deviceModeExplanation(blocked, b.identity.deviceMode) : null,
    };
  };
  const planView = (b: Box, answer: BenchPlan) => ({
    plan: answer,
    deviceMode: answer.candidates.map((c) => deviceModeCheck(b, c)),
  });

  const state = () => {
    const s = gate.status;
    return {
      app: 'obliwan-bench',
      version: currentVersion(),
      window: { mode: windowMode, detail: windowDetail },
      baseUrl: gate.baseUrl,
      baseUrlSource: gate.source,
      urlEditable: urlEditable(),
      phase: phase(),
      station: s && (s.state === 'pending' || s.state === 'approved')
        ? { name: s.name, stationId: s.stationId, verificationCode: s.verificationCode }
        : null,
      suggestedUrl: s && s.state === 'redirected' ? s.suggestedUrl : null,
      text: s ? describeStation(s) : null,
      update: updateAnswer?.available ? { available: updateAnswer.available } : null,
      // The first card's: the single-router path reads its box here.
      box: defaultCard().box ? publicBox(defaultCard().box!) : null,
      busy: defaultCard().busy,
    };
  };

  // ── what each card shows: its colour and the ONE next action ──────────────

  /** A successful preparation: ready to box, or not to be shipped as is. */
  const preparedTone = (s: PrepareSummary): { tone: CardTone; action: string } => {
    const confirmed = s.localCheck.identityMatches === true && s.localCheck.lanReachable !== false;
    if (!confirmed && s.abandoned) return { tone: 'warn', action: 'Abandonné : débranché avant d\'avoir confirmé sa configuration. Ne l\'expédiez pas : mettez-le de côté et appelez un technicien.' };
    if (!confirmed) return { tone: 'warn', action: 'Ne l\'expédiez pas : il n\'a pas confirmé sa configuration. Mettez-le de côté et appelez un technicien.' };
    if (s.testOverride) return { tone: 'warn', action: 'TEST : ne l\'expédiez pas à un client (mode appareil non conforme).' };
    if (s.concentrator.state !== 'provisioned') return { tone: 'warn', action: 'Lisez l\'avertissement sur l\'accès au concentrateur avant de l\'expédier.' };
    return { tone: 'ok', action: 'Prêt : débranchez et mettez en carton.' };
  };
  const cardState = (c: Card): { tone: CardTone; action: string } => {
    const slot = c.box?.slot ?? c.shown.slot;
    const port = slot ? ` (${slot.label})` : '';
    if (c.busy && c.abandoned) return { tone: 'bad', action: 'Abandon demandé : attendez quelques secondes la fin de l\'opération.' };
    if (unplugged(c)) {
      return {
        tone: 'bad',
        action: c.stage === 'write'
          ? `Débranché pendant l'écriture ! Ne le mettez pas de côté : rebranchez-le sur le même port${port} ; la préparation recommencera.`
          : `Débranché ? Rebranchez-le sur le même port${port} ; la préparation reprendra.`,
      };
    }
    switch (c.busy) {
      case 'find': return { tone: 'wait', action: 'Attendez : recherche du routeur…' };
      case 'plan': return { tone: 'wait', action: 'Attendez : ObliWAN prépare le plan…' };
      case 'unlock':
        if (c.timer?.countdownEndsAt) return { tone: 'act', action: 'Appuyez UNE fois brièvement sur RESET à l\'arrière du routeur.' };
        return c.stage === 'reboot'
          ? { tone: 'hold', action: 'NE PAS DÉBRANCHER : le routeur redémarre.' }
          : { tone: 'wait', action: 'Attendez : envoi de la demande au routeur…' };
      case 'upgrade':
        if (c.stage === 'write') return { tone: 'hold', action: 'NE PAS DÉBRANCHER : envoi de la mise à jour au routeur.' };
        if (c.stage === 'reboot') return { tone: 'hold', action: 'NE PAS DÉBRANCHER : le routeur installe RouterOS et redémarre.' };
        return { tone: 'wait', action: 'Attendez : préparation de la mise à jour de RouterOS…' };
      case 'prepare':
        if (c.stage === 'write') return { tone: 'hold', action: 'NE PAS DÉBRANCHER : écriture de la configuration.' };
        if (c.stage === 'check') return { tone: 'hold', action: 'NE PAS DÉBRANCHER : le routeur redémarre et applique sa configuration.' };
        if (c.stage === 'report') return { tone: 'wait', action: 'Attendez : enregistrement du résultat dans ObliWAN…' };
        return { tone: 'wait', action: 'Attendez : ObliWAN prépare la configuration…' };
      default:
        break;
    }
    if (c.result && !c.result.ok) return { tone: 'bad', action: `Erreur : ${c.result.message ?? 'inconnue'}` };
    if (c.result?.summary) return preparedTone(c.result.summary);
    if (!c.box) return { tone: 'idle', action: 'Branchez le routeur sur une prise libre de l\'établi, puis saisissez son adresse MAC et son mot de passe.' };
    if (!c.plan) return { tone: 'act', action: 'Choisissez le client et le site.' };
    if (c.plan.answer.candidates.length === 0) return { tone: 'act', action: 'Cliquez sur « Mettre à jour RouterOS puis continuer ».' };
    if (c.plan.answer.replaces) return { tone: 'act', action: 'Ce site a déjà un routeur : vérifiez, cochez la confirmation du remplacement, puis cliquez sur « Préparer le routeur ».' };
    return { tone: 'act', action: 'Vérifiez, puis cliquez sur « Préparer le routeur ».' };
  };
  const cardView = (c: Card) => {
    const st = cardState(c);
    const slot = c.box?.slot ?? c.shown.slot;
    return {
      id: c.id,
      tone: st.tone,
      action: st.action,
      step: c.busy ? c.progress : null,
      busy: c.busy,
      mac: c.box?.mac ?? c.macClaim ?? c.shown.mac,
      slot: slot ? { label: slot.label, iface: slot.iface, address: slot.address } : null,
      site: c.plan
        ? { id: c.plan.siteId, code: str(c.plan.answer.site?.code) || null, name: str(c.plan.answer.site?.name) }
        : c.shown.site,
      startedAt: c.shown.startedAt,
      endedAt: c.busy ? null : c.shown.endedAt,
      timer: c.timer,
      unplugged: unplugged(c),
      abandoned: c.busy !== null && c.abandoned,
      attention: c.attention,
      result: c.result ? { kind: c.result.kind, ok: c.result.ok, code: c.result.code, unplugged: c.result.unplugged } : null,
    };
  };
  const slotsView = () => {
    const reading = readSlots();
    return {
      slots: reading.slots.map((s) => ({
        label: s.label,
        iface: s.iface,
        address: s.address,
        card: [...cards.values()].find((c) => c.box?.slot?.address === s.address)?.id ?? null,
      })),
      refused: reading.refused,
    };
  };

  /**
   * Every `watchMs`: the links, then each card's colour. A card that starts
   * needing the technician bumps `attention` (the page beeps) and flashes the
   * window — except where the technician's own click led (a search, a plan:
   * he is looking at that screen).
   */
  let lastFlash = 0;
  const flash = (): void => {
    if (now() - lastFlash < FLASH_GAP_MS) return;
    lastFlash = now();
    try {
      (deps.flash ?? (() => flashWindow(TITLE_PART)))();
    } catch {
      /* a window that cannot flash still beeps */
    }
  };
  const observeCards = (): void => {
    sampleLinks();
    let bump = false;
    for (const c of cards.values()) {
      const tone = cardState(c).tone;
      const prev = c.lastTone;
      const clicked = prev === 'wait' && (c.lastBusy === 'find' || c.lastBusy === 'plan');
      if (prev !== null && prev !== 'idle' && tone !== prev && NEEDS_TECH.includes(tone) && !clicked) {
        c.attention++;
        bump = true;
      }
      c.lastTone = tone;
      c.lastBusy = c.busy;
    }
    if (bump) flash();
  };
  const watcher = setInterval(observeCards, timing.watchMs);
  watcher.unref();

  // ── routes ─────────────────────────────────────────────────────────────────

  async function find(card: Card, body: Record<string, unknown>) {
    await requireApprovedLive();
    const mac = normalizeMac(str(body.mac));
    if (!mac || !isUnicastMac(mac)) {
      throw new HttpError(400, 'L\'adresse MAC saisie n\'est pas lisible : 12 caractères hexadécimaux sont attendus (par exemple 48:A9:8A:12:34:56), avec ou sans séparateurs. Recopiez-la depuis l\'étiquette du routeur.');
    }
    const password = typeof body.password === 'string' ? body.password : '';
    const fallback = str(body.host) || DEFAULT_BENCH_ADDRESS;
    const username = str(body.username) || DEFAULT_ACCOUNT;
    const port = body.port === undefined || body.port === '' || body.port === null ? DEFAULT_API_PORT : positiveInt(body.port);
    if (!port || port > 65535) throw new HttpError(400, 'Le port de l\'API RouterOS doit être un entier entre 1 et 65535.');
    // One router, one card: the same MAC searched for, held, or known as one
    // of another card's box's own interfaces.
    const twin = [...cards.values()].find((c) => c !== card
      && (c.macClaim === mac || c.box?.mac === mac || (c.box?.identity.interfaceMacs ?? []).some((m) => normalizeMac(m) === mac)));
    if (twin) {
      throw new HttpError(
        409,
        `Ce routeur (${mac}) est déjà en préparation sur ${cardName(twin)} : un routeur ne se prépare que sur une seule carte. Reprenez cette carte-là, ou fermez-la avant de le rechercher ici.`,
        { code: 'SAME_MAC', card: twin.id },
      );
    }
    claimBusy(card, 'find');
    forget(card);
    card.macClaim = mac;
    card.shown = { mac, slot: null, site: null, startedAt: now(), endedAt: null };
    const generation = card.generation;
    try {
      card.progress = 'Recherche du routeur sur le réseau…';
      const reading = readSlots();
      let heard: { candidates: MndpCandidate[]; neighbours: MndpNeighbour[] } = { candidates: [], neighbours: [] };
      try {
        heard = await hear(mac, reading.slots);
      } catch {
        // no MNDP on this machine: the bench address decides
      }
      // Another card's router heard in the typed MAC's window (one batch) is
      // never this one: it neither routes nor refuses this search.
      const others = [...cards.values()].filter((c) => c !== card && c.box).map((c) => ownMacs(c.box!));
      const foreign = (m: string): boolean => others.some((s) => s.has(m));
      const candidate = heard.candidates.find((c) => !foreign(c.mac)) ?? null;
      // Idle cards whose box is heard elsewhere now: moved there first, so
      // that the holds below are where the boxes are.
      if (reading.slots.length) followMoves(card, heard.neighbours);
      // Which link the box is on, and from which address to dial it
      // (slots.ts): refused before any dial when two boxes would answer.
      const route = planBoxRoute({
        fallbackHost: fallback,
        slots: reading.slots,
        candidates: heard.candidates,
        neighbours: heard.neighbours,
        heldBy: (s) => holderOf(card, s, heard.neighbours),
        foreign,
      });
      if (!route.ok) throw new HttpError(route.code === 'SLOT_HELD' || route.code === 'NO_FREE_SLOT' ? 409 : 422, route.message, { code: route.code });
      let lastError: FactoryProvisioningError | null = null;
      let lastVia: Box['foundVia'] | null = null;
      // Nothing heard, several links: what each link answered.
      const perLink: string[] = [];
      for (const a of route.attempts) {
        try {
          const identity = await identifyFactoryBox(
            { host: a.host, port, username, password, expectedMac: mac, localAddress: a.localAddress, onProgress: onStep(card) },
            applyDeps,
          );
          if (card.generation !== generation) throw new HttpError(409, 'Recherche abandonnée : une autre action l\'a remplacée.');
          // A box that is not in its factory state was somebody's router, or
          // one an earlier run already prepared. The bench reassigns routers
          // too (operator, 2026-10-03), so this is no longer a refusal: the
          // findings are shown, and erasing it needs an explicit confirmation
          // at the preparation. What proves it is THE box on the label is the
          // MAC proof above, not its state.
          if (identity.systemIdentity === null || identity.userNames === null || identity.addresses === null) {
            // Every factory account may read these three menus: a refusal is
            // not a factory box, and an unread one cannot be called factory.
            throw new HttpError(
              422,
              'Ce routeur n\'a pas laissé lire son nom, ses comptes ou ses adresses : impossible de vérifier qu\'il sort d\'usine. Rien n\'a été modifié. Vérifiez que vous utilisez le compte « admin » et le mot de passe de l\'étiquette, puis relancez la recherche ; si cela se reproduit, mettez-le de côté et appelez un technicien.',
              { code: 'NOT_FACTORY' },
            );
          }
          const notFactory = factoryStateFindings(identity, a.host);
          // The same box under another of its MACs (the typed one is its
          // ether2, another card typed its ether1): one box, one card. The
          // check before the search already refuses a MAC of a box another
          // card HOLDS; this one is reached when both searches run at once
          // and neither card held the box when the other started.
          const own = new Set(identity.interfaceMacs.map((m) => normalizeMac(m)));
          const same = [...cards.values()].find((c) => c !== card && c.box && (own.has(c.box.mac) || c.box.identity.interfaceMacs.some((m) => own.has(normalizeMac(m)))));
          if (same) {
            throw new HttpError(
              409,
              `Ce routeur est déjà en préparation sur ${cardName(same)} (sous l'adresse MAC ${same.box!.mac}) : un routeur ne se prépare que sur une seule carte. Rien n'a été modifié ; reprenez cette carte-là.`,
              { code: 'SAME_BOX', card: same.id },
            );
          }
          const box: Box = {
            host: a.host, port, username, password, mac, foundVia: a.via, localAddress: a.localAddress, slot: a.slot, identity, blocked: null,
            previouslyConfigured: notFactory,
          };
          card.box = box;
          card.shown.slot = a.slot;
          if (a.slot) displacedBy(card, a.slot);
          return { box: publicBox(box) };
        } catch (err) {
          if (!(err instanceof FactoryProvisioningError)) throw err;
          lastError = err;
          lastVia = a.via;
          // Only "nothing answered there" moves on to the next address: a box
          // that answered and refused (password, MAC) has said its piece —
          // except while the free links are tried one after the other
          // (nothing heard): there, a refusal may be ANOTHER link's box.
          const nextLink = route.heardOn === null && a.slot !== null;
          if (a.slot && nextLink) {
            perLink.push(`${a.slot.label} : ${err.code === 'MAC_MISMATCH' ? 'un autre routeur' : err.code === 'AUTH_FAILED' ? 'mot de passe refusé' : err.code === 'CONNECT_FAILED' ? 'rien ne répond' : 'refusé'}`);
          }
          if (err.code !== 'CONNECT_FAILED' && err.code !== 'INVALID_INPUT' && !(nextLink && (err.code === 'MAC_MISMATCH' || err.code === 'AUTH_FAILED'))) break;
        }
      }
      if (lastError?.code === 'AUTH_FAILED' && candidate?.identity && candidate.identity !== FACTORY_IDENTITY) {
        // MNDP heard this MAC under another name, and the label password is
        // refused: a configured router, not a factory one.
        throw new HttpError(
          422,
          `Ce routeur a déjà été configuré : il s'annonce sous le nom « ${candidate.identity.slice(0, 60)} » et refuse le mot de passe de l'étiquette. Rien n'a été modifié. Pour le réaffecter, saisissez son mot de passe administrateur ACTUEL à la place de celui de l'étiquette, puis relancez la recherche.`,
          { code: 'NOT_FACTORY' },
        );
      }
      if (perLink.length > 1) {
        throw new HttpError(
          422,
          `Le routeur ${mac} n'a été trouvé sur aucune prise libre de ce poste (${perLink.join(' ; ')}). Rien n'a été modifié. Vérifiez qu'il est branché sur une prise libre et allumé depuis au moins une minute, et que l'adresse MAC et le mot de passe sont ceux de son étiquette, puis relancez la recherche.`,
          { code: 'NOT_ON_ANY_SLOT' },
        );
      }
      const where = candidate ? '' : ` Aucun routeur portant cette adresse MAC n'a répondu à la découverte réseau ; l'adresse ${fallback} a été essayée.`;
      const other = lastError?.code === 'MAC_MISMATCH' && lastVia === 'address'
        ? (route.heardOn ? ` Un seul routeur par prise : débranchez les autres de la ${route.heardOn.label}.` : ' Si plusieurs routeurs sont branchés sur ce poste, débranchez tous les autres.')
        : '';
      throw new HttpError(422, `${lastError?.message ?? 'Routeur introuvable.'}${lastError?.code === 'CONNECT_FAILED' ? where : ''}${other}`, { code: lastError?.code ?? null });
    } catch (err) {
      failed(card, 'find', err);
      throw err;
    } finally {
      card.macClaim = null;
      release(card);
    }
  }

  /**
   * The device-mode wizard: ask the box for every feature the chosen
   * candidate needs (scheduler included, see `ALWAYS_NEEDED`), keep the
   * request open across the activation window while the preparer presses
   * RESET, wait for the reboot, take the MAC proof again and read the mode
   * again. Resolves with the fresh box when nothing is blocked any more.
   */
  async function deviceModeWizard(card: Card, body: Record<string, unknown>) {
    await requireApprovedLive();
    const box = card.box;
    if (!box) throw new HttpError(409, 'Recherchez d\'abord le routeur.');
    const revisionId = positiveInt(body.revisionId);
    const candidate = card.plan?.answer.candidates.find((c) => c.revisionId === revisionId);
    const check = deviceModeCheck(box, candidate);
    if (check.blocked.length === 0) return { box: publicBox(box), allowed: check.needed, already: true };
    // Every needed feature that is not already printed `yes`: asking for one
    // that is merely unknown costs nothing, and the press is spent once.
    const features = check.needed.filter((f) => featureVerdict(box.identity.deviceMode, f) !== 'allowed');
    claimBusy(card, 'unlock');
    const generation = card.generation;
    try {
      const pressLabel = 'Appuyez UNE fois brièvement sur le bouton RESET à l\'arrière du routeur — ou débranchez puis rebranchez son alimentation.';
      card.progress = 'Envoi de la demande au routeur…';
      let sentAt: number | null = null;
      const outcome = await requestDeviceModeUpdate(
        {
          host: box.host, port: box.port, username: box.username, password: box.password, expectedMac: box.mac, features,
          localAddress: box.localAddress,
          waitMs: timing.deviceModeWindowMs + timing.deviceModeGraceMs,
          onSent: () => {
            sentAt = now();
            card.progress = pressLabel;
            card.timer = { countdownEndsAt: sentAt + timing.deviceModeWindowMs };
          },
        },
        applyDeps,
      ).catch((err: unknown) => {
        if (err instanceof FactoryProvisioningError) throw new HttpError(422, err.message, { code: err.code });
        throw err;
      });
      if (outcome.outcome === 'window-expired' || outcome.outcome === 'awaiting-confirmation') {
        throw new HttpError(408, 'Le routeur n\'a pas reçu de confirmation dans les 5 minutes : rien n\'a changé. Cliquez sur « Recommencer », puis appuyez sur RESET dès que le compte à rebours démarre.', { timeout: true });
      }
      const windowEnd = (sentAt ?? now()) + timing.deviceModeWindowMs;
      const since = now();
      const deadline = Math.max(windowEnd, since) + timing.deviceModeRebootMs;
      // The instruction to press and its countdown stay on screen only while
      // a press is still awaited: the request was answered at once, the box
      // has not gone down since, and the window is open. Once the session
      // dropped or the box went away, the press happened (or the power was
      // cut): a second press, or RESET held while it boots, is exactly what
      // must not be asked for (held through the boot, RESET resets the
      // configuration, or more — MikroTik's reset-button behaviour).
      let pressed = outcome.outcome === 'session-dropped';
      const awaitingPress = () => !pressed && outcome.outcome === 'acknowledged' && now() < windowEnd;
      const drawTimer = () => {
        card.timer = awaitingPress() ? { countdownEndsAt: windowEnd, since, deadline } : { since, deadline };
        card.stage = pressed ? 'reboot' : null;
      };
      drawTimer();
      if (!awaitingPress()) card.progress = pressed ? 'Le routeur redémarre… Ne le débranchez pas.' : 'Lecture du nouveau mode du routeur…';
      const back = await waitForBox({
        req: { host: box.host, port: box.port, username: box.username, password: box.password, expectedMac: box.mac, localAddress: box.localAddress },
        // Lengthened by the time the box's link spent down: a box plugged
        // in again on its port is still waited for — unless the technician
        // gave up on it (« Abandonner »): then it ends at the next attempt.
        deadline: () => (card.abandoned ? 0 : deadline + extension(card)),
        pollMs: timing.pollMs,
        dial: deps.dial,
        discover: locate(box),
        sleep,
        now,
        onTick: (elapsed, seen) => {
          if (seen === 'absent') pressed = true;
          drawTimer();
          card.progress = seen === 'absent'
            ? `Le routeur redémarre… ${frenchDuration(elapsed)} écoulées. Ne le débranchez pas.`
            : (awaitingPress() ? pressLabel : 'Lecture du nouveau mode du routeur…');
        },
        accept: (identity, sawItGo) => {
          const still = blockedFeatures(identity.deviceMode, check.needed);
          if (still.length === 0) return 'done';
          if (sawItGo) {
            return { fail: `Le routeur a redémarré mais bloque toujours ${featureList(still)}. Cliquez sur « Recommencer », puis appuyez sur RESET pendant le compte à rebours.` };
          }
          return 'wait';
        },
      }).catch((err: unknown) => {
        if (!(err instanceof BoxWaitError)) throw err;
        if (err.code === 'TIMEOUT') {
          sampleLinks();
          if (card.abandoned) {
            throw new HttpError(408, 'Abandonné à votre demande : le routeur a été débranché pendant son redémarrage, et rien n\'a été préparé. Rebranchez-le sur une prise libre, attendez qu\'il ait démarré, puis relancez sa recherche — ou mettez-le de côté.', { timeout: true, code: 'ABANDONED' });
          }
          if (card.link.downSince !== null) {
            throw new HttpError(408, `Le routeur est resté débranché : rebranchez-le sur le même port${box.slot ? ` (${box.slot.label})` : ''}, attendez qu'il ait démarré, puis relancez la recherche du routeur ; la préparation recommencera.`, { timeout: true, code: 'UNPLUGGED' });
          }
          throw new HttpError(408, 'Le routeur n\'a pas changé de mode dans le temps prévu. Cliquez sur « Recommencer », puis appuyez sur RESET dès que le compte à rebours démarre.', { timeout: true });
        }
        throw new HttpError(422, err.message, { code: err.code });
      });
      if (card.generation !== generation) throw new HttpError(409, 'Le routeur a été oublié entre-temps : relancez la recherche du routeur.');
      box.identity = back.identity;
      movedTo(card, box, back.localAddress);
      // What an earlier compile found blocked, judged again on the NEW
      // reading (it may belong to another candidate than this one).
      if (box.blocked) {
        const rest = blockedFeatures(box.identity.deviceMode, box.blocked.features);
        box.blocked = rest.length
          ? { revisionId: box.blocked.revisionId, features: rest, message: deviceModeExplanation(rest, box.identity.deviceMode) }
          : null;
      }
      return { box: publicBox(box), allowed: check.needed, already: false };
    } catch (err) {
      failed(card, 'unlock', err);
      throw err;
    } finally {
      release(card);
    }
  }

  /** The plan, asked of ObliWAN for this box; shared by `plan` and `upgrade`. */
  const askPlan = async (card: Card, api: BenchApi, siteId: number, box: Box) => {
    const generation = card.generation;
    const answer = await api.plan(siteId, benchBox(box, api)).catch((err: unknown) => {
      // A plan is a read: when the refusal was the reading's time, the
      // refusal itself carried the platform's clock — ask once more on it.
      if (err instanceof BenchApiError && err.kind === 'refused' && /observedAt/.test(err.message) && api.clockSkewMs !== null) {
        return api.plan(siteId, benchBox(box, api));
      }
      throw err;
    }).catch(platformError);
    if (card.generation !== generation) throw new HttpError(409, 'Le routeur a changé entre-temps : recommencez.');
    card.shown.site = { id: siteId, code: str(answer.site?.code) || null, name: str(answer.site?.name) };
    return answer;
  };

  /** "Nothing fits", in French, with the platform's own reasons. */
  const noCandidateMessage = (answer: BenchPlan): string => {
    // The platform says WHY in its warnings (no published template for this
    // customer, RouterOS below a template's minimum, model not targeted…).
    // The preparer needs that sentence to tell the template manager what to
    // fix: dropping it left "contact somebody" with nothing to tell them.
    const why = Array.isArray(answer.warnings)
      ? answer.warnings.filter((w): w is string => typeof w === 'string' && w.trim() !== '').slice(0, 6)
      : [];
    return 'ObliWAN ne propose aucun modèle de configuration pour ce site et ce routeur. Rien n\'a été fait.'
      + (why.length ? ' Raison : ' + why.join(' ') : ' Contactez la personne qui gère les modèles.');
  };

  /** One site, one card: another card planning or holding `siteId`. */
  const siteHolder = (self: Card, siteId: number): Card | null =>
    [...cards.values()].find((c) => c !== self && (c.siteClaim === siteId || c.plan?.siteId === siteId)) ?? null;
  const refuseSameSite = (holder: Card): never => {
    const s = holder.plan?.answer.site;
    const name = s ? ` « ${[str(s.code), str(s.name)].filter(Boolean).join(' — ')} »` : '';
    throw new HttpError(
      409,
      `Le site${name} est déjà en préparation sur ${cardName(holder)} : un site ne se prépare que sur une seule carte à la fois. Choisissez un autre site, ou reprenez cette carte-là.`,
      { code: 'SAME_SITE', card: holder.id },
    );
  };

  async function plan(card: Card, body: Record<string, unknown>) {
    const api = requireApproved();
    const siteId = positiveInt(body.siteId);
    if (!siteId) throw new HttpError(400, 'Choisissez un site.');
    const box = card.box;
    if (!box) throw new HttpError(409, 'Recherchez d\'abord le routeur.');
    const holder = siteHolder(card, siteId);
    if (holder) refuseSameSite(holder);
    claimBusy(card, 'plan');
    card.siteClaim = siteId;
    try {
      card.progress = 'Préparation du plan par ObliWAN…';
      card.plan = null;
      const answer = await askPlan(card, api, siteId, box);
      if (answer.candidates.length === 0) {
        const up = answer.upgrade;
        if (up?.required && up.target) {
          // Offered, not done: the one button on the page starts it.
          card.plan = { siteId, answer };
          return {
            ...planView(box, answer),
            upgrade: { from: box.identity.router.version, to: up.target.version, minimum: up.minimum },
          };
        }
        if (up?.required) {
          throw new HttpError(
            422,
            `Ce routeur est en RouterOS ${box.identity.router.version ?? 'de version inconnue'}, et le modèle de configuration exige au moins ${up.minimum ?? 'une version plus récente'}. `
              + `${up.targetRefusal ?? ''} Rien n'a été fait : prévenez l'administrateur d'ObliWAN.`.trim(),
          );
        }
        throw new HttpError(422, noCandidateMessage(answer));
      }
      card.plan = { siteId, answer };
      return planView(box, answer);
    } catch (err) {
      failed(card, 'plan', err);
      throw err;
    } finally {
      card.siteClaim = null;
      release(card);
    }
  }

  /** "Mettre à jour RouterOS puis continuer": the upgrade, then the plan again. */
  async function upgrade(card: Card) {
    const api = await requireApprovedLive();
    const box = card.box;
    const planned = card.plan;
    if (!box) throw new HttpError(409, 'Recherchez d\'abord le routeur.');
    const up = planned?.answer.upgrade;
    if (!planned || !up?.required || !up.target) throw new HttpError(409, 'Aucune mise à jour n\'est proposée pour ce routeur : choisissez d\'abord le site.');
    claimBusy(card, 'upgrade');
    const generation = card.generation;
    try {
      let result;
      try {
        result = await upgradeRouterOs(
          {
            host: box.host, port: box.port, username: box.username, password: box.password, expectedMac: box.mac,
            localAddress: box.localAddress,
            target: { version: up.target.version, minimum: up.minimum, maximum: up.maximum, packages: up.packages },
            // Not enough room for the packages: factory-reset to a minimal
            // configuration and let the router update itself through ether1
            // (routerosUpgrade.ts, RESET FOR SPACE). The preparation resets it again.
            // Never for a box that was configured before (reassignment): the
            // reset is only for a factory box; its own update still runs.
            resetWhenNoSpace: box.previouslyConfigured.length === 0,
          },
          {
            dial: deps.dial,
            sftpUpload: applyDeps.sftpUpload,
            download: deps.download,
            cacheDir: deps.packageCacheDir,
            discover: locate(box),
            sleep,
            now,
            timing: { rebootWaitMs: timing.rebootWaitMs, pollMs: timing.pollMs },
            waitExtensionMs: () => extension(card),
            stopWaiting: () => card.abandoned,
            onProgress: (p) => {
              card.progress = p.label;
              card.timer = p.since !== undefined ? { since: p.since, deadline: p.deadline } : null;
              card.stage = p.phase === 'uploading' || p.phase === 'resetting' ? 'write'
                : p.phase === 'rebooting' || p.phase === 'waiting' || p.phase === 'router-update' ? 'reboot' : null;
            },
          },
        );
      } catch (err) {
        if (!(err instanceof RouterOsUpgradeError)) throw err;
        sampleLinks();
        const cut = card.link.downSince !== null || card.link.cutInWrite;
        const port = box.slot ? ` (${box.slot.label})` : '';
        // After a reboot the box may be anything: it is searched for again.
        if (err.rebooted) forget(card);
        if (card.abandoned && err.code === 'NOT_BACK') {
          const e = new HttpError(422, `Abandonné à votre demande : le routeur a été débranché pendant sa mise à jour de RouterOS, qui a peut-être été installée ou non. Rebranchez-le sur une prise libre${port ? ` — de préférence la même${port}` : ''}, attendez qu'il ait démarré, puis relancez sa recherche ; s'il ne répond plus, mettez-le de côté et appelez un technicien.`, { code: 'ABANDONED', rebooted: err.rebooted });
          failed(card, 'upgrade', e, true);
          throw e;
        }
        if (cut && (err.code === 'NOT_BACK' || err.code === 'UPLOAD_FAILED')) {
          const message = err.rebooted
            ? `Le routeur a été débranché pendant sa mise à jour. Rebranchez-le sur le même port${port}, attendez qu'il ait démarré, puis relancez la recherche du routeur ; la préparation recommencera.`
            : `Le routeur a été débranché pendant l'envoi de la mise à jour : rien n'a été installé. Rebranchez-le sur le même port${port}, puis cliquez à nouveau sur « Mettre à jour RouterOS puis continuer » ; la mise à jour recommencera.`;
          const e = new HttpError(422, message, { code: 'UNPLUGGED', rebooted: err.rebooted });
          failed(card, 'upgrade', e, true);
          throw e;
        }
        throw new HttpError(422, err.message, { code: err.code, rebooted: err.rebooted });
      }
      if (card.generation !== generation) throw new HttpError(409, 'Le routeur a été oublié entre-temps : relancez la recherche du routeur.');
      box.identity = result.identity;
      movedTo(card, box, result.localAddress);
      card.stage = null;
      card.progress = 'Préparation du plan par ObliWAN…';
      const answer = await askPlan(card, api, planned.siteId, box);
      const upgraded = {
        from: result.from,
        to: result.to,
        method: result.method,
        downloaded: result.packages.filter((p) => !p.cached).length,
        cached: result.packages.filter((p) => p.cached).length,
      };
      if (answer.candidates.length === 0) {
        card.plan = null;
        return { upgraded, box: publicBox(box), planError: noCandidateMessage(answer) };
      }
      card.plan = { siteId: planned.siteId, answer };
      return { upgraded, box: publicBox(box), ...planView(box, answer) };
    } catch (err) {
      if (!card.result) failed(card, 'upgrade', err);
      throw err;
    } finally {
      release(card);
    }
  }

  /**
   * After the reset: wait (bounded) for MNDP to announce this box under the
   * allocation's NEW name, then — only when the plan named the router's LAN
   * address and this PC obtained ONE new address inside the new LAN since
   * the preparation started — one ping, sent from that address.
   *
   * "New since the start" is what ties the ping to the bench link: an
   * interface of this PC that was already in that range before the reset
   * (an office network overlapping the customer's LAN) did not get it from
   * the box, and a ping out of it would answer for some other host. Two new
   * ones is ambiguous and nothing is pinged — which is also the case of two
   * cards whose boxes lease addresses in the same range at the same time.
   * `lanReachable` null = not tried.
   *
   * The box is recognised by one of its OWN MACs (`locate`), not by the
   * typed MAC's window: on a bench of one batch, the window also covers the
   * box of another card. The wait is lengthened by the time the box's link
   * spent down (a cable pulled during the reboot and put back).
   *
   * What it proves: the box rebooted and ran the file far enough to set its
   * name (the access block, after the template body). It does NOT prove the
   * template body succeeded — the box's own success marker says that, read by
   * ObliWAN once the box reaches the concentrator.
   */
  const localCheck = async (card: Card, box: Box, allocation: BenchPlan['allocation'], addressesBefore: Set<string>): Promise<BenchLocalCheck> => {
    const expected = allocation.system_identity;
    const since = now();
    // « Abandonner » (an unplugged box the technician gave up on) ends it at
    // the next round, unconfirmed: the card then says not to ship it.
    const deadline = () => (card.abandoned ? since : since + timing.localCheckMs + extension(card));
    card.timer = { since, deadline: since + timing.localCheckMs };
    const where = locate(box);
    let seen: string | null = null;
    for (;;) {
      const elapsed = now() - since;
      card.progress = `Le routeur redémarre et applique sa configuration… ${frenchDuration(elapsed)} écoulées (${frenchDuration(timing.localCheckMs)} au plus). Ne le débranchez pas.`;
      try {
        const c = await where(box.mac);
        if (c?.identity) seen = c.identity;
      } catch {
        /* no MNDP: nothing heard this round */
      }
      if (expected !== null && seen === expected) break;
      if (now() + timing.pollMs > deadline()) return { mndpIdentity: seen, identityMatches: false, lanReachable: null };
      await sleep(timing.pollMs);
    }
    let lanReachable: boolean | null = null;
    const lanIp = allocation.lan_router_ip;
    const fresh = lanIp ? localAddresses().filter((a) => !addressesBefore.has(a) && ipv4InSubnet(a, allocation.lan_subnet)) : [];
    if (lanIp && fresh.length === 1) {
      card.progress = 'Vérification du réseau local du routeur…';
      lanReachable = await ping(lanIp, fresh[0]).catch(() => false);
    }
    return { mndpIdentity: seen, identityMatches: true, lanReachable };
  };

  async function prepare(card: Card, body: Record<string, unknown>) {
    const api = await requireApprovedLive();
    const box = card.box;
    const planned = card.plan;
    const remember = (e: Omit<HistoryEntry, 'at' | 'site' | 'tenant' | 'mac' | 'serial' | 'model'>): void => {
      const site = planned?.answer.site as { code?: unknown; name?: unknown } | undefined;
      const tenant = planned?.answer.tenant as { name?: unknown } | undefined;
      appendHistory(deps.historyFile ?? null, {
        at: new Date(now()).toISOString(),
        site: site ? `${typeof site.code === 'string' ? `${site.code} — ` : ''}${typeof site.name === 'string' ? site.name : ''}` : null,
        tenant: typeof tenant?.name === 'string' ? tenant.name : null,
        mac: box?.mac ?? null,
        serial: box?.identity.router.serial ?? null,
        model: box?.identity.router.model ?? box?.identity.router.board ?? null,
        ...e,
      });
    };
    if (!box) throw new HttpError(409, 'Recherchez d\'abord le routeur.');
    const siteId = positiveInt(body.siteId);
    if (!planned || !siteId || planned.siteId !== siteId) throw new HttpError(409, 'Choisissez d\'abord le site (le plan ne correspond pas).');
    const holder = siteHolder(card, siteId);
    if (holder) refuseSameSite(holder);
    const revisionId = positiveInt(body.revisionId);
    const candidate = planned.answer.candidates.find((c) => c.revisionId === revisionId);
    if (!revisionId || !candidate) {
      throw new HttpError(400, 'Choisissez le modèle de configuration proposé par ObliWAN.');
    }
    if (box.previouslyConfigured.length && body.confirmWipe !== true) {
      throw new HttpError(
        409,
        `Ce routeur a déjà servi (${box.previouslyConfigured.join(', ')}) : cochez la confirmation qu'il peut être entièrement effacé, puis relancez la préparation. Rien n'a été modifié.`,
        { code: 'CONFIRM_WIPE' },
      );
    }
    // The site's current router, which this preparation retires (the plan's
    // `replaces`, kept with the card's plan): the operator's decision, ticked
    // on the summary. Judged HERE against THIS card's plan, by device id — a
    // confirmation the page gave for another plan, or another device,
    // confirms nothing — and only then carried to the compile, which judges
    // it again against the device that holds the site's login now.
    const replaces = planned.answer.replaces;
    if (replaces && positiveInt(body.confirmReplaceDeviceId) !== replaces.deviceId) {
      throw new HttpError(
        409,
        `Ce site a déjà un routeur (appareil n°${replaces.deviceId}) : cochez la confirmation de son remplacement, puis relancez la préparation. Rien n'a été modifié.`,
        { code: 'CONFIRM_REPLACE', replaces },
      );
    }
    const override = body.deviceModeOverride === true;
    if (override && str(body.overrideConfirm).toUpperCase() !== OVERRIDE_PHRASE) {
      throw new HttpError(400, `Pour continuer malgré le mode appareil, tapez exactement « ${OVERRIDE_PHRASE} ».`);
    }
    const given = (typeof body.bench === 'object' && body.bench !== null ? body.bench : {}) as Record<string, unknown>;
    const bench: Record<string, string> = {};
    for (const v of planned.answer.benchVariables) {
      const value = typeof given[v.key] === 'string' ? (given[v.key] as string) : '';
      if (v.required && value.trim() === '') throw new HttpError(400, `Le champ « ${v.label} » est obligatoire.`);
      if (value !== '') bench[v.key] = value;
    }
    // Before anything is committed (the compile allocates and provisions the
    // concentrator): the plan's own device-mode needs, against the box.
    const before = deviceModeCheck(box, candidate);
    if (before.blocked.length && !override) {
      throw new HttpError(409, before.message ?? 'Ce routeur bloque une fonction nécessaire.', {
        blocked: { features: before.blocked, message: before.message }, wizard: true,
      });
    }

    claimBusy(card, 'prepare');
    card.stage = 'compile';
    const generation = card.generation;
    // This PC's addresses BEFORE the box is touched: the local check pings
    // the new LAN only from an address obtained after this point.
    const addressesBefore = new Set(localAddresses());
    let deviceId: number | null = null;
    const report = async (
      status: 'applied' | 'failed',
      detail: string,
      check: BenchLocalCheck | null = null,
      // The SIM card read before the reset: undefined when nothing was read.
      sim?: SimCardReading | null,
    ): Promise<{ recorded: boolean; error: string | null }> => {
      if (deviceId === null) return { recorded: false, error: null };
      card.stage = 'report';
      card.progress = 'Enregistrement du résultat dans ObliWAN…';
      try {
        await api.result(deviceId, status, detail, {
          localCheck: check ? { ...check, mndpIdentity: wireIdentity(check.mndpIdentity) } : null,
          deviceModeOverride: override,
          ...(sim !== undefined ? { sim } : {}),
        });
        return { recorded: true, error: null };
      } catch (err) {
        return { recorded: false, error: err instanceof Error ? err.message : String(err) };
      }
    };
    let cut = false;
    const refuse = async (status: number, message: string, extra: Record<string, unknown> = {}): Promise<never> => {
      const r = await report('failed', message);
      throw new HttpError(status, message, { ...extra, deviceId, resultRecorded: r.recorded });
    };
    try {
      // Before anything is committed: the box is still there, and still THIS
      // box. The compile allocates the router's PPP identity and creates its
      // concentrator account; a box unplugged (or swapped) since it was found
      // would otherwise be noticed only by the write, after both. A read-only
      // MAC proof over the box's link — also the only way to see a router
      // pulled from a VLAN switch, whose link never goes down (slots.ts).
      card.progress = 'Vérification que le routeur est toujours branché…';
      try {
        await identifyFactoryBox(
          { host: box.host, port: box.port, username: box.username, password: box.password, expectedMac: box.mac, localAddress: box.localAddress },
          applyDeps,
        );
      } catch (err) {
        if (!(err instanceof FactoryProvisioningError)) throw err;
        if (err.code === 'CONNECT_FAILED' || err.code === 'SESSION_LOST') {
          throw new HttpError(
            422,
            `Le routeur ne répond plus${box.slot ? ` sur la ${box.slot.label}` : ''} : il a peut-être été débranché. Rien n'a été fait, ni sur le routeur ni dans ObliWAN. Vérifiez qu'il est branché${box.slot ? ` sur le même port (${box.slot.label})` : ''} et allumé, attendez une minute, puis cliquez à nouveau sur « Préparer le routeur ».`,
            { code: 'UNPLUGGED' },
          );
        }
        throw new HttpError(422, `${err.message} Rien n'a été fait dans ObliWAN : relancez la recherche du routeur.`, { code: err.code });
      }
      if (card.generation !== generation) throw new HttpError(409, 'Préparation abandonnée : le routeur a été oublié entre-temps. Rien n\'a été fait.');
      card.progress = 'ObliWAN prépare la configuration de ce routeur…';
      const compiled = await api.compile(siteId, revisionId, benchBox(box, api), bench, {
        deviceModeOverride: override,
        confirmReplaceDeviceId: replaces ? replaces.deviceId : null,
      }).catch(platformError);
      deviceId = compiled.deviceId;
      if (compiled.concentrator.state === 'failed') {
        // The CHR account this file dials was NOT created. Wiping the box now
        // would ship a router that cannot reach ObliWAN; stopping here costs a
        // re-run once the concentrator is fixed, and the box is untouched.
        await refuse(422, `ObliWAN n'a pas pu créer l'accès de ce routeur au concentrateur${compiled.concentrator.message ? ` (${compiled.concentrator.message})` : ''}. Rien n'a été envoyé au routeur ; signalez-le à un administrateur puis relancez la préparation.`);
      }
      if (card.generation !== generation) {
        await refuse(409, 'Préparation abandonnée : le routeur a été oublié pendant la compilation. Rien n\'a été envoyé au routeur.');
      }
      if (override && compiled.testOverride !== true) {
        await refuse(422, 'ObliWAN n\'a pas confirmé que ce routeur est enregistré comme un TEST (mode appareil non conforme). Rien n\'a été envoyé au routeur ; relancez sans l\'option de test, ou demandez à l\'administrateur de mettre ObliWAN à jour.');
      }
      // What goes on the box: the split files when the server sent them, the
      // single file otherwise.
      const files: CompiledProvisioningFile[] = compiled.files
        ? compiled.files.map((f) => ({ fileName: f.name, content: f.content, sha256: f.sha256, role: f.role }))
        : [{ fileName: compiled.fileName, content: compiled.content, sha256: compiled.sha256, role: 'runner' }];
      if (files.some((f) => sha256Hex(f.content) !== f.sha256)) {
        await refuse(422, 'Le fichier de configuration reçu ne correspond pas à l\'empreinte annoncée par ObliWAN (SHA-256) : il a pu être altéré ou tronqué en route. Rien n\'a été envoyé au routeur ; relancez la préparation.');
      }
      if (files.some((f) => !COMPILED_FILE_NAME_PATTERN.test(f.fileName)) || !PROVISION_TAG_PATTERN.test(compiled.tag)) {
        await refuse(422, 'ObliWAN a fourni un nom de fichier ou une étiquette inutilisable sur un routeur. Rien n\'a été envoyé au routeur.');
      }
      const denied = blockedFeatures(box.identity.deviceMode, featuresUsedBy(files.map((f) => f.content).join('\n')));
      if (denied.length && !override) {
        // The box is KEPT: the wizard can allow these and the preparation be
        // run again, without searching for the router anew.
        box.blocked = { revisionId, features: denied, message: deviceModeExplanation(denied, box.identity.deviceMode) };
        await refuse(422, box.blocked.message, { blocked: box.blocked, wizard: true });
      }
      let applied;
      card.stage = 'write';
      card.link.cutInWrite = false;
      try {
        applied = await applyFactoryProvisioning(
          {
            host: box.host,
            port: box.port,
            username: box.username,
            password: box.password,
            expectedMac: box.mac,
            localAddress: box.localAddress,
            tag: compiled.tag,
            compiledFiles: files,
            simWait: { budgetMs: timing.simWaitMs, retryMs: timing.simRetryMs },
            // Drawn like the bench's other waits: what it waits for, the
            // elapsed time, and how long at most (the page's timer line).
            onSimWait: (t) => {
              card.progress = `${SIM_WAIT_TEXT[t.waitingFor]}… ${frenchDuration(t.elapsedMs)} écoulées (${frenchDuration(t.deadline - t.startedAt)} au plus).`;
              card.timer = { since: t.startedAt, deadline: t.deadline };
            },
            onProgress: (step) => {
              onStep(card)(step);
              // The SIM wait's timer ends with it: the upload is not timed.
              if (step === 'uploading') card.timer = null;
              // The reset reboots the box: its link going down from here on
              // is taken for that reboot, not a pulled cable. This step is
              // announced just BEFORE the reset command is sent, and a cable
              // pulled in that instant drops the session exactly as the reset
              // does (routerosApply's 'session-dropped'): that box is then NOT
              // reset, keeps its files, and the local check ends unconfirmed —
              // orange, « ne l'expédiez pas », never green.
              if (step === 'resetting') card.stage = 'reboot';
            },
          },
          // This application's clock bounds the SIM wait, as it does its other waits.
          { ...applyDeps, sleep, now },
        );
      } catch (err) {
        // Read the link NOW: a cable pulled mid-upload fails the session at
        // once, before the next periodic reading would have seen it.
        sampleLinks();
        if (err instanceof FactoryProvisioningError && box.slot && (card.link.downSince !== null || card.link.cutInWrite)) {
          // Thrown before the reset (applyFactoryProvisioning's contract):
          // the box is not reset. But its session died with the cable, so
          // the clean-up of what was already uploaded could not run: the
          // site's files — complete or partial, holding its secrets — may
          // still be on the box's flash. The next run on THIS box removes
          // them before uploading (STALE_PROVISIONING_FILE); a box set aside
          // instead keeps them, hence the instruction not to.
          cut = true;
          return await refuse(422, `Le routeur a été débranché pendant l'écriture de sa configuration : il n'a pas été réinitialisé, mais il peut garder en mémoire une partie du fichier de configuration du site, avec ses mots de passe. Ne le mettez pas de côté ainsi : rebranchez-le sur le même port (${box.slot.label}), puis cliquez sur « Recommencer » ; la préparation recommencera et effacera ce fichier. S'il ne peut pas être rebranché, remettez-le à un technicien en le signalant.`, {
            code: 'UNPLUGGED',
          });
        }
        const message = err instanceof FactoryProvisioningError ? err.message : `Erreur inattendue pendant l'écriture : ${err instanceof Error ? err.message : String(err)}`;
        return await refuse(err instanceof FactoryProvisioningError ? 422 : 500, message, {
          code: err instanceof FactoryProvisioningError ? err.code : null,
        });
      }
      card.stage = 'check';
      const check = await localCheck(card, box, planned.answer.allocation, addressesBefore);
      const detail = `Fichiers ${applied.upload.paths.join(', ')} déposés (${applied.upload.method}, ${applied.upload.bytes} octets, taille ${applied.upload.sizeCheck}, contenu ${applied.upload.contentCheck}) ; `
        + `réinitialisation : ${applied.reset.outcome} ; vérification locale : ${check.identityMatches ? 'nom annoncé' : `non confirmée (vu : ${check.mndpIdentity ?? 'rien'})`}`
        + `${!check.identityMatches && card.abandoned ? ' ; attente abandonnée par le préparateur (routeur débranché)' : ''}`
        + ` ; carte SIM : ${applied.sim
          ? (applied.simRead.attempts > 1 ? `lue après ${frenchDuration(applied.simRead.waitedMs)} d'attente du modem` : 'lue')
          : `aucune lue (${simNote(applied.simRead) ?? applied.simRead.outcome})`}`
        + `${override ? ' ; TEST : mode appareil non conforme' : ''}.`;
      const r = await report('applied', detail, check, applied.sim);
      const summary: PrepareSummary = {
        deviceId,
        reset: applied.reset.outcome,
        concentrator: compiled.concentrator,
        resultRecorded: r.recorded,
        resultError: r.error,
        site: planned.answer.site,
        allocation: planned.answer.allocation,
        localCheck: check,
        testOverride: override,
        upload: { files: applied.upload.paths.length, method: applied.upload.method },
        abandoned: !check.identityMatches && card.abandoned,
        warnings: compiled.warnings,
        sim: applied.sim ?? null,
        simNote: simNote(applied.simRead),
      };
      card.result = { kind: 'prepare', ok: true, message: null, code: null, summary, unplugged: false };
      card.shown.endedAt = now();
      remember({
        ok: true, deviceId, pppUsername: (planned.answer.allocation as { ppp_username?: string | null }).ppp_username ?? null,
        iccid: applied.sim?.iccid ?? null, test: override, message: null,
      });
      forget(card); // the factory password and the plan go with the box
      return summary;
    } catch (err) {
      failed(card, 'prepare', err, cut);
      remember({ ok: false, deviceId: null, pppUsername: null, iccid: null, test: body.deviceModeOverride === true, message: err instanceof Error ? err.message.slice(0, 300) : String(err).slice(0, 300) });
      throw err;
    } finally {
      release(card);
    }
  }

  async function route(req: IncomingMessage, res: ServerResponse, path: string, url: URL): Promise<void> {
    const method = req.method ?? 'GET';
    if (method === 'GET' && path === '/') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ...SECURITY_HEADERS,
      });
      res.end(PAGE);
      return;
    }
    if (method === 'GET' && path === '/api/instance') {
      json(res, 200, { app: 'obliwan-bench', pid: process.pid, version: currentVersion() });
      return;
    }
    if (method === 'POST' && path === '/api/window') {
      watch.reopened();
      hooks.reopen?.();
      json(res, 200, { ok: true });
      return;
    }
    if (method === 'POST' && path === '/api/heartbeat') {
      watch.heartbeat();
      res.writeHead(204, SECURITY_HEADERS);
      res.end();
      return;
    }
    if (method === 'GET' && path === '/api/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', connection: 'keep-alive', ...SECURITY_HEADERS });
      res.write(': ouvert\n\n');
      watch.streamOpened();
      const ping = setInterval(() => res.write(': ping\n\n'), 10_000);
      req.on('close', () => {
        clearInterval(ping);
        watch.streamClosed();
      });
      return;
    }
    if (method === 'GET' && path === '/api/state') {
      if (url.searchParams.get('refresh') === '1') await refresh('fresh');
      json(res, 200, state());
      return;
    }
    if (method === 'GET' && path === '/api/progress') {
      // Times on THIS process's clock, with `now` beside them: the page draws
      // an elapsed time and a countdown from the difference, whatever its own
      // clock says.
      const card = cardFor(req, url);
      json(res, 200, { card: card.id, busy: card.busy, label: card.progress, timer: card.timer, now: now() });
      return;
    }
    if (method === 'GET' && path === '/api/cards') {
      // The board: every card's colour and next action, and the links. Read
      // only, and on this PC alone: no router is dialled to answer it.
      json(res, 200, { cards: [...cards.values()].map(cardView), slots: slotsView(), now: now(), history: todaysHistory(deps.historyFile ?? null, new Date(now())) });
      return;
    }
    if (method === 'GET' && path === '/api/slots') {
      json(res, 200, slotsView());
      return;
    }
    if (method === 'POST' && path === '/api/cards') {
      // « Préparer un autre routeur »: a new card, whatever the others do.
      await readJsonBody(req);
      if (phase() !== 'approved') throw new HttpError(403, NOT_APPROVED, { gate: true });
      const idle = [...cards.values()].filter((c) => !c.busy && !c.box && !c.result && c.shown.startedAt === null);
      if (idle.length) {
        // An untouched card is already there: that one, rather than a pile of
        // empty cards.
        json(res, 200, { card: cardView(idle[0]) });
        return;
      }
      if (cards.size >= MAX_CARDS) throw new HttpError(409, `Déjà ${MAX_CARDS} cartes ouvertes : fermez les cartes terminées, puis recommencez.`);
      json(res, 200, { card: cardView(newCard()) });
      return;
    }
    if (method === 'POST' && path === '/api/cards/close') {
      // The technician is done with this card (boxed, or set aside): its box,
      // password and plan are forgotten, and its link is free again.
      await readJsonBody(req);
      const card = cardFor(req, url);
      if (card.busy) throw new HttpError(409, 'Une opération est en cours sur ce routeur : attendez son résultat avant de fermer sa carte.');
      forget(card);
      cards.delete(card.id);
      if (cards.size === 0) newCard();
      json(res, 200, { cards: [...cards.values()].map(cardView) });
      return;
    }
    if (method === 'POST' && path === '/api/cards/abandon') {
      // « Abandonner »: the technician gives up on a box that looks unplugged
      // (its card is red), instead of the wait running on for up to
      // `maxUnplugPauseMs`. Only then: a box that is merely slow to reboot is
      // waited for. A wait for the box (reboot, local check) ends at its next
      // attempt; a step already talking to the box (a write, the device-mode
      // request awaiting its press) ends by its own error or window first.
      // The operation then answers as on a timeout, and the card can be
      // closed.
      await readJsonBody(req);
      const card = cardFor(req, url);
      sampleLinks();
      if (!card.busy || !unplugged(card)) {
        throw new HttpError(409, 'Ce routeur n\'est pas signalé débranché : il n\'y a rien à abandonner. Attendez la fin de l\'opération.', { code: 'NOT_UNPLUGGED' });
      }
      card.abandoned = true;
      json(res, 200, { card: cardView(card) });
      return;
    }
    if (method === 'POST' && path === '/api/url') {
      const body = await readJsonBody(req);
      if (phase() === 'approved') throw new HttpError(409, 'Ce poste est autorisé : l\'adresse d\'ObliWAN ne se change pas ici.');
      if (!urlEditable()) {
        throw new HttpError(403, phase() === 'revoked'
          ? 'Ce poste est révoqué : l\'adresse d\'ObliWAN ne se change pas ici.'
          : 'L\'adresse d\'ObliWAN a été fixée par l\'administrateur : elle ne se change pas depuis ce poste.');
      }
      const given = normaliseBenchUrl(str(body.url));
      if (!given) throw new HttpError(400, 'Adresse invalide : attendu http(s)://nom-du-serveur, par exemple https://obliwan.example.com');
      for (const c of cards.values()) forget(c);
      useUrl(given, 'typed');
      await refresh('fresh');
      json(res, 200, state());
      return;
    }
    if (method === 'POST' && path === '/api/station/renew') {
      if (phase() !== 'revoked') throw new HttpError(409, 'Ce poste n\'est pas révoqué.');
      await refresh('renew');
      json(res, 200, state());
      return;
    }
    if (method === 'GET' && path === '/api/outcome') {
      // `?op=` — what became of THAT request (the page lost its answer);
      // without it — the latest operation, if its answer never went out (a
      // window reopened while it ran, or after).
      const op = url.searchParams.get('op');
      const rec = op !== null
        ? outcomes.find((o) => o.op === op) ?? null
        : [...outcomes].reverse().find((o) => o.pending || !o.delivered) ?? null;
      if (op !== null && !rec) throw new HttpError(404, 'Cette demande n\'est jamais arrivée à l\'application : rien n\'a été fait. Recommencez.');
      if (rec && !rec.pending) rec.delivered = true;
      json(res, 200, { outcome: rec ? { op: rec.op, card: rec.card, kind: rec.kind, pending: rec.pending, status: rec.status, body: rec.body } : null });
      return;
    }
    if (method === 'POST' && path === '/api/update/apply') {
      // The installer closes this application: never in the middle of an
      // operation on a router — on any card.
      if (busyCards().length) throw new HttpError(409, 'Une opération est en cours sur le routeur : attendez son résultat avant d\'installer la mise à jour.');
      const check = updateAnswer;
      if (!check?.available || !gate.baseUrl) throw new HttpError(409, 'Aucune mise à jour disponible.');
      const r = await applyUpdate(gate.baseUrl, check, execPath, { installerUrl: cfg.source === 'installer' ? cfg.baseUrl : null });
      json(res, r.launched ? 200 : 502, r.launched ? { ok: true, message: r.message } : { error: r.message });
      if (r.launched) setTimeout(() => hooks.exit?.(), 1_500).unref();
      return;
    }

    // ── gated: the router and the platform, on the card the request names ──
    if (method === 'POST' && path === '/api/router/find') {
      const card = cardFor(req, url);
      const body = await readJsonBody(req);
      await tracked(req, res, card, 'find', () => find(card, body));
      return;
    }
    if (method === 'POST' && path === '/api/router/device-mode') {
      const card = cardFor(req, url);
      const body = await readJsonBody(req);
      await tracked(req, res, card, 'device-mode', () => deviceModeWizard(card, body));
      return;
    }
    if (method === 'POST' && path === '/api/router/upgrade') {
      const card = cardFor(req, url);
      await readJsonBody(req);
      await tracked(req, res, card, 'upgrade', () => upgrade(card));
      return;
    }
    if (method === 'POST' && path === '/api/router/forget') {
      const card = cardFor(req, url);
      if (card.busy === 'prepare' || card.busy === 'upgrade' || card.busy === 'unlock') {
        throw new HttpError(409, 'Une opération est en cours sur ce routeur : attendez son résultat.');
      }
      forget(card);
      json(res, 200, { ok: true });
      return;
    }
    if (method === 'GET' && path === '/api/card') {
      // What the page needs to show a card again in its steps (the window
      // switched to another card, or was reopened): its box, its plan.
      const card = cardFor(req, url);
      json(res, 200, {
        card: cardView(card),
        box: card.box ? publicBox(card.box) : null,
        plan: card.box && card.plan ? { siteId: card.plan.siteId, ...planView(card.box, card.plan.answer) } : null,
        upgrade: card.box && card.plan && card.plan.answer.candidates.length === 0 && card.plan.answer.upgrade?.target
          ? { from: card.box.identity.router.version, to: card.plan.answer.upgrade.target.version, minimum: card.plan.answer.upgrade.minimum }
          : null,
        outcome: [...outcomes].reverse().find((o) => o.card === card.id && o.kind !== 'find' && o.kind !== 'plan') ?? null,
      });
      return;
    }
    if (method === 'GET' && path === '/api/tenants') {
      const api = requireApproved();
      json(res, 200, { tenants: await api.tenants().catch(platformError) });
      return;
    }
    if (method === 'GET' && path === '/api/sites') {
      const api = requireApproved();
      const tenantId = positiveInt(url.searchParams.get('tenantId'));
      if (!tenantId) throw new HttpError(400, 'Choisissez d\'abord le client.');
      const search = (url.searchParams.get('search') ?? '').trim().slice(0, 100);
      json(res, 200, { sites: await api.sites(tenantId, search).catch(platformError) });
      return;
    }
    if (method === 'POST' && path === '/api/plan') {
      const card = cardFor(req, url);
      const body = await readJsonBody(req);
      await tracked(req, res, card, 'plan', () => plan(card, body));
      return;
    }
    if (method === 'POST' && path === '/api/prepare') {
      const card = cardFor(req, url);
      const body = await readJsonBody(req);
      await tracked(req, res, card, 'prepare', () => prepare(card, body));
      return;
    }
    json(res, 404, { error: 'Introuvable.' });
  }

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    // Every request, the page included: without the per-run token nothing on
    // this machine can drive the bench, nor read which ObliWAN it talks to.
    const supplied = url.searchParams.get('t') ?? req.headers['x-bench-token'];
    if (!tokenMatches(supplied, token)) {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
      res.end('Forbidden');
      return;
    }
    route(req, res, url.pathname, url).catch((err: unknown) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (err instanceof HttpError) {
        json(res, err.status, { error: err.message, ...err.extra });
        return;
      }
      // Never a stack to the page; the log keeps what support needs.
      logError(`bench request ${req.method} ${url.pathname}: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
      json(res, 500, { error: err instanceof Error ? err.message : String(err) });
    });
  });

  let port = 0;
  return {
    server,
    token,
    watch,
    async listen() {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        // Loopback ONLY: the bench LAN is the network the routers are on.
        server.listen(0, '127.0.0.1', () => resolve());
      });
      port = (server.address() as AddressInfo).port;
      return port;
    },
    url() {
      return `http://127.0.0.1:${port}/?t=${token}`;
    },
    setWindow(mode, detail) {
      windowMode = mode;
      windowDetail = detail;
    },
    busy() {
      const c = busyCards()[0];
      return c && c.busy ? { seq: c.seq, kind: c.busy } : null;
    },
    close() {
      clearInterval(poller);
      clearInterval(updatePoller);
      clearInterval(watcher);
      server.closeAllConnections?.();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

// ============================================================================
// The process: one instance, one window, gone when the window is — once no
// operation on a router is running
// ============================================================================

async function probeInstance(lock: InstanceLock & { port: number; token: string }): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${lock.port}/api/instance`, {
      headers: { 'x-bench-token': lock.token },
      signal: AbortSignal.timeout(1_500),
    });
    const body = (await res.json()) as { app?: unknown };
    return res.ok && body.app === 'obliwan-bench';
  } catch {
    return false;
  }
}

const TITLE = 'ObliWAN — Préparation des routeurs';

export async function runGui(): Promise<void> {
  const claim = await claimInstance(instanceLockPath(), probeInstance);
  if (!claim.owner) {
    // Already running: ask IT to open its window, and leave.
    let ok = false;
    try {
      const res = await fetch(`http://127.0.0.1:${claim.running.port}/api/window`, {
        method: 'POST',
        headers: { 'x-bench-token': claim.running.token },
        signal: AbortSignal.timeout(5_000),
      });
      ok = res.ok;
    } catch {
      ok = false;
    }
    if (!ok) await showMessageBox(TITLE, 'L\'application est déjà ouverte mais ne répond pas. Fermez sa fenêtre, puis relancez-la.');
    // NOT process.exit(): right after a fetch, Node 24 on Windows was seen to
    // abort in libuv (`!(handle->flags & UV_HANDLE_CLOSING)`, src\win\async.c)
    // — a crash code instead of 0. Nothing else holds the loop: it drains.
    process.exitCode = ok ? 0 : 1;
    return;
  }
  process.on('exit', () => claim.release());

  const hooks: BenchAppHooks = {};
  const app = createBenchApp({ hooks, historyFile: defaultHistoryFile() });
  try {
    await app.listen();
  } catch (err) {
    claim.release();
    await showMessageBox(TITLE, `L'application n'a pas pu démarrer son serveur local : ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
  claim.publish(Number(new URL(app.url()).port), app.token);
  const url = app.url();
  // Nowhere to read it in the shipped executable (no console); a developer
  // running the bundle under node sees it.
  console.log(`ObliWAN bench: interface at ${url}`);

  let opening = false;
  const open = async (): Promise<void> => {
    if (opening) return;
    opening = true;
    try {
      const w = await openAppWindow(url);
      app.setWindow(w.mode, w.detail);
      if (w.child) {
        const started = Date.now();
        w.child.once('exit', () => app.watch.edgeExited(Date.now() - started));
      }
      if (w.mode === 'none') {
        // No address and no "open it in a browser": a browser tab is not this
        // application's window (window.ts, "NO BROWSER FALLBACK").
        await showMessageBox(TITLE, `La fenêtre de l'outil d'établi n'a pas pu s'ouvrir : ${w.detail ?? 'raison inconnue'}.\n\nRelancez l'outil ; si cela se reproduit, signalez-le avec le fichier bench-error.log de %LOCALAPPDATA%\\ObliWAN.`);
        // A reopen during an operation on a router keeps the process alive
        // to finish it (the watch below leaves once it is done).
        if (app.busy() === null) void leave(1, null);
      }
    } finally {
      opening = false;
    }
  };

  let leaving = false;
  let watchTimer: NodeJS.Timeout | null = null;
  const leave = async (code: number, message: string | null): Promise<void> => {
    if (leaving) return;
    leaving = true;
    if (watchTimer) clearInterval(watchTimer);
    claim.release();
    await app.close().catch(() => undefined);
    if (message) await showMessageBox(TITLE, message, 'info');
    // Let the loop drain rather than process.exit() (see the second-instance
    // path above); a handle that still holds it — an Edge child still open
    // when an update starts — is cut after 5 s.
    process.exitCode = code;
    setTimeout(() => process.exit(code), 5_000).unref();
  };
  hooks.reopen = () => void open();
  hooks.exit = () => void leave(0, null);
  process.on('SIGINT', () => void leave(0, null));
  process.on('SIGTERM', () => void leave(0, null));

  await open();
  if (leaving) return; // no window could be opened: already on the way out
  // The operation on whose behalf the window was last reopened.
  let reopenedFor: number | null = null;
  watchTimer = setInterval(() => {
    const v = app.watch.verdict();
    if (v === 'alive') return;
    // Never leave in the middle of an operation on a router: the process IS
    // the operation (an upgrade between its upload and its reboot, a file
    // with the site's secrets half on the box, a result not yet reported to
    // ObliWAN). The window comes back, once per operation, so that the
    // technician sees how it ends (the page reads the outcome back); closed
    // again, the operation still runs to its end, and the application leaves
    // then. Only an explicit signal (SIGINT/SIGTERM) leaves at once.
    const op = app.busy();
    if (op) {
      if (reopenedFor !== op.seq) {
        reopenedFor = op.seq;
        app.watch.reopened();
        void open();
      }
      return;
    }
    if (v === 'window-closed') void leave(0, null);
    else if (v === 'never-opened') {
      void leave(1, 'La fenêtre de l\'application ne s\'est jamais affichée ; l\'application s\'arrête. Relancez-la, et si le problème persiste, signalez-le avec le fichier bench-error.log de %LOCALAPPDATA%\\ObliWAN.');
    }
  }, 1_000);
}
