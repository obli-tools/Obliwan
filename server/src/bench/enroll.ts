/**
 * ObliWAN — the bench provisioning core.
 *
 * ┌─ WHAT THIS IS FOR ───────────────────────────────────────────────────────┐
 * │ An order preparer has a brand-new router on a workbench, on their own     │
 * │ LAN, with its factory password. ObliWAN cannot reach it: there is no      │
 * │ tunnel yet, and there will not be one until the box is configured. So     │
 * │ something local has to do the first configuration — and that something is │
 * │ the only place in the product allowed to write local accounts.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY IT IS TYPESCRIPT AND NOT GO, UNLIKE THE OTHER OBLI* AGENTS ─────────┐
 * │ Obliview and Obliance ship Go agents because they do OS-level work:       │
 * │ hardware UUIDs, PawnIO, airgap. This tool does VENDOR PROTOCOL work —     │
 * │ RouterOS binary API, SSH dialects, SonicOS REST — every line of which is  │
 * │ already written, reviewed and harnessed in `services/drivers` and         │
 * │ `services/transport`.                                                    │
 * │                                                                          │
 * │ Rewriting it in Go would create a SECOND renderer for the same devices.   │
 * │ The day the two disagree by one space, every freshly prepared router      │
 * │ arrives with drift on its first collection, on exactly the                │
 * │ population just installed, found weeks later. One implementation, shared  │
 * │ with the server, versioned with it.                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE TWO REFUSALS THAT MAKE THIS SAFE ───────────────────────────────────┐
 * │ 1. IT PROPOSES A TENANT, IT NEVER ASSIGNS ONE. The preparer picks a       │
 * │    customer from a list on a workbench, at 4pm, on their fortieth box.    │
 * │    That is exactly the human step our checks distrust: get it wrong       │
 * │    and customer A's variables render onto customer B's router. So the     │
 * │    device lands `pending` and unmanaged — the same quarantine CHR         │
 * │    discovery uses — and a human binds it afterwards, in the UI, with the  │
 * │    identity the box actually reported in front of them.                   │
 * │                                                                          │
 * │ 2. THE FACTORY PASSWORD NEVER LEAVES THIS PROCESS. It is typed by the     │
 * │    preparer, used to open one session, and dropped. It is not sent to     │
 * │    ObliWAN, not stored, and not in the enrolment payload. The credential  │
 * │    ObliWAN will later use is the one this tool CREATES, and that one goes │
 * │    to the vault through the normal path, never through here.              │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import type { DeviceFamily, TransportKind } from '@obliwan/shared';
import { DEVICE_FAMILIES } from '@obliwan/shared';
import { getDriver } from '../services/drivers/registry';
import type { DriverContext, ResolvedTransport } from '../services/drivers/types';

/** What the preparer types, and nothing more. */
export interface BenchTarget {
  /** Address on the WORKBENCH lan. Never recorded as identity. */
  host: string;
  port?: number;
  family: DeviceFamily;
  /** Factory account. Used once, never transmitted, never stored. */
  username: string;
  password: string;
  /** Which transport to speak. Defaults per family. */
  transport?: TransportKind;
}

/** What the tool learned from the box itself. */
export interface BenchIdentity {
  family: DeviceFamily;
  brand: string | null;
  model: string | null;
  osVersion: string | null;
  /** Read off the hardware. This is what makes the far side recognise the box
   *  rather than create a second row for it. */
  serial: string | null;
  systemIdentity: string | null;
}

/** The payload posted to `/api/devices/enroll`. Deliberately small, and
 *  deliberately WITHOUT a status, a tenant binding or any secret. */
export interface EnrolmentRequest {
  identity: BenchIdentity;
  /** A SUGGESTION. The server records it as such and binds nothing. */
  proposedTenantId: number | null;
  /** Free label the preparer typed — a site code, an order number. */
  note: string | null;
  /** Which workstation did this, from the suite's machine-identity pattern. */
  preparedBy: string | null;
  preparedAt: string;
}

/**
 * The families this tool can IDENTIFY from the bench, and the transport each
 * is read over. A family missing here is not offered by the GUI or the CLI,
 * and `readBenchIdentity` refuses it by name (`NOT_ON_THE_BENCH`).
 */
const BENCH_TRANSPORT: Readonly<Partial<Record<DeviceFamily, TransportKind>>> = {
  mikrotik_routeros6: 'routeros_api',
  mikrotik_routeros7: 'routeros_api',
  draytek_vigor: 'ssh',
  zyxel_standalone: 'ssh',
  sonicwall_sonicos: 'rest',
};

/**
 * Why the other families are not offered. Both used to sit in the dropdown
 * and failed on every read, whatever the preparer typed:
 *   - `zyxel_cpe` is identified from the ACS's last Inform or over SNMP. The
 *     bench has no database (so no Inform) and no SNMP setting, and the driver
 *     has no SSH or web inventory path — the bench handed it an SSH transport
 *     it never reads.
 *   - `zyxel_nebula` is identified by the Zyxel cloud API with an organisation
 *     key, not by the box. The bench handed it a username and a password, and
 *     the driver refused for want of an API key "in the vault".
 */
const NOT_ON_THE_BENCH: Readonly<Partial<Record<DeviceFamily, string>>> = {
  zyxel_cpe:
    'un CPE Zyxel (zyxel_cpe) s\'identifie par l\'ACS (le dernier Inform) ou par SNMP, et cet outil '
    + 'n\'a ni l\'un ni l\'autre. Il s\'enrôle par l\'ACS d\'ObliWAN : à son premier Inform il se '
    + 'signale sur la page ACS, où un opérateur le rattache.',
  zyxel_nebula:
    'un équipement Nebula (zyxel_nebula) s\'identifie par l\'API du cloud Zyxel avec une clé '
    + 'd\'organisation, pas en interrogeant l\'équipement : cet outil ne peut pas le lire depuis l\'établi.',
};

/** The families the GUI and the CLI offer — every family that has a bench
 *  transport, in `DEVICE_FAMILIES` order. */
export const BENCH_FAMILIES: readonly DeviceFamily[] = DEVICE_FAMILIES.filter((f) => BENCH_TRANSPORT[f] !== undefined);

/** Null when the bench can identify `family`; otherwise the sentence to show. */
export function benchFamilyRefusal(family: string): string | null {
  if ((BENCH_FAMILIES as readonly string[]).includes(family)) return null;
  const reason = NOT_ON_THE_BENCH[family as DeviceFamily];
  return reason
    ? `Famille non prise en charge sur l'établi : ${reason}`
    : `Famille inconnue : ${family || '(vide)'}`;
}

/**
 * Build the one-shot driver context. No database, no vault, no arbiter — this
 * process has none of them and must not grow them: a bench tool that needs a
 * connection string is a bench tool that cannot leave the office.
 *
 * `noDatabase` says so to the drivers. Without it the DrayTek driver asked the
 * ACS first — a database read of the box's last Inform — which in this bundle
 * reaches the db stub and failed every DrayTek read before the device was
 * dialled. (Zyxel CPE had the same defect; it is no longer offered at all, see
 * `NOT_ON_THE_BENCH`.)
 */
function benchContext(target: BenchTarget): DriverContext {
  const transport = target.transport ?? BENCH_TRANSPORT[target.family] ?? 'ssh';
  const resolved: ResolvedTransport = {
    transport,
    enabled: true,
    priority: 0,
    host: target.host,
    port: target.port ?? null,
    useTls: transport === 'rest',
    tlsFingerprintSha256: null,
    params: {},
    credentials: { username: target.username, password: target.password },
  };
  return {
    // There is no device row yet — that is the point of enrolling. The drivers
    // use these only for logging and correlation.
    deviceId: 0,
    tenantId: 0,
    family: target.family,
    transports: [resolved],
    timeoutMs: 20_000,
    noDatabase: true,
  };
}

/**
 * Step 1 — ask the box what it is.
 *
 * Runs BEFORE anything is written. A preparer who selected the wrong family in
 * the dropdown finds out here, from the hardware, instead of after a failed
 * push into a CLI that does not speak the dialect they chose.
 */
export async function readBenchIdentity(target: BenchTarget): Promise<BenchIdentity> {
  // Refused HERE as well as in both front ends: the dropdown is a convenience,
  // this is the rule.
  const refusal = benchFamilyRefusal(target.family);
  if (refusal) throw new Error(refusal);
  const driver = getDriver(target.family);
  const inv = await driver.getInventory(benchContext(target));
  return {
    family: target.family,
    brand: inv.brand ?? null,
    model: inv.model ?? null,
    osVersion: inv.osVersion ?? null,
    serial: inv.serial ?? null,
    systemIdentity: inv.systemIdentity ?? null,
  };
}

/**
 * Step 2 — turn what the box reported into an enrolment.
 *
 * PURE, so the refusal below is testable without a router and without a server.
 * The refusal matters more than the mapping: a box that reports neither a
 * serial nor a system identity cannot be recognised later, and enrolling it
 * would create a row that no future connection can be matched against.
 * `assertTargetBinding` would then refuse it forever, which is a device the
 * platform can see and never touch — worse than one it never knew about.
 */
export function buildEnrolment(
  identity: BenchIdentity,
  opts: { proposedTenantId?: number | null; note?: string | null; preparedBy?: string | null; now: string },
): EnrolmentRequest {
  if (!identity.serial && !identity.systemIdentity) {
    throw new Error(
      'The device reported neither a serial number nor a system identity. ObliWAN would have no ' +
        'way to recognise it on a later connection, so it is not enrolled. Check the ' +
        'credentials and the selected family, then read the identity again.',
    );
  }
  return {
    identity,
    proposedTenantId: opts.proposedTenantId ?? null,
    note: opts.note ?? null,
    preparedBy: opts.preparedBy ?? null,
    preparedAt: opts.now,
  };
}

/**
 * Who is enrolling, as far as the platform is concerned: the URL it talks to
 * and the header that proves which workstation it is. `BenchStation`
 * (`./station.ts`) is the implementation.
 */
export interface EnrolmentStation {
  /** The ONLY URL the header may be sent to — it was registered there. */
  readonly baseUrl: string;
  /** May throw when the token cannot be read or filed locally; reported as
   *  this workstation's problem, never as the platform's. */
  authHeader(): { authorization: string };
}

/** Long enough for a slow platform, short enough that a preparer is told. */
const ENROL_TIMEOUT_MS = 30_000;

/**
 * Step 3 — hand it to the platform.
 *
 * ┌─ AS AN APPROVED WORKSTATION, AND ONLY TO ITS OWN SERVER ─────────────────┐
 * │ `POST /api/devices/enroll` is guarded by `requireApprovedBenchStation`   │
 * │ (server/src/middleware/benchStation.ts): it wants                        │
 * │ `Authorization: Bench <token>` from a workstation a platform             │
 * │ administrator has approved. The station carries both the header and the  │
 * │ URL, and the URL is taken FROM it rather than passed beside it: a token  │
 * │ registered at one instance must never be sent to another, and a second   │
 * │ argument is a second thing that can disagree. The station is REQUIRED —  │
 * │ a header obtained by default is the one the next caller forgets.         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The anonymous design that stood here before was unreachable in fact —
 * mounted under the server's tenant router, the route answered 401 to every
 * bench call before its own middleware ran — and when it was made reachable the
 * decision went the other way: one token PER WORKSTATION, revocable on its own,
 * stored server-side only as a sha256, granting no operator session and no
 * read of the fleet (server/src/middleware/benchEnrolment.ts says why). The
 * per-device approval did not go away; it is now the second gate.
 *
 * Still true, and still the point: no ROUTER credential travels. The factory
 * password is not in this payload, and the station token authorises the desk,
 * never the box.
 *
 * The answer is the house envelope `{ success, data: { deviceId, status } }`.
 * It used to be cast whole to `{ deviceId, status }`, so both read back
 * `undefined` and the preparer was shown "équipement #undefined" — the row
 * number an administrator needs to find the box. Anything that is not that
 * shape is now refused by name rather than displayed.
 *
 * ── 201 IS "CREATED", 200 IS "ALREADY THERE" ─────────────────────────────
 * The server answers a repeat of this station's own pending enrolment of the
 * same serial with 200 and the FIRST call's device id (`judgeEnrolmentRetry`),
 * and a new row with 201. `created` carries that difference out. Without it,
 * the GUI told a preparer "la fiche #N a quand même été créée… demandez à un
 * administrateur de la supprimer" and then, one click later, "Fiche créée :
 * #N" — the same row, which the second request had not created at all.
 *
 * ── WHICH FAILURES MAY HAVE CREATED THE RECORD ───────────────────────────
 * Every failure is reported for what it is, because the advice differs:
 *   - the station file (a local problem: nothing was sent);
 *   - a 3xx: not followed — the token goes to the station's own URL and no
 *     further (`station.ts`) — and nothing was enrolled;
 *   - no answer in time, a connection reset after the request left
 *     (`CUT_AFTER_SENDING`), or an answer cut while its body was being read:
 *     the record MAY exist, and a retry from this desk is matched by serial
 *     instead of duplicated. The body read used to sit outside every `try`, so
 *     a cut there escaped as a bare "terminated" — exactly the case the
 *     timeout sentence was written for;
 *   - any other failure to get an answer: "ObliWAN injoignable", as before.
 */
export async function submitEnrolment(
  station: EnrolmentStation,
  body: EnrolmentRequest,
): Promise<{ deviceId: number; status: string; created: boolean }> {
  // Before the request, and outside its `try`: a station file that cannot be
  // read or written is a problem on THIS workstation, and used to come out as
  // "ObliWAN injoignable (ENOTDIR …)".
  let auth: { authorization: string };
  try {
    auth = station.authHeader();
  } catch (err) {
    throw new Error(
      `le jeton de ce poste n'a pas pu être lu ou enregistré sur cet ordinateur (${errorText(err)}) : `
        + 'rien n\'a été envoyé à ObliWAN.',
    );
  }

  const url = `${station.baseUrl.replace(/\/+$/, '')}${ENROL_PATH}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...auth },
      body: JSON.stringify(body),
      // Never followed: a 307/308 would re-send the enrolment to wherever
      // `Location` points, minus the Authorization header. See `station.ts`.
      redirect: 'manual',
      signal: AbortSignal.timeout(ENROL_TIMEOUT_MS),
    });
  } catch (err) {
    if (isTimeout(err)) {
      // The request left; the answer did not come back. The record may exist.
      throw new Error(`pas de réponse d'ObliWAN en ${ENROL_TIMEOUT_MS / 1000} s : ${MAY_EXIST}`);
    }
    const code = causeCode(err);
    if (code && CUT_AFTER_SENDING.has(code)) {
      throw new Error(`la connexion à ObliWAN a été coupée avant sa réponse (${code}) : ${MAY_EXIST}`);
    }
    throw new Error(`ObliWAN injoignable (${code ?? errorText(err)})`);
  }

  if (res.status >= 300 && res.status <= 399) {
    await res.text().catch(() => '');
    const raw = res.headers.get('location');
    let location = raw;
    try {
      if (raw) location = new URL(raw, url).toString();
    } catch {
      /* shown as received */
    }
    throw new Error(
      `ObliWAN a répondu par une redirection (${res.status}${location ? ` vers ${location}` : ''}) : `
        + 'ce poste ne la suit pas — son jeton ne part qu\'à l\'adresse où il a été enregistré — et '
        + 'rien n\'a été enrôlé. Indiquez directement l\'adresse finale d\'ObliWAN comme URL.',
    );
  }

  let text: string;
  try {
    text = await res.text();
  } catch (err) {
    const detail = isTimeout(err) ? `rien reçu de plus en ${ENROL_TIMEOUT_MS / 1000} s` : causeCode(err) ?? errorText(err);
    if (res.ok) {
      throw new Error(
        `ObliWAN a accepté l'enrôlement (${res.status}) mais sa réponse a été coupée (${detail}) : le `
          + 'numéro de la fiche n\'est pas arrivé. Relancez l\'enrôlement depuis ce poste : si '
          + 'l\'équipement a un numéro de série, ObliWAN répond avec la même fiche au lieu d\'en créer '
          + 'une seconde.',
      );
    }
    throw new Error(`ObliWAN a refusé l'enrôlement (${res.status}) ; sa réponse a été coupée (${detail}).`);
  }
  let parsed: { data?: unknown; error?: unknown } | null = null;
  try {
    parsed = JSON.parse(text) as { data?: unknown; error?: unknown };
  } catch {
    parsed = null;
  }
  if (!res.ok) {
    const said = typeof parsed?.error === 'string' ? parsed.error : text.slice(0, 300);
    if (res.status === 401 || res.status === 403) {
      // The platform refused the DESK, not the box: unknown token (401), not
      // approved yet or revoked (403). Its own sentence says which.
      throw new Error(`ce poste n'est pas autorisé à enrôler (${res.status}) : ${said}`);
    }
    throw new Error(`enrolment refused (${res.status}): ${said}`);
  }
  const data = parsed?.data as { deviceId?: unknown; status?: unknown } | undefined;
  if (
    !data
    || typeof data.deviceId !== 'number'
    || !Number.isInteger(data.deviceId)
    || data.deviceId <= 0
    || typeof data.status !== 'string'
  ) {
    throw new Error(
      `unexpected enrolment response (${res.status}): no device number in it — check the device `
        + `list on ${station.baseUrl} before enrolling this box again. ${text.slice(0, 200)}`,
    );
  }
  // Only a 201 says a row was created. A 200 is the server recognising this
  // station's own earlier enrolment of the same serial; any other 2xx is not
  // a creation this tool may announce.
  return { deviceId: data.deviceId, status: data.status, created: res.status === 201 };
}

const ENROL_PATH = '/api/devices/enroll';

const MAY_EXIST =
  'la fiche a peut-être été créée. Relancez l\'enrôlement depuis ce poste : si l\'équipement a un '
  + 'numéro de série, ObliWAN répond avec la même fiche au lieu d\'en créer une seconde.';

/** Socket errors that mean the request may have reached the server before the
 *  connection died — as opposed to a connection that was never made. */
const CUT_AFTER_SENDING: ReadonlySet<string> = new Set([
  'ECONNRESET',
  'EPIPE',
  'UND_ERR_SOCKET',
  'UND_ERR_CLOSED',
]);

function isTimeout(err: unknown): boolean {
  const name = (err as Error | null)?.name;
  return name === 'TimeoutError' || (name === 'AbortError' && (err as { cause?: { name?: string } }).cause?.name === 'TimeoutError');
}

function causeCode(err: unknown): string | null {
  const cause = (err as { cause?: { code?: unknown } } | null)?.cause;
  return typeof cause?.code === 'string' ? cause.code : null;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
