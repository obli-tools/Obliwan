// ============================================================================
// ObliWAN — bench compile: the run-after-reset file, compiled by the SERVER
// ============================================================================
//
// `POST /api/bench/v1/compile` and `POST /api/bench/v1/devices/:id/result`.
// The bench application uploads the file this module returns byte for byte
// (`applyFactoryProvisioning({ compiled })` in bench/routerosApply.ts): it
// checks the SHA-256, the file name and that the file removes itself, and it
// assembles NOTHING around it. So everything that must run on the box after
// the factory reset is in this file, in this order:
//
//   (a) the interface-wait prelude — bounded `:while … :delay 1s` loops for
//       the ethernet ports the body names, `lte1` when the body names it, and
//       the radios of the box's Wi-Fi stack when the body uses them. A box
//       just out of a reset runs its script before every port exists, and a
//       body that configures `ether5` before `ether5` exists stops there;
//   (b) the customer template, rendered for this site, up to `# obliwan:tail`,
//       inside `:do { } on-error={ }` with an end-of-body sentinel as its last
//       statement, so a body that stops half-way still reaches (c);
//   (c) the ObliWAN access block: the allocated system identity; a dedicated
//       `obliwan` account, reachable from the management range only, whose
//       password is generated here, per device, and stored in the vault as
//       this device's credential; the ssh service opened to the management
//       range IN ADDITION to the addresses the template allowed (a
//       customer's own admin range is reproduced as the fleet has it, an ssh
//       left open to all ends restricted to the management range); and,
//       LAST, the management API: api-ssl on 8729, restricted to the
//       management range, serving a certificate made on the box — a local CA
//       `obliwan-ca`, then `obliwan-api` signed by it, both reused when
//       already there (`apiSslAccessLines`, shared/src/managementAccess.ts:
//       the one source of those lines, made to be shared with the change job
//       that brings routers already in service to the same state). The
//       plain `api` service is NOT written: it stays as the template set it.
//       The customer templates DISABLE api and api-ssl, as the fleet has
//       them: without this block a box would leave the bench unreachable by
//       ObliWAN's API. The certificate step comes last so that a refusal
//       there (logged by the certificate's name) still leaves the account and
//       ssh in place — the run ends FAILED, and the box is reachable by ssh
//       to be put right. Then, in a block of its own
//       and only when the tenant's SNMP_AUTO_TARGET_CREDENTIAL names a v1/v2c
//       credential, the SNMP community ObliWAN polls with — ADDED, restricted
//       to the management range, when the box has no community of that name;
//       KEPT as the customer set it (name, access, comment) when it has one —
//       the templates rename the default community to `snmp_community`, which
//       is often that very name — with only the management prefixes it lacks
//       added to its addresses. `/snmp community add` of a name the box
//       already holds fails, and it used to end every such run FAILED;
//   (d) the success marker: a log line and a `/system script` entry named
//       after the tag, either `obliwan-provision-ok-<tag>` or
//       `obliwan-provision-failed-<tag>`, which the bench and ObliWAN can read.
//       `ok` needs every block to have reached its last line: the body, the
//       access block and, when written, the SNMP block — each of which logs
//       its own `reason=` when it stops on an error;
//   (e) the file's removal of itself (it holds credentials in clear), then
//       the template's tail — the lines after `# obliwan:tail`, whose
//       `/ip dhcp-client release` must be, and is, the LAST line of the file:
//       the operator's DHCP scripts only bootstrap after a release.
//
// That single file is the LEGACY answer (`content`), kept for bench builds
// that predate `files`. Its flaw: RouterOS parses a script whole before it
// runs any of it, so one syntax error in the template skipped everything —
// the access block, the marker and the removal of the file holding the
// credentials. The same compile now also answers `files` — a runner holding
// no credential and no template text, one file per section and one for the
// tail, each read and parsed on its own by the runner, which removes every
// file, proves them gone and always writes the marker. `splitFile.ts` holds
// that design and its evidence.
//
// Device-mode: the features the RENDERED revision uses (`bodyFeatures.ts`)
// are judged against the reading the bench sends (`box.deviceMode`) before
// anything is committed — a denied one refuses the compile — unless the
// bench declares `deviceModeOverride` (an operator's decision, for a remote
// test). Under that override, and only then, a statement using a DENIED
// feature is wrapped, in both forms, so that it fails alone. The reading is
// stored on the device as one observation (`deviceModeColumns`).
//
// ┌─ THE SECRETS RULE: THE FILE IS DELIVERED ONCE AND KEPT NOWHERE ─────────┐
// │ The content carries the L2TP secret, the ObliWAN account's password, the │
// │ bench secrets (a SIM PIN) and every vault secret the template           │
// │ interpolates. It exists in memory for the length of the request: it is  │
// │ never logged, never stored, never put in an error message. What is      │
// │ stored (`bench_provisionings`, `audit_log`) is its SHA-256, the SHA-256  │
// │ of the REDACTED render, the tag and the file name. The response carries │
// │ `Cache-Control: no-store` (set by the controller).                       │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHAT IS REASONED, NOT OBSERVED ─────────────────────────────────────────┐
// │ No RouterOS box has run a file from this compiler. In particular: that   │
// │ `run-after-reset` runs a body wrapped in one `:do { }` exactly as the    │
// │ legacy bench runner's `/import` of the same wrapping did; that           │
// │ `/ip service get … address` and `/snmp community get … addresses` return │
// │ arrays the `:foreach` below can walk, each entry spelled as `[:tostr]`   │
// │ prints it (a management prefix is recognised by that text only), and    │
// │ that `[:toarray "<prefix>,<prefix>"]` walks the management range; that  │
// │ `/snmp community add` of an existing name fails; and that a running      │
// │ script may remove its own file. The `/certificate` behaviours the        │
// │ api-ssl lines rely on are listed, each with its evidence or marked       │
// │ REASONED, in shared/src/managementAccess.ts; how the ssh and api-ssl     │
// │ lines tell the configured service from a CONNECTION entry of the same    │
// │ name (listed by RouterOS 7.24.5 for every open session [prod]), and what │
// │ of that is REASONED, in shared/src/routerOsService.ts. The bench harness │
// │ runs the compiled file on a MODEL of those menus                         │
// │ (testing/fakeRouterOsScript.ts), which proves the file's own logic, not  │
// │ RouterOS's behaviour.                                                    │
// └──────────────────────────────────────────────────────────────────────────┘

import crypto from 'node:crypto';
import type { Knex } from 'knex';
import {
  ACTIVE_CHANGE_JOB_STATUSES,
  API_SSL_PORT,
  HARDCODED_DEFAULTS,
  OBLIWAN_ACCOUNT,
  OBLIWAN_GROUP_POLICY,
  SETTINGS_KEYS,
  apiSslAccessLines,
  routerOsServiceSelect,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { AllocationError, computedForSite, previewForSite, type ComputedSiteValues } from '../allocation';
import { renderForSite, SiteRenderError, type BoxFacts } from '../template/siteRender.service';
import { upsertAssignment } from '../template/assignment.service';
import { linkLineByDeviceIccid, type SimLinkOutcome } from '../sim/deviceLink.service';
import { hostAddress, provisionConcentratorSecret, type ConcentratorSecretState } from '../change/concentratorSecret.service';
import { isWithinMaintenanceWindow } from '../change/jobQueue.service';
import { currentKeyVersion, decrypt, encrypt } from '../secretVault.service';
import { appendAudit } from '../attestation/auditLog.service';
import { settingsService } from '../settings.service';
import { getRouterOsPool } from '../fleet/routerosPool';
import { generateAccountPassword } from './obliwanAccount';
import {
  BenchApiError,
  benchDeclarationsOf,
  boxFactsOf,
  deviceModeRefusal,
  listBenchCandidates,
  loadBenchSite,
  MANAGEMENT_RANGE_KEY,
  PPP_TAKEN_REASON,
  preRenderRedacted,
  readManagementRange,
  revisionSourceFeatures,
  serialTakenReason,
  takeoverRefusal,
  wifiStackMismatch,
  type BenchBoxInput,
  type BenchVariableDecl,
  type SiteDeviceFacts,
} from './planning.service';
import { deniedFeatures, deviceModeColumns, deviceModeFeaturesOf } from './bodyFeatures';
import { usableCredentialTenants } from '../snmp/credential.service';
import {
  GATED_GLOBAL,
  PROVISION_PREFIX,
  RUNNER_HEADER,
  SECTION_HEADER,
  MAX_COMPILED_FILES,
  SECTION_READ_LIMIT_BYTES,
  SECTION_SENTINEL,
  assembleSplitFiles,
  gatedHeadLines,
  type CompiledFile,
} from './splitFile';

// ============================================================================
// Constants
// ============================================================================

/** The account ObliWAN dials the box with, its user group and that group's
 *  policy (`policy` and, since the operator decision of 2026-10-05,
 *  `sensitive` granted — why is written beside the constants; the group is
 *  removed and re-added on every preparation, so a re-prepared box gets the
 *  current list): shared/src/managementAccess.ts, because
 *  the management_access job creates the SAME account on a router already in
 *  service, and the two writers must not drift apart. Re-exported here for
 *  the modules and harnesses that read them from the bench. */
export { OBLIWAN_ACCOUNT, OBLIWAN_GROUP_POLICY };
/** The ssh port written into the access block and into the ssh transport
 *  row. The API's (api-ssl, 8729) is shared/src/managementAccess.ts's
 *  `API_SSL_PORT`, written by `apiSslAccessLines` and into the routeros_api
 *  row. The group's `api` policy is what lets the account log in over the
 *  RouterOS API, api-ssl included. */
const SSH_PORT = 22;

/** The most `/file get … contents` reads on an OLDER RouterOS build
 *  (bench/splitFile.ts, its evidence box: older builds stopped at 4095).
 *  The two sections ObliWAN writes itself — `access` (identity, account,
 *  ssh, api-ssl) and `snmp` — must fit it whole: they are not cut, and a box
 *  that truncated `access` would end with no ObliWAN account, no ssh and no
 *  api-ssl at once. Their size depends on the management range (each prefix
 *  is written a few times), the identity, the tag and the password, never on
 *  the template; a range that would not fit is refused at the compile
 *  (`assembleSplitCompiledFiles`, on the provisional assembly of step 3:
 *  before the concentrator account is touched and before any device row is
 *  written — the site's allocation, committed at step 2, stays committed, as
 *  for every refusal after that step). */
export const OLDER_BUILD_READ_LIMIT_BYTES = 4095;
/** The sections `OLDER_BUILD_READ_LIMIT_BYTES` binds. */
const OBLIWAN_SECTION_IDS: ReadonlySet<string> = new Set(['access', 'accounts', 'snmp']);

/** Wait budgets of the prelude, in seconds. */
export const PRELUDE_WAIT = { ethernet: 60, lte: 120, radios: 60 } as const;

/** How long the compile waits for the concentrator account. */
export const CONCENTRATOR_WAIT_MS = 20_000;

/** The line a converted template writes between its body and its tail. */
export const TAIL_MARKER = '# obliwan:tail';

const BODY_SENTINEL = 'obliwanBodyDone';
const ACCESS_SENTINEL = 'obliwanAccessDone';
const SNMP_SENTINEL = 'obliwanSnmpDone';
/** Names only this compiler may write: a body that wrote one could mark its
 *  own success or split the file wrongly. */
const RESERVED_IN_BODY = [
  BODY_SENTINEL, ACCESS_SENTINEL, SNMP_SENTINEL, SECTION_SENTINEL, GATED_GLOBAL, 'obliwanFailed',
  PROVISION_PREFIX, '# obliwan-compiled', RUNNER_HEADER, SECTION_HEADER,
];

/** The bench's own rules (bench/routerosApply.ts), restated: a tag and a file
 *  name outside them are refused there before anything is dialled. */
const TAG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.rsc$/;
/** What may sit between double quotes in the access block with no escaping. */
const IDENTITY_RE = /^[A-Za-z0-9._-]{1,64}$/;
const COMMUNITY_RE = /^[A-Za-z0-9._-]{1,32}$/;

// ============================================================================
// Pure helpers — exported for the harness
// ============================================================================

/** The `obliwan` account's password, generated per device: bench/
 *  obliwanAccount.ts, the one generator the management_access job uses too
 *  when it creates the same account on a router in service. */
export { generateAccountPassword };

export function sha256Hex(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Which lines are `/ip dhcp-client` commands, and whether each releases a
 * client or installs a script. Follows RouterOS's menu context: a line that is
 * only a path (`/ip dhcp-client`) makes the following relative commands
 * (`add … script=…`, `release [find]`) commands of that menu. Comment lines are
 * nothing. A heuristic over text, not a parser: a `script=` continued onto a
 * `\` line is not seen.
 */
function dhcpClientLines(lines: string[]): Array<{ release: boolean; script: boolean }> {
  let menu = '';
  return lines.map((raw) => {
    const l = raw.trim();
    if (l === '' || l.startsWith('#')) return { release: false, script: false };
    if (/^\/[A-Za-z0-9 /-]*$/.test(l)) {
      menu = l;
      return { release: false, script: false };
    }
    const inline = /dhcp-client\b/.test(l);
    const relative = !l.startsWith('/') && /dhcp-client\s*$/.test(menu);
    if (!inline && !relative) return { release: false, script: false };
    return {
      release: inline ? /dhcp-client[\s/]+release\b/.test(l) : /(?:^|[{;\s])release\b/.test(l),
      script: /\bscript=/.test(l),
    };
  });
}

/**
 * The rendered text split on `# obliwan:tail`. The tail is what runs after the
 * file has removed itself. A DHCP client release must be the LAST line of the
 * whole file (operator rule: the operator's DHCP scripts only bootstrap after a
 * release, and a line after it would run on a box that is already being
 * re-addressed), so a release is admitted only as the tail's last non-blank
 * line — a release in the body would run before the access block, the marker
 * and the self-removal. A body that installs a DHCP-client script must end the
 * file with that release. Throws a BenchApiError naming the rule; never quotes
 * a line (a line may hold a secret).
 */
export function splitRendered(text: string): { head: string[]; tail: string[] } {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  const at: number[] = [];
  lines.forEach((l, i) => { if (l.trim() === TAIL_MARKER) at.push(i); });
  if (at.length > 1) {
    throw new BenchApiError(422, `Le modèle contient ${at.length} lignes « ${TAIL_MARKER} » : une seule est admise.`, 'template');
  }
  const trimEnd = (xs: string[]): string[] => {
    const out = [...xs];
    while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
    return out;
  };
  const head = trimEnd(at.length === 1 ? lines.slice(0, at[0]) : lines);
  const tail = trimEnd(at.length === 1 ? lines.slice(at[0] + 1) : []);
  const headDhcp = dhcpClientLines(head);
  if (headDhcp.some((x) => x.release)) {
    throw new BenchApiError(
      422,
      `Le corps du modèle libère le client DHCP avant « ${TAIL_MARKER} » : cette libération doit être la toute dernière ligne du fichier, après le bloc d’accès ObliWAN. Placez-la après « ${TAIL_MARKER} » et corrigez le modèle.`,
      'template',
    );
  }
  const releases = dhcpClientLines(tail)
    .map((x, i) => ({ i, release: x.release }))
    .filter((x) => x.release);
  if (releases.length > 0 && releases[releases.length - 1].i !== tail.length - 1) {
    throw new BenchApiError(
      422,
      `La fin du modèle (après « ${TAIL_MARKER} ») doit se terminer par la libération du client DHCP : une ligne la suit. Corrigez le modèle.`,
      'template',
    );
  }
  if (releases.length === 0 && headDhcp.some((x) => x.script)) {
    throw new BenchApiError(
      422,
      `Le modèle installe un script sur le client DHCP sans le libérer en dernière ligne : les scripts DHCP ne démarrent qu’après une libération. Ajoutez « :do { /ip dhcp-client release [find] } on-error={} » après « ${TAIL_MARKER} » et corrigez le modèle.`,
      'template',
    );
  }
  if (head.every((l) => l.trim() === '' || l.trim().startsWith('#'))) {
    throw new BenchApiError(422, 'Le modèle rendu ne contient aucune commande avant sa fin : il n’y a rien à appliquer.', 'template');
  }
  return { head, tail };
}

/** Template residue or a secret placeholder that survived the render. Judged
 *  on the final text; the message names the rule, never the line. */
export function assertNoResidue(content: string): void {
  if (/__OBLIWAN_SECRET_/i.test(content)) {
    throw new BenchApiError(422, 'Un secret non substitué subsiste dans le fichier compilé : rien n’est délivré.', 'residue');
  }
  for (const line of content.split('\n')) {
    if (/\{\{.*\}\}/.test(line) || /\{%.*%\}/.test(line) || /\{#.*#\}/.test(line)) {
      throw new BenchApiError(422, 'Une expression de modèle non interprétée subsiste dans le fichier compilé : rien n’est délivré.', 'residue');
    }
  }
}

function assertNoReservedNames(lines: string[]): void {
  for (const l of lines) {
    if (RESERVED_IN_BODY.some((r) => l.includes(r))) {
      throw new BenchApiError(
        422,
        `Le modèle utilise un nom réservé au compilateur d’ObliWAN (${RESERVED_IN_BODY.filter((r) => !r.startsWith('#')).join(', ')}, ou une ligne « # obliwan-compiled » / « # obliwan-section ») : il pourrait simuler le succès de la préparation. Corrigez le modèle.`,
        'template',
      );
    }
  }
}

/** The prelude's waits, decided on what the rendered text names. */
export function preludeLines(text: string, wifiStack: 'wifi' | 'wireless'): string[] {
  const wait = (budget: number, finder: string): string =>
    `:while (([:len [${finder}]] = 0) && ($obliwanWait < ${budget})) do={ :delay 1s; :set obliwanWait ($obliwanWait + 1) }`;
  const block = (budget: number, finders: string[]): string[] => [
    ':do {',
    ':local obliwanWait 0',
    ...finders.map((f) => wait(budget, f)),
    '} on-error={}',
  ];
  const named = (re: RegExp): number[] =>
    [...new Set([...text.matchAll(re)].map((m) => Number(m[1])))].filter((n) => n >= 1 && n <= 64).sort((a, b) => a - b);

  const out: string[] = ['# 1. Wait for the interfaces the configuration names (bounded).'];
  out.push(...block(PRELUDE_WAIT.ethernet, [
    '/interface ethernet find',
    ...named(/\bether(\d+)\b/g).map((n) => `/interface ethernet find where default-name="ether${n}"`),
  ]));
  if (/\blte1\b/.test(text)) {
    out.push(...block(PRELUDE_WAIT.lte, ['/interface lte find where name="lte1"']));
  }
  const menu = wifiStack === 'wifi' ? 'wifi' : 'wireless';
  const radio = wifiStack === 'wifi' ? 'wifi' : 'wlan';
  const radios = named(new RegExp(`\\b${radio}(\\d+)\\b`, 'g'));
  const usesMenu = new RegExp(`/interface[ /]${menu}\\b`).test(text);
  if (radios.length > 0 || usesMenu) {
    out.push(...block(PRELUDE_WAIT.radios, [
      `/interface ${menu} find`,
      ...radios.map((n) => `/interface ${menu} find where name="${radio}${n}"`),
    ]));
  }
  return out;
}

export interface AssembleInput {
  tag: string;
  fileName: string;
  head: string[];
  tail: string[];
  wifiStack: 'wifi' | 'wireless';
  identity: string;
  mgmt: string[];
  password: string;
  snmpCommunity: string | null;
  /** The historical accounts re-injected on every preparation (`readLegacyAccounts`). */
  legacy?: LegacyAccount[];
  /** The device-mode features the box's reading denies, when the compile is
   *  made under a declared override (empty otherwise: a denial without one is
   *  refused before any file is assembled). Their statements are wrapped to
   *  fail alone; nothing else is. */
  gated?: readonly string[];
}

/**
 * Lines that leave `$<stem>From` holding the entries `current` returns, in
 * their order, followed by every management prefix they do not already list,
 * `$<stem>Kept` holding how many non-empty entries `current` returned, and
 * `$<stem>Added` holding how many prefixes were appended (0: the list
 * already allowed the whole management range, entry for entry). Empty entries
 * are dropped. An entry is recognised by its text: a management prefix that
 * RouterOS prints differently from the variable (`10.0.0.1/24` stored as
 * `10.0.0.0/24`) is appended once more — a duplicate entry, never a lost one —
 * and a wider entry that merely CONTAINS a prefix (`0.0.0.0/0`) does not count
 * as listing it. Declares five locals named after `stem` — three when
 * `counts` is false: `Kept` and `Added` are then neither declared nor kept,
 * for a caller that never reads them (the ssh lines, whose access section
 * has 4095 bytes to fit and the configured-row selection to pay for:
 * shared/src/routerOsService.ts).
 *
 * The management range is walked by ONE loop over
 * `[:toarray "<prefix>,<prefix>…"]`, each element compared and appended as
 * `[:tostr]` prints it — so a prefix costs its own text once, not a copy of
 * the loop: both the access and the SNMP section must fit the 4095 bytes an
 * older build reads (`OLDER_BUILD_READ_LIMIT_BYTES`). That `:toarray` splits
 * the string at its commas is REASONED, the conversion the api-ssl lines rely
 * on too (shared/src/managementAccess.ts); whatever type it gives an element,
 * `[:tostr]` of it is compared and written, so a prefix it would print
 * differently is, at worst, the duplicate described above — never lost.
 */
/** `current` reads the list; `fallback`, when given, is read instead if
 *  `current` fails — `/ip service` calls the list `available-from` on recent
 *  RouterOS 7 (7.24.5) and `address` before, and a `get` of a name the
 *  build does not know is an error. */
function widenedAddressLines(stem: string, current: string, mgmt: string[], fallback?: string, counts = true): string[] {
  const have = `${stem}Have`;
  const from = `${stem}From`;
  const kept = `${stem}Kept`;
  const added = `${stem}Added`;
  const seen = `${stem}Seen`;
  const append = (value: string): string =>
    `:if ([:len $${from}] > 0) do={ :set ${from} ($${from} . ",") }; :set ${from} ($${from} . ${value})`;
  return [
    ...(fallback === undefined
      ? [`:local ${have} [${current}]`]
      : [`:local ${have}; :do {:set ${have} [${current}]} on-error={:set ${have} [${fallback}]}`]),
    `:local ${from} ""`,
    ...(counts ? [`:local ${kept} 0`, `:local ${added} 0`] : []),
    `:local ${seen} false`,
    `:foreach p in=$${have} do={ :if ([:len [:tostr $p]] > 0) do={ ${append('[:tostr $p]')}${counts ? `; :set ${kept} ($${kept} + 1)` : ''} } }`,
    `:foreach m in=[:toarray "${mgmt.join(',')}"] do={ :set ${seen} false; `
      + `:foreach p in=$${have} do={ :if ([:tostr $p] = [:tostr $m]) do={ :set ${seen} true } }; `
      + `:if ($${seen} = false) do={ ${append('[:tostr $m]')}${counts ? `; :set ${added} ($${added} + 1)` : ''} } }`,
  ];
}

/**
 * The ObliWAN access block, (c) in the file header, followed by the SNMP
 * block when the tenant names a community.
 *
 * The SNMP block NEVER removes a community and never changes what the
 * customer set on one: a community of that name already on the box — the
 * templates rename the default one to their `snmp_community`, and that is
 * often the very community ObliWAN polls with — keeps its name, its read and
 * write access, its comment and every address it had; the management
 * prefixes it lacks are appended, and when it lacks none it is not written at
 * all. A kept community whose `addresses` reads back EMPTY is not written
 * either: the normaliser reads an empty list as "from anywhere"
 * (`normalizeRouterOsExport`, `/snmp/community`), and appending the management
 * range to it would narrow the customer's own monitoring to that range — what
 * RouterOS itself does with an empty list there is not observed, and the
 * reading that cannot cut the customer is the one kept. Only a box with no
 * community of that name gets one added, restricted to the management range,
 * read-only, commented `obliwan:access`. The block has its own sentinel and
 * its own `reason=snmp-community-failed`: a real failure there (the `add` or
 * the `set` refused) still ends the run FAILED, and names itself instead of
 * hiding inside the access block's reason. Which branch ran is logged
 * (`snmp-community=added|kept-addresses-widened|kept-unchanged|
 * kept-empty-addresses`).
 */
export function accessLines(input: Pick<AssembleInput, 'tag' | 'identity' | 'mgmt' | 'password' | 'snmpCommunity'> & { legacy?: LegacyAccount[] }): string[] {
  return [
    // The single file's own numbering; the split form's `access` section has
    // its section header instead (and every byte counts there).
    '# 3. ObliWAN access',
    ...accessBlockLines(input), ...accountsBlockLines({ ...input, legacy: input.legacy ?? [] }), ...(snmpBlockLines(input) ?? []),
  ];
}

// ============================================================================
// The historical accounts: admin, hotline, api
// ============================================================================
//
// OPERATOR RULE (2026-10-03, not negotiable): every router the bench prepares
// carries the fleet's historical accounts — `admin` with the fleet admin
// password, `hotline` (read) and `api` (api group) — WHATEVER the template
// does. Four customer templates set them; customer D's set none, and its
// first router left the bench with the label password on `admin`. So the
// access block writes them, idempotently: an account the template already
// made only gets its password (and group) set again, a missing one is added.
// `admin` is required: without its password the compile is refused, naming
// the variable. The other two are written when their password is set.
// Read from the same variables as the templates — the tenant's own value
// first, the instance's otherwise — decrypted here for the file only, which
// already carries secrets and is delivered once (header).

export interface LegacyAccount { name: 'admin' | 'hotline' | 'api'; group: 'read' | 'api' | null; password: string }

const LEGACY_ACCOUNTS = [
  { name: 'admin', key: 'admin_password', group: null, required: true },
  { name: 'hotline', key: 'helpdesk_user_password', group: 'read', required: false },
  { name: 'api', key: 'legacy_api_user_password', group: 'api', required: false },
] as const;

/** The group the templates create for the `api` account (customer D's
 *  template, verbatim), created only when the box has none of that name. */
const LEGACY_API_GROUP_POLICY =
  'api,!local,!telnet,!ssh,!ftp,!reboot,!read,!write,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api';

/** A RouterOS double-quoted string; control characters are refused (by the
 *  caller, without echoing the value), never escaped away. */
function legacyQuote(v: string): string {
  return `"${v.replace(/[\\"$?]/g, (c) => `\\${c}`)}"`;
}

/** The levels the bench render reads (it renders for the SITE, without a
 *  group), most specific first — the same order as variableResolver. */
const LEGACY_SCOPE_ORDER = ['site', 'tenant', 'global', 'instance'] as const;
export type LegacyVariableScope = (typeof LEGACY_SCOPE_ORDER)[number];

/**
 * One historical-account variable for a site, decrypted: the most specific
 * level that holds the key wins, and an empty or missing value is null. The
 * ONE resolution of these keys — the bench re-injects the accounts with it,
 * and the reconciliation's bulk attach (fleet/reconcileAttach.service.ts)
 * logs in with the `admin` password it finds, so the two cannot disagree on
 * which password a site's router carries. The management_access job
 * (change/managementAccess.service.ts) reads it the same way to align the
 * `obliwan` group of a router already on `obliwan`. `siteId` null — a device
 * filed under no site — reads the tenant, global and instance levels only:
 * never another site's.
 */
export async function resolveLegacyVariable(
  key: string,
  tenantId: number,
  siteId: number | null,
  q: Knex | Knex.Transaction = db,
): Promise<{ value: string; scope: LegacyVariableScope } | null> {
  const rows = (await q('config_variables')
    .where({ key })
    .where((w) => w
      .where((x) => (siteId === null
        ? x.whereRaw('false')
        : x.where({ scope: 'site', tenant_id: tenantId, scope_id: siteId })))
      .orWhere((x) => x.where({ scope: 'tenant', tenant_id: tenantId }).whereNull('scope_id'))
      .orWhere((x) => x.where({ scope: 'global', tenant_id: tenantId }).whereNull('scope_id'))
      .orWhere((x) => x.where({ scope: 'instance' }).whereNull('tenant_id').whereNull('scope_id')))
    .select('scope', 'value', 'is_secret', 'secret_enc')) as Array<{ scope: string; value: unknown; is_secret: boolean; secret_enc: string | null }>;
  for (const scope of LEGACY_SCOPE_ORDER) {
    const row = rows.find((r) => r.scope === scope);
    if (!row) continue;
    let value: string | null = null;
    if (row.is_secret) value = row.secret_enc ? decrypt(row.secret_enc) : null;
    else if (typeof row.value === 'string') value = row.value;
    // The most specific row decides, even empty: a level that blanks the key
    // does not fall through to a broader one (the bench always read it so).
    return value === null || value === '' ? null : { value, scope };
  }
  return null;
}

export async function readLegacyAccounts(tenantId: number, siteId: number, q: Knex | Knex.Transaction = db): Promise<LegacyAccount[]> {
  const out: LegacyAccount[] = [];
  for (const a of LEGACY_ACCOUNTS) {
    const password = (await resolveLegacyVariable(a.key, tenantId, siteId, q))?.value ?? null;
    if (password === null) {
      if (a.required) {
        throw new BenchApiError(
          409,
          `La variable « ${a.key} » n'est pas renseignée (Variables → Instance, ou celles du client) : le compte « ${a.name} » doit être remis sur chaque routeur préparé. Renseignez-la, puis relancez la préparation.`,
          'legacy_accounts',
        );
      }
      continue;
    }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(password)) {
      throw new BenchApiError(409, `La variable « ${a.key} » contient un caractère de contrôle : corrigez-la, puis relancez la préparation.`, 'legacy_accounts');
    }
    out.push({ name: a.name, group: a.group, password });
  }
  return out;
}

/**
 * OPERATOR RULE (2026-10-03, every tenant): MAC-telnet, MAC-Winbox and RoMON are
 * NEVER restricted. A router whose MAC access was limited to its LAN list could not
 * be reached from the bench port it was plugged in, and with its tunnel down
 * nothing reached it at all. Whatever a template sets, the bench reopens all
 * three, each statement failing alone.
 */
function macAccessLines(tag: string): string[] {
  const fail = `on-error={ :log error "${PROVISION_PREFIX} detail tag=${tag} reason=mac-access-failed" }`;
  return [
    '# MAC-telnet, MAC-Winbox and RoMON open (operator rule). RoMON is refused, and logged, while device-mode forbids it.',
    `:do { /tool mac-server set allowed-interface-list=all } ${fail}`,
    `:do { /tool mac-server mac-winbox set allowed-interface-list=all } ${fail}`,
    `:do { /tool romon set enabled=yes } on-error={ :log error "${PROVISION_PREFIX} detail tag=${tag} reason=romon-failed" }`,
  ];
}

/**
 * Each statement in its OWN `:do {} on-error={}`, after ssh and api-ssl: a
 * policy name an older build does not know, or a group a template removed,
 * must not cancel the management access — it logs its own reason instead.
 * `admin` is ADDED (group full) when a template removed it: the rule is that
 * every prepared router carries it.
 */
function legacyAccountLines(legacy: LegacyAccount[], tag: string): string[] {
  if (legacy.length === 0) return [];
  const fail = (what: string) => `on-error={ :log error "${PROVISION_PREFIX} detail tag=${tag} reason=legacy-account-${what}-failed" }`;
  const lines = ['# Historical accounts (admin, hotline, api): re-injected on every preparation.'];
  if (legacy.some((l) => l.group === 'api')) {
    // `rest-api` is a RouterOS 7 policy: a build that refuses it gets the same group without it.
    lines.push(
      `:do { :if ([:len [/user group find where name="api"]] = 0) do={ :do { /user group add name=api policy=${LEGACY_API_GROUP_POLICY} } `
        + `on-error={ /user group add name=api policy=${LEGACY_API_GROUP_POLICY.replace(',!rest-api', '')} } } } ${fail('api-group')}`,
    );
  }
  for (const l of legacy) {
    const pw = legacyQuote(l.password);
    const group = l.group ?? 'full';
    const set = l.group === null ? `/user set [find where name="${l.name}"] password=${pw}` : `/user set [find where name="${l.name}"] group=${l.group} password=${pw}`;
    lines.push(
      `:do { :if ([:len [/user find where name="${l.name}"]] = 0) do={ /user add name=${l.name} group=${group} password=${pw} } else={ ${set} } } ${fail(l.name)}`,
    );
  }
  return lines;
}

/** The access block alone: the split file's `access` section. */
function accessBlockLines(input: Pick<AssembleInput, 'tag' | 'identity' | 'mgmt' | 'password'>): string[] {
  const mgmt = input.mgmt.join(',');
  return [
    ':do {',
    `/system identity set name="${input.identity}"`,
    `:do { /user remove [find where name="${OBLIWAN_ACCOUNT}"] } on-error={}`,
    `:do { /user group remove [find where name="${OBLIWAN_ACCOUNT}"] } on-error={}`,
    `/user group add name=${OBLIWAN_ACCOUNT} policy=${OBLIWAN_GROUP_POLICY} comment="obliwan:access"`,
    `/user add name=${OBLIWAN_ACCOUNT} group=${OBLIWAN_ACCOUNT} address="${mgmt}" password="${input.password}" comment="obliwan:access"`,
    // ssh: the management prefixes are ADDED to whatever the template allowed,
    // so a customer's own admin range survives, and one the template already
    // allowed is not listed twice; an ssh left open to all (no address) is
    // narrowed to the management range.
    // The CONFIGURED ssh row: an open SSH session is listed beside it as a
    // dynamic entry named ssh on RouterOS 7.24.5 (shared/src/routerOsService.ts),
    // and a `set` that reached that entry would fail the whole block. The
    // locals are `oSsh…` (they were `obliwanSsh…`) and the counts the ssh
    // lines never read are not kept: the selection costs bytes, and this
    // section must fit 4095 of them (`OLDER_BUILD_READ_LIMIT_BYTES`).
    routerOsServiceSelect('ssh', 'oSsh'),
    ...widenedAddressLines('oSsh', '/ip service get $oSsh available-from', input.mgmt, '/ip service get $oSsh address', false),
    `/ip service set $oSsh disabled=no port=${SSH_PORT} address=$oSshFrom`,
    // The management API, LAST (file header, (c)): a certificate refused or
    // not signed stops the block here, after ssh and the account are in
    // place, and logs its own `reason=api-ssl-certificate-…` naming the
    // certificate before the block's `access-block-failed`.
    ...apiSslAccessLines({ identity: input.identity, mgmtPrefixes: input.mgmt, logPrefix: `${PROVISION_PREFIX} detail tag=${input.tag}` }),
    `:global ${ACCESS_SENTINEL} "${input.tag}"`,
    `} on-error={ :log error "${PROVISION_PREFIX} detail tag=${input.tag} reason=access-block-failed" }`,
  ];
}

/**
 * The historical accounts and the MAC/RoMON reopening (the split file's
 * `accounts` section). A section of their own: in the access section they
 * pushed it past what an older build reads of one file (4095 bytes), and in
 * the SNMP section too, once the reopening joined them (a customer D
 * compile reached 4315). Every statement is isolated, so the section has no
 * sentinel of its own beyond the runner's.
 */
function accountsBlockLines(input: Pick<AssembleInput, 'tag' | 'legacy'>): string[] {
  return [...legacyAccountLines(input.legacy ?? [], input.tag), ...macAccessLines(input.tag)];
}

/** The SNMP block alone (the split file's `snmp` section), or null when the
 *  tenant names no community. */
function snmpBlockLines(input: Pick<AssembleInput, 'tag' | 'mgmt' | 'snmpCommunity'>): string[] | null {
  if (input.snmpCommunity === null) return null;
  const mgmt = input.mgmt.join(',');
  const name = input.snmpCommunity;
  const detail = `${PROVISION_PREFIX} detail tag=${input.tag}`;
  return [
    '# 3b. The SNMP community ObliWAN polls with: added when the box has none of that name, otherwise kept as the customer set it, the management range added to its addresses (an empty list, i.e. from anywhere, is left as it is).',
    ':do {',
    `:local obliwanSnmp [/snmp community find where name="${name}"]`,
    ':if ([:len $obliwanSnmp] = 0) do={',
    `/snmp community add name="${name}" addresses="${mgmt}" read-access=yes write-access=no comment="obliwan:access"`,
    `:log info "${detail} snmp-community=added"`,
    '} else={',
    ...widenedAddressLines('obliwanSnmp', '/snmp community get $obliwanSnmp addresses', input.mgmt),
    `:if ($obliwanSnmpKept = 0) do={ :log info "${detail} snmp-community=kept-empty-addresses" } else={ :if ($obliwanSnmpAdded > 0) do={ /snmp community set $obliwanSnmp addresses=$obliwanSnmpFrom; :log info "${detail} snmp-community=kept-addresses-widened" } else={ :log info "${detail} snmp-community=kept-unchanged" } }`,
    '}',
    '/snmp set enabled=yes',
    `:global ${SNMP_SENTINEL} "${input.tag}"`,
    `} on-error={ :log error "${detail} reason=snmp-community-failed" }`,
  ];
}

/** The input checks shared by both forms. */
function assertAssembleInput(input: AssembleInput): void {
  if (!TAG_RE.test(input.tag)) throw new BenchApiError(500, 'Étiquette de préparation invalide.', 'internal');
  if (!FILE_NAME_RE.test(input.fileName)) throw new BenchApiError(500, 'Nom de fichier de préparation invalide.', 'internal');
  if (!IDENTITY_RE.test(input.identity)) {
    throw new BenchApiError(409, 'L’identité système allouée à ce site contient des caractères qu’un routeur ne peut pas recevoir tels quels (lettres, chiffres, « . », « _ », « - » seulement).', 'identity');
  }
  if (!/^[A-Za-z0-9]{16,64}$/.test(input.password)) throw new BenchApiError(500, 'Mot de passe de compte invalide.', 'internal');
  if (input.mgmt.length === 0 || input.mgmt.some((p) => !/^[0-9A-Fa-f.:]+\/\d{1,3}$/.test(p))) {
    throw new BenchApiError(409, 'Plage d’administration invalide.', 'management_range');
  }
  if (input.snmpCommunity !== null && !COMMUNITY_RE.test(input.snmpCommunity)) {
    throw new BenchApiError(500, 'Communauté SNMP invalide.', 'internal');
  }
  assertNoReservedNames([...input.head, ...input.tail]);
}

/** The whole LEGACY file, (a) to (e) in the header. Pure; throws a
 *  BenchApiError when an input could not be written without escaping. Under
 *  an override, a statement using a feature of `gated` is wrapped to fail
 *  alone, and such a failure ends the run FAILED (`obliwanGated`); with
 *  nothing gated the body is written line for line. */
export function assembleCompiledFile(input: AssembleInput): string {
  assertAssembleInput(input);
  const tag = input.tag;
  const snmp = snmpBlockLines(input) !== null;
  const lines: string[] = [
    `# obliwan-compiled v1 tag=${tag}`,
    '# Compiled by ObliWAN for /system reset-configuration run-after-reset. It holds credentials',
    '# in clear and removes itself before the tail.',
    `:log info "${PROVISION_PREFIX} start tag=${tag}"`,
    `:global ${BODY_SENTINEL} ""`,
    `:global ${ACCESS_SENTINEL} ""`,
    `:global ${SNMP_SENTINEL} ""`,
    `:global ${GATED_GLOBAL} ""`,
    ...preludeLines([...input.head, ...input.tail].join('\n'), input.wifiStack),
    '# 2. The customer configuration, rendered for this site.',
    ':do {',
    ...gatedHeadLines(input.head, 'body', tag, new Set(input.gated ?? [])),
    `:global ${BODY_SENTINEL} "${tag}"`,
    `} on-error={ :log error "${PROVISION_PREFIX} detail tag=${tag} reason=body-stopped-on-error" }`,
    ...accessLines(input),
    '# 4. Success marker.',
    `:global ${BODY_SENTINEL}`,
    `:global ${ACCESS_SENTINEL}`,
    ...(snmp ? [`:global ${SNMP_SENTINEL}`] : []),
    `:global ${GATED_GLOBAL}`,
    `:if (($${BODY_SENTINEL} = "${tag}") && ($${ACCESS_SENTINEL} = "${tag}")${snmp ? ` && ($${SNMP_SENTINEL} = "${tag}")` : ''} && ([:len $${GATED_GLOBAL}] = 0)) do={`,
    `:log info "${PROVISION_PREFIX} ok tag=${tag}"`,
    `:do { /system script add name="${PROVISION_PREFIX}-ok-${tag}" comment="${PROVISION_PREFIX} ok tag=${tag}" source="" } on-error={}`,
    '} else={',
    `:log error "${PROVISION_PREFIX} FAILED tag=${tag}"`,
    `:do { /system script add name="${PROVISION_PREFIX}-failed-${tag}" comment="${PROVISION_PREFIX} FAILED tag=${tag}" source="" } on-error={}`,
    '}',
    '# 5. This file holds credentials: it removes itself, then the template tail runs.',
    `:do { /file remove [find where name="${input.fileName}" or name="flash/${input.fileName}"] } on-error={}`,
  ];
  if (input.tail.length > 0) lines.push(TAIL_MARKER, ...input.tail);
  const content = `${lines.join('\n')}\n`;
  assertNoResidue(content);
  return content;
}

/**
 * The SPLIT form (`splitFile.ts`): a runner named like the legacy file — the
 * run-after-reset target, written from constants only — and one file per
 * section, the tail's included. A file the box could read whole on NO
 * RouterOS build (`SECTION_READ_LIMIT_BYTES`) is refused here: shipped, it
 * could only end `section-truncated`. Between the 4095 bytes older builds
 * read and that limit, the runner's byte count is what decides on the box —
 * for the template's sections. ObliWAN's own (`access`, `snmp`) must fit the
 * 4095 bytes whole (`OLDER_BUILD_READ_LIMIT_BYTES`): a management range too
 * long for that is refused here, naming the range.
 */
export function assembleSplitCompiledFiles(input: AssembleInput): CompiledFile[] {
  assertAssembleInput(input);
  const { runner, sections } = assembleSplitFiles({
    tag: input.tag,
    runnerName: input.fileName,
    prelude: preludeLines([...input.head, ...input.tail].join('\n'), input.wifiStack),
    head: input.head,
    access: accessBlockLines(input),
    accessSentinel: ACCESS_SENTINEL,
    accounts: accountsBlockLines(input),
    snmp: snmpBlockLines(input),
    snmpSentinel: SNMP_SENTINEL,
    tailMarker: TAIL_MARKER,
    tail: input.tail,
    gated: input.gated ?? [],
  });
  for (const s of sections) {
    const size = Buffer.byteLength(s.content, 'utf8');
    if (s.id === 'accounts' && size > OLDER_BUILD_READ_LIMIT_BYTES) {
      // Its size is the accounts' passwords, not the management range.
      throw new BenchApiError(
        409,
        `La partie « accounts » du fichier de préparation ferait ${size} octets : un RouterOS d’une version ancienne n’en lit que ${OLDER_BUILD_READ_LIMIT_BYTES}, et le routeur finirait sans ses comptes historiques (admin, hotline, api). Raccourcissez leurs mots de passe (variables d’instance ou du client), puis relancez la préparation.`,
        'legacy_accounts',
      );
    }
    if (OBLIWAN_SECTION_IDS.has(s.id) && size > OLDER_BUILD_READ_LIMIT_BYTES) {
      throw new BenchApiError(
        409,
        `La partie « ${s.id} » du fichier de préparation ferait ${size} octets : un RouterOS d’une version ancienne n’en lit que ${OLDER_BUILD_READ_LIMIT_BYTES}, et le routeur finirait sans `
          + (s.id === 'access' ? 'compte ObliWAN, sans ssh et sans api-ssl. ' : 'la communauté SNMP d’ObliWAN. ')
          + `La plage d’administration (variable « ${MANAGEMENT_RANGE_KEY} ») compte ${input.mgmt.length} préfixe(s) : regroupez-la en moins de préfixes, puis relancez la préparation.`,
        'management_range',
      );
    }
    if (size > SECTION_READ_LIMIT_BYTES) {
      throw new BenchApiError(
        422,
        `Le modèle produit un fichier de préparation de ${size} octets (partie « ${s.id} ») : aucun RouterOS ne lit plus de ${SECTION_READ_LIMIT_BYTES} octets d’un fichier, et cette partie ne s’exécuterait jamais. `
          + 'Le corps n’est découpé qu’entre deux commandes, et jamais quand il déclare une variable à son premier niveau (:local, :global, :set) : retirez ces déclarations ou raccourcissez la commande la plus longue, puis corrigez le modèle.',
        'template',
      );
    }
  }
  const files: CompiledFile[] = [runner, ...sections.map(({ name, content, sha256, role }) => ({ name, content, sha256, role }))];
  if (files.length > MAX_COMPILED_FILES) {
    throw new BenchApiError(
      422,
      `Le modèle produit ${files.length} fichiers de préparation : le bench n’en accepte que ${MAX_COMPILED_FILES}. Raccourcissez le corps du modèle, puis relancez.`,
      'template',
    );
  }
  for (const f of files) {
    if (!FILE_NAME_RE.test(f.name)) throw new BenchApiError(500, 'Nom de fichier de préparation invalide.', 'internal');
    assertNoResidue(f.content);
  }
  return files;
}

/** The bench strings, typed per their declaration. Keys the chosen revision
 *  does not declare at the bench level are dropped (the plan offers the union
 *  of every candidate's); an empty optional value is absent, not "". */
export function benchValuesFor(decls: BenchVariableDecl[], raw: unknown): Record<string, string | number | boolean> {
  if (raw !== undefined && raw !== null && (typeof raw !== 'object' || Array.isArray(raw))) {
    throw new BenchApiError(400, 'Les valeurs saisies au banc (« bench ») doivent être un objet.', 'bad_input');
  }
  const given = (raw ?? {}) as Record<string, unknown>;
  const out: Record<string, string | number | boolean> = {};
  for (const d of decls) {
    const v = Object.prototype.hasOwnProperty.call(given, d.key) ? given[d.key] : undefined;
    if (v !== undefined && v !== null && typeof v !== 'string') {
      throw new BenchApiError(400, `La valeur saisie pour « ${d.label} » doit être du texte.`, 'bad_input');
    }
    const t = typeof v === 'string' ? v.trim() : '';
    if (t === '') {
      if (d.required) throw new BenchApiError(400, `« ${d.label} » est obligatoire pour ce modèle.`, 'bad_input');
      continue;
    }
    if (d.type === 'integer') {
      if (!/^-?\d{1,15}$/.test(t)) throw new BenchApiError(400, `« ${d.label} » doit être un nombre entier.`, 'bad_input');
      out[d.key] = Number(t);
    } else if (d.type === 'number') {
      if (!/^-?\d{1,15}(\.\d{1,15})?$/.test(t)) throw new BenchApiError(400, `« ${d.label} » doit être un nombre.`, 'bad_input');
      out[d.key] = Number(t);
    } else if (d.type === 'boolean') {
      if (t !== 'true' && t !== 'false') throw new BenchApiError(400, `« ${d.label} » doit valoir « true » ou « false ».`, 'bad_input');
      out[d.key] = t === 'true';
    } else {
      out[d.key] = t;
    }
  }
  return out;
}

/** What a compile KEEPS of the bench values (migration 063): the non-secret
 *  ones as typed, and the names of the secret ones that were typed — never a
 *  secret's value. Pure; exported for the harness. */
export function keptBenchValues(
  decls: BenchVariableDecl[],
  values: Record<string, string | number | boolean>,
): { values: Record<string, string | number | boolean>; secretKeys: string[] } {
  const kept: Record<string, string | number | boolean> = {};
  const secretKeys: string[] = [];
  for (const d of decls) {
    if (!Object.prototype.hasOwnProperty.call(values, d.key)) continue;
    if (d.secret) secretKeys.push(d.key);
    else kept[d.key] = values[d.key];
  }
  return { values: kept, secretKeys: secretKeys.sort() };
}

/** RouterOS major version -> device family. A version the bench could not
 *  read, or one that is neither 6 nor 7+, is refused rather than guessed. */
export function familyOf(rosVersion: string | null): 'mikrotik_routeros6' | 'mikrotik_routeros7' {
  const m = rosVersion ? /^(\d+)\./.exec(rosVersion) : null;
  const major = m ? Number(m[1]) : NaN;
  if (major === 6) return 'mikrotik_routeros6';
  if (major >= 7) return 'mikrotik_routeros7';
  throw new BenchApiError(409, 'La version de RouterOS du routeur n’a pas pu être lue : relancez l’identification du routeur.', 'box');
}

// ============================================================================
// Injectable seams (the harness replaces them)
// ============================================================================

export interface BenchCompileDeps {
  provisionConcentrator: (input: { tenantId: number; siteId: number }, timeoutMs: number) => Promise<ConcentratorSecretState>;
  generatePassword: () => string;
  /** The redacted pre-render of step 1b (`preRenderRedacted`); the harness
   *  makes it answer null to drive the sources fallback. */
  preRender: typeof preRenderRedacted;
}

const defaultDeps: BenchCompileDeps = {
  provisionConcentrator: (input, timeoutMs) => provisionConcentratorSecret({ ...input, requestedBy: null }, timeoutMs),
  generatePassword: generateAccountPassword,
  preRender: preRenderRedacted,
};
let deps: BenchCompileDeps = { ...defaultDeps };

export function setBenchCompileDeps(partial: Partial<BenchCompileDeps>): void {
  deps = { ...deps, ...partial };
}
export function resetBenchCompileDeps(): void {
  deps = { ...defaultDeps };
}

// ============================================================================
// Reads
// ============================================================================

/** The SNMP community of the v2c credential the tenant names in
 *  SNMP_AUTO_TARGET_CREDENTIAL, or null: none named, not found, or SNMPv3
 *  (which a community line cannot express). The community the box gets is
 *  then exactly the one ObliWAN polls with. */
async function snmpCommunityFor(
  tenantId: number,
  reused: { id: number; group_id: number | null } | null,
  newDeviceGroupId: number | null,
): Promise<string | null> {
  let credentialId = 0;
  if (reused) {
    const s = await settingsService.resolveForDevice(tenantId, reused.id, reused.group_id);
    credentialId = Number(s[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL]?.value ?? 0);
  } else if (newDeviceGroupId !== null) {
    // A new device placed in the bench's default group inherits through that
    // group's chain, exactly as `resolveForDevice` will read it once the row
    // exists — the community the box gets is the one it will be polled with.
    const g = await settingsService.resolveForGroup(tenantId, newDeviceGroupId);
    const own = g.overrides[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL];
    credentialId = Number(own ?? g.resolved[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL]?.value ?? 0);
  } else {
    const g = await settingsService.resolveGlobal(tenantId);
    const override = g.overrides[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL];
    credentialId = Number(override ?? g.resolved[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL]?.value ?? 0);
  }
  if (!Number.isSafeInteger(credentialId) || credentialId <= 0) return null;
  const cred = (await db('snmp_credentials')
    .where({ id: credentialId })
    .whereIn('tenant_id', usableCredentialTenants(tenantId))
    .first('name', 'version', 'community_enc')) as { name: string; version: string; community_enc: string | null } | undefined;
  if (!cred || (cred.version !== 'v2c' && cred.version !== 'v1') || !cred.community_enc) return null;
  const community = decrypt(cred.community_enc);
  if (!COMMUNITY_RE.test(community)) {
    throw new BenchApiError(
      409,
      `La communauté SNMP de l’identifiant « ${cred.name} » contient des caractères qu’ObliWAN n’écrit pas dans un routeur sans les échapper (lettres, chiffres, « . », « _ », « - », 32 au plus). Changez-la, puis relancez.`,
      'snmp',
    );
  }
  return community;
}

/** The group the tenant's BENCH_DEFAULT_GROUP names, as the compile applies it. */
export interface BenchDefaultGroup {
  /** The group a NEW device row is placed in; null: none named, or refused. */
  groupId: number | null;
  /** Set when the setting names a group this compile refused to apply. */
  warning: string | null;
}

/**
 * The tenant's BENCH_DEFAULT_GROUP, judged. Read at the workspace level only
 * (the setting is `workspaceOnly`: the device does not exist yet, so there is
 * no chain to inherit through). 0 — the default — is no group, silently: that
 * is the bench's behaviour before the setting existed. A value naming no
 * group of THIS tenant — a group deleted since (device_groups rows are
 * deleted, not flagged), or an id of another tenant's — is never applied: the
 * device is created with no group and the compile says so in its warnings,
 * worded the same way for both so the answer is no oracle over another
 * tenant's group ids. The composite FK `(group_id, tenant_id)` (migration
 * 014) would refuse the cross-tenant insert anyway, but as a 500 after the
 * concentrator was touched; this refuses it before anything is written.
 */
export async function benchDefaultGroup(tenantId: number): Promise<BenchDefaultGroup> {
  const key = SETTINGS_KEYS.BENCH_DEFAULT_GROUP;
  const overrides = await settingsService.getByScope(tenantId, 'global', null);
  const groupId = Number(overrides[key] ?? HARDCODED_DEFAULTS[key]);
  if (!Number.isSafeInteger(groupId) || groupId <= 0) return { groupId: null, warning: null };
  const row = await db('device_groups').where({ id: groupId, tenant_id: tenantId }).first('id');
  if (row) return { groupId, warning: null };
  return { groupId: null, warning: benchGroupWarning(groupId) };
}

function benchGroupWarning(groupId: number): string {
  return `Le groupe par défaut des routeurs préparés au banc (réglage « ${SETTINGS_KEYS.BENCH_DEFAULT_GROUP} », groupe #${groupId}) n’existe pas dans cet espace : le routeur est enregistré sans groupe, et les notifications liées à un groupe ne l’atteindront pas. Signalez-le à un administrateur, qui corrigera le réglage et rangera ce routeur dans son groupe ; le routeur lui-même peut être expédié.`;
}

/** The variable declarations of the chosen revision, re-checked as a
 *  candidate for THIS box: the plan's list is advice, the compile decides. */
async function chosenRevision(tenantId: number, revisionId: number, box: BenchBoxInput) {
  const { candidates } = await listBenchCandidates(tenantId, box);
  const chosen = candidates.find((c) => c.revisionId === revisionId);
  if (!chosen) {
    throw new BenchApiError(
      409,
      `Le modèle choisi (révision #${revisionId}) n’est pas proposé pour ce routeur et ce site : relancez le plan et choisissez parmi les modèles proposés.`,
      'revision',
    );
  }
  return chosen;
}

// ============================================================================
// The compile
// ============================================================================

export interface BenchStationRef { id: number; name: string }

export interface BenchCompileResult {
  /** The LEGACY single file (`assembleCompiledFile`), for bench builds that
   *  predate `files`. */
  fileName: string;
  content: string;
  sha256: string;
  tag: string;
  deviceId: number;
  concentrator: { state: 'provisioned' | 'pending' | 'failed'; message: string };
  /** The split form, runner first (`assembleSplitCompiledFiles`): the
   *  runner is named `fileName` and is the run-after-reset target. */
  files: CompiledFile[];
  /** The device-mode features the rendered revision uses, sorted. */
  deviceModeFeatures: string[];
  /** Present only when the bench declared `deviceModeOverride`: its echo. */
  testOverride?: boolean;
  /** The group a CREATED device was placed in (BENCH_DEFAULT_GROUP); null
   *  when none applied, and on a reused row, which keeps its own. */
  groupId: number | null;
  /** What the operator should know and that refused nothing (additive):
   *  today, a default group naming no group of this tenant. */
  warnings: string[];
}

function allocationRefusal(err: AllocationError): BenchApiError {
  return new BenchApiError(409, `L’adressage de ce site est refusé : ${err.message}`, `allocation_${err.reason.toLowerCase()}`);
}

function renderRefusal(err: SiteRenderError): BenchApiError {
  const status = err.code === 'NOT_FOUND' ? 404 : err.code === 'BAD_INPUT' ? 400 : err.code === 'REVISION_REFUSED' ? 409 : 422;
  // SiteRenderError messages name keys and rules, never a secret's value
  // (siteRender.service), so the reason is forwarded.
  return new BenchApiError(status, `Le rendu du modèle est refusé : ${err.message}`, `render_${err.code.toLowerCase()}`);
}

function concentratorMessage(c: ConcentratorSecretState): string {
  if (c.state === 'provisioned') return 'Le compte PPP de ce site est présent sur le concentrateur.';
  if (c.state === 'pending') {
    return `Le compte PPP de ce site n’est pas encore confirmé sur le concentrateur${c.jobId ? ` (tâche #${c.jobId})` : ''} : le routeur se connectera dès qu’il sera créé. ${c.message}`;
  }
  return `Le compte PPP de ce site n’a pas pu être créé sur le concentrateur : ${c.message}`;
}

// ============================================================================
// The concentrator account: when a 'pending' may release a file
// ============================================================================
//
// 'provisioned' releases the file: the service says it only of a job that
// SUCCEEDED, i.e. that read the account on the CHR — added and read back, or
// found present (an adopted account included). 'failed' never does. A
// 'pending' releases it only when a job that will create THIS site's account
// really is in the queue AND the operator can see it: `provisionConcentrator`
// also answers 'pending' with NO job (the CHR busy with another job past the
// wait), and between its last read and now the job may have ended. So the
// job is re-read here, and the allocation's mirror with it.
//
// What the operator sees is the mirror (`site_provisioning`, the Allocation
// page), and it is read two ways:
//  - 'pending' on THIS job: the page says the account is not confirmed yet.
//    A job the queue could claim now is enough.
//  - 'provisioned': the page says the account IS there. The service keeps
//    that on purpose while a re-verification runs (`keepProvisioned`: writing
//    'pending' over it would let an operator release a live allocation), so
//    the page never mentions the new job. It releases only when (1) the job it
//    names SUCCEEDED for this very account — same CHR, login and address as
//    allocated today — and (2) a worker HOLDS the new job under a live lease:
//    with the page saying "present", a job merely waiting in the queue is a
//    promise nobody can see, and an account removed from the CHR by hand
//    would stay "present" on screen while no process re-creates it. A running
//    worker with a free slot (`MAX_CONCURRENT_JOBS`) claims within one
//    `POLL_INTERVAL_MS` (3 s), well inside `CONCENTRATOR_WAIT_MS`, so this
//    refuses only when nothing took the job during the whole wait: no worker,
//    or every slot busy for all of it.
//
// What a refusal leaves committed, and why each is harmless:
//  - the site's allocation (`computedForSite`, step 2): idempotent — the next
//    compile reads the same login, address and identity back;
//  - a concentrator job that `provisionConcentrator` queued and that is still
//    in flight, with the allocation's mirror naming it ('pending') or left
//    'provisioned' on the earlier job: additive only (it adds the account
//    when absent, writes nothing when it is there, refuses a conflict), and
//    the next compile's `ensureConcentratorSecret` returns that same job
//    instead of queueing a second one.
// Nothing for the box: no device row, transport, vault credential, compile
// record or audit row is written before this decision.
//
// What it cannot prove: that a worker process exists. On a 'pending' mirror
// a queued job is judged claimable — the claim's own filter restated (status,
// attempts left, due, inside the job's window, and the maintenance window of
// the site its device sits on: `eligibleJobIds` in jobQueue.service) — not
// claimed; the worker's liveness lives in another process and is not
// recorded anywhere. The claim also scans only the first `PICK_SCAN_LIMIT`
// due jobs of the whole queue, which is not restated: a claimable job behind
// a full scan window waits longer than this judgement assumes.

/** A concentrator job, as re-read for the decision: the one a 'pending'
 *  names, or the one a 'provisioned' mirror names. */
export interface PendingJobFacts {
  kind: string;
  status: string;
  /** The CHR the job writes to. */
  deviceId: number;
  /** status 'queued', attempts left, due, inside its window if any, and
   *  inside the maintenance window of its device's site if any — what the
   *  claim itself filters on. */
  claimable: boolean;
  /** A worker holds an unexpired lease on it. */
  leased: boolean;
  errorMessage: string | null;
  outcomeDetail: string | null;
  /** The SITE's tenant and the site, from `concentrator_secret_jobs`. */
  tenantId: number;
  siteId: number;
  pppUsername: string;
  remoteAddress: string | null;
}

/** The allocation's mirror of the CHR side (`site_provisioning`), which the
 *  Allocation page shows. */
export interface ConcentratorMirrorFacts {
  state: string;
  jobId: number | null;
  /** The job `jobId` names, re-read — consulted only when `state` is
   *  'provisioned'; null when there is none, it is gone, or it is not a
   *  concentrator job. */
  job: PendingJobFacts | null;
}

export interface PendingExpectation {
  tenantId: number;
  siteId: number;
  concentratorId: number;
  pppUsername: string;
  tunnelIp: string;
}

export type ConcentratorRelease =
  | { release: true; state: ConcentratorSecretState }
  | { release: false; code: string; message: string };

/** Appended to every refusal: what stays committed (header above). */
const NOTHING_FOR_THE_BOX =
  'Rien n’est enregistré pour ce routeur ; seul l’adressage du site, déjà réservé, est conservé, et la prochaine compilation le réutilise tel quel.';
const NOT_RELEASED = 'Le fichier n’est pas délivré : un routeur configuré sans son compte ne joindrait jamais ObliWAN.';

/** The job writes THIS site's account as it is allocated today: same CHR,
 *  tenant, site, login and tunnel address. */
function matchesAllocation(job: PendingJobFacts, expected: PendingExpectation): boolean {
  return job.kind === 'concentrator_secret'
    && job.deviceId === expected.concentratorId
    && job.tenantId === expected.tenantId
    && job.siteId === expected.siteId
    && job.pppUsername === expected.pppUsername
    && job.remoteAddress !== null
    && job.remoteAddress === hostAddress(expected.tunnelIp);
}

/**
 * Pure: may this 'pending' release the file? `job` is null when the job the
 * state names does not exist (or is not a concentrator job), `mirror` null
 * when the site has no allocation row.
 *
 * The operator-visible state is the mirror, read as the section header says:
 * 'pending' naming THIS job releases a job the queue could claim now;
 * 'provisioned' releases only when the job it names succeeded for this very
 * account AND a worker holds the new job under a live lease. Anything else
 * ('failed', no row, another job's 'pending') means the page an operator
 * watches does not say that this account is being created.
 */
export function judgePendingConcentrator(
  c: ConcentratorSecretState,
  job: PendingJobFacts | null,
  mirror: ConcentratorMirrorFacts | null,
  expected: PendingExpectation,
): ConcentratorRelease {
  if (c.state !== 'pending') {
    throw new TypeError(`judgePendingConcentrator judges a 'pending' state, not '${c.state}'`);
  }
  const jobId = c.jobId;
  if (jobId === null) {
    return {
      release: false,
      code: 'concentrator_no_job',
      message: `Le compte PPP de ce site n’est pas confirmé sur le concentrateur et aucune tâche ne le crée (${c.message}). ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} Relancez la compilation dans un instant.`,
    };
  }
  if (job === null || job.kind !== 'concentrator_secret') {
    return {
      release: false,
      code: 'concentrator_no_job',
      message: `La tâche #${jobId} annoncée pour créer le compte PPP de ce site est introuvable. ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} Relancez la compilation.`,
    };
  }
  const inFlightNote = `La tâche #${jobId} reste en file : elle ne fait qu’ajouter le compte s’il manque, et la prochaine compilation la reprend au lieu d’en créer une autre.`;
  if (!matchesAllocation(job, expected)) {
    return {
      release: false,
      code: 'concentrator_job_mismatch',
      message: `La tâche #${jobId} ne crée pas le compte PPP de ce site tel qu’il est alloué aujourd’hui (concentrateur, identifiant ou adresse différents) : le routeur recevrait un compte que le concentrateur n’aurait pas. ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} Attendez la fin de la tâche #${jobId} (fiche du concentrateur), puis relancez.`,
    };
  }
  if (job.status === 'succeeded') {
    // Ended between the service's last read and this one: the fresher answer.
    return {
      release: true,
      state: { state: 'provisioned', jobId, message: job.outcomeDetail ?? 'provisioned' },
    };
  }
  if (!(ACTIVE_CHANGE_JOB_STATUSES as readonly string[]).includes(job.status)) {
    return {
      release: false,
      code: 'concentrator_failed',
      message: `La tâche #${jobId} chargée de créer le compte PPP de ce site sur le concentrateur s’est terminée sans le créer (${job.errorMessage ?? job.status}). ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} Corrigez la cause indiquée sur la fiche du concentrateur, puis relancez.`,
    };
  }
  const stalled = job.status === 'queued' ? !job.claimable : !job.leased;
  if (stalled) {
    return {
      release: false,
      code: 'concentrator_job_stalled',
      message: `La tâche #${jobId} chargée de créer le compte PPP de ce site n’est plus prise en charge (${job.status === 'queued' ? 'aucune tentative restante, pas encore due, ou hors de sa fenêtre ou de la fenêtre de maintenance de son site' : 'son processus a cessé de la suivre'}) : le compte ne serait pas créé. ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} Relancez la compilation une fois la tâche #${jobId} terminée.`,
    };
  }
  if (mirror !== null && mirror.state === 'pending' && mirror.jobId === jobId) {
    return { release: true, state: c };
  }
  if (mirror !== null && mirror.state === 'provisioned') {
    const earlier = mirror.job;
    const readBefore = mirror.jobId !== null ? `tâche #${mirror.jobId}` : 'tâche inconnue';
    if (earlier === null || earlier.status !== 'succeeded' || !matchesAllocation(earlier, expected)) {
      return {
        release: false,
        code: 'concentrator_not_shown',
        message: `La page Allocation affiche le compte PPP de ce site comme présent sur le concentrateur (${readBefore}), mais cette lecture ne porte pas sur le compte tel qu’il est alloué aujourd’hui (tâche introuvable, non réussie, ou concentrateur, identifiant ou adresse différents) : rien ne dirait à un opérateur que la tâche #${jobId} doit encore le créer. ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} ${inFlightNote} Relancez la compilation une fois la tâche #${jobId} terminée.`,
      };
    }
    if (!job.leased) {
      return {
        release: false,
        code: 'concentrator_not_shown',
        message: `La page Allocation affiche le compte PPP de ce site comme présent (${readBefore}), et la nouvelle vérification, tâche #${jobId}, n’a encore été prise en charge par aucun processus : si le compte a été retiré du concentrateur depuis, rien ne dirait à un opérateur que ce routeur l’attend. ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} ${inFlightNote} Relancez la compilation dans un instant.`,
      };
    }
    return { release: true, state: c };
  }
  const seen = mirror === null
    ? 'aucun'
    : `« ${mirror.state} »${mirror.jobId !== null ? `, tâche #${mirror.jobId}` : ''}`;
  return {
    release: false,
    code: 'concentrator_not_shown',
    message: `L’état du compte PPP affiché pour ce site (page Allocation : ${seen}) ne mentionne pas la tâche #${jobId} qui le crée : rien ne dirait à un opérateur que ce routeur attend son compte. ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX} ${inFlightNote}`,
  };
}

/**
 * One concentrator job as `judgePendingConcentrator` reads it, or null when
 * the row is gone or has no `concentrator_secret_jobs` subject. `claimable`
 * restates the claim's own filter (`eligibleJobIds` / `claimNextJob` in
 * jobQueue.service): the SQL half as written there, and the maintenance
 * window of the site the job's device sits on through the same
 * `isWithinMaintenanceWindow`, so a job the worker would skip is not judged
 * claimable.
 */
async function readConcentratorJob(jobId: number): Promise<PendingJobFacts | null> {
  const row = (await db('change_jobs as j')
    .join('concentrator_secret_jobs as c', 'c.job_id', 'j.id')
    .join('devices as d', 'd.id', 'j.device_id')
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .where('j.id', jobId)
    .first(
      'j.kind as kind',
      'j.status as status',
      'j.device_id as device_id',
      'j.error_message as error_message',
      'c.tenant_id as tenant_id',
      'c.site_id as site_id',
      'c.ppp_username as ppp_username',
      'c.outcome_detail as outcome_detail',
      's.maintenance_window as maintenance_window',
      's.timezone as timezone',
      db.raw('host(c.remote_address) AS remote_address'),
      db.raw(
        "(j.status = 'queued' AND j.attempt < j.max_attempts"
        + ' AND (j.scheduled_for IS NULL OR j.scheduled_for <= now())'
        + ' AND (j.window_start IS NULL OR now() >= j.window_start)'
        + ' AND (j.window_end IS NULL OR now() < j.window_end)) AS claimable',
      ),
      db.raw('(j.lease_expires_at IS NOT NULL AND j.lease_expires_at > now()) AS leased'),
    )) as
    | {
        kind: string; status: string; device_id: number | string; error_message: string | null;
        tenant_id: number | string; site_id: number | string; ppp_username: string;
        outcome_detail: string | null; maintenance_window: unknown; timezone: string | null;
        remote_address: string | null; claimable: boolean; leased: boolean;
      }
    | undefined;
  if (!row) return null;
  return {
    kind: row.kind,
    status: row.status,
    deviceId: Number(row.device_id),
    claimable: row.claimable === true && isWithinMaintenanceWindow(row.maintenance_window, row.timezone).open,
    leased: row.leased === true,
    errorMessage: row.error_message,
    outcomeDetail: row.outcome_detail,
    tenantId: Number(row.tenant_id),
    siteId: Number(row.site_id),
    pppUsername: row.ppp_username,
    remoteAddress: row.remote_address,
  };
}

/** Re-read what `judgePendingConcentrator` decides on — the job the
 *  'pending' names, the allocation's mirror and, when that mirror says
 *  'provisioned', the job it names — and decide. Exported for the bench-api
 *  harness, which drives it on real rows. */
export async function judgePendingFromDb(
  c: ConcentratorSecretState,
  expected: PendingExpectation,
): Promise<ConcentratorRelease> {
  const job = c.jobId !== null ? await readConcentratorJob(c.jobId) : null;
  const m = (await db('site_provisioning')
    .where({ site_id: expected.siteId, tenant_id: expected.tenantId })
    .first('concentrator_state', 'concentrator_job_id')) as
    | { concentrator_state: string; concentrator_job_id: string | number | null }
    | undefined;
  let mirror: ConcentratorMirrorFacts | null = null;
  if (m) {
    const mirrorJobId = m.concentrator_job_id === null ? null : Number(m.concentrator_job_id);
    mirror = {
      state: m.concentrator_state,
      jobId: mirrorJobId,
      job: m.concentrator_state === 'provisioned' && mirrorJobId !== null ? await readConcentratorJob(mirrorJobId) : null,
    };
  }
  return judgePendingConcentrator(c, job, mirror, expected);
}

/**
 * Compile the run-after-reset file for one box and one site. Commits the
 * site's allocation (idempotent), creates or reuses the device row — a created
 * one placed in the tenant's BENCH_DEFAULT_GROUP when that names one of its
 * groups (`benchDefaultGroup`; otherwise no group, and `warnings` says why) —
 * pins it to the compiled revision (`pinBenchAssignment`), stores the ObliWAN
 * account in the vault, records the compile with what the fleet render needs
 * to render that revision again (the non-secret bench values, the box facts
 * on the device row: migration 063) — and returns the file, in both forms
 * (legacy single file and split files).
 *
 * `deviceModeOverride`: null when the bench declared nothing, otherwise its
 * declaration — true compiles a revision the box's device-mode reading denies
 * (an operator's decision for a remote test) and is recorded on the compile
 * and on the device. `confirmReplaceDeviceId`: the device the bench confirmed
 * it replaces (the plan's `replaces`); a compile that would retire a device
 * is refused unless it names that very device.
 */
export async function compileForBox(input: {
  station: BenchStationRef;
  siteId: number;
  revisionId: number;
  box: BenchBoxInput;
  bench: unknown;
  deviceModeOverride?: boolean | null;
  confirmReplaceDeviceId?: number | null;
}): Promise<BenchCompileResult> {
  const { station, box } = input;
  const override = input.deviceModeOverride === true;
  const deviceMode = box.deviceMode ?? null;
  const confirmReplace = input.confirmReplaceDeviceId ?? null;
  const { site, tenant } = await loadBenchSite(input.siteId);
  const tenantId = tenant.id;

  // ── 1. Re-validate everything the plan said ──────────────────────────────
  if (box.wifi_stack === null) {
    throw new BenchApiError(409, 'La pile Wi-Fi du routeur (« wifi » ou « wireless ») n’a pas pu être lue : relancez l’identification du routeur.', 'box');
  }
  const family = familyOf(box.ros_version);
  const chosen = await chosenRevision(tenantId, input.revisionId, box);
  const benchDecls = benchDeclarationsOf(chosen.varSchema);
  const benchValues = benchValuesFor(benchDecls, input.bench);
  const mgmt = await readManagementRange();
  if (!mgmt.ok) throw new BenchApiError(409, mgmt.message, 'management_range');
  // Refused here, before anything is committed, when admin's password is unset.
  const legacy = await readLegacyAccounts(tenantId, site.id);

  const reuse = box.serial
    ? ((await db('devices')
        .where({ tenant_id: tenantId, site_id: site.id, brand: 'mikrotik', serial: box.serial })
        .first('id', 'group_id')) as { id: number; group_id: number | null } | undefined) ?? null
    : null;
  // The group a NEW row is placed in (a reused row keeps its own), judged
  // here so the SNMP community below is resolved through the same chain the
  // poller will read, and re-checked in the transaction that inserts.
  const defaultGroup = await benchDefaultGroup(tenantId);
  const snmpCommunity = await snmpCommunityFor(tenantId, reuse, reuse ? null : defaultGroup.groupId);

  // ── 1b. Before anything is committed: the takeover and the device-mode ───
  // On the allocation PREVIEW (it commits nothing): the devices this compile
  // would take over, the replacement's confirmation included, and the
  // device-mode features of a REDACTED render made with the preview's values.
  // Both are judged again after the commit, on the committed login and on the
  // real render (step 3): the preview is what the commit WILL write for a site
  // not yet allocated, and what it already holds otherwise.
  //
  // When no redacted render can be made here, the revision's SOURCES decide
  // (`revisionSourceFeatures`): every branch of every condition counted, they
  // over-approximate what any render of them can need — so nothing denied
  // there means nothing denied in the render, and something denied there is
  // refused HERE, before the site's addresses are reserved, even if the
  // branch needing it would not have been taken (the override lifts it).
  // What the scan cannot see is a command a variable's VALUE injects: only
  // that reaches step 3's refusal after the commit, which says so.
  let preview: Awaited<ReturnType<typeof previewForSite>> | null = null;
  try {
    preview = await previewForSite(tenantId, site.id);
  } catch (err) {
    // The commit below refuses with the same reason, worded for the bench.
    if (!(err instanceof AllocationError)) throw err;
  }
  if (preview !== null) {
    await inspectTakeover(db, {
      tenantId, siteId: site.id, serial: box.serial, pppUsername: preview.ppp_username, confirmReplaceDeviceId: confirmReplace,
    }, false);
    if (deviceMode !== null && !override) {
      const redacted = await deps.preRender({
        tenantId, siteId: site.id, candidate: chosen, computed: preview.values, bench: benchValues, box,
      });
      const fromSources = redacted === null;
      const needed = redacted !== null ? deviceModeFeaturesOf(redacted) : (await revisionSourceFeatures(chosen.revisionId)) ?? [];
      const denied = deniedFeatures(deviceMode, needed);
      if (denied.length > 0) throw deviceModeRefusal(chosen.templateName, denied, deviceMode, false, fromSources);
    }
  }

  // ── 2. The allocation — committed here, and only here ────────────────────
  let computed: ComputedSiteValues;
  try {
    computed = await computedForSite(tenantId, site.id);
  } catch (err) {
    if (err instanceof AllocationError) throw allocationRefusal(err);
    throw err;
  }
  if (computed.system_identity === null) {
    throw new BenchApiError(
      409,
      'Aucune identité système n’est allouée à ce site : définissez le modèle d’identité dans la politique d’allocation du client, puis relancez.',
      'identity',
    );
  }
  if (!IDENTITY_RE.test(computed.system_identity)) {
    throw new BenchApiError(409, 'L’identité système allouée à ce site contient des caractères qu’un routeur ne peut pas recevoir tels quels (lettres, chiffres, « . », « _ », « - » seulement).', 'identity');
  }

  // The PPP password: rendered only where the revision declares it COMPUTED
  // and SECRET. Declared at another level, the template reads the shared
  // instance password — which is the CHR's password only in 'shared' mode.
  const computedMap: Record<string, unknown> = { ...computed.values };
  const props = (chosen.varSchema.properties ?? {}) as Record<string, Record<string, unknown> | undefined>;
  const pppDecl = props.ppp_password;
  if (pppDecl && pppDecl['x-obliwan-level'] === 'computed') {
    if (pppDecl['x-obliwan-secret'] !== true) {
      throw new BenchApiError(422, 'Le modèle déclare « ppp_password » calculé sans le déclarer secret : le mot de passe apparaîtrait en clair dans les traces. Corrigez le modèle.', 'template');
    }
    computedMap.ppp_password = computed.ppp_password;
  } else if (pppDecl && computed.ppp_password_mode === 'per_site') {
    throw new BenchApiError(
      409,
      'Ce client utilise un mot de passe PPP propre à chaque site, et le modèle lit « ppp_password » ailleurs qu’au niveau « computed » : le routeur recevrait un autre mot de passe que le concentrateur. Corrigez le modèle ou la politique d’allocation.',
      'template',
    );
  }

  // ── 3. The render, with the secrets spliced (memory only) ───────────────
  const facts = boxFactsOf(box) as BoxFacts;
  let rendered: Awaited<ReturnType<typeof renderForSite>>;
  try {
    rendered = await renderForSite({
      tenantId,
      siteId: site.id,
      revisionId: chosen.revisionId,
      computed: computedMap,
      bench: benchValues,
      box: facts,
      mode: 'secrets',
    });
  } catch (err) {
    if (err instanceof SiteRenderError) throw renderRefusal(err);
    throw err;
  }
  const { head, tail } = splitRendered(rendered.text);
  assertNoResidue(rendered.text);
  const wifiStack = box.wifi_stack as 'wifi' | 'wireless';
  const identity = computed.system_identity as string;
  const stackMismatch = wifiStackMismatch(rendered.text, wifiStack);
  if (stackMismatch) {
    throw new BenchApiError(422, `Le modèle « ${chosen.templateName} » rendu pour ce routeur ne convient pas : ${stackMismatch}. Corrigez le modèle (lisez box.wifi_stack) ou choisissez-en un autre.`, 'template');
  }
  // The features of THIS render decide (step 1b judged a render made with the
  // preview's values, or the revision's sources when none could be made). A
  // refusal here, after the commit, takes a denied feature that neither
  // showed: a command a value injected, or a render that differs from the
  // pre-render. Under the override, the denied features are wrapped (`gated`).
  const features = deviceModeFeaturesOf(rendered.redacted);
  const denied = deniedFeatures(deviceMode, features);
  if (denied.length > 0 && !override) throw deviceModeRefusal(chosen.templateName, denied, deviceMode, true);

  // Every refusal that needs no write is decided BEFORE the concentrator is
  // touched: a compile refused after step 4 would leave an L2TP account on
  // the shared CHR for a box that never received its file. The device checks
  // are re-run, locked, in the transaction of step 5.
  await inspectTakeover(db, {
    tenantId, siteId: site.id, serial: box.serial, pppUsername: computed.ppp_username, confirmReplaceDeviceId: confirmReplace,
  }, false);
  const password = deps.generatePassword();
  // The device id is not known yet: the provisional tag holds ten digits for
  // it, as many as an `increments` id can have, so that a section this
  // assembly finds small enough (`OLDER_BUILD_READ_LIMIT_BYTES`) is never
  // found too large in the transaction, after the concentrator was touched.
  const provisionalTag = `s${site.id}-d${'9'.repeat(10)}-00000000`;
  const provisional = {
    tag: provisionalTag, fileName: `obliwan-${provisionalTag}.rsc`, head, tail, wifiStack,
    identity, mgmt: mgmt.prefixes, password, snmpCommunity, gated: denied, legacy,
  };
  assembleCompiledFile(provisional);
  assembleSplitCompiledFiles(provisional);

  // ── 4. The concentrator account — before anything is written for the box ─
  // Released on 'provisioned', or on a 'pending' whose job is re-read and
  // found genuinely queued and shown to the operator (section above
  // `judgePendingConcentrator`, which also says what a refusal leaves).
  const offered = await deps.provisionConcentrator({ tenantId, siteId: site.id }, CONCENTRATOR_WAIT_MS);
  if (offered.state === 'failed') {
    throw new BenchApiError(
      409,
      `${concentratorMessage(offered)} ${NOT_RELEASED} ${NOTHING_FOR_THE_BOX}`,
      'concentrator_failed',
    );
  }
  let concentrator: ConcentratorSecretState = offered;
  if (offered.state === 'pending') {
    const verdict = await judgePendingFromDb(offered, {
      tenantId,
      siteId: site.id,
      concentratorId: computed.concentrator_id,
      pppUsername: computed.ppp_username,
      tunnelIp: computed.tunnel_ip,
    });
    if (!verdict.release) {
      logger.warn(
        { stationId: station.id, tenantId, siteId: site.id, jobId: offered.jobId, code: verdict.code },
        'Bench compile refused: a pending concentrator account failed its re-check (job, allocation mirror)',
      );
      throw new BenchApiError(409, verdict.message, verdict.code);
    }
    concentrator = verdict.state;
  }

  // ── 5. Device, credential, file and record — one transaction ─────────────
  const result = await db.transaction(async (trx) => {
    const persisted = await persistDevice(trx, {
      tenantId, siteId: site.id, box, family, computed, identity, station, override, confirmReplaceDeviceId: confirmReplace,
      defaultGroupId: defaultGroup.groupId,
    });
    const groupWarning = persisted.groupWarning ?? (persisted.created ? defaultGroup.warning : null);
    // The API channel is api-ssl (8729, TLS) — the only API service the
    // access block enables — with NO fingerprint pinned: the certificate is
    // generated on the box when the file runs, so nothing here can know it.
    // The first contact pins it (trust on first use): for a bench box that is
    // the automatic conformity check (fleet/autoConfirm.service.ts), whose
    // first session writes the pin before the identity assertion and every
    // later session, which must then present the same certificate; the
    // RouterOS pool's `onFingerprint` pins the same way for a device it
    // reaches first. ssh stays ssh on 22.
    for (const [transport, port, useTls] of [['routeros_api', API_SSL_PORT, true], ['ssh', SSH_PORT, false]] as const) {
      // A reused row keeps nothing of the previous box's access: a stale
      // private key would be tried before the password (ssh.transport prefers
      // it, and the obliwan account has no authorised key), a pinned TLS
      // fingerprint and the transport knobs were another box's, and a pending
      // rotation's next secret was minted for a password this box never had.
      const columns = {
        enabled: true,
        host: computed.tunnel_ip,
        port,
        username: OBLIWAN_ACCOUNT,
        secret_enc: encrypt(password),
        key_version: currentKeyVersion(),
        private_key_enc: null,
        use_tls: useTls,
        tls_fingerprint_sha256: null,
        params: JSON.stringify({}),
        secret_next_enc: null,
        secret_next_key_version: null,
        secret_next_at: null,
      };
      await trx('device_transports')
        .insert({ device_id: persisted.deviceId, transport, ...columns })
        .onConflict(['device_id', 'transport'])
        .merge({ ...columns, updated_at: trx.fn.now() });
    }

    const tag = `s${site.id}-d${persisted.deviceId}-${crypto.randomBytes(4).toString('hex')}`;
    // The device is attached to the revision it is compiled with, so the
    // fleet's preview, plan and rollout resolve it (`pinBenchAssignment`).
    const assignment = await pinBenchAssignment(trx, {
      tenantId, deviceId: persisted.deviceId, revisionId: chosen.revisionId, tag, station,
    });
    const fileName = `obliwan-${tag}.rsc`;
    const assembled = { tag, fileName, head, tail, wifiStack, identity, mgmt: mgmt.prefixes, password, snmpCommunity, gated: denied, legacy };
    const content = assembleCompiledFile(assembled);
    const files = assembleSplitCompiledFiles(assembled);
    const sha256 = sha256Hex(content);
    // Identifiers only: never a file's content.
    const manifest = files.map((f) => ({ name: f.name, role: f.role, sha256: f.sha256, bytes: Buffer.byteLength(f.content, 'utf8') }));
    const kept = keptBenchValues(benchDecls, benchValues);
    await trx('bench_provisionings').insert({
      tenant_id: tenantId,
      site_id: site.id,
      device_id: persisted.deviceId,
      station_id: station.id,
      revision_id: chosen.revisionId,
      tag,
      file_name: fileName,
      content_sha256: sha256,
      redacted_sha256: rendered.redactedSha256,
      concentrator_state: concentrator.state,
      concentrator_job_id: concentrator.jobId,
      outcome: 'compiled',
      files: JSON.stringify(manifest),
      device_mode_features: JSON.stringify(features),
      device_mode_denied: JSON.stringify(denied),
      device_mode_override: override,
      // What the fleet render needs to render this revision as compiled
      // (migration 063): the non-secret typed values, and the NAMES of the
      // secret ones — never their values (the banner above).
      bench_values: JSON.stringify(kept.values),
      bench_secret_keys: JSON.stringify(kept.secretKeys),
    });
    await appendAudit({
      tenantId,
      actorType: 'automation',
      actorId: `bench-station:${station.id}`,
      actorName: station.name.slice(0, 128),
      action: 'bench.compiled',
      entityType: 'device',
      entityId: persisted.deviceId,
      after: {
        siteId: site.id,
        siteCode: site.code,
        revisionId: chosen.revisionId,
        templateName: chosen.templateName,
        tag,
        fileName,
        contentSha256: sha256,
        redactedSha256: rendered.redactedSha256,
        substitutedSecrets: rendered.substitutedSecrets,
        concentratorState: concentrator.state,
        concentratorJobId: concentrator.jobId,
        deviceCreated: persisted.created,
        replacedDeviceId: persisted.replacedDeviceId,
        // The group a created row was placed in (a reused row keeps its own,
        // and records null here), and why a configured one was not applied.
        groupId: persisted.groupId,
        groupWarning,
        templateId: assignment.templateId,
        assignmentId: assignment.assignmentId,
        boxMac: box.mac,
        boxSerial: box.serial,
        files: manifest,
        deviceModeFeatures: features,
        deviceModeDenied: denied,
        deviceModeOverride: override,
        deviceMode,
      },
    }, trx);
    return {
      tag, fileName, content, sha256, files, deviceId: persisted.deviceId, created: persisted.created,
      groupId: persisted.groupId, groupWarning,
    };
  });
  if (result.groupWarning !== null) {
    logger.warn(
      { stationId: station.id, tenantId, siteId: site.id, deviceId: result.deviceId, setting: SETTINGS_KEYS.BENCH_DEFAULT_GROUP },
      'Bench compile: the default group names no group of this tenant; the device was created with no group',
    );
  }

  // The transport just changed: drop any pooled session opened with the old
  // password (a reused device), as `upsertTransport` does.
  getRouterOsPool().close(String(result.deviceId));
  logger.info(
    {
      stationId: station.id, tenantId, siteId: site.id, deviceId: result.deviceId, tag: result.tag, created: result.created,
      concentrator: concentrator.state, files: result.files.length, deviceModeDenied: denied, deviceModeOverride: override,
    },
    'Bench compile released a configuration file',
  );

  return {
    fileName: result.fileName,
    content: result.content,
    sha256: result.sha256,
    tag: result.tag,
    deviceId: result.deviceId,
    concentrator: { state: concentrator.state, message: concentratorMessage(concentrator) },
    files: result.files,
    deviceModeFeatures: features,
    ...(input.deviceModeOverride === true || input.deviceModeOverride === false ? { testOverride: input.deviceModeOverride } : {}),
    groupId: result.groupId,
    warnings: result.groupWarning !== null ? [result.groupWarning] : [],
  };
}

/** The reason every assignment the bench writes starts with: how a later
 *  compile of the same device recognises its own (`pinBenchAssignment`). */
export const BENCH_ASSIGNMENT_REASON = 'Prepared at the bench';

/**
 * Attach the device to the revision it is compiled with: a DEVICE-scoped
 * template assignment PINNED to that revision, through `upsertAssignment` —
 * the table's single write path, which re-checks that the device is this
 * tenant's and the revision this template's. Device scope outranks every
 * group and tenant assignment (assignment.service, rule 1): the box runs THIS
 * revision, whatever the fleet's wider assignments would pick, until somebody
 * changes the pin. Without it the fleet resolved no revision for a bench box,
 * and every preview, plan or rollout of it ended on "no assignment".
 *
 * Re-preparing the same device: the upsert re-pins its assignment of the same
 * template; an earlier BENCH assignment of it to ANOTHER template is removed
 * (the box no longer runs that one — two device-scoped assignments of two
 * templates would make "which one applies" a tie). An assignment somebody
 * made by hand (any other reason) is left alone.
 *
 * Pinned, not `latest_published`: a revision published after this compile
 * was never rendered for this box, and following it would make the next plan
 * push a configuration nobody looked at for it.
 */
async function pinBenchAssignment(
  trx: Knex.Transaction,
  p: { tenantId: number; deviceId: number; revisionId: number; tag: string; station: BenchStationRef },
): Promise<{ assignmentId: string; templateId: string }> {
  const rev = (await trx('template_revisions').where({ id: p.revisionId }).first('template_id')) as
    | { template_id: string | number }
    | undefined;
  if (!rev) {
    throw new BenchApiError(409, `La révision #${p.revisionId} du modèle n’existe plus : relancez le plan.`, 'revision');
  }
  const templateId = String(rev.template_id);
  await trx('template_assignments')
    .where({ tenant_id: p.tenantId, scope: 'device', scope_id: p.deviceId })
    .whereNot('template_id', templateId)
    .where('reason', 'like', `${BENCH_ASSIGNMENT_REASON}%`)
    .del();
  const { id } = await upsertAssignment(p.tenantId, {
    scope: 'device',
    scopeId: p.deviceId,
    templateId,
    revisionId: p.revisionId,
    reason: `${BENCH_ASSIGNMENT_REASON} by station "${p.station.name.slice(0, 128)}" (#${p.station.id}), tag ${p.tag}: pinned to the revision the box was compiled with.`,
    createdBy: null,
  }, trx);
  return { assignmentId: String(id), templateId };
}

type TakeoverRow = SiteDeviceFacts & { tenant_id: number; site_id: number | null; notes: string | null };

/**
 * The devices a compile would take over — the same box (site + serial) and
 * the holder of the site's PPP login — judged by `takeoverRefusal`, or a 409.
 * Read-only. Run once BEFORE the concentrator is written, so a refusal leaves
 * nothing on the shared CHR, and again with row locks inside the transaction
 * that writes, so an edit made between the two is still judged.
 */
async function inspectTakeover(
  q: Knex,
  p: { tenantId: number; siteId: number; serial: string | null; pppUsername: string; confirmReplaceDeviceId: number | null },
  lock: boolean,
): Promise<{ existing: TakeoverRow | null; pppHolder: TakeoverRow | null }> {
  const pick = async (where: (b: Knex.QueryBuilder) => void): Promise<TakeoverRow | null> => {
    const b = q('devices as d').modify(where).orderBy('d.id').first(
      'd.id as id', 'd.tenant_id as tenant_id', 'd.site_id as site_id', 'd.status as status',
      'd.is_managed as is_managed', 'd.notes as notes',
      q.raw('EXISTS (SELECT 1 FROM bench_provisionings b WHERE b.device_id = d.id) AS bench_prepared'),
    );
    const row = (await (lock ? b.forUpdate() : b)) as TakeoverRow | undefined;
    return row ? { ...row, id: Number(row.id), is_managed: row.is_managed === true, bench_prepared: row.bench_prepared === true } : null;
  };
  const refuse = (row: TakeoverRow, role: 'reuse' | 'retire'): void => {
    const why = takeoverRefusal(row, role);
    if (why) throw new BenchApiError(409, `Rien n’a été compilé. ${why}`, 'device_confirmed');
  };

  let existing: TakeoverRow | null = null;
  if (p.serial) {
    const serial = p.serial;
    existing = await pick((b) => b.where({ 'd.tenant_id': p.tenantId, 'd.site_id': p.siteId, 'd.brand': 'mikrotik', 'd.serial': serial }));
    if (!existing) {
      const holder = await pick((b) => b.where({ 'd.brand': 'mikrotik', 'd.serial': serial }));
      if (holder) {
        throw new BenchApiError(409, `Rien n’a été compilé. ${serialTakenReason(holder.id, Number(holder.tenant_id) === p.tenantId)}`, 'serial_taken');
      }
    } else {
      refuse(existing, 'reuse');
    }
  }

  const reusedId = existing?.id ?? null;
  const pppHolder = await pick((b) => {
    b.where('d.ppp_username', p.pppUsername);
    if (reusedId !== null) b.whereNot('d.id', reusedId);
  });
  if (pppHolder) {
    if (Number(pppHolder.tenant_id) !== p.tenantId || Number(pppHolder.site_id) !== p.siteId) {
      throw new BenchApiError(409, `Rien n’a été compilé. ${PPP_TAKEN_REASON}`, 'ppp_taken');
    }
    refuse(pppHolder, 'retire');
    // Retiring a device is the bench operator's decision, made on the plan's
    // `replaces`: it must name THIS device — a confirmation given for another
    // one (the holder changed since the plan) confirms nothing.
    if (p.confirmReplaceDeviceId !== pppHolder.id) {
      throw new BenchApiError(
        409,
        `Ce site a déjà un routeur (appareil #${pppHolder.id}) : le préparer le remplacera, et le désactivera. Rien n’a été compilé. Confirmez au banc le remplacement de l’appareil #${pppHolder.id}, puis relancez.`,
        'replace_unconfirmed',
      );
    }
  }
  return { existing, pppHolder };
}

/**
 * Create the device row, or reuse the one this site already has for this
 * serial. The identity semantics are the enrolment's: status `pending`
 * and `is_managed` false on a new row — confirmed by nobody yet, refused by
 * every write job — and `enrolled_by_station_id` names the desk.
 *
 * The (concentrator, PPP login) pair is written directly rather than through
 * `createDevice`'s claim check: it is not chosen by the caller but read from
 * the allocator's own reservation for this very site (`computedForSite`).
 *
 * A REPLACEMENT box: the login is unique across devices, so another device of
 * the SAME site holding it is retired — login and tunnel address cleared,
 * transports disabled, status `disabled`, a note naming its successor — when
 * `takeoverRefusal` admits it (an unconfirmed bench box, or one the operator
 * already disabled). A holder anywhere else is a conflict the bench cannot
 * settle. A reused row goes back to `pending` and unmanaged: the box was
 * reset and re-prepared, and a human confirms it again.
 *
 * The box's device-mode reading is written as ONE observation of the five
 * `device_mode*` columns (`deviceModeColumns`, the rules of
 * `recordDeviceMode`): no reading writes none of them, and a reused row keeps
 * its earlier reading then. `bench_device_mode_override` records this
 * compile's declaration, true or false, on a reused row too.
 *
 * The group: a NEW row is placed in `defaultGroupId` (BENCH_DEFAULT_GROUP,
 * judged by `benchDefaultGroup`), re-read here under `FOR KEY SHARE` so a
 * group deleted since the judgement is not inserted (the FK would refuse it,
 * as a 500 after the concentrator was touched) but reported as
 * `groupWarning`, and cannot be deleted before this transaction commits. A
 * REUSED row keeps the group it has: where it sits was decided after it was
 * first prepared, by somebody who could see it.
 */
async function persistDevice(
  trx: Knex.Transaction,
  p: {
    tenantId: number; siteId: number; box: BenchBoxInput; family: string;
    computed: ComputedSiteValues; identity: string; station: BenchStationRef;
    override: boolean; confirmReplaceDeviceId: number | null;
    defaultGroupId: number | null;
  },
): Promise<{ deviceId: number; created: boolean; replacedDeviceId: number | null; groupId: number | null; groupWarning: string | null }> {
  const { tenantId, siteId, box, computed } = p;
  const { existing, pppHolder } = await inspectTakeover(
    trx, { tenantId, siteId, serial: box.serial, pppUsername: computed.ppp_username, confirmReplaceDeviceId: p.confirmReplaceDeviceId }, true,
  );

  let replacedDeviceId: number | null = null;
  if (pppHolder) {
    replacedDeviceId = Number(pppHolder.id);
    const note = `Replaced at the bench on ${new Date().toISOString()} (station #${p.station.id}): login and tunnel address moved to the new box.`;
    await trx('devices').where({ id: replacedDeviceId, tenant_id: tenantId }).update({
      ppp_username: null,
      tunnel_ip: null,
      status: 'disabled',
      notes: pppHolder.notes ? `${pppHolder.notes}\n${note}` : note,
      updated_at: trx.fn.now(),
    });
    await trx('device_transports').where({ device_id: replacedDeviceId }).update({ enabled: false, updated_at: trx.fn.now() });
  }

  const columns = {
    family: p.family,
    brand: 'mikrotik',
    model: box.model,
    serial: box.serial,
    os_version: box.ros_version,
    // The box facts a template reads besides model and version (migration
    // 063), for the fleet render of this device.
    board: box.board,
    wifi_stack: box.wifi_stack,
    system_identity: p.identity,
    ppp_username: computed.ppp_username,
    tunnel_ip: computed.tunnel_ip,
    concentrator_id: computed.concentrator_id,
    enrolled_by_station_id: p.station.id,
    bench_device_mode_override: p.override,
    ...(deviceModeColumns(box.deviceMode ?? null) ?? {}),
    // The file just compiled sets lte1's APN from the bench value: an APN
    // chosen earlier on the device page (migration 065) is older than that
    // and must not win over it in later renders (render.service).
    lte_apn_profile: null,
  };
  if (existing) {
    await trx('devices').where({ id: existing.id, tenant_id: tenantId }).update({
      ...columns,
      status: 'pending',
      is_managed: false,
      updated_at: trx.fn.now(),
    });
    return { deviceId: Number(existing.id), created: false, replacedDeviceId, groupId: null, groupWarning: null };
  }
  let groupId: number | null = null;
  let groupWarning: string | null = null;
  if (p.defaultGroupId !== null) {
    const group = await trx('device_groups').where({ id: p.defaultGroupId, tenant_id: tenantId }).forKeyShare().first('id');
    if (group) groupId = p.defaultGroupId;
    else groupWarning = benchGroupWarning(p.defaultGroupId);
  }
  const [row] = (await trx('devices')
    .insert({
      ...columns,
      tenant_id: tenantId,
      site_id: siteId,
      group_id: groupId,
      name: p.identity,
      role: 'cpe',
      status: 'pending',
      is_managed: false,
      notes: `Prepared at the bench by station "${p.station.name}" (#${p.station.id}) for site #${siteId}; MAC ${box.mac}.`,
    })
    .returning('id')) as Array<{ id: number }>;
  return { deviceId: Number(row.id), created: true, replacedDeviceId, groupId, groupWarning };
}

// ============================================================================
// The bench's report
// ============================================================================

/** What the bench checked on its own side after the run (additive). */
export interface BenchLocalCheck {
  /** The identity the box announced over MNDP, or null when none was heard. */
  mndpIdentity: string | null;
  /** The bench's own judgement: that identity is the one it expected. */
  identityMatches: boolean;
  /** The customer LAN answered from the bench; null when not tested. */
  lanReachable: boolean | null;
}

/** `localCheck` of a result body, or null when absent. Judged, never repaired. */
export function parseLocalCheck(raw: unknown): BenchLocalCheck | null {
  if (raw === undefined || raw === null) return null;
  const bad = (field: string): never => {
    throw new BenchApiError(400, `Rapport du banc invalide : le champ « localCheck${field} » est absent ou illisible.`, 'bad_input');
  };
  if (typeof raw !== 'object' || Array.isArray(raw)) return bad('');
  const r = raw as Record<string, unknown>;
  let mndpIdentity: string | null = null;
  if (r.mndpIdentity !== undefined && r.mndpIdentity !== null) {
    if (typeof r.mndpIdentity !== 'string') return bad('.mndpIdentity');
    const t = r.mndpIdentity.trim();
    // What a RouterOS identity may hold, printable, bounded: it is stored and shown.
    if (t.length > 255 || !/^[\x20-\x7e]*$/.test(t)) return bad('.mndpIdentity');
    mndpIdentity = t === '' ? null : t;
  }
  if (typeof r.identityMatches !== 'boolean') return bad('.identityMatches');
  if (r.lanReachable !== undefined && r.lanReachable !== null && typeof r.lanReachable !== 'boolean') return bad('.lanReachable');
  return { mndpIdentity, identityMatches: r.identityMatches, lanReachable: typeof r.lanReachable === 'boolean' ? r.lanReachable : null };
}

/** The SIM card the bench read in the box's modem (`readSimCard`). */
export interface BenchSimReading {
  iccid: string;
  imsi: string | null;
}

/**
 * `sim` of a result body: undefined when absent (nothing was read — an older
 * bench, a failed run), null for "read, and no SIM found", or the reading.
 * Judged, never repaired: the shapes are the ones `sim_lines.iccid` and the
 * device columns hold (migrations 032 and 063).
 */
export function parseBenchSim(raw: unknown): BenchSimReading | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === null) return null;
  const bad = (field: string): never => {
    throw new BenchApiError(400, `Rapport du banc invalide : le champ « sim${field} » est absent ou illisible.`, 'bad_input');
  };
  if (typeof raw !== 'object' || Array.isArray(raw)) return bad('');
  const r = raw as Record<string, unknown>;
  if (typeof r.iccid !== 'string' || !/^[0-9]{18,22}$/.test(r.iccid)) return bad('.iccid');
  if (r.imsi !== undefined && r.imsi !== null && (typeof r.imsi !== 'string' || !/^[0-9]{6,15}$/.test(r.imsi))) return bad('.imsi');
  return { iccid: r.iccid, imsi: typeof r.imsi === 'string' ? r.imsi : null };
}

/**
 * Record what the bench says happened to the file it uploaded. Accepted only
 * from the station that compiled it, and only for its latest compile of that
 * device; a repeat of the same report is answered as a success (and changes
 * nothing).
 *
 * `localCheck` and `deviceModeOverride` are additive. Both are RECORDED as
 * the bench reported them, never used to change the outcome the bench
 * reported: `local_check` keeps, beside the bench's own `identityMatches`,
 * `identityMatchesDevice` — the MNDP identity compared here with the identity
 * the compile gave the device (null when none was heard). A
 * `deviceModeOverride` that contradicts the compile's own record is logged
 * and audited (`deviceModeOverrideMatches: false`); the compile's record is
 * the one that stands.
 *
 * What reads them: no decision, today. `local_check`,
 * `reported_device_mode_override`, `bench_provisionings.device_mode_override`
 * and `devices.bench_device_mode_override` are the AUDIT record of what the
 * bench declared and observed. Auto-confirmation (fleet/autoConfirm.service)
 * judges the box's own proof read over ObliWAN's channel and consults none of
 * them. If a bench claim is ever wired into a decision, it can only DENY one
 * (an `identityMatches: false` holding a confirmation back), never grant it:
 * the bench is the party whose box is being judged.
 *
 * `sim` (additive): the card the bench read in the box's modem before the
 * reset. It IS stored, on the device (migration 063), and it is the one bench
 * claim that changes something: the line of the device's tenant carrying that
 * ICCID is linked to the device (`linkLineByDeviceIccid`, which never moves a
 * line linked to another router and never crosses a tenant). What that grants
 * is an attribution on a screen — which store a low-data alert is about — not
 * an access, a confirmation or a spend.
 */
export async function recordBenchResult(input: {
  station: BenchStationRef;
  deviceId: number;
  status: unknown;
  detail: unknown;
  localCheck?: unknown;
  deviceModeOverride?: unknown;
  sim?: unknown;
}): Promise<void> {
  if (input.status !== 'applied' && input.status !== 'failed') {
    throw new BenchApiError(400, 'Le statut doit valoir « applied » ou « failed ».', 'bad_input');
  }
  const status = input.status;
  const detail = typeof input.detail === 'string'
    // eslint-disable-next-line no-control-regex
    ? input.detail.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, 2000)
    : '';
  const localCheck = parseLocalCheck(input.localCheck);
  if (input.deviceModeOverride !== undefined && input.deviceModeOverride !== null && typeof input.deviceModeOverride !== 'boolean') {
    throw new BenchApiError(400, 'Rapport du banc invalide : « deviceModeOverride » doit valoir true ou false.', 'bad_input');
  }
  const reportedOverride = typeof input.deviceModeOverride === 'boolean' ? input.deviceModeOverride : null;
  const sim = parseBenchSim(input.sim);
  await db.transaction(async (trx) => {
    const row = (await trx('bench_provisionings')
      .where({ device_id: input.deviceId, station_id: input.station.id })
      .orderBy('compiled_at', 'desc')
      .orderBy('id', 'desc')
      .forUpdate()
      .first('id', 'tenant_id', 'tag', 'outcome', 'device_mode_override')) as
      | { id: number; tenant_id: number; tag: string; outcome: string; device_mode_override: boolean }
      | undefined;
    if (!row) {
      throw new BenchApiError(404, `Aucune configuration n’a été compilée par ce poste pour l’appareil #${input.deviceId}.`, 'not_found');
    }
    if (row.outcome !== 'compiled') {
      if (row.outcome === status) return;
      throw new BenchApiError(409, `Le résultat de la préparation ${row.tag} a déjà été enregistré (« ${row.outcome} »).`, 'already_reported');
    }
    let stored: (BenchLocalCheck & { identityMatchesDevice: boolean | null }) | null = null;
    if (localCheck !== null) {
      const dev = (await trx('devices').where({ id: input.deviceId, tenant_id: row.tenant_id }).first('system_identity')) as
        | { system_identity: string | null }
        | undefined;
      stored = {
        ...localCheck,
        identityMatchesDevice: localCheck.mndpIdentity === null ? null : localCheck.mndpIdentity === (dev?.system_identity ?? null),
      };
    }
    const overrideMatches = reportedOverride === null ? null : reportedOverride === (row.device_mode_override === true);
    if (overrideMatches === false) {
      logger.warn(
        { stationId: input.station.id, deviceId: input.deviceId, tag: row.tag, reported: reportedOverride, compiled: row.device_mode_override === true },
        'Bench result: the reported device-mode override contradicts the compile record; the compile record stands',
      );
    }
    await trx('bench_provisionings').where({ id: row.id }).update({
      outcome: status,
      outcome_detail: detail || null,
      outcome_at: trx.fn.now(),
      local_check: stored === null ? null : JSON.stringify(stored),
      reported_device_mode_override: reportedOverride,
    });
    // The SIM card: stored on the device as ONE reading (a null one clears
    // the previous card: the box was read again and holds none), then the
    // line of this tenant carrying it linked — by the ICCID alone.
    let simLink: SimLinkOutcome | null = null;
    if (sim !== undefined) {
      const tenantId = Number(row.tenant_id);
      const dev = (await trx('devices').where({ id: input.deviceId, tenant_id: tenantId }).first('site_id')) as
        | { site_id: number | null }
        | undefined;
      if (dev) {
        await trx('devices').where({ id: input.deviceId, tenant_id: tenantId }).update({
          sim_iccid: sim?.iccid ?? null,
          sim_imsi: sim?.imsi ?? null,
          sim_read_at: trx.fn.now(),
          updated_at: trx.fn.now(),
        });
        if (sim !== null) {
          simLink = await linkLineByDeviceIccid(trx, {
            tenantId, deviceId: input.deviceId, siteId: dev.site_id === null ? null : Number(dev.site_id), iccid: sim.iccid,
          });
          if (simLink.outcome === 'linked_elsewhere') {
            logger.warn(
              { stationId: input.station.id, deviceId: input.deviceId, lineId: simLink.lineId, otherDeviceId: simLink.otherDeviceId },
              'Bench result: the SIM line carrying this ICCID is linked to another router; the link is left as it is',
            );
          }
        }
      }
    }
    await appendAudit({
      tenantId: Number(row.tenant_id),
      actorType: 'automation',
      actorId: `bench-station:${input.station.id}`,
      actorName: input.station.name.slice(0, 128),
      action: status === 'applied' ? 'bench.applied' : 'bench.failed',
      entityType: 'device',
      entityId: input.deviceId,
      after: {
        tag: row.tag,
        outcome: status,
        detail,
        localCheck: stored,
        deviceModeOverride: reportedOverride,
        deviceModeOverrideMatches: overrideMatches,
        // Absent: nothing read. null: read, no SIM. The link's outcome says
        // `no_line` alike for none, a pooled line and another tenant's.
        ...(sim !== undefined ? { sim, simLink } : {}),
      },
    }, trx);
  });
}
