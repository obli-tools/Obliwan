// ============================================================================
// @obliwan/shared — `/ip service` rows that are NOT services: the connection
// entries recent RouterOS lists beside them
// ============================================================================
//
// OBSERVED on a production router, RouterOS 7.24.5, 2026-10-05
// (`/ip service print detail`; flags D - DYNAMIC, X - DISABLED, I - INVALID,
// c - CONNECTION):
//    1      name="ssh" port=22 proto=tcp available-from=100.64.0.0/10,… vrf=main max-sessions=20
//   14  D c name="winbox" port=8291 proto=tcp local=192.0.2.1 remote=198.51.100.254:23871
//   16      name="api-ssl" port=8729 proto=tcp available-from=100.64.0.0/10 certificate=obliwan-api …
//   17  D c name="api-ssl" port=8729 proto=tcp local=192.0.2.1 remote=198.51.100.254:40082
// Every OPEN CONNECTION to a service is listed as a DYNAMIC entry carrying the
// service's own name, with `local`/`remote` and no `available-from`. `/export`
// does not list them. What it cost: the `legacy_compliance` line
// `/ip service set [find where name="ssh"] address=…`, sent over ObliWAN's own
// SSH session, matched that session's entry too; RouterOS changed the service
// (the export shows it) and answered "failure: this is configured elsewhere"
// for the entry, and the job recorded the line as refused. The same trap waits
// for every find/get/set/print of `/ip service` BY NAME while anybody —
// ObliWAN included — is connected through that service: api-ssl over the API,
// ssh over SSH, winbox from a technician. A reader that takes "the row named X"
// may take the connection entry: no `available-from` reads as "open to every
// address", no `certificate` as none.
//
// THE RULE, for every reader and writer in the tree: a row that is dynamic, or
// that carries `local`/`remote`, is not a service — never picked, never
// written, never reported. Two configured rows of one name are not a reading:
// nothing is picked.
//
// ON THE CONSOLE (`routerOsServiceSelect`, `routerOsServiceSet`): the
// configured row is chosen row by row, with `get <row> dynamic` inside
// `:do { } on-error={ }` — never with `find where … !dynamic`. RouterOS 7.16 is
// still in the fleet; it lists no connection entry, and its `/ip service` may
// have no `dynamic` property at all. Whether `find where … and !dynamic` then
// errors, matches every row or matches none is UNKNOWN — and a property named
// in a `where` clause may be refused when the line is PARSED, before any
// `on-error` can run, which would fail the whole line on that build. `get`
// takes the property name as an argument VALUE, checked when it runs: a
// failure there is caught, and the row then counts as a service — every row a
// 7.16 box lists is one. REASONED, not observed:
//   - that `get <row> dynamic` answers "true" on a connection entry and
//     "false" on a service on 7.24.5 (the D flag is the `dynamic` property, as
//     on every other menu that has one);
//   - that a `get` of a property the build does not know fails AT RUN TIME on
//     7.16 — the same assumption the repo's reads already make for
//     `available-from`, `random-source-port` and `/system device-mode`;
//   - that at most one configured row carries a given name (the services are
//     fixed singletons); if two did, the LAST one found would be written;
//   - that `set` of an EMPTY id (no configured row found) fails, so the
//     statement fails loud rather than doing nothing.
//
// THROUGH THE API (`routerOsServiceRowIsConnection`,
// `routerOsConfiguredServiceRows`, `routerOsServiceRowNamed`): a row answered
// `dynamic=true` (or `connection=true`), or carrying `local`/`remote`, is
// dropped; a reader that sends a `.proplist` names
// `ROUTEROS_SERVICE_CONNECTION_PROPS` in it (a property the build does not
// have is simply absent from the reply — the assumption the readers already
// make for `available-from`). That the API lists the connection entries as the
// console prints them is REASONED; the filter costs nothing if it does not.
//
// `/export` lists no dynamic entry: the export parser, the NCM normaliser and
// everything that reads a snapshot (drift, the Management-Path Guard) are
// unaffected by this file and do not use it.

/** What `routerOsServiceSet` names the local holding the configured row's id. */
export const ROUTEROS_SERVICE_ID_VAR = 'obliwanSvc';

/** The properties an API `.proplist` must name for
 *  `routerOsServiceRowIsConnection` to see a connection entry. */
export const ROUTEROS_SERVICE_CONNECTION_PROPS = ['dynamic', 'local', 'remote'] as const;

/** A service name or a local the console text cannot carry unescaped. */
export class RouterOsServiceInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RouterOsServiceInputError';
  }
}

const SERVICE_NAME_RE = /^[a-z][a-z0-9-]{0,31}$/;
const LOCAL_NAME_RE = /^[A-Za-z][A-Za-z0-9]{0,31}$/;

function assertServiceName(name: string): void {
  if (!SERVICE_NAME_RE.test(name)) throw new RouterOsServiceInputError('A RouterOS service name is lowercase letters, digits and "-".');
}

/**
 * ONE console statement line that declares the local `idVar` and leaves in it
 * the id of the CONFIGURED `/ip service` row named `name` — a row whose
 * `dynamic` reads "true" is skipped, a row whose `get … dynamic` fails is
 * taken (file header) — or the empty string when there is none. Its loop
 * variable (`r`) lives inside the loop only. Meant for a script, or a console
 * line, that then uses `$<idVar>`. Written compact: the bench's access
 * section carries it twice and must fit 4095 bytes
 * (server/src/services/bench/compile.service.ts).
 */
export function routerOsServiceSelect(name: string, idVar: string): string {
  assertServiceName(name);
  if (!LOCAL_NAME_RE.test(idVar) || idVar === 'r') {
    throw new RouterOsServiceInputError('The local holding the service id is letters and digits, and not the loop\'s own r.');
  }
  return `:local ${idVar} ""; :foreach r in=[/ip service find where name="${name}"] do={ `
    + `:do { :if ([:tostr [/ip service get $r dynamic]] != "true") do={ :set ${idVar} $r } } on-error={ :set ${idVar} $r } }`;
}

/**
 * ONE self-contained console statement: `/ip service set <the configured row
 * named name> <props>`, inside its own `:do { }` (its locals stay in it; an
 * error leaves it, there is no `on-error`). `props` is the caller's, already
 * safe to write (no line break, braces balanced). No configured row of that
 * name: the `set` has no id to work on and fails (file header).
 */
export function routerOsServiceSet(name: string, props: string, idVar: string = ROUTEROS_SERVICE_ID_VAR): string {
  if (/[\r\n]/.test(props) || props.trim() === '') throw new RouterOsServiceInputError('The service properties are one non-empty line.');
  return `:do { ${routerOsServiceSelect(name, idVar)}; /ip service set $${idVar} ${props.trim()} }`;
}

const truthy = (v: unknown): boolean => ['true', 'yes'].includes(String(v ?? '').trim().toLowerCase());
const present = (v: unknown): boolean => v !== undefined && v !== null && String(v).trim() !== '';

/** A `/ip/service/print` row, as the RouterOS API answers it, that is a
 *  dynamic or connection entry rather than a configured service. */
export function routerOsServiceRowIsConnection(row: Readonly<Record<string, unknown>>): boolean {
  return truthy(row.dynamic) || truthy(row.connection) || present(row.local) || present(row.remote);
}

/** The configured service rows of a `/ip/service/print` answer, in order. */
export function routerOsConfiguredServiceRows<T extends Readonly<Record<string, unknown>>>(rows: readonly T[]): T[] {
  return rows.filter((r) => !routerOsServiceRowIsConnection(r));
}

export type RouterOsServiceRowPick<T> =
  | { kind: 'row'; row: T }
  | { kind: 'absent' }
  | { kind: 'ambiguous'; count: number };

/** The ONE configured row named `name` (case and padding ignored): `absent`
 *  when there is none, `ambiguous` when there are several — never one of them. */
export function routerOsServiceRowNamed<T extends Readonly<Record<string, unknown>>>(
  rows: readonly T[],
  name: string,
): RouterOsServiceRowPick<T> {
  const want = name.trim().toLowerCase();
  const named = routerOsConfiguredServiceRows(rows).filter((r) => String(r.name ?? '').trim().toLowerCase() === want);
  if (named.length === 0) return { kind: 'absent' };
  if (named.length > 1) return { kind: 'ambiguous', count: named.length };
  return { kind: 'row', row: named[0] };
}
