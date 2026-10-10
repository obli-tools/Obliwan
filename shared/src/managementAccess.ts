// ============================================================================
// @obliwan/shared — the management API: API-SSL on 8729, certificate made ON the router
// ============================================================================
//
// THE DECISION (operator, binding). ObliWAN dials a router's RouterOS API over
// TLS only: `api-ssl` on 8729, restricted to the management range, serving a
// certificate GENERATED ON THE ROUTER — a local CA, then a server certificate
// that CA signs. ObliWAN pins the fingerprint it sees on first contact
// (trust-on-first-use, transport/routeros/connection.ts). The plain `api`
// service (8728) is never written here: it stays as the template set it (the
// customer templates disable it). Why TLS at all: the L2TP sessions that carry
// the management traffic are not encrypted (`use-encryption=no`) and cross the
// internet, so a cleartext API session would carry the account's password in
// the clear on every poll.
//
// THIS FILE IS THE ONE SOURCE of the RouterOS lines that do it, made for two
// writers that must not drift apart: the bench compile's access block
// (server/src/services/bench/compile.service.ts), and the change job that
// brings routers already in service to the same state over SSH. It also says
// what the result must look like (`apiSslExpectedState`), so a conformity
// check reads the same expectation the lines write. Pure: no socket, no file.
//
// WHAT THE LINES DO, in order:
//   1. `obliwan-ca`: found by name. Absent → added (key-usage=key-cert-sign,
//      crl-sign) and self-signed, then WAITED FOR (bounded `:delay` loop) until
//      it has its private key and a fingerprint. Present with both → REUSED
//      as it is. Present without them → REFUSED, logged by name, never
//      deleted.
//   2. `obliwan-api`: the same, its common-name the router's system identity,
//      key-usage=digital-signature,key-encipherment,tls-server, signed with
//      ca=obliwan-ca. Reuse is what keeps the fingerprint ObliWAN pinned: a
//      new key on every run would read, to the pin, as an interception. A
//      reused certificate's common-name and issuer are not checked: the pin,
//      not the name, is what authenticates the router to ObliWAN.
//   3. `/ip service set $oasSvc disabled=no port=8729
//      address="<management prefixes>" certificate="obliwan-api"` — the
//      SERVER certificate, never the CA — where `$oasSvc` is the CONFIGURED
//      api-ssl row, chosen on the same line by `routerOsServiceSelect`
//      (shared/src/routerOsService.ts): RouterOS 7.24.5 lists every open
//      api-ssl connection as a dynamic `/ip service` entry named api-ssl, and
//      a `set [find where name="api-ssl"]` made while ObliWAN (or anybody) is
//      connected over api-ssl would hit that entry too and fail [prod,
//      2026-10-05: the same trap, seen on ssh]. No configured row: the `set`
//      fails, and the caller's `on-error` sees the block stop.
// A certificate step that is refused or fails logs `<logPrefix>
// reason=api-ssl-certificate-<why> certificate=<name>` and then raises
// `:error`, so the caller's own
// `:do { } on-error={ }` sees the block stop; nothing after the failed step
// runs, and api-ssl is never pointed at a certificate that is not ready. A
// template this run added and failed to sign is removed (it is this run's
// own); nothing found on the box is ever removed.
//
// ┌─ ROUTEROS BEHAVIOUR RELIED ON, WITH ITS EVIDENCE ────────────────────────┐
// │ [docs] = MikroTik RouterOS manual (help.mikrotik.com).                   │
// │ [prod] = observed on a production router.                                │
// │ - `/certificate add` makes a TEMPLATE; `sign` makes the certificate and  │
// │   the template goes: "Certificate template is deleted right after a      │
// │   certificate is signed" [docs, Certificates]. So the record's id        │
// │   CHANGES across `sign`: the lines find the certificate by NAME again on │
// │   every look, never by a remembered id.                                  │
// │ - That the signed certificate keeps the template's name when `sign` is   │
// │   given no `name=`: REASONED (the [docs] example signs `CA-Template`     │
// │   with no name; the fix sequence `explainTlsRefusal` prints, in          │
// │   transport/routeros/connection.ts, relies on it too). `sign` also takes │
// │   `name=` ([docs]: `sign Server … name=ServerCA`); the lines do not pass │
// │   it — whether naming a certificate after its own template collides is   │
// │   not observed. If the name is not kept,                                 │
// │   the lines never find their certificate again: every fresh box waits    │
// │   the whole bound and ends `not-signed` naming `obliwan-ca` — loud,      │
// │   never api-ssl on a wrong certificate (bench harness, run on a model    │
// │   that breaks this assumption on purpose).                               │
// │ - Signing a certificate WITHOUT key-cert-sign with no `ca=` fails with   │
// │   "CA not found" [prod]: hence a CA first, then the server certificate   │
// │   signed by it. The key-usage values used are in the [docs] list.        │
// │ - Signing takes time: "The time of the key signing process depends on    │
// │   the key size … it might take a substantial time … on less powerful     │
// │   CPU-based devices" [docs]. Whether `sign` returns to a script before   │
// │   the key exists is NOT documented: REASONED both ways, hence the        │
// │   bounded wait (`CERTIFICATE_SIGN_WAIT_SECONDS` per certificate).        │
// │ - Flag K is "private-key" and `fingerprint` is a read-only property of a │
// │   certificate [docs]. That `get … private-key` answers a value `:tostr`  │
// │   spells "true", and that a template has no fingerprint (the `get` fails │
// │   or answers empty): REASONED. Either way the test is conservative — a   │
// │   reading it cannot make is "not ready", which ends in a refusal, never  │
// │   in api-ssl pointed at an unsigned certificate. The manual lists        │
// │   `private-key` only as that flag, not among the properties: a `get` of  │
// │   it may fail outright. Should it fail, read otherwise ("yes"), or the   │
// │   fingerprint never appear, every fresh box ends `not-signed` and a box  │
// │   already holding the pair `conflict`: loud, and the bench harness runs  │
// │   those cases.                                                           │
// │ - `days-valid` defaults to 365 [docs]; 3650 is written. Validity counts  │
// │   from the router's CLOCK WHEN IT SIGNS, and nothing here checks that    │
// │   clock. The bench runs these lines early in boot (run-after-reset); a   │
// │   box with no battery-backed clock and no NTP answer yet may sign with   │
// │   a wrong date — what such a box reads then is not observed. A clock at  │
// │   1970 makes a certificate that expires in 1980: "3650 days" is a        │
// │   service life only for a box whose clock was right when it signed. The  │
// │   lines do not read the clock at all: the fleet job that shares them     │
// │   admits only `/certificate` and the api-ssl service (its allow-list in  │
// │   server/src/services/change/managementAccess.service.ts), and a read    │
// │   of `/system clock` is neither. The window a certificate got is on the  │
// │   certificate itself (`invalid-before`, `invalid-after`, read-only       │
// │   [docs]): a lab check. ObliWAN's client                                 │
// │   checks the pinned fingerprint, not dates (connection.ts,               │
// │   `rejectUnauthorized: false`); whether RouterOS keeps serving an        │
// │   EXPIRED certificate on api-ssl is UNOBSERVED — a lab check. A reused   │
// │   certificate's dates are never looked at. That RouterOS accepts 3650:   │
// │   REASONED (common usage, no maximum documented).                        │
// │ - api-ssl's default port is 8729 and `certificate` defaults to `none`    │
// │   [docs, Services]; "In the case no certificate is used in /ip service   │
// │   settings then an anonymous Diffie-Hellman cipher has to be used"       │
// │   [docs, API] — suites ObliWAN refuses (no certificate, nothing to pin). │
// │ - api-ssl serving the CA certificate instead of the server one made the  │
// │   handshake fail with TLS alert 40 [prod]: the service line names        │
// │   `obliwan-api`, and `apiSslStateDifferences` flags any other name.      │
// │ - `address=` restricts who may use the service [docs, Services: "access  │
// │   to the service is denied for sources not matching the specified        │
// │   addresses"].                                                           │
// │ - Certificate names are unique on a router, so `find where name=` gives  │
// │   at most one: REASONED. `/ip service set … certificate=` of a name that │
// │   does not exist fails: REASONED.                                        │
// │ - `[:toarray "obliwan-ca,obliwan-api"]` is an array of the two names,    │
// │   walked in that order by `:foreach`: REASONED (`:toarray` is the        │
// │   manual's conversion to an array; the comma split is common usage).     │
// │ - Written for RouterOS 7. RouterOS 6 has the same `/certificate` menu    │
// │   and api-ssl: REASONED, not checked on a box.                           │
// │ No line of this file has run on a router. The bench harness runs it on a │
// │ MODEL of the script engine (server/src/services/bench/testing/           │
// │ fakeRouterOsScript.ts) that encodes the behaviours above BY ASSUMPTION:  │
// │ it proves the lines' own logic, not RouterOS — so one run on a lab       │
// │ RouterOS 7 box is a precondition of the first use on a fleet, not an     │
// │ option.                                                                  │
// └──────────────────────────────────────────────────────────────────────────┘
//
// HOW THE LINES ARE MEANT TO RUN. As part of a SCRIPT (a run-after-reset file,
// a `/system script` source, an imported section): they declare `:local`
// variables and loop, which an interactive console line by line does not
// carry. They belong INSIDE the caller's `:do { … } on-error={ … }` — that
// a `:error` raised inside it is caught by its `on-error` is REASONED, the
// same assumption the bench runner (bench/splitFile.ts) already makes — and
// hold no comment line (`API_SSL_ACCESS_COMMENT` is the caller's to place
// outside its block). The locals they declare are named in
// `API_SSL_SCRIPT_LOCALS` so a caller can avoid them.

import { routerOsServiceSelect } from './routerOsService';

/** The RouterOS service ObliWAN's API channel uses. */
export const API_SSL_SERVICE = 'api-ssl' as const;
/** api-ssl's default port [docs, Services]. Written explicitly anyway. */
export const API_SSL_PORT = 8729;
/** The local CA made on the router. Signs `OBLIWAN_API_CERTIFICATE` only. */
export const OBLIWAN_CA_CERTIFICATE = 'obliwan-ca';
/** The server certificate api-ssl serves. Never the CA (alert 40, [prod]). */
export const OBLIWAN_API_CERTIFICATE = 'obliwan-api';
/** A CA must be able to sign certificates ("CA not found" otherwise, [prod]). */
export const OBLIWAN_CA_KEY_USAGE = 'key-cert-sign,crl-sign';
export const OBLIWAN_API_KEY_USAGE = 'digital-signature,key-encipherment,tls-server';
/** Both certificates; RouterOS's own default is 365 [docs]. */
export const CERTIFICATE_DAYS_VALID = 3650;
/** One-second `:delay`s the lines allow, per certificate THIS run signed,
 *  for its private key and fingerprint to appear (so a little more than this
 *  many seconds in all). A certificate found already on the box is looked at
 *  once: waiting would not make a foreign record ours. */
export const CERTIFICATE_SIGN_WAIT_SECONDS = 120;

/** Every `reason=` the lines log, after `API_SSL_REASON_PREFIX`:
 *  - `sign-failed`: `add` or `sign` raised an error (the template this run
 *    added is removed);
 *  - `not-signed`: this run signed it, and no private key and fingerprint
 *    appeared within the wait;
 *  - `conflict`: a certificate of that name was ALREADY on the box without a
 *    private key and a fingerprint — refused, left exactly as it was. */
export const API_SSL_CERTIFICATE_REASONS = ['sign-failed', 'not-signed', 'conflict'] as const;
export type ApiSslCertificateReason = (typeof API_SSL_CERTIFICATE_REASONS)[number];
export const API_SSL_REASON_PREFIX = 'api-ssl-certificate-';

/** A comment line a caller may write ABOVE its block holding the lines. */
export const API_SSL_ACCESS_COMMENT =
  `# ObliWAN management API: ${API_SSL_SERVICE} on ${API_SSL_PORT} from the management range, serving ${OBLIWAN_API_CERTIFICATE} `
  + `(signed by ${OBLIWAN_CA_CERTIFICATE}, both made on this router); api is left as it is.`;

/** The script locals the lines declare (a caller must not declare these). */
export const API_SSL_SCRIPT_LOCALS = [
  'oasLog', 'oasName', 'oasStop', 'oasMiss', 'oasHow', 'oasOk', 'oasWait', 'oasId', 'oasSvc',
] as const;

export interface ApiSslAccessInput {
  /** The router's system identity: the server certificate's common-name.
   *  `[A-Za-z0-9._-]{1,64}` — written between double quotes unescaped, and
   *  64 is the X.509 upper bound for a common name. */
  identity: string;
  /** The management prefixes api-ssl is restricted to, as RouterOS writes
   *  them (`10.0.0.0/24`). Never empty. */
  mgmtPrefixes: readonly string[];
  /** What every `:log` line of the block starts with (the bench writes
   *  `obliwan-provision detail tag=<tag>`). Letters, digits, space and
   *  `._:=/-` only: it sits between double quotes unescaped. */
  logPrefix: string;
}

/** An input the lines could not carry without escaping. The message names
 *  the field, never its value. */
export class ManagementAccessInputError extends Error {
  readonly field: 'identity' | 'mgmtPrefixes' | 'logPrefix';
  constructor(field: 'identity' | 'mgmtPrefixes' | 'logPrefix', message: string) {
    super(message);
    this.name = 'ManagementAccessInputError';
    this.field = field;
  }
}

const IDENTITY_RE = /^[A-Za-z0-9._-]{1,64}$/;
const PREFIX_RE = /^[0-9A-Fa-f.:]+\/\d{1,3}$/;
const LOG_PREFIX_RE = /^[A-Za-z0-9 ._:=/-]{1,160}$/;

/** Throws `ManagementAccessInputError` on an input the lines cannot carry. */
export function assertApiSslAccessInput(input: ApiSslAccessInput): void {
  if (!IDENTITY_RE.test(input.identity)) {
    throw new ManagementAccessInputError('identity', 'The system identity holds characters a certificate common-name cannot receive unescaped (letters, digits, ".", "_", "-" only, 64 at most).');
  }
  if (input.mgmtPrefixes.length === 0 || input.mgmtPrefixes.some((p) => !PREFIX_RE.test(p))) {
    throw new ManagementAccessInputError('mgmtPrefixes', 'The management range is empty or holds an entry that is not an address prefix.');
  }
  if (!LOG_PREFIX_RE.test(input.logPrefix)) {
    throw new ManagementAccessInputError('logPrefix', 'The log prefix holds characters a RouterOS string cannot receive unescaped.');
  }
}

const [LOG, NAME, STOP, MISS, HOW, OK, WAIT, ID, SVC] = API_SSL_SCRIPT_LOCALS;

/**
 * The RouterOS 7 lines that leave api-ssl on 8729, restricted to the
 * management range, serving `obliwan-api` (file header). Idempotent: a second
 * run on the same router reuses both certificates and rewrites the service
 * with the same values. Never writes the plain `api` service. Throws
 * `ManagementAccessInputError` on an input it cannot carry.
 *
 * Written compact on purpose — ONE loop over the two certificates, short
 * locals, the log prefix held once — because the bench ships it inside its
 * `access` section file, and older RouterOS builds read a file only up to
 * 4095 bytes (bench/splitFile.ts). `apiSslAccessLines` alone is about 2 kB
 * with two management prefixes (the api-ssl row selection of item 3 included),
 * each further prefix adding its own text once (`address=`); the bench
 * compile refuses a range whose access section
 * would not fit (`OLDER_BUILD_READ_LIMIT_BYTES`, bench/compile.service.ts).
 */
export function apiSslAccessLines(input: ApiSslAccessInput): string[] {
  assertApiSslAccessInput(input);
  const W = CERTIFICATE_SIGN_WAIT_SECONDS;
  const days = `days-valid=${CERTIFICATE_DAYS_VALID}`;
  const find = `[/certificate find where name=$${NAME}]`;
  const ready = `(([:tostr [/certificate get $${ID} private-key]] = "true") && ([:len [/certificate get $${ID} fingerprint]] > 0))`;
  const addCa = `/certificate add name=$${NAME} common-name=$${NAME} ${days} key-usage=${OBLIWAN_CA_KEY_USAGE}; /certificate sign $${NAME}`;
  const addApi = `/certificate add name=$${NAME} common-name="${input.identity}" ${days} key-usage=${OBLIWAN_API_KEY_USAGE}; `
    + `/certificate sign $${NAME} ca="${OBLIWAN_CA_CERTIFICATE}"`;
  return [
    `:local ${LOG} "${input.logPrefix}"; `
      + [STOP, MISS, HOW, ID].map((v) => `:local ${v} ""`).join('; ') + `; :local ${OK} false; :local ${WAIT} 0`,
    // The CA first: the server certificate is signed by it.
    `:foreach ${NAME} in=[:toarray "${OBLIWAN_CA_CERTIFICATE},${OBLIWAN_API_CERTIFICATE}"] do={`,
    `:set ${OK} false; :set ${WAIT} 0; :set ${ID} ${find}`,
    // Absent: added and signed by this run, then waited for. A template this
    // run added and could not sign is this run's own, and removed.
    `:if ([:len $${ID}] = 0) do={ :set ${HOW} "created"; :set ${MISS} "not-signed"; `
      + `:do { :if ($${NAME} = "${OBLIWAN_CA_CERTIFICATE}") do={ ${addCa} } else={ ${addApi} } } `
      + `on-error={ :set ${STOP} "sign-failed"; :do { /certificate remove ${find} } on-error={} } `
      // Present: looked at once (the wait already spent), never removed.
      + `} else={ :set ${HOW} "reused"; :set ${MISS} "conflict"; :set ${WAIT} ${W} }`,
    // Found again by NAME on every look: signing replaces the template's id.
    `:while (([:len $${STOP}] = 0) && ($${OK} = false)) do={ :do { :set ${ID} ${find}; :set ${OK} ${ready} } on-error={}; `
      + `:if ($${OK} = false) do={ :if ($${WAIT} >= ${W}) do={ :set ${STOP} $${MISS} } else={ :delay 1s; :set ${WAIT} ($${WAIT} + 1) } } }`,
    `:if ([:len $${STOP}] > 0) do={ :log error ($${LOG} . " reason=${API_SSL_REASON_PREFIX}" . $${STOP} . " certificate=" . $${NAME}); `
      + `:error ("api-ssl certificate " . $${NAME} . ": " . $${STOP}) }`,
    `:log info ($${LOG} . " api-ssl-certificate=" . $${HOW} . " certificate=" . $${NAME})`,
    '}',
    // ONE line: the configured api-ssl row (a connection entry of that name
    // skipped, header item 3), then the write on it.
    `${routerOsServiceSelect(API_SSL_SERVICE, SVC)}; `
      + `/ip service set $${SVC} disabled=no port=${API_SSL_PORT} address="${input.mgmtPrefixes.join(',')}" certificate="${OBLIWAN_API_CERTIFICATE}"`,
    `:log info ($${LOG} . " ${API_SSL_SERVICE}=enabled port=${API_SSL_PORT} certificate=${OBLIWAN_API_CERTIFICATE}")`,
  ];
}

// ============================================================================
// ObliWAN's own account on the router: `obliwan`
// ============================================================================
//
// OPERATOR DECISION 2026-10-04 (binding): ObliWAN logs in to a router — API
// and SSH — with its OWN account, `obliwan`, in a group of the same name,
// never with a customer's or a technician's account. Two writers create it,
// and they must not drift apart, so both read the constants below:
//   - the bench's access block (server/src/services/bench/compile.service.ts),
//     on a box it has just reset (it removes and re-adds the account);
//   - the `management_access` change job (server/src/services/change/
//     managementAccess.service.ts), on a router ALREADY IN SERVICE that lacks
//     it — the one written exception to "no user creation on in-service
//     routers". That job adds the group and the user when they are absent,
//     never removes, renames or re-passwords one it finds, and switches
//     ObliWAN's SSH and API channels to the account only once a fresh login
//     with it has been proven over api-ssl AND over SSH. The one change it
//     makes to something it finds is the alignment of the group's policy
//     described under `OBLIWAN_GROUP_POLICY`.

/** The account ObliWAN dials the box with, and its user group. */
export const OBLIWAN_ACCOUNT = 'obliwan';
/** What the account may do — `sensitive` INCLUDED.
 *
 *  OPERATOR DECISION 2026-10-05 (explicit, binding; it replaces the earlier
 *  rule that kept `sensitive` out of this group as the no-secrets barrier). Observed
 *  that day on a production RouterOS 7 router: with the group policy
 *  `local,ssh,ftp,reboot,read,write,policy,test,api` the account could NOT
 *  read the preflight `.backup` over SFTP ("Resource temporarily
 *  unavailable"), while `admin` downloaded the same file — so every guarded
 *  job stopped at its preflight backup. `sensitive` is therefore appended.
 *  What was OBSERVED is that one difference (this list fails the pull,
 *  `admin` succeeds); that `sensitive` ALONE is what unlocks the `.backup`
 *  read is REASONED, not observed — `admin`'s `full` group also grants
 *  winbox, password, web, sniff, romon and rest-api, and no box has yet been
 *  seen pulling the file with exactly this list plus `sensitive`.
 *  There is no group barrier for that rule any more: the account CAN read secrets
 *  on the router. The no-secrets rule itself stays, and rests on ObliWAN's code alone —
 *  ObliWAN never runs `/export show-sensitive=yes` outside the learning-mode
 *  exception (operator decision 2026-10-04), and no snapshot carries a
 *  secret.
 *
 *  `policy` is granted too, and for its own reason: ObliWAN's dead-man
 *  (change/rollback.service.ts, change/safeApply.service.ts) creates its
 *  `/system script` and `/system scheduler` entries with
 *  `policy=read,write,policy,test`, and RouterOS does not let an account give
 *  a script a policy its own group lacks — so without `policy` every push to
 *  a bench-prepared box would fail to arm its safety net (risk #1). The
 *  bench harness ties this list to the policies the arm path requests, so the
 *  two cannot drift apart silently.
 *
 *  A group ObliWAN made BEFORE this decision (the bench, or the
 *  management_access job) carries the same list without `sensitive`. The
 *  bench recreates the group on every preparation; on a router in service the
 *  management_access job aligns it — one `/user group set`, only on a group
 *  named `obliwan` that carries `OBLIWAN_ACCOUNT_COMMENT` and grants exactly
 *  this list minus `sensitive`, sent by an account that itself holds
 *  `sensitive` and `policy`: the job's SSH account, or — on a router already
 *  dialled as `obliwan` — the historical `admin` account from the vault, on a
 *  separate session (server/src/services/change/managementAccess.service.ts).
 *  Three things that design rests on are REASONED from the RouterOS manual,
 *  not observed on a box:
 *    - that RouterOS refuses an account granting a policy its own group
 *      lacks — so `obliwan` cannot grant ITSELF `sensitive`, and the job
 *      never asks it to;
 *    - that `[find where name=obliwan comment="obliwan:access"]` ANDs its two
 *      conditions (a group whose comment changed matches nothing, and the
 *      read-back then fails the job);
 *    - that `sensitive` alone unlocks the `.backup` read (above). */
export const OBLIWAN_GROUP_POLICY = 'local,ssh,ftp,reboot,read,write,policy,test,api,sensitive';
/** The comment both writers put on the group and on the user. */
export const OBLIWAN_ACCOUNT_COMMENT = 'obliwan:access';

// ============================================================================
// The expected result — what a conformity check compares against
// ============================================================================

/** The api-ssl record the lines leave. Certificates themselves are not part
 *  of it: the NCM does not model `/certificate`, and what proves the right
 *  certificate is served is the service's `certificate` name plus the
 *  fingerprint ObliWAN pins on first contact. */
export interface ApiSslExpectedState {
  service: typeof API_SSL_SERVICE;
  enabled: true;
  port: typeof API_SSL_PORT;
  /** The management prefixes ALONE, as written into `address=`. */
  address: readonly string[];
  certificate: typeof OBLIWAN_API_CERTIFICATE;
}

export function apiSslExpectedState(mgmtPrefixes: readonly string[]): ApiSslExpectedState {
  return {
    service: API_SSL_SERVICE,
    enabled: true,
    port: API_SSL_PORT,
    address: [...mgmtPrefixes],
    certificate: OBLIWAN_API_CERTIFICATE,
  };
}

export interface ApiSslStateDifference {
  field: 'present' | 'enabled' | 'port' | 'address' | 'certificate';
  expected: string;
  actual: string;
}

/**
 * How a `/ip/service/print` row of api-ssl, as the RouterOS API answers it
 * (`disabled` "true"/"false", `port`, `address` comma-joined, `certificate`),
 * differs from `apiSslExpectedState`. Empty = conformant. `null` (no api-ssl
 * row) is one `present` difference. The address list is compared as a SET of
 * the strings RouterOS prints: a prefix the router prints in another spelling
 * than the management range variable holds is a difference — a human looks,
 * never a false "conformant". That the API prints these four fields this way
 * is REASONED (autoConfirm.service reads the same menu the same way).
 */
export function apiSslStateDifferences(
  row: Readonly<Record<string, string | undefined>> | null,
  mgmtPrefixes: readonly string[],
): ApiSslStateDifference[] {
  const want = apiSslExpectedState(mgmtPrefixes);
  if (row === null) return [{ field: 'present', expected: want.service, actual: '' }];
  const out: ApiSslStateDifference[] = [];
  const disabled = (row.disabled ?? '').trim().toLowerCase();
  const enabled = disabled === 'false' || disabled === 'no' ? 'true' : disabled === 'true' || disabled === 'yes' ? 'false' : '?';
  if (enabled !== 'true') out.push({ field: 'enabled', expected: 'true', actual: enabled });
  const port = (row.port ?? '').trim();
  if (port !== String(want.port)) out.push({ field: 'port', expected: String(want.port), actual: port });
  const have = [...new Set((row.address ?? '').split(',').map((a) => a.trim()).filter((a) => a !== ''))].sort();
  const wanted = [...new Set(want.address)].sort();
  if (have.join(',') !== wanted.join(',')) out.push({ field: 'address', expected: wanted.join(','), actual: have.join(',') });
  const certificate = (row.certificate ?? '').trim();
  if (certificate !== want.certificate) out.push({ field: 'certificate', expected: want.certificate, actual: certificate });
  return out;
}
