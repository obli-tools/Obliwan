// ============================================================================
// @obliwan/shared — RBAC capability vocabulary
// ============================================================================
//
// THIS FILE IS THE SINGLE SOURCE OF TRUTH for what a user may do in ObliWAN
// Every other place that names a capability —
// the `permission_sets` table, `team_permissions.capabilities`, the RBAC
// middleware, the Obligate SSO payload, the admin UI — MUST import from here
// and never re-declare its own list.
//
// Naming convention: `<domain>.<verb>`. Values are persisted in the database
// and exchanged with Obligate: they are a wire format. NEVER rename a value;
// add a new one and migrate.
//
// Not all of these were wired at first — the vocabulary is laid down once, up
// front, because that is the only moment it is free.

export const CAPABILITIES = {
  // ── Fleet / inventory ──────────────────────────────────────────────────
  /** See sites, devices, transports (metadata only — never configuration). */
  DEVICE_READ: 'device.read',
  /** Create / edit / delete sites, devices and their transport records. */
  DEVICE_WRITE: 'device.write',
  /**
   * Create, edit and bulk-import SITES — the customer record: code, name,
   * address, contact. Never a device, never a transport, never a site deletion
   * (those stay DEVICE_WRITE).
   *
   * Nor CHANGING the push schedule of an existing site — its maintenance window
   * and its timezone (`SITE_SCHEDULE_FIELDS` below). Those look like customer
   * data and are not: the window gates every push to the site's routers, a
   * NULL window is read as OPEN (change/jobQueue.service.ts), and the window is
   * evaluated in the site's timezone. Blanking it, or moving the timezone,
   * releases queued pushes into trading hours. That stays DEVICE_WRITE
   * (`SITE_SCHEDULE_CAPABILITY`). A route that lets SITE_WRITE alone change an
   * existing site must therefore run `refuseSiteScheduleChange()`
   * (server/src/middleware/siteSchedule.ts), and an import must refuse a
   * timezone change on an existing site the same way. Setting them while
   * CREATING a site is allowed: a new site has no router for the window to
   * gate, and its default — no window at all — is already "open".
   *
   * Split out of DEVICE_WRITE for the account manager (`account_manager` set
   * below): typing in forty stores from a spreadsheet is her job, while
   * approving a quarantined router — the act that lets plans and collections
   * reach a box — or opening a channel to one is not. DEVICE_WRITE implies
   * it (`CAPABILITY_IMPLIES`), so every holder of DEVICE_WRITE keeps exactly the
   * site rights it had.
   */
  SITE_WRITE: 'site.write',
  /** Review the CHR discovery quarantine and bind a PPP session to a device. */
  DEVICE_DISCOVER: 'device.discover',
  /**
   * See THIS tenant's CHR <-> sites reconciliation — which concentrator
   * accounts of its own have no site, which sites will find no account, which
   * ones are suspect — and re-read the concentrator's /ppp/secret (a READ on
   * the shared CHR: nothing is written to it). It also opens the CHR column of
   * the site import's dry run.
   *
   * Three limits, all enforced by the server and none by the screen:
   *   - the tenant is the session's (`req.tenantId`), never a parameter: the
   *     full reconciliation of ANY tenant stays a platform-admin act
   *     (allocation.routes.ts, requireRole('admin'));
   *   - it answers only when the tenant's login template NAMES the tenant
   *     (`LoginMatcher.namesTenant`). A template such as
   *     "{site.code}.customers.example" reads every customer's accounts on a
   *     shared CHR, so its "orphans" may be somebody else's stores: that
   *     reconciliation is refused, with the reason;
   *   - the view is REDACTED (reconcile.service `redactReport`): no other
   *     tenant, no account nobody explains, no address, profile, pool or
   *     concentrator identity, no adoption holder, no password (none is ever
   *     read).
   *
   * Not a capability of the allocation itself: allocating, creating a site in
   * another tenant and the per-CHR re-read by id stay platform-admin.
   */
  RECONCILE_READ: 'reconcile.read',

  // ── Configuration ──────────────────────────────────────────────────────
  //
  // CONFIG_READ is deliberately DISTINCT from DEVICE_READ. A config
  // snapshot may carry residual sensitive material (PSK, PPP secrets, IPsec
  // keys) even with `show-sensitive=no`; seeing the fleet must not imply
  // seeing its configuration.
  /** Read config snapshots, the NCM and semantic diffs. */
  CONFIG_READ: 'config.read',
  /** Author normalization rules and edit the desired NCM. Does NOT push. */
  CONFIG_WRITE: 'config.write',

  // ── Templates & intent ─────────────────────────────────────────────────
  /** Read templates, partials, revisions and resolved variables. */
  TEMPLATE_READ: 'template.read',
  /**
   * Author / publish templates and partials.
   * This capability is the security boundary in front of the
   * Nunjucks renderer, which runs on the host holding the fleet credentials.
   */
  TEMPLATE_WRITE: 'template.write',
  /**
   * Type the per-site values of variables a PUBLISHED template revision has
   * already declared AND opened to site entry — a VLAN id, a subnet, a site
   * code — and nothing else.
   *
   * This is the line between typed data entry and template authoring. The
   * holder writes only at scope `site`, only keys that EVERY published
   * declaration of an active template visible to the tenant marks
   * `x-obliwan-level: 'site'`, and only values that validate against those
   * declarations. A secret declared `x-obliwan-secret` goes to the vault, and
   * is writable here only when its author opened it the same way.
   *
   * The opt-in is per key and it is the author's, because this capability is
   * role-derived — every holder of the builtin `user` set (and of the
   * `account_manager` set) holds it — and a site value outranks every group and the tenant. A key the
   * author published at any other level (a management CIDR, a tenant-wide
   * password) stays TEMPLATE_WRITE's to set for a site. She cannot add a key,
   * cannot write at any other level and cannot touch a template body — so she
   * changes WHAT a template renders for one site, inside the keys and types its
   * author published for that, never HOW it renders.
   */
  SITE_VARIABLES_WRITE: 'site_variables.write',

  // ── Plan & change ──────────────────────────────────────────────────────
  /** Compile a plan (read-only: computes PlanOp[], touches no device). */
  PLAN_CREATE: 'plan.create',
  /** Enqueue a change_job that actually writes to an equipment. */
  CHANGE_APPLY: 'change.apply',
  /** Four-eyes approval of a plan, and override of a Management-Path Guard veto. */
  CHANGE_APPROVE: 'change.approve',
  /** Start / pause / abort a wave rollout. */
  ROLLOUT_MANAGE: 'rollout.manage',

  // ── Drift & query ──────────────────────────────────────────────────────
  /** Read drift runs, findings and their attribution. */
  DRIFT_READ: 'drift.read',
  /** Acknowledge / ignore a drift finding. */
  DRIFT_MANAGE: 'drift.manage',
  /** Run Fleet Query DSL queries and save them. */
  QUERY_RUN: 'query.run',

  // ── SNMP & telemetry ───────────────────────────────────────────────────
  /** Read interfaces, counters, time series and thresholds. */
  SNMP_READ: 'snmp.read',
  /** Manage SNMP targets, communities / v3 users, discovery and thresholds. */
  SNMP_ADMIN: 'snmp.admin',

  // ── ACS TR-069 ─────────────────────────────────────────────────────────
  /** Manage CPEs, the CWMP task queue, parameter maps and firmware files. */
  ACS_ADMIN: 'acs.admin',

  // ── Mobile data lines / SIM fleet ──────────────────────────────────────
  /** See SIM lines, their remaining data, and the re-invoicing report. */
  SIM_READ: 'sim.read',
  /**
   * Assign a line to a tenant, a site or a router, set its low-data threshold
   * and opt it into automatic top-ups. Changes WHAT gets proposed; never buys.
   */
  SIM_MANAGE: 'sim.manage',
  /**
   * Approve a top-up proposal, or record one bought on the partner's portal.
   *
   * This is the only capability in the whole vocabulary that authorises a
   * purchase. It is deliberately NOT implied by SIM_MANAGE: deciding that a
   * line should be watched is an inventory act, deciding that money leaves the
   * company is not — the same split as CHANGE_APPLY against CHANGE_APPROVE.
   */
  SIM_RECHARGE: 'sim.recharge',

  // ── Secrets ────────────────────────────────────────────────────────────
  /** Create / rotate / delete credentials in the vault. Never reveals them. */
  CREDENTIAL_MANAGE: 'credential.manage',
  /**
   * Reveal a stored secret in clear. Deliberately separate from
   * CREDENTIAL_MANAGE, and neither implies the other (`CAPABILITY_IMPLIES`):
   * rotating is an operator act, revealing is not, and revealing must not
   * bring the right to rewrite where a credential is sent.
   */
  SECRET_READ: 'secret.read',

  // ── Administration (inherited from the Obli* base) ─────────────────────
  /**
   * Reorder this tenant's groups and set their CONFIGURATION — the flags that
   * are not the group's identity: `isGeneral` (readable by every member),
   * `groupNotifications` (consolidated alerts) and `sortOrder` — exactly
   * Obliance's `groups.manage` (`POST /groups/reorder`, the group config
   * PATCH). Migration 084 renamed it from `group.write` and rewrote every
   * stored grant.
   *
   * It is NOT what lets anybody edit, move, delete or create a group: those
   * are TEAM grants, group by group, as in Obliance (`routes/groups.routes.ts`).
   * Editing, moving and deleting need a platform admin or an 'rw' team grant on
   * the group, inherited down the closure (`requireGroupWrite`); creating needs
   * a team of the tenant with `can_create` (`requireCanCreate`). A tenant-wide
   * capability that let a holder rename any group would make the per-group
   * grants decorative.
   */
  GROUPS_MANAGE: 'groups.manage',
  /**
   * Manage users, teams and permission sets.
   *
   * NO ROUTE CONSULTS IT TODAY. `/api/users`, `/api/teams` and
   * `/api/permission-sets` are `requireRole('admin')`: an account is global —
   * one password, one `users.role`, memberships in several tenants — so
   * resetting the password of a user who is also admin of another tenant, or
   * rewriting her memberships, reaches past any one tenant. Holding this by
   * name confers nothing until a tenant-scoped user administration exists; it
   * is PLATFORM_ONLY (`PLATFORM_ONLY_CAPABILITIES` below): refused in every
   * permission set and stripped at resolution, whatever the source.
   */
  USERS_MANAGE: 'users.manage',
  /** Create / edit / delete tenants and their memberships. */
  TENANTS_MANAGE: 'tenants.manage',
  /**
   * This tenant's operating POLICIES: release the change kill-switch
   * (changes.routes.ts — engaging it is CHANGE_APPLY), the SLA objectives and
   * the deletion of an issued SLA report (sla.routes.ts), and the weather
   * quorum policy (weather.routes.ts). A tenant admin holds it.
   *
   * It does NOT open the inherited settings tree (`/api/settings`), the SMTP
   * servers (`/api/smtp-servers`) or SSO: those are `requireRole('admin')`.
   * The settings tree carries `snmp_auto_target_credential` — which credential
   * gets attached to every new SNMP target — and choosing a fleet credential
   * is CREDENTIAL_MANAGE ground, which a tenant admin is deliberately not
   * given. Opening the tree per key is a separate decision, not a repair.
   */
  SETTINGS_MANAGE: 'settings.manage',
  /**
   * Route this tenant's alerts: list its channels, bind them to its groups and
   * devices, enable / disable / rename, test and delete them
   * (`routes/notifications.routes.ts`, every read and write scoped to the
   * caller's tenant by `notification.service`).
   *
   * Two acts stay with a PLATFORM admin even for a holder: writing a channel's
   * `config` (creating one, or a PUT that carries `config`) — it is the
   * address the server POSTs to (webhook URL, Gotify / ntfy server), and the
   * plugins fetch it as typed — and sharing a channel into other tenants.
   */
  NOTIFICATIONS_MANAGE: 'notifications.manage',
  /** Read the append-only audit log and the command audit. */
  AUDIT_READ: 'audit.read',
  /** Export a tenant (templates, inventory, variables) to a portable bundle. */
  EXPORT_RUN: 'export.run',
  /**
   * Import a bundle, including conflict resolution.
   *
   * NO ROUTE CONSULTS IT. `/api/import-export` is `requireRole('admin')` as a
   * whole (routes/importExport.routes.ts). Like USERS_MANAGE it is therefore
   * PLATFORM_ONLY (below).
   */
  IMPORT_RUN: 'import.run',
} as const;

export type Capability = (typeof CAPABILITIES)[keyof typeof CAPABILITIES];

export const CAPABILITY_DOMAINS = [
  'fleet',
  'config',
  'template',
  'change',
  'drift',
  'telemetry',
  'acs',
  'mobile',
  'secrets',
  'admin',
] as const;

export type CapabilityDomain = (typeof CAPABILITY_DOMAINS)[number];

export interface CapabilityInfo {
  key: Capability;
  domain: CapabilityDomain;
  label: string;
  description: string;
  /**
   * True when granting this capability lets the holder change the state of a
   * physical equipment, or read material that must not leak. The admin UI
   * flags these; read-only permission-set seeds keep them out.
   */
  sensitive: boolean;
}

/**
 * Full catalogue, ordered for display. `permissionSet.service` serves this
 * list verbatim — it must not maintain a copy of its own.
 */
export const CAPABILITY_CATALOG: readonly CapabilityInfo[] = [
  { key: CAPABILITIES.DEVICE_READ, domain: 'fleet', label: 'Read fleet', description: 'View sites, devices and transports (metadata only)', sensitive: false },
  { key: CAPABILITIES.DEVICE_WRITE, domain: 'fleet', label: 'Manage fleet', description: 'Create, edit and delete sites, devices and transports', sensitive: false },
  { key: CAPABILITIES.SITE_WRITE, domain: 'fleet', label: 'Edit sites', description: 'Create, edit and import sites — never devices, never a deletion, never the maintenance window or timezone of an existing site', sensitive: false },
  { key: CAPABILITIES.DEVICE_DISCOVER, domain: 'fleet', label: 'Bind discoveries', description: 'Review the PPP discovery quarantine and bind devices', sensitive: false },
  // Not sensitive: its own tenant only, redacted, and the one thing it makes
  // the server do on the CHR is a /ppp/secret READ whose `.proplist` keeps the
  // passwords off the wire.
  { key: CAPABILITIES.RECONCILE_READ, domain: 'fleet', label: 'Reconcile CHR accounts', description: "See this workspace's concentrator accounts against its sites and re-read the concentrator — only when its login rule names the workspace", sensitive: false },

  { key: CAPABILITIES.CONFIG_READ, domain: 'config', label: 'Read configuration', description: 'View config snapshots, the NCM and semantic diffs', sensitive: true },
  { key: CAPABILITIES.CONFIG_WRITE, domain: 'config', label: 'Edit configuration', description: 'Author normalization rules and the desired NCM', sensitive: false },

  { key: CAPABILITIES.TEMPLATE_READ, domain: 'template', label: 'Read templates', description: 'View templates, partials, revisions and variables', sensitive: false },
  { key: CAPABILITIES.TEMPLATE_WRITE, domain: 'template', label: 'Author templates', description: 'Write and publish templates and partials', sensitive: true },
  // NOT sensitive, unlike TEMPLATE_WRITE above it: every value it can write is
  // typed against a declaration a template author already published, for a
  // key that author explicitly opened to site entry (`x-obliwan-level:
  // 'site'`), so it can neither make the renderer evaluate anything new nor
  // override, for one site, a value the author kept at tenant or group level
  // (see the constant).
  { key: CAPABILITIES.SITE_VARIABLES_WRITE, domain: 'template', label: 'Fill site variables', description: 'Set the per-site values of variables that published templates open to site entry', sensitive: false },

  { key: CAPABILITIES.PLAN_CREATE, domain: 'change', label: 'Compile plans', description: 'Compute a change plan without touching any equipment', sensitive: false },
  { key: CAPABILITIES.CHANGE_APPLY, domain: 'change', label: 'Apply changes', description: 'Enqueue a change job that writes to an equipment', sensitive: true },
  { key: CAPABILITIES.CHANGE_APPROVE, domain: 'change', label: 'Approve changes', description: 'Four-eyes approval and Management-Path Guard override', sensitive: true },
  { key: CAPABILITIES.ROLLOUT_MANAGE, domain: 'change', label: 'Manage rollouts', description: 'Start, pause and abort wave rollouts', sensitive: true },

  { key: CAPABILITIES.DRIFT_READ, domain: 'drift', label: 'Read drift', description: 'View drift runs, findings and their attribution', sensitive: false },
  { key: CAPABILITIES.DRIFT_MANAGE, domain: 'drift', label: 'Manage drift', description: 'Acknowledge and ignore drift findings', sensitive: false },
  { key: CAPABILITIES.QUERY_RUN, domain: 'drift', label: 'Run fleet queries', description: 'Execute and save Fleet Query DSL queries', sensitive: false },

  { key: CAPABILITIES.SNMP_READ, domain: 'telemetry', label: 'Read telemetry', description: 'View interfaces, counters, time series and thresholds', sensitive: false },
  { key: CAPABILITIES.SNMP_ADMIN, domain: 'telemetry', label: 'Manage SNMP', description: 'Manage SNMP targets, credentials and thresholds', sensitive: true },

  { key: CAPABILITIES.ACS_ADMIN, domain: 'acs', label: 'Manage ACS', description: 'Manage CPEs, CWMP tasks, parameter maps and firmware', sensitive: true },

  { key: CAPABILITIES.SIM_READ, domain: 'mobile', label: 'Read SIM fleet', description: 'View mobile lines, remaining data and the re-invoicing report', sensitive: false },
  { key: CAPABILITIES.SIM_MANAGE, domain: 'mobile', label: 'Manage SIM fleet', description: 'Assign lines, set data thresholds and opt lines into top-ups', sensitive: false },
  // `sensitive` because holding it means being able to commit spend, which is
  // the one consequence in this vocabulary that no rollback undoes.
  { key: CAPABILITIES.SIM_RECHARGE, domain: 'mobile', label: 'Approve top-ups', description: 'Approve a data top-up, or record one bought on the partner portal', sensitive: true },

  { key: CAPABILITIES.CREDENTIAL_MANAGE, domain: 'secrets', label: 'Manage credentials', description: 'Create, rotate and delete vault credentials', sensitive: true },
  { key: CAPABILITIES.SECRET_READ, domain: 'secrets', label: 'Reveal secrets', description: 'Display a stored secret in clear text', sensitive: true },

  { key: CAPABILITIES.GROUPS_MANAGE, domain: 'admin', label: 'Manage groups', description: "Reorder this workspace's groups and set their configuration (general, consolidated alerts) — editing, moving, deleting and creating a group are team grants", sensitive: false },
  { key: CAPABILITIES.USERS_MANAGE, domain: 'admin', label: 'Manage users', description: 'Reserved: no route honours it — users, teams and permission sets are platform-admin only', sensitive: true },
  { key: CAPABILITIES.TENANTS_MANAGE, domain: 'admin', label: 'Manage tenants', description: 'Create, edit and delete tenants and memberships', sensitive: true },
  { key: CAPABILITIES.SETTINGS_MANAGE, domain: 'admin', label: 'Manage settings', description: 'Release the kill-switch, set SLA objectives and the weather quorum policy — not the settings tree, SMTP or SSO', sensitive: true },
  { key: CAPABILITIES.NOTIFICATIONS_MANAGE, domain: 'admin', label: 'Manage notifications', description: "Bind this workspace's channels to groups and devices; enable, test or delete them", sensitive: false },
  { key: CAPABILITIES.AUDIT_READ, domain: 'admin', label: 'Read audit', description: 'Read the audit log and the command audit', sensitive: true },
  { key: CAPABILITIES.EXPORT_RUN, domain: 'admin', label: 'Export', description: 'Export a tenant to a portable bundle', sensitive: true },
  { key: CAPABILITIES.IMPORT_RUN, domain: 'admin', label: 'Import', description: 'Reserved: no route honours it — bundle import is platform-admin only', sensitive: true },
];

export const ALL_CAPABILITIES: Capability[] = CAPABILITY_CATALOG.map((c) => c.key);

const CAPABILITY_SET: ReadonlySet<string> = new Set<string>(ALL_CAPABILITIES);

/** Narrowing guard for values coming from the DB, the API or Obligate. */
export function isCapability(value: unknown): value is Capability {
  return typeof value === 'string' && CAPABILITY_SET.has(value);
}

/** Drops anything unknown — never trust a persisted or federated list blindly. */
export function sanitizeCapabilities(values: readonly unknown[]): Capability[] {
  return values.filter(isCapability);
}

/**
 * Capabilities that cannot usefully be held alone.
 *
 * The built-in sets are coherent, but a hand-made permission set granting
 * CHANGE_APPLY without PLAN_CREATE produces a grant that can enqueue a change
 * and then cannot read the queue, the job, its steps or the kill-switch state —
 * every one of those is PLAN_CREATE. Worse on the rollout screen: the blast
 * radius is computed per device through PLAN_CREATE routes, so each device
 * answers 403, the safety net reads "not established", and fail-closed turns the
 * whole fleet DEGRADED. Honest, and unusable.
 *
 * Expressed as an implication rather than documented as a caveat: a rule nobody
 * can violate beats a rule everybody must remember.
 */
export const CAPABILITY_IMPLIES: Readonly<Partial<Record<Capability, readonly Capability[]>>> = {
  // Applying presupposes seeing what you applied.
  [CAPABILITIES.CHANGE_APPLY]: [CAPABILITIES.PLAN_CREATE],
  // Overriding the guard presupposes being able to read the verdict you overrule.
  [CAPABILITIES.CHANGE_APPROVE]: [CAPABILITIES.PLAN_CREATE],
  // A rollout is a batch of change jobs.
  [CAPABILITIES.ROLLOUT_MANAGE]: [CAPABILITIES.PLAN_CREATE, CAPABILITIES.CHANGE_APPLY],
  // SITE_WRITE was carved OUT of DEVICE_WRITE, so DEVICE_WRITE keeps it: no
  // holder of the broader grant loses a site right the day the split lands.
  [CAPABILITIES.DEVICE_WRITE]: [CAPABILITIES.SITE_WRITE],
  // Editing a site presupposes seeing the site list you are editing.
  [CAPABILITIES.SITE_WRITE]: [CAPABILITIES.DEVICE_READ],
  // Comparing the CHR's accounts with the sites presupposes seeing the sites.
  [CAPABILITIES.RECONCILE_READ]: [CAPABILITIES.DEVICE_READ],
  // Writing a config without reading it is a diff against nothing.
  [CAPABILITIES.CONFIG_WRITE]: [CAPABILITIES.CONFIG_READ],
  // Whoever may author a template may also fill in what it declares for a
  // site; the reverse is deliberately NOT true — typing a value is not
  // authoring the code that consumes it.
  [CAPABILITIES.TEMPLATE_WRITE]: [CAPABILITIES.TEMPLATE_READ, CAPABILITIES.SITE_VARIABLES_WRITE],
  [CAPABILITIES.DRIFT_MANAGE]: [CAPABILITIES.DRIFT_READ],
  [CAPABILITIES.SNMP_ADMIN]: [CAPABILITIES.SNMP_READ],
  // Assigning a line presupposes seeing the fleet you are assigning from.
  [CAPABILITIES.SIM_MANAGE]: [CAPABILITIES.SIM_READ],
  // Approving a top-up presupposes reading the balance that justifies it. The
  // reverse is deliberately NOT true, and neither is SIM_MANAGE ⇒ SIM_RECHARGE:
  // an inventory grant must never turn into a spending grant by implication.
  [CAPABILITIES.SIM_RECHARGE]: [CAPABILITIES.SIM_READ],
  // SECRET_READ implies NOTHING, and neither does CREDENTIAL_MANAGE. This
  // table used to say `SECRET_READ ⇒ CREDENTIAL_MANAGE` ("revealing a
  // secret presupposes managing the credential"), at a time when SECRET_READ
  // had no route and the implication was its only effect. Its routes exist now
  // (server/src/routes/secretReveal.routes.ts) and a tenant ADMIN holds it, for
  // debugging — and CREDENTIAL_MANAGE is not a read: it writes a transport's
  // host and port (the address the server dials) and declares
  // concentrators, whose /ppp/secret the allocator believes. Reading a
  // password to debug a router must not hand anybody that, so the two are
  // granted separately. The reveal routes that need both (an SNMP credential:
  // the whole `snmp_credentials` table, listing included, is CREDENTIAL_MANAGE)
  // demand both, explicitly.
};

/**
 * Closes a capability list under `CAPABILITY_IMPLIES`.
 *
 * Call this where capabilities are RESOLVED for a request, not where they are
 * stored: the stored grant stays exactly what an administrator typed, and the
 * expansion is what the request is evaluated against.
 */
export function expandCapabilities(values: readonly Capability[]): Capability[] {
  const held = new Set<Capability>(values);
  // Fixed point rather than one pass: an implication may itself imply.
  for (let changed = true; changed; ) {
    changed = false;
    for (const c of [...held]) {
      for (const implied of CAPABILITY_IMPLIES[c] ?? []) {
        if (!held.has(implied)) { held.add(implied); changed = true; }
      }
    }
  }
  return ALL_CAPABILITIES.filter((c) => held.has(c));
}

export function capabilitiesByDomain(domain: CapabilityDomain): CapabilityInfo[] {
  return CAPABILITY_CATALOG.filter((c) => c.domain === domain);
}

// ── Which capabilities a permission set may carry ──────────────────────────
//
// Since migration 084 a permission set IS the tenant role (`user_tenants.role`
// is a `permission_sets.slug`) and the runtime grants what its row lists — the
// matrix screen is authoritative, a tick is a grant to every holder in every
// tenant. Three classes of capability are therefore treated specially, once,
// here; the set-write API, the resolver and the matrix all read these lists.

/**
 * Honoured only by `requireRole('admin')` routes: an account and a tenant are
 * GLOBAL objects (one password, memberships in several tenants), so no
 * tenant-scoped grant can carry them. Refused by the set-write API, stripped
 * from every source at resolution (a set row edited by hand, a team pin, an
 * Obligate assertion), shown locked in the matrix.
 */
export const PLATFORM_ONLY_CAPABILITIES: readonly Capability[] = [
  CAPABILITIES.TENANTS_MANAGE,
  CAPABILITIES.USERS_MANAGE,
  CAPABILITIES.IMPORT_RUN,
];

/**
 * Never in a permission set — granted BY NAME only (a capability pinned on a
 * team grant, or asserted per user by Obligate). CREDENTIAL_MANAGE writes a
 * transport's host and port — the address the server dials — and declares
 * concentrators, whose /ppp/secret the allocator believes: not something one
 * inherits from a role picked in a dropdown.
 */
export const BY_NAME_ONLY_CAPABILITIES: readonly Capability[] = [
  CAPABILITIES.CREDENTIAL_MANAGE,
];

/**
 * May sit in a set, but only by an EXPLICIT tick: no entry of
 * `CAPABILITY_IMPLIES` may ever produce one of these (the RBAC harness asserts
 * it), and the matrix asks for a confirmation naming the consequence — money
 * that no rollback refunds, secrets in clear, the second pair of eyes.
 */
export const EXPLICIT_ONLY_CAPABILITIES: readonly Capability[] = [
  CAPABILITIES.SIM_RECHARGE,
  CAPABILITIES.SECRET_READ,
  CAPABILITIES.CHANGE_APPROVE,
];

/** Why a capability cannot be ticked into a set, or null when it can. */
export function setLockReason(cap: string): 'platform_only' | 'by_name_only' | null {
  if ((PLATFORM_ONLY_CAPABILITIES as readonly string[]).includes(cap)) return 'platform_only';
  if ((BY_NAME_ONLY_CAPABILITIES as readonly string[]).includes(cap)) return 'by_name_only';
  return null;
}

/** May this capability be stored in a permission set? */
export function assignableToSet(cap: string): boolean {
  return isCapability(cap) && setLockReason(cap) === null;
}

// ── Tenant roles ────────────────────────────────────────────────────────────

/**
 * `user_tenants.role` — since migration 084 a `permission_sets.slug`, enforced
 * by a FOREIGN KEY (an unknown role is impossible, not merely harmless). The
 * four BUILTIN roles below are GLOBAL sets, shared by every tenant like
 * Obliance's, and cannot be deleted; any other slug is a custom set created in
 * the matrix. Obligate is the source of truth for SSO users: ObliWAN
 * advertises its sets (app-info) and applies the slug Obligate sends for each
 * tenant as-is, an unknown one falling back to `viewer`
 * (server/src/services/obligateRoles.ts).
 *
 * Order = the order Obligate and the pickers show them, widest first.
 *
 *   admin            tenant administrator — every capability of its set on
 *                    what its TEAMS cover (no team, nothing: migration 087),
 *                    applies AND approves changes, approves top-ups, reveals
 *                    secrets; never `credential.manage` and nothing
 *                    PLATFORM_ONLY
 *   user             day-to-day fleet work (was `member`, set `operator`):
 *                    devices, configuration snapshots, discoveries, plans,
 *                    drift, queries, reconciliation; applies no change
 *   account_manager  « Chargé(e) de compte »: sites and their variables,
 *                    devices and their health, SIM lines, reconciliation —
 *                    read only on everything that dials a box
 *   viewer           consultation only: no configuration snapshot, no
 *                    write of any kind
 *
 * WHAT a role may do is the set; WHERE is the user's TEAMS (`team_permissions`
 * 'ro' / 'rw' on a group — inherited down the closure — on a device, or on the
 * ungrouped devices), exactly as in Obliance. Only the PLATFORM admin
 * (`users.role = 'admin'`) sees the whole tenant without a team; the tenant
 * `admin` holds every capability of its set on what its teams cover, and with
 * no team sees nothing (migration 087 — Obliance's `isAdmin` is the platform
 * role, never the tenant one).
 */
export const BUILTIN_TENANT_ROLES = ['admin', 'user', 'account_manager', 'viewer'] as const;
export type BuiltinTenantRole = (typeof BUILTIN_TENANT_ROLES)[number];

/** A `permission_sets.slug` held as a tenant role (builtin or custom). */
export type TenantRole = string;

/**
 * The tenant administrator role: every capability of its set (WHAT). Since
 * migration 087 it is NOT tenant-wide: WHERE comes from its teams, like
 * everybody else's.
 */
export const TENANT_ADMIN_ROLE: BuiltinTenantRole = 'admin';
/** The role a membership gets when a local writer names none. */
export const DEFAULT_TENANT_ROLE: BuiltinTenantRole = 'user';
/** The role an SSO membership gets when Obligate sends a role ObliWAN does not know. */
export const FALLBACK_TENANT_ROLE: BuiltinTenantRole = 'viewer';

/**
 * Role values ObliWAN itself used to write before 084, still accepted on the
 * way IN (an Obligate configured against the old app-info, an old client) and
 * translated — never stored. `member` was the operator set, now `user`.
 */
export const LEGACY_TENANT_ROLE_ALIASES: Readonly<Record<string, BuiltinTenantRole>> = {
  member: 'user',
};

/** Slugs a custom set may never take: wire values of the past or of the platform role. */
export const RESERVED_ROLE_SLUGS: readonly string[] = ['member', 'operator', 'platform_admin', 'root'];

export function isBuiltinTenantRole(value: unknown): value is BuiltinTenantRole {
  return typeof value === 'string' && (BUILTIN_TENANT_ROLES as readonly string[]).includes(value);
}

/** Syntax of a set slug (`permission_sets.slug`, varchar 64). Existence is a DB question. */
export function isRoleSlugSyntax(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value);
}

/** @deprecated since 084 a role is any existing set slug; kept for old harnesses. */
export const TENANT_ROLES = BUILTIN_TENANT_ROLES;
/** @deprecated use `isBuiltinTenantRole` (UI ordering) or a DB lookup (validation). */
export const isTenantRole = isBuiltinTenantRole;

/**
 * The site fields that schedule pushes rather than describe a customer: the
 * maintenance window (NULL = open, change/jobQueue.service.ts) and the
 * timezone it is evaluated in. Changing them on an EXISTING site takes
 * `SITE_SCHEDULE_CAPABILITY`, which SITE_WRITE alone does not give (see
 * SITE_WRITE). Spelled as the API body spells them (`validators/site.schema`),
 * and exported here so a site form can leave the same two read-only for a
 * holder of SITE_WRITE alone instead of keeping its own copy of the list.
 */
export const SITE_SCHEDULE_FIELDS = ['maintenanceWindow', 'timezone'] as const;
export type SiteScheduleField = (typeof SITE_SCHEDULE_FIELDS)[number];
export const SITE_SCHEDULE_CAPABILITY: Capability = CAPABILITIES.DEVICE_WRITE;

/**
 * HISTORICAL seed material for `permission_sets`: migration 001 seeds a fresh
 * database from this array (`account_manager` also by migration 051 on
 * databases created before it), and migration 084 then rewrites every row into
 * `ROLE_PERMISSION_SETS` (below) — `operator` becomes `user`, `engineer`
 * becomes a custom set without CREDENTIAL_MANAGE. Nothing reads this array at
 * runtime any more; it is kept, unchanged, because 001 imports it and a fresh
 * install must keep producing the database 084 was written against. Do not
 * edit it to change a role: edit `ROLE_PERMISSION_SETS` and write a migration.
 */
export const BUILTIN_PERMISSION_SETS: ReadonlyArray<{
  slug: string;
  name: string;
  capabilities: Capability[];
}> = [
  {
    slug: 'viewer',
    name: 'Viewer',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SIM_READ,
    ],
  },
  {
    slug: 'operator',
    name: 'Operator',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.DEVICE_WRITE,
      CAPABILITIES.DEVICE_DISCOVER,
      CAPABILITIES.CONFIG_READ,
      CAPABILITIES.TEMPLATE_READ,
      // Day-to-day site provisioning: an account manager types the per-site
      // values a published template asks for. TEMPLATE_WRITE stays out of this
      // set, which is the whole point of the split.
      CAPABILITIES.SITE_VARIABLES_WRITE,
      CAPABILITIES.PLAN_CREATE,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.DRIFT_MANAGE,
      CAPABILITIES.QUERY_RUN,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SIM_READ,
    ],
  },
  {
    slug: 'engineer',
    name: 'Network engineer',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.DEVICE_WRITE,
      CAPABILITIES.DEVICE_DISCOVER,
      CAPABILITIES.CONFIG_READ,
      CAPABILITIES.CONFIG_WRITE,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.TEMPLATE_WRITE,
      CAPABILITIES.PLAN_CREATE,
      CAPABILITIES.CHANGE_APPLY,
      CAPABILITIES.ROLLOUT_MANAGE,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.DRIFT_MANAGE,
      CAPABILITIES.QUERY_RUN,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SNMP_ADMIN,
      CAPABILITIES.CREDENTIAL_MANAGE,
      CAPABILITIES.SIM_READ,
      CAPABILITIES.SIM_MANAGE,
      // SIM_RECHARGE is deliberately absent from every builtin set. It commits
      // spend, so it is granted the way CHANGE_APPROVE is — named explicitly by
      // whoever hands it out, never inherited from "is an engineer".
    ],
  },
  {
    // « Chargé(e) de compte » — no existing role fitted the job. A
    // member (the operator set) reads configuration snapshots (CONFIG_READ),
    // binds PPP discoveries, approves quarantined routers and compiles
    // plans; a tenant admin approves changes and top-ups and reveals secrets.
    // This is the list she needs and nothing else. Appended LAST so a fresh
    // install (001, seeded from this array) and an upgraded one (051) give it
    // the same row position.
    slug: 'account_manager',
    name: 'Account manager',
    capabilities: [
      // The sites and their deployment state, the devices and their health
      // (the `device_health_checks` verdict rides on the device list and
      // detail reads), presence, uplink, reachability.
      CAPABILITIES.DEVICE_READ,
      // Create, edit and import sites — not devices, not a site deletion, and
      // not the push schedule of an existing site (see SITE_WRITE).
      CAPABILITIES.SITE_WRITE,
      // The per-site values a published template opened to site entry; a
      // secret one goes to the vault and is never read back by this set.
      CAPABILITIES.SITE_VARIABLES_WRITE,
      // Interfaces, counters and thresholds, and the unified log journal
      // (syslog, traps, RouterOS /log as already stored — logs.routes.ts files
      // it under the same telemetry capability). Not flagged sensitive; the
      // viewer holds it. Pulling /log off a router NOW dials the box and is
      // DEVICE_WRITE, like test-connection and the on-demand health check.
      CAPABILITIES.SNMP_READ,
      // SEE the SIM lines, their remaining data and the re-invoicing report.
      // Read only: attaching a line, setting its threshold or opting it into
      // top-up proposals is SIM_MANAGE, which the spec ("see SIM lines")
      // does not give her; an operator who wants her to attach lines adds it
      // here AND to the literal list in migration 051 (the harness compares).
      CAPABILITIES.SIM_READ,
      // Her own tenant's CHR <-> sites reconciliation, redacted, and the
      // re-read of the concentrator behind it (by design: view +
      // re-read). Refused by the server when the tenant's login template
      // names no tenant (see RECONCILE_READ). Added by migration 062 to the
      // catalogue row 051 seeded; the harness compares the two.
      CAPABILITIES.RECONCILE_READ,
      // Deliberately ABSENT, each for a stated reason:
      //  - DEVICE_WRITE / DEVICE_DISCOVER: device inventory and identity,
      //    and the on-demand routes that dial a box to read it (test
      //    connection, health check, diagnose, /log pull).
      //  - CONFIG_READ: a snapshot may carry residual secrets.
      //  - TEMPLATE_READ: she fills a site form (SITE_VARIABLES_WRITE opens
      //    `GET /variables/sites/:id` on its own); template bodies are not hers.
      //  - PLAN_CREATE, CHANGE_APPLY, CHANGE_APPROVE, ROLLOUT_MANAGE,
      //    ACS_ADMIN, SNMP_ADMIN, CONFIG_WRITE: nothing she does dials a box to
      //    write it, or opens a channel to one.
      //  - SECRET_READ, CREDENTIAL_MANAGE: no secret in clear, no vault write.
      //  - SIM_MANAGE: see above.
      //  - SIM_RECHARGE: no purchase.
    ],
  },
];

/**
 * The FOUR builtin tenant roles as migration 084 seeds them — global sets,
 * `is_default = true`, not deletable. From 084 on, the RUNTIME reads the
 * `permission_sets` row (an operator may re-tick them in the matrix, and that
 * is a grant); this constant is the seed, the "reset to default" target and the
 * harness oracle. 084 inlines the same lists as literals (a migration
 * describes the vocabulary of its own day) and the harness compares the two.
 *
 * Each list is exactly what the role held in code before 084, with two
 * operator decisions (2026-10-07) on top:
 *  - `user` (was `member`, the `operator` set) gains RECONCILE_READ, so that
 *    `user` covers everything the chargé(e) de compte holds but SITE_WRITE —
 *    which `user` already holds through DEVICE_WRITE;
 *  - `admin` gains GROUPS_MANAGE (reorder + group configuration, as Obliance's
 *    admin) and RECONCILE_READ (which the 062 catalogue row already listed).
 * CREDENTIAL_MANAGE and every PLATFORM_ONLY capability are in none of them.
 * CONFIG_WRITE (the manual « Collecter maintenant », which dials a router) is
 * the admin's only. SIM_RECHARGE, SECRET_READ and CHANGE_APPROVE are the
 * admin's only, each named explicitly.
 */
export const ROLE_PERMISSION_SETS: ReadonlyArray<{
  slug: BuiltinTenantRole;
  name: string;
  description: string;
  capabilities: Capability[];
}> = [
  {
    slug: 'admin',
    name: 'Administrateur',
    // Migration 087 rewrites the 084 text into this one (only when the row
    // still holds 084's literal: an operator's own wording is left alone).
    description: "Toutes les capacités de l'espace, sur ce que couvrent ses équipes ; applique et approuve les changements, approuve les recharges, révèle les secrets.",
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.DEVICE_WRITE,
      CAPABILITIES.DEVICE_DISCOVER,
      CAPABILITIES.RECONCILE_READ,
      CAPABILITIES.CONFIG_READ,
      CAPABILITIES.CONFIG_WRITE,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.TEMPLATE_WRITE,
      CAPABILITIES.PLAN_CREATE,
      CAPABILITIES.CHANGE_APPLY,
      CAPABILITIES.CHANGE_APPROVE,
      CAPABILITIES.ROLLOUT_MANAGE,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.DRIFT_MANAGE,
      CAPABILITIES.QUERY_RUN,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SNMP_ADMIN,
      CAPABILITIES.ACS_ADMIN,
      CAPABILITIES.SIM_READ,
      CAPABILITIES.SIM_MANAGE,
      CAPABILITIES.SIM_RECHARGE,
      CAPABILITIES.SECRET_READ,
      CAPABILITIES.GROUPS_MANAGE,
      CAPABILITIES.SETTINGS_MANAGE,
      CAPABILITIES.NOTIFICATIONS_MANAGE,
      CAPABILITIES.AUDIT_READ,
      CAPABILITIES.EXPORT_RUN,
    ],
  },
  {
    slug: 'user',
    name: 'Utilisateur',
    description: 'Exploitation courante : appareils, instantanés de configuration, découvertes, plans, dérive, requêtes. N’applique aucun changement.',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.DEVICE_WRITE,
      CAPABILITIES.DEVICE_DISCOVER,
      CAPABILITIES.RECONCILE_READ,
      CAPABILITIES.CONFIG_READ,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.SITE_VARIABLES_WRITE,
      CAPABILITIES.PLAN_CREATE,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.DRIFT_MANAGE,
      CAPABILITIES.QUERY_RUN,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SIM_READ,
    ],
  },
  {
    slug: 'account_manager',
    name: 'Chargé(e) de compte',
    description: 'Sites et leurs variables, appareils et leur santé, lignes SIM (lecture), rapprochement CHR. N’écrit sur aucun appareil, ne voit aucun secret, n’achète aucune recharge.',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.SITE_WRITE,
      CAPABILITIES.SITE_VARIABLES_WRITE,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SIM_READ,
      CAPABILITIES.RECONCILE_READ,
    ],
  },
  {
    slug: 'viewer',
    name: 'Lecteur',
    description: 'Consultation : parc, modèles, dérive, télémétrie, lignes SIM. Aucune configuration, aucune écriture.',
    capabilities: [
      CAPABILITIES.DEVICE_READ,
      CAPABILITIES.TEMPLATE_READ,
      CAPABILITIES.DRIFT_READ,
      CAPABILITIES.SNMP_READ,
      CAPABILITIES.SIM_READ,
    ],
  },
];
