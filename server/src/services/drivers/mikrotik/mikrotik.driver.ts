/**
 * ObliWAN — MikroTik RouterOS driver (families `mikrotik_routeros6` and
 * `mikrotik_routeros7`).
 *
 * Primary channel is the RouterOS API (8728, or 8729 with TLS and a pinned
 * fingerprint), reached through the seam in `routerosChannel.ts`.
 * SNMP is a fallback that identifies a box whose API credentials are wrong or
 * whose API service is disabled; it is never the primary, because the API
 * returns strictly more (spec section 1.4, "SNMP as primary for MikroTik" is a
 * rejected option).
 *
 * WHY TWO FAMILIES: RouterOS 6 and 7 are one brand and two command
 * dialects. `/system/health` returns a single record on v6 and rows on v7,
 * wireless moved from `/interface/wireless` to `/interface/wifi`, and menu
 * paths diverge. One family with a version `if` inside every collector is
 * exactly the hard-coded-path failure the capability matrix exists to prevent. The identity
 * menus below happen to be identical on both — which is why this file is one
 * class with a family parameter, and why the telemetry collectors will not be.
 *
 * The version reported by the box is authoritative over the family recorded in
 * `devices.family`: an operator who upgrades a hEX from 6.49 to 7.x changes the
 * dialect, and the inventory has to say so rather than keep speaking v6.
 */

import type {
  DeviceCapabilities,
  DeviceFamily,
  RouterOsDeviceModeFacts,
  TransportKind,
} from '@obliwan/shared';
import { asRouterOsDeviceMode, NO_CAPABILITIES } from '@obliwan/shared';
import { BaseDriver } from '../base';
import {
  DriverError,
  emptyInventory,
  requireTransport,
  type DeviceInventory,
  type DriverContext,
  type ProbeOutcome,
  type ResolvedTransport,
} from '../types';
import { withRouterOsChannel, type RouterOsRow } from './routerosChannel';

/** Capabilities shared by both RouterOS families. */
function routerosCapabilities(family: DeviceFamily): DeviceCapabilities {
  return {
    ...NO_CAPABILITIES,
    supportsRouterosApi: true,
    supportsSsh: true,
    supportsSnmp: true,
    transportPriority: ['routeros_api', 'ssh', 'snmp'] as TransportKind[],

    // Only what is actually implemented is true here. Everything else stays
    // false until the code exists — the flag is a promise to the planner.
    canReadInterfaces: false,
    // STILL FALSE, AND DELIBERATELY SO. The config collection exists: the export
    // is spelled per family from one table in `./driver.ts`
    // (`routerOsExportCommand()`: `/export terse hide-sensitive` on RouterOS 6,
    // `/export terse` on RouterOS 7, never `show-sensitive`, no pty — the no-secrets rule and
    // N13), `services/config/collect.service.ts` runs it over SSH and refuses
    // any export still carrying a secret, and
    // `services/config/normalize.service.ts` turns it into an `NcmDocument`.
    // But `DeviceDriver.exportConfig` is declared `Promise<never>` in
    // `drivers/types.ts`, a file outside this module, so the driver
    // METHOD still throws its dated `NotImplementedError`, and the collection
    // goes through `collect.service.ts` rather than through this driver (the
    // driver-level `collectRouterOsExport()` has no caller). Flipping this
    // flag while the interface method still refuses would promise the planner
    // something it cannot get. It becomes true when the planned signature change
    // lands, in the same commit.
    canExportConfig: false,

    // The concentrator role is what makes MikroTik special in this product
    // (presence comes from the concentrator): /ppp/active + /ppp/active/listen are the source of truth for
    // presence. The CHR is a RouterOS 7 box; a v6 unit can serve the same
    // menus, so the flag is on for both and the ROLE decides who is asked.
    canReadPppSessions: true,
    canStreamPppEvents: true,

    configFormat: 'text_cli',
    applyGranularity: 'line',
    supportsStructuredDiff: true,
    requiresExplicitCommit: false,
    requiresRebootToApply: false,

    // The CHR terminates the whole fleet's tunnels; it is a SPOF and a
    // bottleneck. One socket, multiplexed by tag — not four sessions.
    maxConcurrentSessions: 1,
    minPollIntervalMs: 30_000,
    notes: [
      family === 'mikrotik_routeros6'
        ? 'RouterOS 6: menu paths differ from v7 (/interface/wireless, /system/health as a single record). Collectors are family-specific by design.'
        : 'RouterOS 7: /interface/wifi replaces /interface/wireless and /system/health returns rows.',
      family === 'mikrotik_routeros6'
        ? 'Config export runs as "/export terse hide-sensitive" (RouterOS 6 prints secrets unless told not to), and an export that still carries a secret is refused, never stored.'
        : 'Config export runs as "/export terse" (RouterOS 7 hides secrets unless asked for show-sensitive, which is never sent), and an export that still carries a secret is refused, never stored.',
      'Identity is ppp_username + system_identity + serial, never the tunnel IP.',
    ],
  };
}

export class MikrotikRouterOsDriver extends BaseDriver {
  readonly id: string;
  readonly brand = 'mikrotik' as const;
  readonly family: DeviceFamily;
  readonly capabilities: DeviceCapabilities;

  constructor(family: DeviceFamily = 'mikrotik_routeros7') {
    super();
    this.family = family;
    this.id = family;
    this.capabilities = routerosCapabilities(family);
  }

  async probe(ctx: DriverContext): Promise<ProbeOutcome> {
    return this.runProbe(ctx, [
      {
        transport: 'routeros_api',
        run: (channel) => this.inventoryOverApi(ctx, channel),
      },
      {
        transport: 'snmp',
        run: async (channel) => {
          const { inventory, identity } = await this.identifyOverSnmp(ctx, channel);
          // "RouterOS 7.14.3 (stable) ..." — the only version signal SNMP has.
          return { ...inventory, osVersion: versionFromSysDescr(identity.sysDescr) };
        },
      },
    ]);
  }

  async getInventory(ctx: DriverContext): Promise<DeviceInventory> {
    const api = ctx.transports.find((t) => t.transport === 'routeros_api' && t.enabled);
    if (api) return this.inventoryOverApi(ctx, api);

    const snmp = requireTransport(ctx, 'snmp');
    const { inventory, identity } = await this.identifyOverSnmp(ctx, snmp);
    return { ...inventory, osVersion: versionFromSysDescr(identity.sysDescr) };
  }

  /**
   * Four menus, one channel. `/system/routerboard` is the only source of a
   * serial — and a CHR (a virtual machine) legitimately has none, which is why
   * the identity rule makes identity a triple and not a serial alone.
   */
  private async inventoryOverApi(
    ctx: DriverContext,
    channel: ResolvedTransport,
  ): Promise<DeviceInventory> {
    const timeoutMs = ctx.timeoutMs ?? 15_000;

    return withRouterOsChannel(
      channel,
      async (ros) => {
        const resource = firstRow(await ros.query('/system/resource/print', { timeoutMs }));
        const identity = firstRow(await ros.query('/system/identity/print', { timeoutMs }));

        // A CHR has no RouterBOARD menu at all; a trap there is expected, not
        // a failure of the whole inventory.
        let routerboard: RouterOsRow = {};
        try {
          routerboard = firstRow(await ros.query('/system/routerboard/print', { timeoutMs }));
        } catch {
          routerboard = {};
        }

        // ── /system/device-mode: can this box hold a dead-man at all? ───────
        // The menu does not exist before RouterOS 7.13, and a service account
        // without the policy gets a trap on one that does. Both arrive here as
        // a rejected promise (`routerosChannel` turns a `!trap` into a
        // DriverError rather than an empty row set), and both mean UNKNOWN —
        // never `enterprise`. Defaulting an unanswered menu to the permissive
        // mode would tell the planner that a fleet of unprobed routers can all
        // be armed, which is the backup-safety failure this read exists to surface.
        //
        // `observedAt` is stamped BEFORE the query so a refusing menu still
        // records that the question was put: "asked, no answer" and "never
        // asked" are different facts and the inventory keeps them apart.
        const deviceModeAskedAt = new Date().toISOString();
        let deviceMode: RouterOsDeviceModeFacts;
        try {
          const rows = await ros.query('/system/device-mode/print', { timeoutMs });
          deviceMode = parseRouterOsDeviceMode(rows[0] ?? null, deviceModeAskedAt);
        } catch {
          deviceMode = parseRouterOsDeviceMode(null, deviceModeAskedAt);
        }

        const version = resource['version'] ?? null;
        const observedFamily = familyFromVersion(version);

        return {
          ...emptyInventory('routeros_api'),
          brand: this.brand,
          // What the box says it runs wins over what the database remembers.
          family: observedFamily ?? this.family,
          model:
            routerboard['model'] ??
            routerboard['board-name'] ??
            resource['board-name'] ??
            resource['platform'] ??
            null,
          serial: routerboard['serial-number'] ?? null,
          osVersion: cleanVersion(version),
          systemIdentity: identity['name'] ?? null,
          boardName: resource['board-name'] ?? null,
          uptimeSeconds: this.parseUptimeSeconds(resource['uptime']),
          managementAddress: channel.host,
          deviceMode,
        };
      },
      { timeoutMs, deviceId: ctx.deviceId },
    );
  }
}

function firstRow(rows: RouterOsRow[]): RouterOsRow {
  if (!rows || rows.length === 0) {
    throw new DriverError('RouterOS returned no row for a /print of a singleton menu', 'PROTOCOL_ERROR', {
      transport: 'routeros_api',
    });
  }
  return rows[0];
}

/** `7.14.3 (stable)` -> `7.14.3`. Exported so a version read over SSH is
 *  stored as the API inventory stores it. */
export function cleanVersion(raw: string | null): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  const match = /^([0-9][0-9a-zA-Z.\-_]*)/.exec(trimmed);
  return match ? match[1] : trimmed || null;
}

/** Major version -> family. Anything but 6 or 7 returns null: guessing a
 *  dialect for RouterOS 8 would be inventing one. */
export function familyFromVersion(raw: string | null): DeviceFamily | null {
  const version = cleanVersion(raw);
  if (!version) return null;
  const major = Number(version.split('.')[0]);
  if (major === 6) return 'mikrotik_routeros6';
  if (major === 7) return 'mikrotik_routeros7';
  return null;
}

/**
 * `/system/device-mode/print` -> `RouterOsDeviceModeFacts`.
 *
 * `row === null` is "the menu did not answer" — a trap, or a `/print` that
 * produced no row at all. It parses to all-nulls WITH the timestamp, because
 * having asked is itself a fact (see the call site).
 *
 * NOTHING IS DERIVED HERE. This function reports what the row printed and
 * stops; the one inference ObliWAN permits — `home` implies the scheduler is
 * denied — lives in `deadmanReadiness()` in shared, where it is stated once and
 * read by both the server and the client. A parser that quietly filled
 * `schedulerAllowed: true` because the mode said `enterprise` would make the
 * stored column indistinguishable from a flag the router actually printed.
 */
export function parseRouterOsDeviceMode(
  row: RouterOsRow | null,
  observedAt: string,
): RouterOsDeviceModeFacts {
  if (!row) {
    return {
      mode: null,
      schedulerAllowed: null,
      fetchAllowed: null,
      raw: null,
      observedAt,
    };
  }
  return {
    // An unrecognised mode narrows to null, not to a guess: the one inference
    // `deadmanReadiness()` makes (from `home`) is characterised for the modes
    // MikroTik documents and for nothing a future firmware might print.
    mode: asRouterOsDeviceMode(row['mode']),
    schedulerAllowed: parseRouterOsFlag(row['scheduler']),
    fetchAllowed: parseRouterOsFlag(row['fetch']),
    raw: { ...row },
    observedAt,
  };
}

/**
 * RouterOS prints `yes`/`no`; the API layer may hand over `true`/`false`.
 * Anything else — an absent key, an empty string, a padded one, a word a future
 * firmware introduces — is `null`.
 *
 * Trimmed BEFORE the emptiness test, and never coerced with `Number()` or `!!`:
 * every JavaScript whitespace string is falsy-adjacent in one coercion or
 * another, and in the SIM fleet code exactly that turned a blanked partner field into a
 * confident zero across a whole fleet.
 */
function parseRouterOsFlag(raw: string | undefined): boolean | null {
  const value = (raw ?? '').trim().toLowerCase();
  if (value === 'yes' || value === 'true') return true;
  if (value === 'no' || value === 'false') return false;
  return null;
}

export function versionFromSysDescr(sysDescr: string | null): string | null {
  if (!sysDescr) return null;
  const match = /RouterOS\s+v?([0-9][0-9a-zA-Z.\-_]*)/i.exec(sysDescr);
  return match ? match[1] : null;
}
