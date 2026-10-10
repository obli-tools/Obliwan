// ============================================================================
// @obliwan/shared — the ACCESS LINK a site is declared with (migration 076)
// ============================================================================
//
// WHY A DECLARATION. Whole customers run stores with NO fixed line by design
// (a 4G router is the store's only uplink). ObliWAN used to INFER the access
// link from the router (a WAN-class interface in the snapshot or among the
// SNMP interfaces), and three screens presented cellular as abnormal: the 4G
// backup watch (backup4g.service.ts), the uplink card and the fleet
// anomalies. The operator now SAYS what the site is:
//
//   null            not declared — ObliWAN infers, exactly as before 076;
//   'fixed'         a fixed line with a 4G backup: cellular IS a backup, and
//                   the backup alert's "has a fixed uplink" premise holds
//                   even when inference finds no fixed interface;
//   'cellular_only' 4G only, by design: cellular is the NOMINAL path, never
//                   a backup, never an alert, never an anomaly.
//
// Tri-state on purpose, and NO default anywhere: a site nobody declared is
// not "fixed", and defaulting it would turn 400 inferred sites into 400
// declared ones nobody declared.

/** The two declared values. `null` (not declared) is the third state. */
export const SITE_UPLINK_KINDS = ['fixed', 'cellular_only'] as const;
export type SiteUplinkKind = (typeof SITE_UPLINK_KINDS)[number];
/** What a site carries: a declared kind, or null = not declared (inferred). */
export type SiteUplinkDeclaration = SiteUplinkKind | null;

export function isSiteUplinkKind(v: unknown): v is SiteUplinkKind {
  return typeof v === 'string' && (SITE_UPLINK_KINDS as readonly string[]).includes(v);
}

/**
 * The CSV column of the site import (`uplink`). Its values, case-insensitive:
 *   auto           -> null            (clears a declaration: ObliWAN infers)
 *   fixe | fixed   -> 'fixed'
 *   4g | cellular_only -> 'cellular_only'
 * An EMPTY cell is not one of them: the import's rule is "an empty cell
 * changes nothing", so the caller tests emptiness first (on trimmed text).
 */
export const SITE_UPLINK_CSV_COLUMN = 'uplink';
export const SITE_UPLINK_CSV_VALUES = ['auto', 'fixe', '4g'] as const;

export function parseSiteUplinkCell(
  text: string,
): { ok: true; kind: SiteUplinkDeclaration } | { ok: false } {
  switch (text.trim().toLowerCase()) {
    case 'auto':
      return { ok: true, kind: null };
    case 'fixe':
    case 'fixed':
      return { ok: true, kind: 'fixed' };
    case '4g':
    case 'cellular_only':
      return { ok: true, kind: 'cellular_only' };
    default:
      return { ok: false };
  }
}

/** The CSV spelling of a declaration (the inverse of `parseSiteUplinkCell`). */
export function siteUplinkCsvValue(kind: SiteUplinkDeclaration): (typeof SITE_UPLINK_CSV_VALUES)[number] {
  return kind === 'fixed' ? 'fixe' : kind === 'cellular_only' ? '4g' : 'auto';
}

/**
 * Labels. The screens translate `sites.uplink.kind.<auto|fixed|cellular_only>`
 * (en + fr); these are the server's own French sentences (row errors, audit)
 * and the i18n defaults, ONE spelling for both.
 */
export const SITE_UPLINK_LABELS: Readonly<Record<'auto' | SiteUplinkKind, { fr: string; en: string }>> = {
  auto: { fr: 'Automatique (non déclaré)', en: 'Automatic (not declared)' },
  fixed: { fr: 'Fixe + secours 4G', en: 'Fixed line + 4G backup' },
  cellular_only: { fr: '4G uniquement', en: '4G only' },
};

/** A bulk declaration carries at most this many site ids (a tenant has a few
 *  hundred; the bound keeps one request one statement). */
export const SITE_UPLINK_BULK_MAX = 5000;
