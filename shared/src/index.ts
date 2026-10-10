// @obliwan/shared — the contract between server and client.
// Keep this file a pure re-export barrel: no logic, no side effects.

export * from './types';
export * from './capabilities';
export * from './tenants';
export * from './settings';
export * from './socketEvents';
export * from './device';

// RouterOS device-mode (7.13+) and what it means for the dead-man. Next to
// `device` because it is an inventory fact, and deliberately NOT inside it:
// `device.ts` declares what a FAMILY can do, this declares what ONE BOX is
// currently allowed to do — and only MikroTik has the notion at all.
export * from './deviceMode';

// The permanent management-channel health check (migration 043). Next to
// `deviceMode` because it is a per-box fact too, and kept out of `device`: that
// file declares what a FAMILY can do, this one what ONE BOX did when asked.
export * from './health';

export * from './telemetry';

// The safe-write contract. Kept next to `device` on
// purpose: it consumes `SafetyLevel` from there and never redefines it.
export * from './change';

// The NCM contract. A sub-barrel: `src/ncm/index.ts` is the
// single place that knows that folder's layout.
export * from './ncm';

// Waved rollouts. Carries the subtree interlock helpers of the concentrator interlock, so
// the composition refusal is expressed once and shared by server and client
// rather than reimplemented on each side.
export * from './rollout';

// Logs, drift attribution and the reachability verdict.
export * from './logs';

// Fleet Query: the DSL types and the field catalogue derived from the
// NCM Zod schemas, never hand-maintained.
export * from './query';

// TR-069 / CWMP. Carries ACS_BRAND_COVERAGE as DATA rather than as prose:
// RouterOS and SonicOS have no CWMP client and never will, and a
// screen that lets an operator believe otherwise is the failure mode here.
export * from './cwmp';

// Intent Compiler: one site intent, four dialects, and a compilation
// that FAILS before any network access when the hardware cannot do it.
export * from './intent';

// Fleet takeover / Golden Site.
export * from './baseline';

// Drift exceptions with a mandatory justification and a review date, plus the
// verifiable compliance attestation. "Expired" is DERIVED, never
// stored: an exception whose review date has passed makes its drift visible
// again, so this cannot become a way to hide drift forever.
export * from './evidence';

// Intervention mode and the change → telemetry aftermath.
export * from './intervention';

// Operator weather. A single site switching to LTE is a flap; twelve
// sites on the same ASN within ten minutes is an operator incident — the whole
// feature is the quorum, not the event.
export * from './weather';

// Hardware replacement detection. `assertTargetBinding` already checked
// identity BEFORE each write; this watches it CHANGE over time — a serial that
// moves is a box that was swapped, and the product used to collect that on every
// connection and throw it away.
export * from './identity';

// Which l2tp-client is the management tunnel (the identity ppp_username): the one
// NAMED l2tp-mgmt, else the sole one carrying the recorded login. One rule
// for the API and the console readers.
export * from './managementTunnel';

// Computed availability. Its value is that reachability can tell "the site was down"
// from "WE lost the tunnel": a management-plane outage is never billed against a
// customer's SLA, and the report says how much time was excluded and why.
export * from './sla';

// End-of-life inventory. "End of support unknown" is an honest answer;
// "supported" for a model absent from the catalogue is not.
export * from './lifecycle';

// Mobile data lines — the SIM fleet behind the LTE uplinks. Carries the
// platform coverage matrix as DATA, like ACS_BRAND_COVERAGE, so a screen cannot
// imply ObliWAN is watching a partner it cannot read; and it is the one place
// the rule "an absent reading is unknown, never zero" is written, because zero
// is the reading that spends money.
export * from './sim';

// RouterOS releases and the fleet target version. The URL builder refuses any
// version, package name or architecture outside a strict allow-list, so no
// download URL is ever assembled from unchecked input.
export * from './firmware';

// The ObliWAN <-> concentrator WireGuard link: the host reaches 100.64.0.0/10
// (every CPE's tunnel address) through the CHR, which masquerades it. The
// transit arithmetic is here so the server and the device page agree on it.
export * from './concentratorLink';

// `/ip service` by name, robust to the CONNECTION entries RouterOS 7.24.5 lists
// beside the services (one dynamic row per open connection, carrying the
// service's name): the console construct every writer uses and the API filter
// every reader uses. Before `managementAccess`, which writes with it.
export * from './routerOsService';

// The management API: api-ssl on 8729 from the management range, serving a
// certificate made ON the router (a local CA, then a server certificate it
// signs). The ONE source of those RouterOS lines — the bench compile and the
// fleet job both write them — and of the state a conformity check expects.
export * from './managementAccess';
export * from './lteApn';
// Bringing a router in service up to the corrected customer templates (the
// `legacy_compliance` change job): the six statements, the allow-list that
// judges them, the plan read off the router and the expected read-back state.
export * from './legacyCompliance';
// Renaming a site's router (the `site_rename` change job): the PPP login on
// the CHR, the management tunnel's user, the identity, the device row — the
// alphabets, the three router lines and the allow-list that judges them.
export * from './siteRename';

// Attaching the online legacy routers the CHR reconciliation lists: closed
// reason codes the server answers in and the screen translates.
export * from './reconcileAttach';

// Quick Setup Tenant: one workspace prepared from its variables table, its
// template, its site list and its allocation rule, judged together and
// written in order. The formats and the pure helpers both sides run.
export * from './tenantSetup';

// A RouterOS API certificate the pool refused, and the re-pin to the
// fingerprint the server recorded as presented (never one typed in).
export * from './tlsPin';

// Recording the deployed LAN of existing (adopted) sites on their allocation:
// closed reason codes the server answers in and the screen translates.
export * from './lanReprise';

// Infrastructure analysis: the `x-obliwan-discover` probe grammar a template
// states on its site-level variables, its validator, and the types the
// read-only analysis of the routers in service answers in.
export * from './infraAnalysis';

// Each customer's INFRASTRUCTURE VPN concentrator (a RouterOS CHR or an
// OPNsense): the kinds, states and views, and the `infra_account` job kind.
export * from './infraConcentrator';

// The ACCESS LINK a site is declared with (migration 076): not declared (null,
// inferred as before), a fixed line with a 4G backup, or 4G only by design —
// which the 4G backup watch, the uplink card and the fleet anomalies read.
export * from './siteUplink';

// Learning mode (the one no-secrets exception, 2026-10-04): the flag, the capture's
// codes, the learned site facts, the break-risk report and the dataset.
export * from './learning';

// Brick 10 — the template extrapolator (proposals mined from a fleet's exports).
export * from './extrapolator';
// Collect a whole client's configurations in one gesture (its progress shape).
export * from './tenantCollect';
// The WAN1 link change job (dhcp / pppoe / static), migration 090.
export * from './wanLink';
// A PPP login with several sessions at once on its concentrator: ambiguous,
// listed by the reconciliation and refused by the attach and the tunnel jobs.
export * from './pppDuplicates';
// Verify, then re-apply, the management access and the template fixes over a
// whole workspace (the reconciliation page; migration 092).
export * from './accessCheck';
// The onboarding assistant (brick 14): step statuses recomputed from the
// database, and the allocation rule read off the CHR accounts.
export * from './onboarding';
// Store opening hours (migration 096): the weekly schedule and dated
// exceptions, workspace -> site, their readable text and their evaluation in
// the site's time zone.
export * from './openingHours';
// Line quality of a store's fixed line (migration 097): nightly pings through
// the fixed line, the night's verdict, the site's status and its views.
export * from './lineQuality';
// The grouped operator outage (migration 095): the site's « Opérateur du lien
// fixe », the provider inference, the wire shapes.
export * from './operatorOutage';
