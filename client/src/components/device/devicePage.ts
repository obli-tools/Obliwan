/**
 * The device page's addresses: its tabs, and the « État » sections of its
 * overview that a status chip can open.
 */

export const DEVICE_TAB_IDS = [
  'overview', 'sim', 'interfaces', 'config', 'drift',
  'changes', 'backups', 'acs', 'logs', 'settings',
] as const;

export type DeviceTabId = (typeof DEVICE_TAB_IDS)[number];

export function isDeviceTabId(value: string | null): value is DeviceTabId {
  return value !== null && (DEVICE_TAB_IDS as readonly string[]).includes(value);
}

export type OverviewSectionId =
  | 'identity' | 'reachability' | 'management' | 'compliance' | 'uplink' | 'sim' | 'template';

/** Where a chip leads: a tab, and on the overview the section that explains it. */
export interface PageTarget {
  tab: DeviceTabId;
  section?: OverviewSectionId;
}

/** A chip click: the nonce changes on every click, so clicking the same chip
 *  twice scrolls back to a section the operator has scrolled away from. */
export interface SectionFocus {
  section: OverviewSectionId;
  nonce: number;
}
