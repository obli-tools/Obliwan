/**
 * ObliWAN — the infrastructure concentrator driver registry: one driver per
 * kind, closed. Tomorrow's OPNsense work replaces the body of
 * `opnsense.driver.ts` and flips its `writesImplemented`; nothing here moves.
 */

import type { InfraConcentratorKind } from '@obliwan/shared';
import { opnsenseDriver } from './opnsense.driver';
import { routerosChrDriver } from './routerosChr.driver';
import type { InfraConcentratorDriver } from './types';

const DRIVERS: Readonly<Record<InfraConcentratorKind, InfraConcentratorDriver>> = Object.freeze({
  routeros_chr: routerosChrDriver,
  opnsense: opnsenseDriver,
});

export function driverFor(kind: InfraConcentratorKind): InfraConcentratorDriver {
  const d = DRIVERS[kind];
  if (!d) throw new Error(`no infrastructure concentrator driver for kind ${String(kind)}`);
  return d;
}
