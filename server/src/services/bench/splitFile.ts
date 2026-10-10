// ============================================================================
// ObliWAN — bench: the run-after-reset configuration as a RUNNER and SECTIONS
// ============================================================================
//
// Pure (no database, no vault). `compileForBox` answers this split form in
// `files` beside the legacy single file (`assembleCompiledFile`, kept for
// bench builds that predate `files`).
//
// ┌─ WHY THE BODY IS NO LONGER ONE BLOCK OF THE RUN-AFTER-RESET FILE ─────────┐
// │ RouterOS parses a whole script before running any of it: a syntax error  │
// │ anywhere and NOTHING runs (MikroTik forum, "Error handling in RouterOS 7 │
// │ Scripting", rextended: "if the script itself have bad syntax inside… is  │
// │ never run"). With the customer body inside the run-after-reset file, one │
// │ bad line of a template meant: no access block, no marker, and — the      │
// │ The secrets rule defect — no removal of the file that holds the          │
// │ credentials in clear. And one runtime error inside the body's single     │
// │ `:do { }` skipped every line after it.                                   │
// │                                                                          │
// │ So the run-after-reset target is a RUNNER that this module writes from   │
// │ constants only — tag, file names, byte counts, interface numbers; not   │
// │ one character of template text — and that therefore parses by           │
// │ construction. Each SECTION (the body cut at statement boundaries, then  │
// │ the ObliWAN access block, then the SNMP block) is a file of its own that │
// │ the runner reads with `/file get … contents`, checks for its exact byte  │
// │ count, turns into code with `:parse` and runs, all inside `:do { }       │
// │ on-error={ }`. A section that is missing, truncated, fails to parse or   │
// │ stops on an error is named in the marker and the next section still     │
// │ runs. The template's TAIL (after `# obliwan:tail`, the DHCP release) is  │
// │ a file too: read and `:parse`d BEFORE the cleanup — so a tail that does  │
// │ not parse is named in the marker, and can never stop the runner — and    │
// │ run LAST, from memory. Whatever happened, the runner then removes every │
// │ section file and the tail file, PROVES each one gone (a file still there │
// │ is named in the marker as `cleanup:<id>,` and logged), writes the       │
// │ marker, removes itself (it holds no credential: a failure there is only │
// │ logged), and runs the tail.                                              │
// │                                                                          │
// │ A section is proven complete by its LAST statement, which sets           │
// │ `obliwanSectionDone` to `<tag>:<section>`: a section that never got      │
// │ there — whatever the reason — is failed, never assumed.                  │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE EVIDENCE, AND WHAT IS ONLY REASONED ─────────────────────────────────┐
// │ - `:parse` defers a section's syntax to run time, where `on-error` can   │
// │   catch it: MikroTik forum, "Error handling?" (2019-03-09, damianivereigh)│
// │   "If you put the code that may have a syntax error into :parse, then    │
// │   you can execute that inside a do { } on-error={} and it will catch     │
// │   syntax errors too". The runner also puts the `:parse` itself inside    │
// │   the `:do`. `/import` is NOT used: MikroTik documents that its syntax   │
// │   errors can be caught only "starting from 7.16.x" (RouterOS manual,     │
// │   Scripting, "Import"), and a box on the bench may be older.             │
// │ - `/file get … contents` reads at most 61439 bytes on a recent RouterOS 7│
// │   and answers an EMPTY value with no error beyond it (MikroTik forum,    │
// │   "Max variable size and reading from or writing to files", 2025-04-13); │
// │   older builds stopped at 4095. Hence the exact byte-count check, and    │
// │   body sections cut at `SECTION_BUDGET_BYTES` (one statement larger than │
// │   that still makes a larger section: the count check names it if the box │
// │   truncates it). A file above `SECTION_READ_LIMIT_BYTES` can be read     │
// │   whole by NO build: the compile refuses it rather than ship a run that  │
// │   can only end `section-truncated`.                                      │
// │ - A code value made by `:parse`, kept in a variable and run later as     │
// │   `$var`, is how RouterOS scripts define functions (RouterOS manual,     │
// │   Scripting, "Functions"): the tail is parsed before the cleanup and run │
// │   after it that way.                                                     │
// │ - NOT observed on a box: that a parsed section run as `$code` sees the   │
// │   menu path lines it contains as a script source does; that a file can   │
// │   be removed while the runner runs (and the runner its own file); that   │
// │   `run-after-reset` runs the runner like any script. The bench harness   │
// │   runs runner and sections on a MODEL of the script engine               │
// │   (testing/fakeRouterOsScript.ts), which proves the files' own logic,    │
// │   not RouterOS.                                                          │
// └──────────────────────────────────────────────────────────────────────────┘
//
// A section that declares a variable at its top level (`:local`, `:global`,
// `:set`) would lose it in the next section (each `:parse`d section is a
// scope of its own), so a body holding one is kept as ONE section: still
// isolated from the runner, no longer cut.
//
// Device-mode: under a declared override, a statement using a feature the
// box's reading DENIES is wrapped to fail alone (`gatedUnitLines`). Nothing
// else is wrapped: a statement using a feature the reading allows or does
// not mention (an L2TP client on a box whose reading says nothing of l2tp)
// fails, if it fails, like any other statement — and is never reported as a
// device-mode failure, a label that would send a technician to the Reset
// button for nothing.

import crypto from 'node:crypto';
import { splitUnits, type BodyUnit } from './bodyFeatures';

export const PROVISION_PREFIX = 'obliwan-provision';
/** Set by a section's last statement to `<tag>:<section id>`. */
export const SECTION_SENTINEL = 'obliwanSectionDone';
/** The device-mode-gated statements that failed, `feature@section,` each. */
export const GATED_GLOBAL = 'obliwanGated';
/** Comment lines only this module writes. */
export const RUNNER_HEADER = '# obliwan-compiled v2 runner';
export const SECTION_HEADER = '# obliwan-section';
/** Below the 4095-byte `/file get … contents` limit of older RouterOS builds,
 *  with room for the section's own header, menu line and sentinel. */
export const SECTION_BUDGET_BYTES = 3500;
/** The most `/file get … contents` reads on a recent RouterOS 7 (header): a
 *  file larger than this can be read whole by no build. */
export const SECTION_READ_LIMIT_BYTES = 61439;

/** The most files a bench build accepts for one compile (bench/benchApi.ts).
 *  Above it the bench answers "files illisible" and nothing is done. */
export const MAX_COMPILED_FILES = 20;
/** The tail file's id: `<runner>-tail.rsc`. */
export const TAIL_FILE_ID = 'tail';

export interface CompiledFile {
  name: string;
  content: string;
  sha256: string;
  role: 'runner' | 'body';
}

export interface CompiledSection extends CompiledFile {
  /** `b01`, `b02`… for the body, then `access`, `snmp` when written, and
   *  `tail` when the template has one (read, never run, before the cleanup). */
  id: string;
}

function sha256(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function bytes(lines: readonly string[]): number {
  return lines.reduce((n, l) => n + Buffer.byteLength(l, 'utf8') + 1, 0);
}

const NOTHING_GATED: ReadonlySet<string> = new Set();

/**
 * One statement as lines: verbatim, or — when it uses a feature of `gated`
 * (the features the box's reading DENIES, compiled under a declared
 * override) — inside its own `:do { } on-error={ }`, preceded by its menu
 * path when it is written relative to one, so that the box refusing the
 * feature fails THAT statement alone. The failure is recorded in
 * `obliwanGated` (which the marker reads: the run is then FAILED, naming the
 * feature and the section) and logged. A declaration is never wrapped: the
 * block would scope it away.
 */
export function gatedUnitLines(unit: BodyUnit, where: string, tag: string, gated: ReadonlySet<string> = NOTHING_GATED): string[] {
  const hits = unit.features.filter((f) => gated.has(f));
  if (hits.length === 0 || unit.kind !== 'command') return unit.lines;
  const what = hits.join('+');
  return [
    ':do {',
    ...(unit.relative && unit.menuLine !== null ? [unit.menuLine] : []),
    ...unit.lines,
    `} on-error={ :global ${GATED_GLOBAL}; :set ${GATED_GLOBAL} ($${GATED_GLOBAL} . "${what}@${where},"); `
      + `:log error "${PROVISION_PREFIX} detail tag=${tag} reason=device-mode-gated feature=${what} section=${where}" }`,
  ];
}

/** The head's statements with every gated one wrapped (the legacy file):
 *  the head itself, line for line, when `gated` is empty. */
export function gatedHeadLines(head: string[], where: string, tag: string, gated: ReadonlySet<string> = NOTHING_GATED): string[] {
  if (gated.size === 0) return head;
  return splitUnits(head).flatMap((u) => gatedUnitLines(u, where, tag, gated));
}

/**
 * The body cut into sections at statement boundaries, each at most
 * `budget` bytes of statements when its statements allow it. A section that
 * starts in the middle of a menu — a relative command (`add …`) before any
 * path line of its own — starts with the menu path in effect there, and only
 * then: a line taken for a path is never replayed where nothing needs it.
 */
export function bodySections(
  head: string[], tag: string, gated: ReadonlySet<string> = NOTHING_GATED, budget = SECTION_BUDGET_BYTES,
): Array<{ id: string; lines: string[] }> {
  const units = splitUnits(head);
  const single = units.some((u) => u.kind === 'declaration');
  const out: Array<{ id: string; lines: string[] }> = [];
  let cur: { units: BodyUnit[]; size: number; code: boolean } | null = null;
  const flush = (): void => {
    if (cur === null) return;
    const id = `b${String(out.length + 1).padStart(2, '0')}`;
    const firstPath = cur.units.findIndex((u) => u.kind === 'path');
    const beforePath = firstPath < 0 ? cur.units : cur.units.slice(0, firstPath);
    const needs = beforePath.find((u) => u.kind === 'command' && u.relative);
    out.push({
      id,
      lines: [
        ...(needs !== undefined && needs.menuLine !== null ? [needs.menuLine] : []),
        ...cur.units.flatMap((u) => gatedUnitLines(u, id, tag, gated)),
      ],
    });
    cur = null;
  };
  for (const u of units) {
    // Measured as written: a gated statement carries its wrapper.
    const size = bytes(gatedUnitLines(u, 'b00', tag, gated));
    if (cur !== null && !single && cur.code && cur.size + size > budget) flush();
    if (cur === null) cur = { units: [], size: 0, code: false };
    cur.units.push(u);
    cur.size += size;
    if (u.kind !== 'blank' && u.kind !== 'comment') cur.code = true;
  }
  flush();
  return out;
}

export interface SplitInput {
  tag: string;
  /** The run-after-reset target: the legacy file's own name. */
  runnerName: string;
  prelude: string[];
  head: string[];
  /** The ObliWAN access block, with its own `:do` and sentinel. */
  access: string[];
  accessSentinel: string;
  /** The historical accounts and the MAC/RoMON reopening, each statement
   *  isolated; empty = no section. */
  accounts?: string[];
  /** The SNMP block, or null when the tenant names no community. */
  snmp: string[] | null;
  snmpSentinel: string;
  tailMarker: string;
  /** The template's tail: a file of its own, parsed before the cleanup and
   *  run last, from memory (header). */
  tail: string[];
  /** The features the box's reading denies, compiled under a declared
   *  override: their statements are wrapped (`gatedUnitLines`). */
  gated?: readonly string[];
}

function sectionFile(runnerName: string, tag: string, id: string, lines: string[]): CompiledSection {
  const name = `${runnerName.replace(/\.rsc$/, '')}-${id}.rsc`;
  const content = `${[`${SECTION_HEADER} ${id} tag=${tag}`, ...lines, `:global ${SECTION_SENTINEL} "${tag}:${id}"`].join('\n')}\n`;
  return { id, name, content, sha256: sha256(content), role: 'body' };
}

/** The tail as a file: no sentinel — it runs after the marker, and what the
 *  marker can know of it is whether it was read whole and parses. */
function tailFile(runnerName: string, tag: string, tailMarker: string, tail: string[]): CompiledSection {
  const name = `${runnerName.replace(/\.rsc$/, '')}-${TAIL_FILE_ID}.rsc`;
  const content = `${[`${SECTION_HEADER} ${TAIL_FILE_ID} tag=${tag}`, tailMarker, ...tail].join('\n')}\n`;
  return { id: TAIL_FILE_ID, name, content, sha256: sha256(content), role: 'body' };
}

const findFile = (name: string): string => `/file find where name="${name}" or name="flash/${name}"`;

/** Runner lines, inside a `:do`, that leave the text of `s` in local
 *  `obliwanText` — or stop with an error, logged, when the file is missing,
 *  ambiguous or not read whole. */
function readFileLines(tag: string, s: CompiledSection, what: 'section' | 'tail'): string[] {
  const detail = `${PROVISION_PREFIX} detail tag=${tag}`;
  return [
    `:local obliwanIds [${findFile(s.name)}]`,
    `:if ([:len $obliwanIds] = 0) do={ :log error "${detail} reason=${what}-missing section=${s.id}"; :error "${what} missing" }`,
    `:if ([:len $obliwanIds] > 1) do={ :log error "${detail} reason=${what}-ambiguous section=${s.id}"; :error "${what} ambiguous" }`,
    ':local obliwanText [/file get [:pick $obliwanIds 0] contents]',
    `:if ([:len $obliwanText] != ${Buffer.byteLength(s.content, 'utf8')}) do={ :log error "${detail} reason=${what}-truncated section=${s.id}"; :error "${what} truncated" }`,
  ];
}

/** The runner lines that read, parse and run one section. */
function runSectionLines(tag: string, s: CompiledSection): string[] {
  const detail = `${PROVISION_PREFIX} detail tag=${tag}`;
  return [
    `# section ${s.id}`,
    `:set ${SECTION_SENTINEL} ""`,
    ':do {',
    ...readFileLines(tag, s, 'section'),
    ':local obliwanCode [:parse $obliwanText]',
    '$obliwanCode',
    `} on-error={ :log error "${detail} reason=section-failed section=${s.id}" }`,
    `:global ${SECTION_SENTINEL}`,
    `:if ($${SECTION_SENTINEL} != "${tag}:${s.id}") do={ :set obliwanFailed ($obliwanFailed . "${s.id},") }`,
  ];
}

/** The runner and its files, in upload order (runner first): the body
 *  sections, access, snmp when written, then the tail when there is one. */
export function assembleSplitFiles(input: SplitInput): { runner: CompiledFile; sections: CompiledSection[] } {
  const { tag } = input;
  const gated = new Set(input.gated ?? []);
  const detail = `${PROVISION_PREFIX} detail tag=${tag}`;
  const runnable: CompiledSection[] = [
    ...bodySections(input.head, tag, gated).map((s) => sectionFile(input.runnerName, tag, s.id, s.lines)),
    sectionFile(input.runnerName, tag, 'access', input.access),
    ...((input.accounts ?? []).length > 0 ? [sectionFile(input.runnerName, tag, 'accounts', input.accounts ?? [])] : []),
    ...(input.snmp !== null ? [sectionFile(input.runnerName, tag, 'snmp', input.snmp)] : []),
  ];
  const tail = input.tail.length > 0 ? tailFile(input.runnerName, tag, input.tailMarker, input.tail) : null;
  const sections = tail !== null ? [...runnable, tail] : runnable;
  const snmp = input.snmp !== null;
  const remove = (name: string, onError = ''): string =>
    `:do { /file remove [find where name="${name}" or name="flash/${name}"] } on-error={${onError}}`;
  const lines: string[] = [
    `${RUNNER_HEADER} tag=${tag}`,
    '# Compiled by ObliWAN for /system reset-configuration run-after-reset. This runner holds no',
    '# credential: it runs each section file of this provisioning on its own, then removes them all.',
    `:log info "${PROVISION_PREFIX} start tag=${tag}"`,
    `:global ${input.accessSentinel} ""`,
    `:global ${input.snmpSentinel} ""`,
    `:global ${SECTION_SENTINEL} ""`,
    `:global ${GATED_GLOBAL} ""`,
    ':local obliwanFailed ""',
    ...input.prelude,
    '# 2. The sections, in order: the customer configuration, then the ObliWAN access.',
    ...runnable.flatMap((s) => runSectionLines(tag, s)),
    ...(tail === null ? [] : [
      '# 3. The template tail: read and parsed now, so a tail that does not parse is named in the marker; run last.',
      ':local obliwanTailCode',
      ':local obliwanTailReady false',
      ':do {',
      ...readFileLines(tag, tail, 'tail'),
      ':set obliwanTailCode [:parse $obliwanText]',
      ':set obliwanTailReady true',
      `} on-error={ :log error "${detail} reason=tail-unusable section=${tail.id}"; :set obliwanFailed ($obliwanFailed . "${tail.id},") }`,
    ]),
    '# 4. Every file the runner read is removed, then proven gone: the sections hold credentials in clear.',
    ...sections.map((s) => remove(s.name)),
    ':local obliwanLeft ""',
    ':do {',
    ...sections.map((s) => `:if ([:len [${findFile(s.name)}]] > 0) do={ :set obliwanLeft ($obliwanLeft . "${s.id},") }`),
    '} on-error={ :set obliwanLeft ($obliwanLeft . "unverified,") }',
    `:if ([:len $obliwanLeft] > 0) do={ :log error ("${detail} reason=cleanup-failed files=" . $obliwanLeft); :set obliwanFailed ($obliwanFailed . "cleanup:" . $obliwanLeft) }`,
    '# 5. Marker: ok only when every section, block and gated statement completed and every file is gone.',
    ':do {',
    `:global ${input.accessSentinel}`,
    `:global ${input.snmpSentinel}`,
    `:global ${GATED_GLOBAL}`,
    `:if ($${input.accessSentinel} != "${tag}") do={ :set obliwanFailed ($obliwanFailed . "access-block,") }`,
    ...(snmp ? [`:if ($${input.snmpSentinel} != "${tag}") do={ :set obliwanFailed ($obliwanFailed . "snmp-block,") }`] : []),
    `:if ([:len $${GATED_GLOBAL}] > 0) do={ :set obliwanFailed ($obliwanFailed . "device-mode:" . $${GATED_GLOBAL}) }`,
    '} on-error={ :set obliwanFailed ($obliwanFailed . "marker,") }',
    ':if ([:len $obliwanFailed] = 0) do={',
    `:log info "${PROVISION_PREFIX} ok tag=${tag}"`,
    `:do { /system script add name="${PROVISION_PREFIX}-ok-${tag}" comment="${PROVISION_PREFIX} ok tag=${tag}" source="" } on-error={}`,
    '} else={',
    `:log error ("${PROVISION_PREFIX} FAILED tag=${tag} sections=" . $obliwanFailed)`,
    `:do { /system script add name="${PROVISION_PREFIX}-failed-${tag}" comment=("${PROVISION_PREFIX} FAILED tag=${tag} sections=" . $obliwanFailed) source="" } on-error={}`,
    '}',
    '# 6. The runner holds no credential: it removes itself (a failure is only logged), then the template tail runs, last.',
    remove(input.runnerName, ` :log warning "${detail} reason=runner-left" `),
    ...(tail === null ? [] : [
      `:if ($obliwanTailReady = true) do={ :do { $obliwanTailCode } on-error={ :log error "${detail} reason=tail-failed section=${tail.id}" } }`,
    ]),
  ];
  const content = `${lines.join('\n')}\n`;
  return { runner: { name: input.runnerName, content, sha256: sha256(content), role: 'runner' }, sections };
}
