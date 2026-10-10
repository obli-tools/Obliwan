import { argv, exit } from 'node:process';
import { writeFileSync } from 'node:fs';
import { logError, showMessageBox } from './window';

/**
 * ObliWAN bench — the entry point of a WINDOWS GUI application.
 *
 * ┌─ THERE IS NO CONSOLE ────────────────────────────────────────────────────┐
 * │ build.mjs patches the executable's PE header to the Windows GUI          │
 * │ subsystem, so double-clicking it opens no console window — and so there  │
 * │ is no console to print a failure into, nor a key to wait for. Node gives │
 * │ a console-less process black-hole stdout/stderr streams (and an empty    │
 * │ stdin), so a stray `console.log` is harmless; but an error printed there │
 * │ is an error nobody sees. Every failure therefore ends in a native        │
 * │ message box and a line in %LOCALAPPDATA%\ObliWAN\bench-error.log.        │
 * │ `window.ts` is imported statically because it has no side effect; every  │
 * │ other module loads after the two handlers below are in place.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ --cli IS GONE, AND SAYS SO ─────────────────────────────────────────────┐
 * │ The prompt-by-prompt mode needed a console: in a GUI-subsystem process   │
 * │ its prompts would go nowhere and its input would never come. It was also │
 * │ the engineer flow (family, port, factory account) the application        │
 * │ replaces. `--cli` now shows a message box saying it was removed, and     │
 * │ exits with code 2.                                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Two switches remain for the build and for support, neither opens a window:
 *   --version            writes the version on stdout (seen through a pipe).
 *   --self-test <file>   writes to stdout and stderr — which, launched with no
 *                        console, must not crash — then writes "ok <version>"
 *                        into <file>. build.mjs runs it on the patched copy.
 */

declare const __BENCH_VERSION__: string | undefined;
const VERSION = typeof __BENCH_VERSION__ === 'string' ? __BENCH_VERSION__ : '0.0.0';
const TITLE = 'ObliWAN — Préparation des routeurs';

let failing = false;
function fatal(what: string, err: unknown): void {
  if (failing) return;
  failing = true;
  const detail = err instanceof Error ? err.message : String(err);
  const log = logError(`${what}: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  void showMessageBox(
    TITLE,
    `${what}\n\n${detail}\n\nOutil d'établi ObliWAN v${VERSION}.`
      + (log ? `\nLe détail est enregistré dans ${log}.` : ''),
  ).then(() => exit(1));
}

process.on('uncaughtException', (err: unknown) => fatal('L\'application s\'est arrêtée de façon imprévue.', err));
process.on('unhandledRejection', (reason: unknown) => fatal('Une opération a échoué sans être traitée.', reason));

async function start(): Promise<void> {
  if (argv.includes('--version')) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  const selfTest = argv.indexOf('--self-test');
  if (selfTest >= 0) {
    const target = argv[selfTest + 1];
    console.log('self-test: stdout');
    console.error('self-test: stderr');
    process.stdout.write('self-test: write\n');
    if (target) writeFileSync(target, `ok ${VERSION}\n`, 'utf8');
    return;
  }
  if (argv.includes('--cli')) {
    await showMessageBox(
      TITLE,
      'Le mode console (--cli) a été retiré : l\'outil d\'établi est désormais une application à fenêtre, '
        + 'sans console où écrire ni lire. Lancez-le sans option, depuis son raccourci.',
      'info',
    );
    exit(2);
  }
  const { runGui } = await import('./gui');
  await runGui();
}

start().catch((err: unknown) => fatal('L\'application n\'a pas pu démarrer.', err));
