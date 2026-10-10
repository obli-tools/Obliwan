import type { SftpUploadFn, SftpUploadRequest } from './routerosApply';

/**
 * ObliWAN bench — put a file on a RouterOS box over SFTP (ssh2).
 *
 * ┌─ WHY SFTP ───────────────────────────────────────────────────────────────┐
 * │ The RouterOS upgrade pushes `.npk` packages of up to tens of MB. The     │
 * │ API's `/file/add contents=` carries a string in one sentence: fine for a │
 * │ configuration script, not for megabytes of binary. FTP would do it, in   │
 * │ cleartext, with the factory password on the wire, and it is a service    │
 * │ RouterOS ships enabled only for that reason. SSH is enabled on a factory │
 * │ RouterOS 7 box, takes the same factory account, and SFTP is part of it.  │
 * │ It is also the provisioning upload's fallback (`applyFactoryProvisioning`│
 * │ in routerosApply.ts) when `/file/add` refuses or keeps a cut file.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE HOST KEY IS NOT CHECKED, AND THAT IS NOT WHERE THE PROOF IS ────────┐
 * │ A factory box generates its SSH host key on first boot: there is nothing │
 * │ to pin it against. Which box received the file is proven on the RouterOS │
 * │ API session that took the MAC proof — `withProvenSession` for the        │
 * │ upgrade, `applyFactoryProvisioning`'s own for the provisioning — kept    │
 * │ open across this upload: the caller lists `/file` THERE and refuses      │
 * │ unless every file it sent is on that box at the size it sent (and, for   │
 * │ the provisioning, reads each one back when RouterOS shows it whole).     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The file is written with OPEN (write, create, truncate — a leftover of the
 * same name is replaced, never appended to), sequential 32 KiB WRITEs with a
 * few in flight, then CLOSE. No chmod, no stat, no rename: the fewest SFTP
 * operations a minimal server must implement. SSH's own MAC protects every
 * byte in transit; the size check on the API session is the proof of arrival.
 *
 * REASONED, NOT OBSERVED: the RouterOS SFTP server has not been driven by
 * this code. `testing/routerosUpgrade.verify.ts` drives it against a real
 * ssh2 SFTP server, which proves the client, not RouterOS's server.
 *
 * ssh2 is loaded lazily: the bench imports this module at start, and the
 * library is only needed when a file goes up by SFTP. Its two optional native helpers
 * (`cpu-features`, `sshcrypto.node`) are `require`d inside try/catch and are
 * absent from the SEA bundle; ssh2 then runs on Node's own crypto.
 */

const CHUNK = 32 * 1024;
const IN_FLIGHT = 8;

type SftpLike = {
  open(path: string, flags: string, cb: (err: Error | undefined, handle: Buffer) => void): void;
  write(handle: Buffer, buf: Buffer, off: number, len: number, pos: number, cb: (err?: Error) => void): void;
  close(handle: Buffer, cb: (err?: Error) => void): void;
};

type ClientLike = {
  on(event: string, listener: (...args: any[]) => void): ClientLike; // eslint-disable-line @typescript-eslint/no-explicit-any
  connect(cfg: Record<string, unknown>): void;
  sftp(cb: (err: Error | undefined, sftp: SftpLike) => void): void;
  end(): void;
};

async function ssh2Client(): Promise<new () => ClientLike> {
  // ssh2 is CommonJS: under tsx `Client` is a named export, in the esbuild CJS
  // bundle it hangs off the module object. Both shapes are accepted.
  const mod = (await import('ssh2')) as unknown as Record<string, unknown>;
  const ns = (mod.default as Record<string, unknown> | undefined) ?? mod;
  const Client = (ns.Client ?? mod.Client) as (new () => ClientLike) | undefined;
  if (typeof Client !== 'function') throw new Error('ssh2 Client introuvable dans cet exécutable');
  return Client;
}

/** Writes `content` at `handle`, `IN_FLIGHT` chunks at a time, in order of offset. */
function writeAll(sftp: SftpLike, handle: Buffer, content: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    let next = 0;
    let pending = 0;
    let failed = false;
    const pump = (): void => {
      if (failed) return;
      if (next >= content.length && pending === 0) {
        resolve();
        return;
      }
      while (pending < IN_FLIGHT && next < content.length) {
        const at = next;
        const len = Math.min(CHUNK, content.length - at);
        next += len;
        pending++;
        sftp.write(handle, content, at, len, at, (err) => {
          pending--;
          if (err) {
            if (!failed) {
              failed = true;
              reject(err);
            }
            return;
          }
          pump();
        });
      }
    };
    pump();
  });
}

/** The default `SftpUploadFn`: one SSH connection per file, closed afterwards. */
export const sftpUploadOverSsh: SftpUploadFn = async (req: SftpUploadRequest) => {
  const Client = await ssh2Client();
  await new Promise<void>((resolve, reject) => {
    const client = new Client();
    let settled = false;
    const finish = (err?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        client.end();
      } catch {
        /* already gone */
      }
      if (err) reject(err);
      else resolve();
    };
    const timer = setTimeout(() => finish(new Error(`pas de fin de transfert en ${Math.round(req.timeoutMs / 1000)} s`)), req.timeoutMs);
    client
      .on('ready', () => {
        client.sftp((err, sftp) => {
          if (err) return finish(err);
          sftp.open(req.remotePath, 'w', (openErr, handle) => {
            if (openErr) return finish(openErr);
            writeAll(sftp, handle, req.content).then(
              () => sftp.close(handle, (closeErr) => finish(closeErr)),
              (writeErr: Error) => sftp.close(handle, () => finish(writeErr)),
            );
          });
        });
      })
      .on('keyboard-interactive', (_name: string, _instr: string, _lang: string, prompts: unknown[], answer: (r: string[]) => void) => {
        // Some RouterOS builds offer keyboard-interactive before password.
        answer(prompts.map(() => req.password));
      })
      .on('error', (err: Error) => finish(err))
      .on('close', () => finish(new Error('connexion SSH fermée avant la fin du transfert')));
    client.connect({
      host: req.host,
      port: req.port,
      username: req.username,
      password: req.password,
      tryKeyboard: true,
      readyTimeout: Math.min(req.timeoutMs, 20_000),
      // The bench link the box sits on (slots.ts): the same source as the API session.
      ...(req.localAddress ? { localAddress: req.localAddress } : {}),
      // See the header: a factory box's host key has nothing to be pinned to.
      hostVerifier: () => true,
    });
  });
};
