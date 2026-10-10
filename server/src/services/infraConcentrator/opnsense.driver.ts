/**
 * ObliWAN — infrastructure concentrator driver: an OPNsense firewall
 * terminating one IPsec tunnel per store (customers D and E).
 *
 * TONIGHT ONLY THE CONNECTION TEST IS REAL. Plan, apply, revoke (and the read
 * of a site's tunnel) refuse with NOT_IMPLEMENTED_YET: today the tunnels are
 * mass-provisioned by the operator's PowerShell scripts, and their model
 * (legacy phase1/phase2 or 23.x "connections", what identifies a store, which
 * PSK) is read from those scripts tomorrow — not invented here.
 *
 * ┌─ THE CALLS, AND WHY THEY ARE REASONED, NOT OBSERVED ───────────────────────┐
 * │ None of this has met a real OPNsense. From the public API documentation:  │
 * │   - authentication: HTTP Basic, the API KEY as user and the API SECRET as │
 * │     password, over HTTPS;                                                 │
 * │   - GET /api/ipsec/connections/search_connection  (23.1+ "Connections")   │
 * │   - GET /api/ipsec/tunnel/search_phase1           (legacy tunnels)        │
 * │ Both are READS. 401 = key/secret refused; 403 = authenticated, but the    │
 * │ API user lacks the IPsec privilege; 404 = the endpoint does not exist on  │
 * │ that version; 200 = a JSON page `{ rows, rowCount, total, current }`.     │
 * │ The list is closed: nothing else is ever requested, and no verb but GET.  │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE CERTIFICATE IS PINNED, AND THE PIN IS CHECKED BEFORE ANY CREDENTIAL ──┐
 * │ RouterOS's rule (transport/routeros/connection.ts): trust on first use,   │
 * │ then any change is a hard refusal. The TLS socket is opened HERE, its     │
 * │ certificate's SHA-256 compared with `tls_fingerprint_sha256`, and only    │
 * │ then is the HTTP request — the Authorization header — written onto that  │
 * │ same socket. Not `RestTransport`'s pin: its `checkServerIdentity` is never │
 * │ called for a self-signed certificate under `rejectUnauthorized: false`    │
 * │ (Node skips the identity check once chain verification failed), so a     │
 * │ wrong pin is accepted there.                                              │
 * │ A first test with no pin records the presented fingerprint and says so;  │
 * │ the operator can compare it with the firewall's (System > Trust) or set   │
 * │ the pin beforehand when declaring the concentrator.                       │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import crypto from 'crypto';
import http from 'http';
import net from 'net';
import tls from 'tls';
import type { InfraDriverResult } from '@obliwan/shared';
import { pinFingerprintIfUnset, revealOpnsenseCredential, getInfraConcentratorRow } from './store';
import {
  InfraConcentratorError,
  NOT_IMPLEMENTED_YET,
  type InfraConcentratorDriver,
  type InfraConcentratorRow,
} from './types';

export const OPNSENSE_NOT_IMPLEMENTED_MESSAGE =
  "Pas encore implémenté pour OPNsense : la lecture, la création et le retrait des tunnels IPsec par site seront " +
  "écrits après l'analyse des scripts PowerShell de provisionnement de masse (clients D et E) que " +
  "l'opérateur apporte le 2026-10-06. Rien n'a été lu ni écrit sur le pare-feu ; seul le test de connexion " +
  'est disponible.';

/** The closed call list (header). REASONED from the public documentation. */
export const OPNSENSE_TEST_CALLS: ReadonlyArray<{ path: string; label: string }> = Object.freeze([
  { path: '/api/ipsec/connections/search_connection', label: 'connexions IPsec (OPNsense 23.1 et suivants)' },
  { path: '/api/ipsec/tunnel/search_phase1', label: 'tunnels IPsec phase 1 (API historique)' },
]);

const TIMEOUT_MS = 10_000;
const MAX_BODY = 1_000_000;

class PinMismatch extends Error {
  constructor(readonly pinned: string, readonly presented: string) {
    super('certificate fingerprint mismatch');
  }
}

/** Open a TLS socket and return it with the SHA-256 of the certificate the
 *  server presented. Nothing is written on it. */
function openTls(host: string, port: number): Promise<{ socket: tls.TLSSocket; fingerprint: string }> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      // The certificate of an appliance is self-signed: the chain cannot be
      // verified, so the PIN is what authenticates it (checked by the caller
      // before anything is written).
      rejectUnauthorized: false,
      servername: net.isIP(host) ? undefined : host,
      timeout: TIMEOUT_MS,
    });
    const fail = (err: Error): void => {
      socket.destroy();
      reject(err);
    };
    socket.once('error', fail);
    socket.once('timeout', () => fail(new Error(`TLS handshake with ${host}:${port} timed out`)));
    socket.once('secureConnect', () => {
      const raw = socket.getPeerCertificate(false)?.raw;
      if (!raw || raw.length === 0) {
        fail(new Error('the server presented no certificate'));
        return;
      }
      socket.removeListener('error', fail);
      socket.setTimeout(0);
      resolve({ socket, fingerprint: crypto.createHash('sha256').update(raw).digest('hex') });
    });
  });
}

/** One GET over a socket whose certificate was ALREADY checked against the pin. */
function getOver(
  socket: tls.TLSSocket,
  host: string,
  path: string,
  authorization: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        method: 'GET',
        host,
        path,
        headers: { Authorization: authorization, Accept: 'application/json', Connection: 'close' },
        createConnection: () => socket,
        timeout: TIMEOUT_MS,
      },
      (res) => {
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size <= MAX_BODY) chunks.push(c);
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error(`GET ${path} timed out`)));
    req.on('error', reject);
    req.end();
  });
}

function rowCount(body: string): number | null {
  try {
    const j = JSON.parse(body) as { rows?: unknown; rowCount?: unknown; total?: unknown };
    if (typeof j.total === 'number') return j.total;
    if (Array.isArray(j.rows)) return j.rows.length;
    if (typeof j.rowCount === 'number') return j.rowCount;
  } catch {
    /* not JSON: counted as unknown */
  }
  return null;
}

/** Remove the credential from a text before it can reach a column. */
function scrubAll(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 4) out = out.split(s).join('***');
  return out;
}

async function testOpnsense(c: InfraConcentratorRow): Promise<InfraDriverResult & { fingerprint?: string | null }> {
  let cred: { key: string; secret: string };
  try {
    cred = revealOpnsenseCredential(c);
  } catch (err) {
    return { ok: false, code: 'NO_CREDENTIAL', message: err instanceof Error ? err.message : String(err), details: [] };
  }
  const basic = Buffer.from(`${cred.key}:${cred.secret}`, 'utf8').toString('base64');
  const secrets = [cred.key, cred.secret, basic];
  const port = c.port ?? 443;
  const details: string[] = [];
  let pin = c.tls_fingerprint_sha256;
  let presented: string | null = null;

  for (const call of OPNSENSE_TEST_CALLS) {
    let opened: { socket: tls.TLSSocket; fingerprint: string };
    try {
      opened = await openTls(c.host, port);
    } catch (err) {
      return {
        ok: false,
        code: 'UNREACHABLE',
        message: `Connexion TLS impossible vers ${c.host}:${port} : ${scrubAll(err instanceof Error ? err.message : String(err), secrets)}`,
        details,
        fingerprint: presented,
      };
    }
    presented = opened.fingerprint;
    try {
      if (pin === null) {
        // Trust on first use, recorded BEFORE the credential is sent; a pin
        // written meanwhile by another test wins and is compared below.
        await pinFingerprintIfUnset(c.id, presented);
        pin = (await getInfraConcentratorRow(c.id)).tls_fingerprint_sha256;
        if (pin === presented) {
          details.push(`Empreinte du certificat épinglée à la première connexion : ${presented}. Comparez-la avec celle du pare-feu.`);
        }
      }
      if (pin !== presented) throw new PinMismatch(pin ?? '', presented);
      const res = await getOver(opened.socket, c.host, call.path, `Basic ${basic}`);
      if (res.status === 401) {
        return {
          ok: false,
          code: 'AUTH_REFUSED',
          message: "OPNsense a refusé la clé et le secret d'API (HTTP 401) : vérifiez-les, puis enregistrez-les à nouveau.",
          details,
          fingerprint: presented,
        };
      }
      if (res.status === 200) {
        const n = rowCount(res.body);
        details.push(`GET ${call.path} — ${call.label} : HTTP 200, ${n === null ? 'réponse non JSON' : `${n} entrée(s)`}.`);
      } else if (res.status === 403) {
        details.push(`GET ${call.path} — ${call.label} : HTTP 403, l'utilisateur d'API n'a pas le privilège IPsec correspondant.`);
      } else if (res.status === 404) {
        details.push(`GET ${call.path} — ${call.label} : HTTP 404, absent sur cette version d'OPNsense.`);
      } else {
        details.push(`GET ${call.path} — ${call.label} : HTTP ${res.status}.`);
      }
    } catch (err) {
      if (err instanceof PinMismatch) {
        return {
          ok: false,
          code: 'TLS_PIN_MISMATCH',
          message:
            `Le certificat présenté par ${c.host}:${port} (SHA-256 ${err.presented}) n'est pas celui qui est épinglé ` +
            `(${err.pinned}). Aucun identifiant n'a été envoyé. Si le certificat du pare-feu a été renouvelé, ` +
            "effacez l'empreinte épinglée puis relancez le test ; sinon, quelqu'un est peut-être sur le chemin.",
          details,
          fingerprint: presented,
        };
      }
      return {
        ok: false,
        code: 'ERROR',
        message: `Échec de l'appel à ${c.host}:${port} : ${scrubAll(err instanceof Error ? err.message : String(err), secrets)}`,
        details,
        fingerprint: presented,
      };
    } finally {
      opened.socket.destroy();
    }
  }
  const any200 = details.some((d) => d.includes('HTTP 200'));
  const all404 = details.every((d) => d.includes('HTTP 404'));
  if (any200) {
    return { ok: true, code: 'OK', message: `Connexion à l'API OPNsense de ${c.name} établie : clé acceptée, certificat épinglé.`, details, fingerprint: presented };
  }
  if (all404) {
    return { ok: false, code: 'API_NOT_FOUND', message: "La clé est acceptée, mais aucun des deux points d'API IPsec n'existe sur ce pare-feu.", details, fingerprint: presented };
  }
  return {
    ok: false,
    code: 'PRIVILEGE_MISSING',
    message: "La clé est acceptée, mais l'utilisateur d'API n'a accès à aucune liste IPsec : ajoutez-lui le privilège IPsec.",
    details,
    fingerprint: presented,
  };
}

function notYet(): never {
  throw new InfraConcentratorError(NOT_IMPLEMENTED_YET, OPNSENSE_NOT_IMPLEMENTED_MESSAGE, 501);
}

export const opnsenseDriver: InfraConcentratorDriver = {
  kind: 'opnsense',
  writesImplemented: false,
  testConnection: testOpnsense,
  async readSiteEntry(c, site) {
    return {
      concentratorId: c.id, siteId: site.siteId, action: 'ensure', decision: 'refused', identifier: null,
      message: OPNSENSE_NOT_IMPLEMENTED_MESSAGE, reasons: [], observed: [], code: NOT_IMPLEMENTED_YET,
    };
  },
  async plan(c, site, action) {
    return {
      concentratorId: c.id, siteId: site.siteId, action, decision: 'refused', identifier: null,
      message: OPNSENSE_NOT_IMPLEMENTED_MESSAGE, reasons: [], observed: [], code: NOT_IMPLEMENTED_YET,
    };
  },
  async apply() {
    return notYet();
  },
  async revoke() {
    return notYet();
  },
  async verify() {
    return notYet();
  },
};
