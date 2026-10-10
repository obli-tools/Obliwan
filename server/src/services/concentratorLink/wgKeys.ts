/**
 * ObliWAN — WireGuard key pairs, generated in-process.
 *
 * A WireGuard key is 32 bytes of Curve25519, written base64 (44 characters).
 * Node's crypto speaks X25519 natively, so no `wg genkey` subprocess is needed
 * on the server (whose image has the tool only for the sidecar's sake).
 *
 * The private scalar is CLAMPED here exactly as `wg genkey` does (RFC 7748
 * §5): X25519 clamps internally anyway, so the public key is the same either
 * way, but a clamped key is what every WireGuard tool prints and expects to
 * read back.
 *
 * Nothing in this file logs, and nothing returns the private key except to
 * the caller that asked for it — which encrypts it into the vault at once.
 */

import crypto from 'crypto';
import { isWireGuardKey } from '@obliwan/shared';

/** PKCS#8 wrapper for a raw X25519 private key (RFC 8410): the fixed DER
 *  prefix, then the 32 key bytes. */
const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

function clamp(raw: Buffer): Buffer {
  const k = Buffer.from(raw);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  return k;
}

/** The public key of a base64 private key. Throws on a malformed one. */
export function wireGuardPublicKeyOf(privateKeyB64: string): string {
  if (!isWireGuardKey(privateKeyB64)) throw new TypeError('not a WireGuard key');
  const der = Buffer.concat([PKCS8_X25519_PREFIX, Buffer.from(privateKeyB64, 'base64')]);
  const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const jwk = crypto.createPublicKey(priv).export({ format: 'jwk' }) as { x?: string };
  if (!jwk.x) throw new Error('X25519 public key export returned no x');
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

export interface WireGuardKeyPair {
  privateKey: string;
  publicKey: string;
}

export function generateWireGuardKeyPair(): WireGuardKeyPair {
  const privateKey = clamp(crypto.randomBytes(32)).toString('base64');
  return { privateKey, publicKey: wireGuardPublicKeyOf(privateKey) };
}
