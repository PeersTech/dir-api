import {base58} from '@scure/base';
import {ed25519} from '@noble/curves/ed25519.js';

/**
 * Identity proofs for the directory. A libp2p peer id is self-certifying:
 * base58(identity-multihash(protobuf-ed25519-pubkey)) — the signing key
 * rides inside the id itself, so there is no key registration step and no
 * trust-on-first-use problem. Every message must be signed by the key its
 * own peer id embeds.
 */

const DOMAIN = 'peers-directory';

/** Ed25519 public key embedded in a PeerId string, or null when the id is
 * malformed / not an Ed25519 identity multihash. */
export function pubkeyFromPeerId(peerId: string): Uint8Array | null {
  try {
    const mh = base58.decode(peerId);
    // 0x00 0x24 || protobuf(0x08 0x01 0x12 0x20 || key[32]) => 38 bytes
    if (mh.length !== 38 || mh[0] !== 0x00 || mh[1] !== 0x24) return null;
    if (mh[2] !== 0x08 || mh[3] !== 0x01 || mh[4] !== 0x12 || mh[5] !== 0x20) return null;
    const key = mh.slice(6);
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

/** Register proof binds the server-issued nonce to this exact peer id. */
export function verifyRegister(peerId: string, nonce: string, sigB64: string): boolean {
  const key = pubkeyFromPeerId(peerId);
  if (!key) return false;
  try {
    return ed25519.verify(
      fromB64(sigB64),
      new TextEncoder().encode(`${DOMAIN}:v1:register:${peerId}:${nonce}`),
      key,
    );
  } catch {
    return false;
  }
}

/** Heartbeat proof carries a timestamp; replays die within the skew window. */
export function verifyHeartbeat(
  peerId: string,
  ts: number,
  sigB64: string,
  now: number,
  skewMs: number,
): boolean {
  if (!Number.isFinite(ts) || Math.abs(now - ts) > skewMs) return false;
  const key = pubkeyFromPeerId(peerId);
  if (!key) return false;
  try {
    return ed25519.verify(
      fromB64(sigB64),
      new TextEncoder().encode(`${DOMAIN}:v1:heartbeat:${peerId}:${ts}`),
      key,
    );
  } catch {
    return false;
  }
}

/** Every multiaddr must terminate at the SAME peer id that signed. This is
 * what makes address poisoning infeasible. Accepts a comma-separated list
 * in PEERS_NODES format. */
export function validMultiaddrs(addrs: unknown, peerId: string): addrs is string {
  if (typeof addrs !== 'string' || addrs.length === 0) return false;
  const parts = splitMultiaddrs(addrs);
  if (parts.length === 0) return false;
  return parts.every(
    (a) => a.startsWith('/') && a.includes('/p2p/') && a.endsWith(`/p2p/${peerId}`),
  );
}

/** Splits a PEERS_NODES style comma-separated multiaddr list and trims
 * each entry. Empty entries are dropped. */
export function splitMultiaddrs(addrs: string): string[] {
  return addrs
    .split(',')
    .map((a) => a.trim())
    .filter((a) => a.length > 0);
}

/** Normalizes a multiaddr list to trimmed, comma-joined form, or null when
 * the input is not a usable string. */
export function normalizeMultiaddrs(addrs: unknown): string | null {
  if (typeof addrs !== 'string') return null;
  const parts = splitMultiaddrs(addrs);
  return parts.length > 0 ? parts.join(',') : null;
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
