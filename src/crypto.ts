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

/** The multiaddr must terminate at the SAME peer id that signed — this is
 * what makes address poisoning infeasible. */
export function validMultiaddr(addr: unknown, peerId: string): addr is string {
  return (
    typeof addr === 'string' &&
    addr.startsWith('/') &&
    addr.includes('/p2p/') &&
    addr.endsWith(`/p2p/${peerId}`)
  );
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
