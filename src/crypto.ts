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
  // Base58 decoding is intentionally quadratic. Reject oversized input before
  // it reaches the decoder so a public query cannot become a CPU amplifier.
  if (typeof peerId !== 'string' || peerId.length === 0 || peerId.length > 128) return null;
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
  if (typeof nonce !== 'string' || typeof sigB64 !== 'string') return false;
  if (nonce.length > 128 || sigB64.length > 256) return false;
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
  if (typeof sigB64 !== 'string' || sigB64.length > 256) return false;
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
  if (typeof addrs !== 'string' || addrs.length === 0 || addrs.length > 4096) return false;
  const parts = splitMultiaddrs(addrs);
  if (parts.length === 0 || parts.length > 16) return false;
  return parts.every((addr) => validMultiaddr(addr, peerId));
}

function validMultiaddr(addr: string, peerId: string): boolean {
  if (
    addr.length > 512 ||
    !addr.startsWith('/') ||
    addr.endsWith('/') ||
    addr.includes('//') ||
    /[\s,]/.test(addr)
  ) {
    return false;
  }

  const p2p = '/p2p/';
  const firstP2P = addr.indexOf(p2p);
  // The peer id must be the final component, and there must be exactly one
  // p2p component. This also prevents a signed address from smuggling extra
  // path components after the signed peer id.
  if (firstP2P <= 0 || firstP2P !== addr.lastIndexOf(p2p)) return false;
  if (addr.slice(firstP2P + p2p.length) !== peerId) return false;

  const components = addr.slice(0, firstP2P).split('/').slice(1);
  if (components.length < 2) return false;

  const network = components[0];
  const host = components[1];
  if (!['ip4', 'ip6', 'dns4', 'dns6', 'dnsaddr'].includes(network)) return false;
  if (network === 'ip4' ? !isIpv4(host) : network === 'ip6' ? !isIpv6(host) : !isDnsName(host)) {
    return false;
  }

  // dnsaddr is a resolver address, not a host/port transport address. It is
  // still a valid PEERS_NODES entry when it terminates in /p2p/<peer id>.
  if (network === 'dnsaddr') return components.length === 2;

  if (components.length < 4) return false;
  const transport = components[2];
  if (transport !== 'tcp' && transport !== 'udp') return false;
  if (!isPort(components[3])) return false;

  // QUIC is a UDP transport with an explicit quic-v1 marker. A marker on TCP
  // is invalid; plain UDP remains a valid multiaddr transport for callers
  // that intentionally advertise it.
  if (components.length === 4) return true;
  return components.length === 5 && transport === 'udp' && components[4] === 'quic-v1';
}

function isPort(value: string): boolean {
  if (!/^\d{1,5}$/.test(value)) return false;
  const port = Number(value);
  return port >= 1 && port <= 65535;
}

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  return (
    parts.length === 4 &&
    parts.every((part) => {
      if (!/^\d{1,3}$/.test(part)) return false;
      if (part.length > 1 && part.startsWith('0')) return false;
      const octet = Number(part);
      return octet >= 0 && octet <= 255;
    })
  );
}

function isIpv6(value: string): boolean {
  if (value.length > 45 || !/^[0-9a-f:.]+$/i.test(value) || value.includes(':::')) return false;
  // Convert an embedded IPv4 suffix into two IPv6 hextets before counting.
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const v4 = value.slice(lastColon + 1);
    if (lastColon < 0 || !isIpv4(v4)) return false;
    const octets = v4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = `${value.slice(0, lastColon)}${high}:${low}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return false;
  const parseHextets = (half: string): string[] | null => {
    if (half === '') return [];
    const parts = half.split(':');
    return parts.every((part) => /^[0-9a-f]{1,4}$/i.test(part)) ? parts : null;
  };
  const left = parseHextets(halves[0]);
  const right = parseHextets(halves[halves.length - 1]);
  if (!left || !right) return false;
  return halves.length === 1 ? left.length === 8 : left.length + right.length < 8;
}

function isDnsName(value: string): boolean {
  const name = value.endsWith('.') ? value.slice(0, -1) : value;
  if (name.length === 0 || name.length > 253) return false;
  return name.split('.').every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
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
