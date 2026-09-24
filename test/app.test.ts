import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { createApp } from '../src/app.js';
import type { NodeRow, RegistryStore } from '../src/types.js';

/**
 * Full registry flow against an in-memory store: challenge → register →
 * heartbeat → list, plus the abuse cases that make the directory
 * trustworthy (fake ids, replayed nonces, address poisoning, spam writes).
 */

let t = 1_700_000_000_000;
const clock = () => t;
const advance = (ms: number) => (t += ms);

class MemoryStore implements RegistryStore {
  nodes = new Map<string, NodeRow>();
  nonces = new Map<string, { nonce: string; expiresAt: number }>();

  async putNonce(p: string, n: string, exp: number, now: number) {
    const existing = this.nonces.get(p);
    if (existing && existing.expiresAt > now) return existing.nonce;
    this.nonces.set(p, { nonce: n, expiresAt: exp });
    return n;
  }
  async takeNonce(p: string, n: string, now: number) {
    const e = this.nonces.get(p);
    if (!e || e.nonce !== n || e.expiresAt <= now) return false;
    this.nonces.delete(p);
    return true;
  }
  async upsertNode(row: NodeRow) {
    this.nodes.set(row.peerId, { ...row });
  }
  async getNode(p: string) {
    const r = this.nodes.get(p);
    return r ? { ...r } : null;
  }
  async listFresh(
    now: number,
    freshMs: number,
    limit: number,
    cursor?: { lastSeen: number; peerId: string },
  ) {
    return [...this.nodes.values()]
      .filter((n) => n.lastSeen > now - freshMs && n.tier !== 'off')
      .filter((n) => {
        if (!cursor) return true;
        // Composite keyset: strictly after the cursor position.
        return (
          n.lastSeen < cursor.lastSeen ||
          (n.lastSeen === cursor.lastSeen && n.peerId < cursor.peerId)
        );
      })
      .sort((a, b) => b.lastSeen - a.lastSeen || (a.peerId < b.peerId ? 1 : -1))
      .slice(0, limit)
      .map((n) => ({ ...n }));
  }
  async count() {
    return this.nodes.size;
  }
  async prune(_now: number, _ttl: number) {}
}

const app = createApp(new MemoryStore(), { now: clock });
const json = async (res: Response) => res.json() as Promise<Record<string, unknown>>;

// --- identity helpers -------------------------------------------------------

function makePeer(): {
  peerId: string;
  sign: (msg: string) => string;
} {
  const priv = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(priv);
  // libp2p identity multihash: 0x00 0x24 || protobuf(0x08 0x01 0x12 0x20 key)
  const mh = new Uint8Array(38);
  mh.set([0x00, 0x24, 0x08, 0x01, 0x12, 0x20], 0);
  mh.set(pub, 6);
  const peerId = toB58(mh);
  return {
    peerId,
    sign: (msg: string) => toB64(ed25519.sign(new TextEncoder().encode(msg), priv)),
  };
}

function toB64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
function toB58(b: Uint8Array): string {
  const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let out = '';
  while (n > 0n) {
    out = ALPH[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const x of b) {
    if (x === 0) out = '1' + out;
    else break;
  }
  return out;
}

async function register(peer: ReturnType<typeof makePeer>, addr?: string): Promise<Record<string, unknown>> {
  const ch = await json(await app.request(`/v1/challenge?peerId=${peer.peerId}`));
  const multiaddrs =
    addr ?? `/ip4/203.0.113.7/tcp/4001/p2p/${peer.peerId}`;
  return json(
    await app.request('/v1/register', {
      method: 'POST',
      body: JSON.stringify({
        peerId: peer.peerId,
        nonce: ch.nonce,
        sig: peer.sign(`peers-directory:v1:register:${peer.peerId}:${ch.nonce}`),
        multiaddrs,
      }),
    }),
  );
}

// --- tests ------------------------------------------------------------------

describe('directory flow', () => {
  it('registers a node with a valid signed challenge', async () => {
    const alice = makePeer();
    const res = await register(alice);
    expect(res.ok).toBe(true);
    expect(res.heartbeatAfterSec).toBeGreaterThan(0);
    expect(await app.request('/healthz')).toBeTruthy();
  });

  it('rejects a signature made by a different key than the id embeds', async () => {
    const alice = makePeer();
    const mallory = makePeer();
    const ch = await json(await app.request(`/v1/challenge?peerId=${alice.peerId}`));
    const res = await json(
      await app.request('/v1/register', {
        method: 'POST',
        body: JSON.stringify({
          peerId: alice.peerId,
          nonce: ch.nonce,
          sig: mallory.sign(`peers-directory:v1:register:${alice.peerId}:${ch.nonce}`),
          multiaddrs: `/ip4/10.9.9.9/tcp/1/p2p/${alice.peerId}`,
        }),
      }),
    );
    expect(res.ok).toBe(false);
  });

  it('rejects malformed peer ids outright', async () => {
    const res = await json(await app.request('/v1/challenge?peerId=not-a-peer-id'));
    expect(res.ok).toBe(false);
  });

  it('does not let a new challenge invalidate an active one', async () => {
    const p = makePeer();
    const first = await json(await app.request(`/v1/challenge?peerId=${p.peerId}`));
    const second = await json(await app.request(`/v1/challenge?peerId=${p.peerId}`));
    expect(second.nonce).toBe(first.nonce);
  });

  it('nonces are single-use (replay fails)', async () => {
    const p = makePeer();
    const ch = await json(await app.request(`/v1/challenge?peerId=${p.peerId}`));
    const body = JSON.stringify({
      peerId: p.peerId,
      nonce: ch.nonce,
      sig: p.sign(`peers-directory:v1:register:${p.peerId}:${ch.nonce}`),
      multiaddrs: `/ip4/203.0.113.7/tcp/4001/p2p/${p.peerId}`,
    });
    expect((await json(await app.request('/v1/register', { method: 'POST', body }))).ok).toBe(true);
    const replay = await json(await app.request('/v1/register', { method: 'POST', body }));
    expect(replay.ok).toBe(false);
  });

  it('refuses multiaddrs pointing at another peer (poisoning)', async () => {
    const owner = makePeer();
    const other = makePeer();
    const res = await register(owner, `/ip4/203.0.113.9/tcp/4001/p2p/${other.peerId}`);
    expect(res.ok).toBe(false);
  });

  it('accepts comma-separated multiaddrs and emits peersNodes for PEERS_NODES', async () => {
    const p = makePeer();
    const a1 = `/ip4/203.0.113.7/tcp/4001/p2p/${p.peerId}`;
    const a2 = `/ip4/203.0.113.8/tcp/4001/p2p/${p.peerId}`;
    const res = await register(p, `${a1},${a2}`);
    expect(res.ok).toBe(true);

    const list = await json(await app.request('/v1/nodes?limit=500'));
    const entry = (list.nodes as { peerId: string; multiaddrs: string; tier: string }[]).find(
      (n) => n.peerId === p.peerId,
    );
    expect(entry).toBeDefined();
    expect(entry?.multiaddrs).toBe(`${a1},${a2}`);
    expect(entry?.tier).toBe('node');
    expect(typeof list.peersNodes).toBe('string');
    expect((list.peersNodes as string).split(',')).toEqual(expect.arrayContaining([a1, a2]));
    // Every entry is a full multiaddr with a peer id suffix, so the
    // string is directly usable as a PEERS_NODES value.
    for (const part of (list.peersNodes as string).split(',')) {
      expect(part).toContain('/p2p/');
    }
  });

  it('rejects a multiaddr list that mixes in another peer id', async () => {
    const owner = makePeer();
    const other = makePeer();
    const res = await register(
      owner,
      `/ip4/203.0.113.7/tcp/4001/p2p/${owner.peerId},/ip4/203.0.113.7/tcp/4002/p2p/${other.peerId}`,
    );
    expect(res.ok).toBe(false);
  });

  it('maps tier to citizen, node, or off and defaults to node', async () => {
    const p = makePeer();
    const ch = await json(await app.request(`/v1/challenge?peerId=${p.peerId}`));
    const res = await json(
      await app.request('/v1/register', {
        method: 'POST',
        body: JSON.stringify({
          peerId: p.peerId,
          nonce: ch.nonce,
          sig: p.sign(`peers-directory:v1:register:${p.peerId}:${ch.nonce}`),
          multiaddrs: `/ip4/203.0.113.7/tcp/4001/p2p/${p.peerId}`,
          tier: 'citizen',
        }),
      }),
    );
    expect(res.ok).toBe(true);

    const list = await json(await app.request('/v1/nodes?limit=500'));
    const entry = (list.nodes as { peerId: string; tier: string }[]).find((n) => n.peerId === p.peerId);
    expect(entry?.tier).toBe('citizen');
  });

  it('rejects unknown tier values with 400 on register and heartbeat', async () => {
    const p = makePeer();
    const ch = await json(await app.request(`/v1/challenge?peerId=${p.peerId}`));
    const badRegister = await json(
      await app.request('/v1/register', {
        method: 'POST',
        body: JSON.stringify({
          peerId: p.peerId,
          nonce: ch.nonce,
          sig: p.sign(`peers-directory:v1:register:${p.peerId}:${ch.nonce}`),
          multiaddrs: `/ip4/203.0.113.7/tcp/4001/p2p/${p.peerId}`,
          tier: 'super',
        }),
      }),
    );
    expect(badRegister.ok).toBe(false);

    const q = makePeer();
    await register(q);
    advance(16 * 60_000); // past freshness window so the heartbeat writes
    const badHeartbeat = await json(
      await app.request('/v1/heartbeat', {
        method: 'POST',
        body: JSON.stringify({
          peerId: q.peerId,
          ts: clock(),
          sig: q.sign(`peers-directory:v1:heartbeat:${q.peerId}:${clock()}`),
          tier: 'super',
        }),
      }),
    );
    expect(badHeartbeat.ok).toBe(false);
  });

  it('heartbeats keep the node fresh and skip redundant writes', async () => {
    const p = makePeer();
    await register(p);

    advance(60_000); // well inside half-interval → ack, no write
    const hbBody = (): string =>
      JSON.stringify({ peerId: p.peerId, ts: clock(), sig: p.sign(`peers-directory:v1:heartbeat:${p.peerId}:${clock()}`) });
    const skipped = await json(await app.request('/v1/heartbeat', { method: 'POST', body: hbBody() }));
    expect(skipped.skipped).toBe(true);

    advance(16 * 60_000); // past freshness window → real write
    const real = await json(await app.request('/v1/heartbeat', { method: 'POST', body: hbBody() }));
    expect(real.ok).toBe(true);
    void skipped;
  });

  it('lists fresh nodes newest-first with pagination cursor', async () => {
    for (let i = 0; i < 5; i++) {
      const p = makePeer();
      advance(1000);
      await register(p);
    }
    const page1 = await json(await app.request('/v1/nodes?limit=3'));
    expect((page1.nodes as unknown[]).length).toBe(3);
    expect(page1.nextCursor).toBeDefined();

    const page2 = await json(
      await app.request(`/v1/nodes?limit=500&cursor=${page1.nextCursor}`),
    );
    expect((page2.nodes as unknown[]).length).toBeGreaterThanOrEqual(2);

    const seen = [
      ...(page1.nodes as { peerId: string }[]),
      ...(page2.nodes as { peerId: string }[]),
    ];
    expect(new Set(seen.map((n) => n.peerId)).size).toBe(seen.length); // no dupes across pages
  });

  it('heartbeat timestamps outside the skew window are rejected', async () => {
    const p = makePeer();
    await register(p);
    advance(16 * 60_000);
    const stale = await json(
      await app.request('/v1/heartbeat', {
        method: 'POST',
        body: JSON.stringify({
          peerId: p.peerId,
          ts: clock() - 60 * 60_000,
          sig: p.sign(`peers-directory:v1:heartbeat:${p.peerId}:${clock() - 60 * 60_000}`),
        }),
      }),
    );
    expect(stale.ok).toBe(false);
  });
});
