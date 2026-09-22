import { Hono, type Context } from 'hono';
import {
  normalizeMultiaddrs,
  pubkeyFromPeerId,
  splitMultiaddrs,
  validMultiaddrs,
  verifyHeartbeat,
  verifyRegister,
} from './crypto.js';
import type { RegistryStore, Tier } from './types.js';

/** Tunables, injected so tests can shrink time. */
export interface AppOptions {
  now?: () => number;
  /** Server-told heartbeat cadence; grows with fleet size to keep D1
   * write volume inside plan limits at 10k nodes. */
  heartbeatAfterSec?: number;
  /** Heartbeats more recent than half the interval skip their write. */
  freshMs?: number;
  /** Clock skew tolerated for signed heartbeats. */
  skewMs?: number;
}

const DEFAULTS = { heartbeatAfterSec: 1800, freshMs: 900_000, skewMs: 900_000 };

export function createApp(store: RegistryStore, opts: AppOptions = {}): Hono {
  const now = opts.now ?? (() => Date.now());
  const interval = opts.heartbeatAfterSec ?? DEFAULTS.heartbeatAfterSec;
  const app = new Hono();

  // JSON everywhere, versioned envelope so old clients never break.
  app.use('*', async (c, next) => {
    await next();
    c.header('X-Peers-Protocol', '1');
  });

  app.get('/healthz', async (c) =>
    c.json({ ok: true, protocol: 1, nodes: await store.count() }),
  );

  app.get('/v1/challenge', async (c) => {
    const peerId = c.req.query('peerId') ?? '';
    if (!pubkeyFromPeerId(peerId)) {
      return c.json({ ok: false, error: 'malformed peer id' }, 400);
    }
    const nonce = crypto.randomUUID().replaceAll('-', '');
    await store.putNonce(peerId, nonce, now() + 5 * 60_000);
    return c.json({ ok: true, nonce, expiresInSec: 300 });
  });

  app.post('/v1/register', async (c) => {
    const body = (await c.req.json().catch(() => null)) as null | Record<string, unknown>;
    if (!body) return json400(c, 'body must be json');
    const { peerId, nonce, sig, multiaddrs } = body as Record<string, string>;
    if (!peerId || !nonce || !sig) return json400(c, 'peerId, nonce, sig required');
    if (!verifyRegister(peerId, String(nonce), String(sig))) {
      return json400(c, 'signature invalid');
    }
    // Fail fast on a bad tier before consuming the single-use nonce.
    const regTier = parseTier(body.tier);
    if (!regTier.ok) return json400(c, 'tier must be citizen, node, or off');
    if (!(await store.takeNonce(peerId, String(nonce), now()))) {
      return json400(c, 'nonce unknown, expired or already used');
    }
    if (!validMultiaddrs(multiaddrs, peerId)) {
      return json400(c, 'multiaddrs must be comma-separated addrs ending in /p2p/<same peer id>');
    }
    await store.upsertNode({
      peerId,
      multiaddrs: normalizeMultiaddrs(multiaddrs) ?? '',
      region: strOrNull(body.region),
      tier: regTier.tier ?? 'node',
      lastSeen: now(),
    });
    return c.json({ ok: true, heartbeatAfterSec: interval });
  });

  app.post('/v1/heartbeat', async (c) => {
    const body = (await c.req.json().catch(() => null)) as null | Record<string, unknown>;
    if (!body) return json400(c, 'body must be json');
    const { peerId, ts, sig, multiaddrs, region } = body as Record<string, unknown>;
    if (
      !verifyHeartbeat(
        String(peerId),
        Number(ts),
        String(sig),
        now(),
        opts.skewMs ?? DEFAULTS.skewMs,
      )
    ) {
      return json400(c, 'signature invalid or clock too far off');
    }
    const hbTier = parseTier(body.tier);
    if (!hbTier.ok) return json400(c, 'tier must be citizen, node, or off');
    const existing = await store.getNode(String(peerId));
    if (!existing && !validMultiaddrs(multiaddrs, String(peerId))) {
      // Unknown nodes may bootstrap straight into a heartbeat, but then we
      // need a bound address. Otherwise they would be unlistable.
      return json400(c, 'unknown node: multiaddrs ending in /p2p/<id> required');
    }

    // Write-skip: inside half the told cadence a heartbeat is an ack, not
    // a write. This is what keeps 10k nodes inside D1 free limits.
    if (existing && now() - existing.lastSeen < (opts.freshMs ?? DEFAULTS.freshMs)) {
      return c.json({ ok: true, skipped: true, heartbeatAfterSec: interval });
    }

    const freshAddrs =
      validMultiaddrs(multiaddrs, String(peerId)) ? (normalizeMultiaddrs(multiaddrs) as string) : null;
    await store.upsertNode({
      peerId: String(peerId),
      multiaddrs: freshAddrs ?? existing?.multiaddrs ?? '',
      region: strOrNull(region) ?? existing?.region ?? null,
      tier: hbTier.tier ?? existing?.tier ?? 'node',
      lastSeen: now(),
    });
    return c.json({ ok: true, heartbeatAfterSec: interval });
  });

  /** Cursor-paginated fresh-node list. Edge-cached briefly: at 10k
   * clients polling hourly this keeps DB reads near zero. */
  app.get('/v1/nodes', async (c) => {
    const limitRaw = Number(c.req.query('limit') ?? '200');
    const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? limitRaw : 200, 1), 500);
    const cursorRaw = c.req.query('cursor');
    const cursor = decodeCursor(cursorRaw);

    const nodes = await store.listFresh(now(), DEFAULTS.freshMs * 2, limit, cursor);
    const last = nodes.at(-1);
    const peersNodes = nodes
      .flatMap((n) => splitMultiaddrs(n.multiaddrs))
      .join(',');
    return c.json({
      ok: true,
      protocol: 1,
      heartbeatAfterSec: interval,
      peersNodes,
      nodes: nodes.map((n) => ({
        multiaddrs: n.multiaddrs,
        peerId: n.peerId,
        lastSeen: n.lastSeen,
        region: n.region,
        tier: n.tier,
      })),
      ...(last ? { nextCursor: `${last.lastSeen}:${last.peerId}` } : {}),
      directoriesHint: [new URL(c.req.url).origin],
    });
  });

  return app;
}

/** Opaque composite cursor: `<lastSeen>:<peerId>`. Ties on timestamp are
 * broken by peer id so pagination is total. */
function decodeCursor(raw: string | undefined): { lastSeen: number; peerId: string } | undefined {
  if (!raw) return undefined;
  const sep = raw.indexOf(':');
  if (sep <= 0) return undefined;
  const lastSeen = Number(raw.slice(0, sep));
  const peerId = raw.slice(sep + 1);
  if (!Number.isFinite(lastSeen) || !peerId) return undefined;
  return { lastSeen, peerId };
}

function json400(c: Context, error: string) {
  return c.json({ ok: false, error }, 400);
}

function strOrNull(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 && v.length <= 32 ? v : null;
}

/** Strict tier parsing for Peers relay tiers: citizen, node, or off.
 * Absent means "keep the default". Anything else is rejected. */
function parseTier(v: unknown): { ok: true; tier?: Tier } | { ok: false } {
  if (v === undefined || v === null || v === '') return { ok: true };
  if (v === 'citizen' || v === 'node' || v === 'off') return { ok: true, tier: v };
  return { ok: false };
}
