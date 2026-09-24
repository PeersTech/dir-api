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
  /** Server-told heartbeat cadence. The current Worker uses the fixed
   * default below; callers may override it for tests or deployments. */
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
    c.header('X-Peers-Protocol', '1');
    await next();
  });

  app.onError((_error, c) =>
    c.json(
      { ok: false, protocol: 1, heartbeatAfterSec: interval, error: 'internal server error' },
      500,
    ),
  );

  app.get('/healthz', async (c) =>
    c.json({ ok: true, protocol: 1, heartbeatAfterSec: interval, nodes: await store.count() }),
  );

  app.get('/v1/challenge', async (c) => {
    const peerId = c.req.query('peerId') ?? '';
    if (!pubkeyFromPeerId(peerId)) {
      return json400(c, interval, 'malformed peer id');
    }
    const nonce = crypto.randomUUID().replaceAll('-', '');
    const activeNonce = await store.putNonce(peerId, nonce, now() + 5 * 60_000, now());
    return c.json({ ok: true, protocol: 1, heartbeatAfterSec: interval, nonce: activeNonce, expiresInSec: 300 });
  });

  app.post('/v1/register', async (c) => {
    const body = (await c.req.json().catch(() => null)) as null | Record<string, unknown>;
    if (!body) return json400(c, interval, 'body must be json');
    const { peerId, nonce, sig, multiaddrs } = body as Record<string, string>;
    if (!peerId || !nonce || !sig) return json400(c, interval, 'peerId, nonce, sig required');
    if (!verifyRegister(peerId, String(nonce), String(sig))) {
      return json400(c, interval, 'signature invalid');
    }
    // Fail fast on a bad tier before consuming the single-use nonce.
    const regTier = parseTier(body.tier);
    if (!regTier.ok) return json400(c, interval, 'tier must be citizen, node, or off');
    if (!validMultiaddrs(multiaddrs, peerId)) {
      return json400(c, interval, 'multiaddrs must be comma-separated addrs ending in /p2p/<same peer id>');
    }
    if (!(await store.takeNonce(peerId, String(nonce), now()))) {
      return json400(c, interval, 'nonce unknown, expired or already used');
    }
    await store.upsertNode({
      peerId,
      multiaddrs: normalizeMultiaddrs(multiaddrs) ?? '',
      region: strOrNull(body.region),
      tier: regTier.tier ?? 'node',
      lastSeen: now(),
    });
    return c.json({ ok: true, protocol: 1, heartbeatAfterSec: interval });
  });

  app.post('/v1/heartbeat', async (c) => {
    const body = (await c.req.json().catch(() => null)) as null | Record<string, unknown>;
    if (!body) return json400(c, interval, 'body must be json');
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
      return json400(c, interval, 'signature invalid or clock too far off');
    }
    const hbTier = parseTier(body.tier);
    if (!hbTier.ok) return json400(c, interval, 'tier must be citizen, node, or off');
    const peerIdString = String(peerId);
    if (region !== undefined && region !== null && (typeof region !== 'string' || region.length > 32)) {
      return json400(c, interval, 'region must be a string no longer than 32 characters');
    }
    const existing = await store.getNode(peerIdString);
    if (multiaddrs !== undefined && !validMultiaddrs(multiaddrs, peerIdString)) {
      return json400(c, interval, 'multiaddrs must be comma-separated addrs ending in /p2p/<same peer id>');
    }
    if (!existing && !validMultiaddrs(multiaddrs, peerIdString)) {
      // Unknown nodes may bootstrap straight into a heartbeat, but then we
      // need a bound address. Otherwise they would be unlistable.
      return json400(c, interval, 'unknown node: multiaddrs ending in /p2p/<id> required');
    }

    const freshAddrs =
      validMultiaddrs(multiaddrs, peerIdString) ? (normalizeMultiaddrs(multiaddrs) as string) : null;
    const freshRegion = strOrNull(region);
    const hasChanges = Boolean(
      existing &&
        ((freshAddrs !== null && freshAddrs !== existing.multiaddrs) ||
          (freshRegion !== null && freshRegion !== existing.region) ||
          (hbTier.tier !== undefined && hbTier.tier !== existing.tier)),
    );

    // Write-skip only applies to a heartbeat that carries no changes. Address
    // migrations must not be silently delayed by the freshness optimization.
    if (existing && !hasChanges && now() - existing.lastSeen < (opts.freshMs ?? DEFAULTS.freshMs)) {
      return c.json({ ok: true, protocol: 1, skipped: true, heartbeatAfterSec: interval });
    }

    await store.upsertNode({
      peerId: peerIdString,
      multiaddrs: freshAddrs ?? existing?.multiaddrs ?? '',
      region: freshRegion ?? existing?.region ?? null,
      tier: hbTier.tier ?? existing?.tier ?? 'node',
      lastSeen: now(),
    });
    return c.json({ ok: true, protocol: 1, heartbeatAfterSec: interval });
  });

  /** Cursor-paginated fresh-node list. The Worker reads D1 directly;
   * operators can add an edge-cache policy at the route boundary later. */
  app.get('/v1/nodes', async (c) => {
    const limitParam = c.req.query('limit');
    const limitRaw = Number(limitParam ?? '200');
    if (!Number.isInteger(limitRaw) || limitRaw < 1 || limitRaw > 500) {
      return json400(c, interval, 'limit must be an integer between 1 and 500');
    }
    const limit = limitRaw;
    const cursorRaw = c.req.query('cursor');
    const cursor = decodeCursor(cursorRaw);
    if (cursorRaw !== undefined && !cursor) {
      return json400(c, interval, 'cursor is invalid');
    }

    const rows = await store.listFresh(
      now(),
      (opts.freshMs ?? DEFAULTS.freshMs) * 2,
      limit + 1,
      cursor,
    );
    const hasMore = rows.length > limit;
    const nodes = rows.slice(0, limit);
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
      ...(hasMore && last ? { nextCursor: `${last.lastSeen}:${last.peerId}` } : {}),
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
  if (!Number.isSafeInteger(lastSeen) || lastSeen < 0 || !peerId || peerId.length > 128) {
    return undefined;
  }
  return { lastSeen, peerId };
}

function json400(c: Context, heartbeatAfterSec: number, error: string) {
  return c.json({ ok: false, protocol: 1, heartbeatAfterSec, error }, 400);
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
