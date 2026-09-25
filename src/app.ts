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
/** Leave room for the protocol fields while keeping the D1 write path small. */
const MAX_JSON_BODY_BYTES = 16 * 1024;
const RATE_WINDOW_MS = 60 * 60_000;
const CHALLENGE_PEER_LIMIT = 20;
const CHALLENGE_IP_LIMIT = 100;
const REGISTER_PEER_LIMIT = 5;
// Every register consumes a challenge nonce, so this must stay *below*
// CHALLENGE_IP_LIMIT (100) or the challenge cap would always bind first and
// this limit would be unreachable. 60/hour is the real per-source cap on D1
// growth; challenges stay available for the rest of the budget.
const REGISTER_IP_LIMIT = 60;
const HEARTBEAT_PEER_LIMIT = 120;
const HEARTBEAT_IP_LIMIT = 1_000;

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

  app.get('/healthz', async (c) => {
    const registeredNodes = await store.count();
    // `nodes` is retained as the legacy total. `metrics.freshNodes` has a
    // deliberately narrower meaning: it is the number of nodes currently
    // eligible for discovery, using the same freshness window and tier rule
    // as /v1/nodes.
    const freshNodes = store.countFresh
      ? await store.countFresh(now(), (opts.freshMs ?? DEFAULTS.freshMs) * 2)
      : null;
    return c.json({
      ok: true,
      protocol: 1,
      heartbeatAfterSec: interval,
      nodes: registeredNodes,
      metrics: {
        registeredNodes,
        ...(freshNodes === null ? {} : { freshNodes }),
      },
    });
  });

  app.get('/v1/challenge', async (c) => {
    const peerId = c.req.query('peerId') ?? '';
    if (!pubkeyFromPeerId(peerId)) {
      return json400(c, interval, 'malformed peer id');
    }
    if (!(await allow(store, `challenge:peer:${peerId}`, now(), RATE_WINDOW_MS, CHALLENGE_PEER_LIMIT))) {
      return json429(c, interval);
    }
    if (!(await allow(store, `challenge:ip:${clientKey(c)}`, now(), RATE_WINDOW_MS, CHALLENGE_IP_LIMIT))) {
      return json429(c, interval);
    }
    const nonce = crypto.randomUUID().replaceAll('-', '');
    const activeNonce = await store.putNonce(peerId, nonce, now() + 5 * 60_000, now());
    return c.json({ ok: true, protocol: 1, heartbeatAfterSec: interval, nonce: activeNonce, expiresInSec: 300 });
  });

  app.post('/v1/register', async (c) => {
    const parsed = await parseJsonObject(c, interval);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;
    if (!hasOnlyFields(body, ['peerId', 'nonce', 'sig', 'multiaddrs', 'tier', 'region'])) {
      return json400(c, interval, 'body contains an unsupported field');
    }
    const { peerId, nonce, sig, multiaddrs } = body;
    if (
      typeof peerId !== 'string' ||
      typeof nonce !== 'string' ||
      typeof sig !== 'string' ||
      typeof multiaddrs !== 'string'
    ) {
      return json400(c, interval, 'peerId, nonce, sig, and multiaddrs must be strings');
    }
    if (body.region !== undefined && body.region !== null && !validRegion(body.region)) {
      return json400(c, interval, 'region must be a string no longer than 32 characters');
    }
    if (!verifyRegister(peerId, nonce, sig)) {
      return json400(c, interval, 'signature invalid');
    }
    // Fail fast on a bad tier before consuming the single-use nonce.
    const regTier = parseTier(body.tier);
    if (!regTier.ok) return json400(c, interval, 'tier must be citizen, node, or off');
    if (!validMultiaddrs(multiaddrs, peerId)) {
      return json400(c, interval, 'multiaddrs must be comma-separated addrs ending in /p2p/<same peer id>');
    }
    if (!(await allow(store, `register:peer:${peerId}`, now(), RATE_WINDOW_MS, REGISTER_PEER_LIMIT))) {
      return json429(c, interval);
    }
    if (!(await allow(store, `register:ip:${clientKey(c)}`, now(), RATE_WINDOW_MS, REGISTER_IP_LIMIT))) {
      return json429(c, interval);
    }
    if (!(await store.takeNonce(peerId, nonce, now()))) {
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
    const parsed = await parseJsonObject(c, interval);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;
    if (!hasOnlyFields(body, ['peerId', 'ts', 'sig', 'multiaddrs', 'region', 'tier'])) {
      return json400(c, interval, 'body contains an unsupported field');
    }
    const { peerId, ts, sig, multiaddrs, region } = body;
    if (
      typeof peerId !== 'string' ||
      typeof ts !== 'number' ||
      !Number.isSafeInteger(ts) ||
      typeof sig !== 'string'
    ) {
      return json400(c, interval, 'peerId, ts, and sig have invalid types');
    }
    if (multiaddrs !== undefined && typeof multiaddrs !== 'string') {
      return json400(c, interval, 'multiaddrs must be a string');
    }
    if (region !== undefined && region !== null && !validRegion(region)) {
      return json400(c, interval, 'region must be a string no longer than 32 characters');
    }
    if (
      !verifyHeartbeat(
        peerId,
        ts,
        sig,
        now(),
        opts.skewMs ?? DEFAULTS.skewMs,
      )
    ) {
      return json400(c, interval, 'signature invalid or clock too far off');
    }
    const hbTier = parseTier(body.tier);
    if (!hbTier.ok) return json400(c, interval, 'tier must be citizen, node, or off');
    if (!(await allow(store, `heartbeat:peer:${peerId}`, now(), RATE_WINDOW_MS, HEARTBEAT_PEER_LIMIT))) {
      return json429(c, interval);
    }
    if (!(await allow(store, `heartbeat:ip:${clientKey(c)}`, now(), RATE_WINDOW_MS, HEARTBEAT_IP_LIMIT))) {
      return json429(c, interval);
    }
    const peerIdString = peerId;
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

type ParsedJsonObject =
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; response: Response };

/** Read at most MAX_JSON_BODY_BYTES and require a plain JSON object. The
 * stream limit is important: checking Content-Length alone would allow a
 * chunked request to bypass the limit. */
async function parseJsonObject(c: Context, heartbeatAfterSec: number): Promise<ParsedJsonObject> {
  const contentLength = c.req.raw.headers.get('content-length');
  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      return { ok: false, response: json400(c, heartbeatAfterSec, 'invalid content-length') };
    }
    if (Number(contentLength) > MAX_JSON_BODY_BYTES) {
      return { ok: false, response: jsonBodyTooLarge(c, heartbeatAfterSec) };
    }
  }

  if (!c.req.raw.body) {
    return { ok: false, response: json400(c, heartbeatAfterSec, 'body must be json') };
  }
  const reader = c.req.raw.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_JSON_BODY_BYTES) {
        await reader.cancel().catch(() => undefined);
        return { ok: false, response: jsonBodyTooLarge(c, heartbeatAfterSec) };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, response: json400(c, heartbeatAfterSec, 'body must be json') };
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return { ok: false, response: json400(c, heartbeatAfterSec, 'body must be json') };
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, response: json400(c, heartbeatAfterSec, 'body must be a json object') };
  }
  return { ok: true, body: value as Record<string, unknown> };
}

function hasOnlyFields(body: Record<string, unknown>, fields: string[]): boolean {
  const allowed = new Set(fields);
  return Object.keys(body).every((field) => allowed.has(field));
}

function validRegion(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 32;
}

function jsonBodyTooLarge(c: Context, heartbeatAfterSec: number): Response {
  return c.json(
    { ok: false, protocol: 1, heartbeatAfterSec, error: 'request body too large' },
    413,
  );
}

async function allow(
  store: RegistryStore,
  key: string,
  now: number,
  windowMs: number,
  limit: number,
): Promise<boolean> {
  return store.allowRequest(key, now, windowMs, limit);
}

function clientKey(c: Context): string {
  return c.req.header('cf-connecting-ip')?.slice(0, 64) || 'unknown';
}

function json429(c: Context, heartbeatAfterSec: number): Response {
  return c.json(
    { ok: false, protocol: 1, heartbeatAfterSec, error: 'rate limit exceeded' },
    429,
  );
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
