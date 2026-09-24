import type { NodeRow, RegistryStore } from './types.js';

/** Minimal structural view of the D1 binding we use, so the typecheck
 * needs nothing outside this repo. */
export interface StmtLike {
  bind(...vals: unknown[]): {
    first<T = unknown>(): Promise<T | null>;
    run(): Promise<unknown>;
    all<T = unknown>(): Promise<{ results: T[] }>;
  };
  first<T = unknown>(): Promise<T | null>;
  run(): Promise<unknown>;
  all<T = unknown>(): Promise<{ results: T[] }>;
}

export interface D1Like {
  prepare(sql: string): StmtLike;
}

/** D1-backed registry store. All statements are keyed on peer_id, so
 * 10k rows is a rounding error; indexes keep listFresh a range scan. */
export class D1Store implements RegistryStore {
  constructor(private readonly db: D1Like) {}

  async putNonce(peerId: string, nonce: string, expiresAt: number, now: number): Promise<string> {
    const inserted = await this.db
      .prepare(
        'INSERT INTO nonces (peer_id, nonce, expires_at) VALUES (?, ?, ?) ' +
          'ON CONFLICT(peer_id) DO UPDATE SET nonce=excluded.nonce, expires_at=excluded.expires_at ' +
          'WHERE nonces.expires_at <= ? RETURNING nonce',
      )
      .bind(peerId, nonce, expiresAt, now)
      .first<{ nonce: string }>();
    if (inserted?.nonce) return inserted.nonce;

    // A live challenge belongs to the peer that requested it. Do not replace
    // it merely because somebody requested another challenge for that ID.
    const existing = await this.db
      .prepare('SELECT nonce FROM nonces WHERE peer_id = ? AND expires_at > ?')
      .bind(peerId, now)
      .first<{ nonce: string }>();
    return existing?.nonce ?? nonce;
  }

  /** Atomic consume: the DELETE ... RETURNING row only when it exists and
   * has not expired — two concurrent registers can never both win. */
  async takeNonce(peerId: string, nonce: string, now: number): Promise<boolean> {
    const res = await this.db
      .prepare('DELETE FROM nonces WHERE peer_id = ? AND nonce = ? AND expires_at > ? RETURNING peer_id')
      .bind(peerId, nonce, now)
      .all<{ peer_id: string }>();
    return res.results.length > 0;
  }

  async upsertNode(row: NodeRow): Promise<void> {
    await this.db
      .prepare(
        'INSERT INTO nodes (peer_id, multiaddrs, region, tier, last_seen) VALUES (?, ?, ?, ?, ?) ' +
          'ON CONFLICT(peer_id) DO UPDATE SET multiaddrs=excluded.multiaddrs, region=excluded.region, ' +
          'tier=excluded.tier, last_seen=excluded.last_seen',
      )
      .bind(row.peerId, row.multiaddrs, row.region, row.tier, row.lastSeen)
      .run();
  }

  async getNode(peerId: string): Promise<NodeRow | null> {
    const row = await this.db
      .prepare('SELECT * FROM nodes WHERE peer_id = ?')
      .bind(peerId)
      .first<Row>();
    return row ? fromRow(row) : null;
  }

  async listFresh(
    now: number,
    freshMs: number,
    limit: number,
    cursor?: { lastSeen: number; peerId: string },
  ): Promise<NodeRow[]> {
    const freshAfter = now - freshMs;
    const rows =
      cursor === undefined
        ? await this.db
            .prepare('SELECT * FROM nodes WHERE last_seen > ? ORDER BY last_seen DESC, peer_id DESC LIMIT ?')
            .bind(freshAfter, limit)
            .all<Row>()
        : await this.db
            .prepare(
              'SELECT * FROM nodes WHERE last_seen > ? AND ' +
                '(last_seen < ? OR (last_seen = ? AND peer_id < ?)) ' +
                'ORDER BY last_seen DESC, peer_id DESC LIMIT ?',
            )
            .bind(freshAfter, cursor.lastSeen, cursor.lastSeen, cursor.peerId, limit)
            .all<Row>();
    return rows.results.map(fromRow);
  }

  async count(): Promise<number> {
    const row = await this.db.prepare('SELECT COUNT(*) AS n FROM nodes').first<{ n: number }>();
    return row?.n ?? 0;
  }

  async prune(now: number, nodeTtlMs: number): Promise<void> {
    await this.db.prepare('DELETE FROM nonces WHERE expires_at <= ?').bind(now).run();
    await this.db.prepare('DELETE FROM nodes WHERE last_seen <= ?').bind(now - nodeTtlMs).run();
  }
}

interface Row {
  peer_id: string;
  multiaddrs: string;
  region: string | null;
  tier: string;
  last_seen: number;
}

function fromRow(r: Row): NodeRow {
  return {
    peerId: r.peer_id,
    multiaddrs: r.multiaddrs,
    region: r.region,
    tier: normalizeTier(r.tier),
    lastSeen: r.last_seen,
  };
}

function normalizeTier(t: string): NodeRow['tier'] {
  return t === 'citizen' || t === 'off' ? t : 'node';
}
