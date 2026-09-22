/** Registry data shapes + the storage seam. Tests inject an in-memory
 * store; production binds D1. Same contract either way. */

/** Relay tier values used by the Peers app: citizen, node, or off. */
export type Tier = 'citizen' | 'node' | 'off';

export interface NodeRow {
  peerId: string;
  /** Comma-separated full multiaddrs, PEERS_NODES format. */
  multiaddrs: string;
  region: string | null;
  tier: Tier;
  lastSeen: number;
}

export interface RegistryStore {
  /** Single-use challenge nonce; expires silently. */
  putNonce(peerId: string, nonce: string, expiresAt: number): Promise<void>;
  /** Atomically consumes the nonce; false when missing/expired/used. */
  takeNonce(peerId: string, nonce: string, now: number): Promise<boolean>;
  upsertNode(row: NodeRow): Promise<void>;
  getNode(peerId: string): Promise<NodeRow | null>;
  /** Newest-first keyset pagination: `cursor` is the composite
   * (lastSeen, peerId) position of the previous page's last row, so rows
   * sharing a timestamp can never straddle or repeat across pages. */
  listFresh(
    now: number,
    freshMs: number,
    limit: number,
    cursor?: { lastSeen: number; peerId: string },
  ): Promise<NodeRow[]>;
  count(): Promise<number>;
  /** Deletes expired nonces and nodes unseen past nodeTtlMs. */
  prune(now: number, nodeTtlMs: number): Promise<void>;
}
