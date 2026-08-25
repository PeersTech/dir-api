-- Directory registry schema (D1 / SQLite)

CREATE TABLE IF NOT EXISTS nodes (
  peer_id   TEXT PRIMARY KEY,
  multiaddr TEXT NOT NULL,
  region    TEXT,
  tier      TEXT NOT NULL DEFAULT 'node',
  last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);

CREATE TABLE IF NOT EXISTS nonces (
  peer_id    TEXT PRIMARY KEY,
  nonce      TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
