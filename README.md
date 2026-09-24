# dir-api: Peers node registry and discovery

Cloudflare Worker (Hono + D1) that answers "which backbone nodes are alive
right now?" Discovery only. No message traffic ever touches this.

The Peers client does not call this service yet. Client integration is
planned but not wired up. Operators distribute `PEERS_NODES` lines by hand
today. They copy the `PEERS_NODES=` line that `peers --node` prints and
paste it into each client. See `docs/running-a-node.md` in the Peers repo.

The intended client flow is: fetch `GET /v1/nodes`, read the top level
`peersNodes` string, and paste it in as the `PEERS_NODES` value. To use
`nodes.json` instead, split that string on commas into an array.

**Production URL:** `https://directory.peers.dpdns.org` (Workers custom
domain. The zone peers.dpdns.org is on Cloudflare).

## API (v1)

| Endpoint | Purpose |
|---|---|
| `GET /v1/challenge?peerId=` | single-use nonce, 5 min TTL |
| `POST /v1/register` | `{peerId, nonce, sig, multiaddrs}` where `multiaddrs` is a comma-separated list in `PEERS_NODES` format. Sig over `peers-directory:v1:register:<peerId>:<nonce>` |
| `POST /v1/heartbeat` | `{peerId, ts, sig[, multiaddrs][, tier]}` every `heartbeatAfterSec`. Inside half the cadence it is a free ack (write-skipped) |
| `GET /v1/nodes?limit=&cursor=` | fresh nodes, keyset-paginated composite cursor `<lastSeen>:<peerId>` |

Every response carries `{ok, protocol: 1, ...}` and `heartbeatAfterSec`.
The service currently uses a fixed 30-minute heartbeat cadence. The
`/v1/nodes` endpoint is queried directly from D1; add an edge-cache policy
before relying on the scale figures below.

### Node records

Each node row has:

- `peerId`: the libp2p peer id.
- `multiaddrs`: comma-separated full multiaddrs. Every entry must end in
  `/p2p/<same peer id>`.
- `region`: optional short string.
- `tier`: one of `citizen`, `node`, or `off`. These match the Peers relay
  tiers. The default is `node`. Any other value is rejected with 400.
- `lastSeen`: epoch milliseconds of the last write.

### /v1/nodes response

The list response includes both shapes:

- `nodes`: structured array of node records with `multiaddrs`, `peerId`,
  `lastSeen`, `region`, and `tier`. Records with `tier: "off"` are omitted
  because they do not forward traffic.
- `peersNodes`: all `multiaddrs` from the page joined with commas. This
  string can be dropped straight into the Peers `PEERS_NODES` env var.
  Split it on commas to write a `nodes.json` array instead.

Pagination uses `nextCursor` when more rows remain.

## Trust model

- A libp2p peer id embeds its own Ed25519 public key. Every request is
  verified against the key inside the id. No accounts, no TOFU.
- Every multiaddr must terminate at `/p2p/<same peer id>`. Address
  poisoning is structurally impossible.
- Nonces are consumed atomically (`DELETE ... RETURNING`). Replays fail.
- Clients still dial and verify locally. A hostile directory can degrade
  onboarding. It cannot read traffic (there is none) or redirect messages.

## Scale notes (1k to 10k nodes)

- Writes are heartbeats only, with a fixed 30-minute cadence. 10k nodes is
  about 480k writes/day, which fits Workers Paid D1 (25M/mo). About 2k nodes
  fit free.
- Reads are cursor-paginated but currently query D1 directly. Add edge
  caching before treating this as a low-read-cost deployment.
- Cron prunes expired nonces and 7-day-dead nodes twice an hour.

## Deploy

```sh
npm ci
npx wrangler login
npx wrangler d1 create dir-api        # paste the id into wrangler.toml
npx wrangler d1 execute dir-api --remote --file schema.sql
npx wrangler deploy                   # attaches directory.peers.dpdns.org
```

Local dev: `npm run dev` (wrangler dev, local D1).

## Tests

```sh
npm test          # full flow + fake-id / replay / poisoning / pagination
```
