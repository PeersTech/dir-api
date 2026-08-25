# dir-api — Peers node registry & discovery

Cloudflare Worker (Hono + D1) that answers "which backbone nodes are alive
right now?" so clients never paste node addresses. Discovery only — no
message traffic ever touches this.

**Production URL:** `https://directory.peers.dpdns.org` (Workers custom
domain; the zone peers.dpdns.org is on Cloudflare).

## API (v1)

| Endpoint | Purpose |
|---|---|
| `GET /v1/challenge?peerId=` | single-use nonce, 5 min TTL |
| `POST /v1/register` | `{peerId, nonce, sig, multiaddr}` — sig over `peers-directory:v1:register:<peerId>:<nonce>` |
| `POST /v1/heartbeat` | `{peerId, ts, sig[, multiaddr]}` every `heartbeatAfterSec`; inside half the cadence it's a free ack (write-skipped) |
| `GET /v1/nodes?limit=&cursor=` | fresh nodes, keyset-paginated composite cursor `<lastSeen>:<peerId>` |

Every response carries `{ok, protocol: 1, …}` and `heartbeatAfterSec` —
the server slows the fleet's heartbeat cadence as it grows, which is what
keeps D1 write volume inside plan limits at 10k+ nodes.

## Trust model

- A libp2p peer id **embeds its own Ed25519 public key**, so every request
  is verified against the key inside the id — no accounts, no TOFU.
- The multiaddr must terminate at `/p2p/<same peer id>` — address
  poisoning is structurally impossible.
- Nonces are consumed atomically (`DELETE … RETURNING`) — replays fail.
- Clients still dial-and-verify locally: a hostile directory can degrade
  onboarding, never read traffic (there is none) or redirect messages.

## Scale notes (1k–10k nodes)

- Writes = heartbeats only, adaptive cadence (30 min default): 10k nodes ≈
  480k writes/day → fits Workers Paid D1 (25M/mo); ~2k nodes fit free.
- Reads edge-cached + cursor pagination; 10k rows is nothing for D1.
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
