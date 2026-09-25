# Directory API hardening plan

**Goal:** Make node discovery compatible with the addresses Peers advertises and safe against basic registry abuse.

**Approach:** Fix QUIC/transport multiaddr validation, add signed mutable metadata and durable replay protection in a backwards-compatible v2 path where practical, add request/rate controls, and expose useful health semantics.

**Files touched:** `src/crypto.ts`, `src/app.ts`, `src/types.ts`, `src/store-d1.ts`, tests, schema/migrations, and API docs.

**Verification:** `npm test`, `npm run typecheck`, and focused transport/signature tests.

**Status:** done — QUIC/multiaddr validation, strict request parsing, D1-backed rate limits, health metrics, tests, and v1 trust-model documentation completed. Durable v2 replay protection remains deferred.
