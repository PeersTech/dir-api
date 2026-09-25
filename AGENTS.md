# Agent Guide

## Project

Cloudflare Worker + Hono + D1 directory service for Peers relay nodes.

## Commands

- Install: `npm ci`
- Test: `npm test`
- Typecheck: `npm run typecheck`
- Local dev: `npm run dev`

## Conventions

- Keep protocol validation in `src/crypto.ts` and route behavior in `src/app.ts`.
- Use the existing versioned JSON response envelope.
- Add regression tests for protocol and validation changes.
- Never log private signing material or accept unbounded request bodies.
- Do not add runtime dependencies without a clear need.

## Verification

Run `npm test` and `npm run typecheck` before committing. Deployment changes must be validated against Wrangler configuration.
