import { createApp } from './app.js';
import { D1Store, type D1Like } from './store-d1.js';

export interface Env {
  DB: D1Like;
}

/** Prune cadence: nonces die in minutes anyway; nodes unseen for 7 days
 * leave the table so churn never grows the dataset. Rate-limit windows are
 * retained for one day and are pruned here as well. */
const NODE_TTL_MS = 7 * 24 * 60 * 60_000;

export default {
  /** The app is constructed per request — Hono setup is microseconds, and
   * this keeps the D1 binding flowing through instead of globals. */
  fetch(request, env, ctx): Response | Promise<Response> {
    return createApp(new D1Store(env.DB)).fetch(request, undefined, ctx);
  },

  scheduled(event, env, ctx): void {
    ctx.waitUntil(new D1Store(env.DB).prune(Date.now(), NODE_TTL_MS));
  },
} satisfies ExportedHandler<Env>;
