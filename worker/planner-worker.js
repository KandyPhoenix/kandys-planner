// ── Kandy's Planner — Cloudflare Worker ──────────────────────────────
// Makes the News ticker reliable (CORS relay for Google News RSS) and is
// the place E*TRADE support will be added.
//
// DEPLOY (2 minutes):
//   1. cloudflare.com → Workers & Pages → Create → Create Worker
//   2. Name it (e.g. "planner") → Deploy → then "Edit code"
//   3. Delete the sample, paste THIS whole file, click Deploy
//   4. Copy the URL it gives you (https://planner.<you>.workers.dev)
//   5. In the Planner → ⚙ Settings → Cloudflare Worker → paste that URL → Save
//
// Endpoints:
//   GET /health           → "ok" (used by the app to verify the URL)
//   GET /proxy?url=<rss>   → fetches an allow-listed RSS feed with CORS
//   (E*TRADE endpoints will be added here once API keys are set as secrets)

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

// Only these hosts may be proxied (prevents this from being an open proxy)
const ALLOW = ['news.google.com'];

export default {
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });

    if (url.pathname === '/health') {
      return new Response('ok', { headers: { ...CORS, 'content-type': 'text/plain' } });
    }

    if (url.pathname === '/proxy') {
      const target = url.searchParams.get('url');
      if (!target) return new Response('missing url', { status: 400, headers: CORS });
      let host;
      try { host = new URL(target).hostname; }
      catch { return new Response('bad url', { status: 400, headers: CORS }); }
      if (!ALLOW.some((a) => host === a || host.endsWith('.' + a))) {
        return new Response('host not allowed', { status: 403, headers: CORS });
      }
      const r = await fetch(target, { headers: { 'User-Agent': 'Mozilla/5.0 PlannerWorker' } });
      const body = await r.text();
      return new Response(body, {
        status: r.status,
        headers: { ...CORS, 'content-type': 'text/xml; charset=utf-8' },
      });
    }

    return new Response(
      "Kandy's Planner Worker is running. Endpoints: /health, /proxy?url=",
      { headers: { ...CORS, 'content-type': 'text/plain' } }
    );
  },
};
