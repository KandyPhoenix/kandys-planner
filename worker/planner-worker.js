// ── Kandy's Planner — Cloudflare Worker ──────────────────────────────
// Stateless relay: news/quotes CORS proxy + Microsoft To Do sign-in & fetch.
// It STORES NOTHING. The Microsoft refresh token lives only in the browser's
// localStorage and is sent per-request; the Worker just forwards to Microsoft.
// Deploy: wrangler deploy --config <this dir>/wrangler.toml  (--dry-run first)

const MS_CLIENT = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; // public client
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-MS-Refresh',
};
const ALLOW = ['news.google.com', 'finance.yahoo.com'];
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...CORS, 'content-type': 'application/json' } });

async function msForm(params) {
  const r = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  });
  return r.json();
}

export default {
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (url.pathname === '/health') return new Response('ok', { headers: { ...CORS, 'content-type': 'text/plain' } });

    // ── CORS relay for allow-listed feeds/quotes ──
    if (url.pathname === '/proxy') {
      const target = url.searchParams.get('url');
      if (!target) return new Response('missing url', { status: 400, headers: CORS });
      let host; try { host = new URL(target).hostname; } catch { return new Response('bad url', { status: 400, headers: CORS }); }
      if (!ALLOW.some((a) => host === a || host.endsWith('.' + a))) return new Response('host not allowed', { status: 403, headers: CORS });
      const r = await fetch(target, { headers: { 'User-Agent': 'Mozilla/5.0 PlannerWorker' } });
      const body = await r.text();
      return new Response(body, { status: r.status, headers: { ...CORS, 'content-type': r.headers.get('content-type') || 'text/plain; charset=utf-8' } });
    }

    // ── Microsoft sign-in relay (device code) — the app shows the code, the app polls ──
    if (url.pathname === '/ms/devicecode') {
      const r = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: MS_CLIENT, scope: 'Tasks.ReadWrite offline_access openid profile' }),
      });
      return new Response(await r.text(), { headers: { ...CORS, 'content-type': 'application/json' } });
    }
    if (url.pathname === '/ms/poll') {
      const dc = url.searchParams.get('device_code'); if (!dc) return json({ error: 'missing device_code' }, 400);
      return json(await msForm({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: MS_CLIENT, device_code: dc }));
    }

    // ── Microsoft To Do — refresh token comes from the browser per request (nothing stored) ──
    if (url.pathname === '/ms/todo') {
      const rt = req.headers.get('X-MS-Refresh'); if (!rt) return json({ error: 'no token' }, 401);
      const tk = await msForm({ grant_type: 'refresh_token', client_id: MS_CLIENT, refresh_token: rt, scope: 'Tasks.ReadWrite offline_access' });
      if (!tk.access_token) return json({ error: 'refresh failed', detail: tk.error_description || tk.error }, 401);
      const at = tk.access_token;
      const lists = ((await (await fetch('https://graph.microsoft.com/v1.0/me/todo/lists', { headers: { Authorization: 'Bearer ' + at } })).json()).value) || [];
      const out = [];
      for (const l of lists.slice(0, 12)) {
        const tasks = ((await (await fetch('https://graph.microsoft.com/v1.0/me/todo/lists/' + l.id + "/tasks?$top=25&$filter=status ne 'completed'", { headers: { Authorization: 'Bearer ' + at } })).json()).value) || [];
        out.push({ id: l.id, name: l.displayName, tasks: tasks.map((t) => ({ id: t.id, title: t.title, due: (t.dueDateTime && t.dueDateTime.dateTime) || null })) });
      }
      return json({ lists: out, refresh: tk.refresh_token || rt });
    }
    if (url.pathname === '/ms/complete' && req.method === 'POST') {
      const rt = req.headers.get('X-MS-Refresh'), list = url.searchParams.get('list'), id = url.searchParams.get('id');
      if (!rt || !list || !id) return json({ error: 'missing token/list/id' }, 400);
      const tk = await msForm({ grant_type: 'refresh_token', client_id: MS_CLIENT, refresh_token: rt, scope: 'Tasks.ReadWrite offline_access' });
      if (!tk.access_token) return json({ error: 'refresh failed' }, 401);
      const r = await fetch('https://graph.microsoft.com/v1.0/me/todo/lists/' + list + '/tasks/' + id, {
        method: 'PATCH', headers: { Authorization: 'Bearer ' + tk.access_token, 'content-type': 'application/json' }, body: JSON.stringify({ status: 'completed' }),
      });
      return json({ ok: r.ok, refresh: tk.refresh_token || rt });
    }

    return new Response("Kandy's Planner Worker (stateless). /health /proxy /ms/devicecode /ms/poll /ms/todo /ms/complete", { headers: { ...CORS, 'content-type': 'text/plain' } });
  },
};
