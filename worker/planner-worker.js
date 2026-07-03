// ── Kandy's Planner — Cloudflare Worker ──────────────────────────────
// Stateless relay: news/quotes CORS proxy + Microsoft To Do + E*TRADE.
// It STORES NOTHING user-specific. The Microsoft refresh token and the E*TRADE
// access token/secret live only in the browser's localStorage and are sent
// per-request; the Worker just signs/forwards to the provider. The E*TRADE
// CONSUMER key/secret are Worker secrets (env.ETRADE_KEY / env.ETRADE_SECRET).
// Deploy: wrangler deploy --config <this dir>/wrangler.toml  (--dry-run first)

const MS_CLIENT = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; // public client
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-MS-Refresh,X-ET-Token,X-ET-Secret',
};
const ALLOW = ['news.google.com', 'finance.yahoo.com'];
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...CORS, 'content-type': 'application/json' } });

// ── OAuth 1.0a (E*TRADE) — RFC3986 encode + HMAC-SHA1 signing ──
function enc(s) { return encodeURIComponent(s).replace(/[!*'()]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()); }
async function hmacSha1(key, msg) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
// Build a signed OAuth Authorization header for a GET request. `extra` holds
// flow-only oauth params (oauth_callback / oauth_verifier). Query params in the
// URL are folded into the signature base per spec.
async function etAuth(method, url, ck, cs, token, tokenSecret, extra) {
  const oauth = {
    oauth_consumer_key: ck,
    oauth_nonce: crypto.randomUUID().replace(/-/g, ''),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_version: '1.0',
  };
  if (token) oauth.oauth_token = token;
  Object.assign(oauth, extra || {});
  const u = new URL(url);
  const params = {};
  u.searchParams.forEach((v, k) => { params[k] = v; });
  Object.assign(params, oauth);
  const base = u.origin + u.pathname;
  const paramStr = Object.keys(params).sort().map((k) => enc(k) + '=' + enc(params[k])).join('&');
  const sigBase = method.toUpperCase() + '&' + enc(base) + '&' + enc(paramStr);
  const signingKey = enc(cs) + '&' + enc(tokenSecret || '');
  oauth.oauth_signature = await hmacSha1(signingKey, sigBase);
  return 'OAuth ' + Object.keys(oauth).sort().map((k) => enc(k) + '="' + enc(oauth[k]) + '"').join(', ');
}
async function etGet(url, ck, cs, token, tokenSecret) {
  const auth = await etAuth('GET', url, ck, cs, token, tokenSecret, {});
  return fetch(url, { headers: { Authorization: auth, Accept: 'application/json' } });
}

async function msForm(params) {
  const r = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  });
  return r.json();
}
function jwtEmail(idt) {
  try { let p = idt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'); while (p.length % 4) p += '='; const j = JSON.parse(atob(p)); return j.preferred_username || j.email || j.upn || ''; }
  catch { return ''; }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (url.pathname === '/health') return new Response('ok', { headers: { ...CORS, 'content-type': 'text/plain' } });

    // ── E*TRADE (OAuth 1.0a). Consumer key/secret = Worker secrets; the user's
    //    access token/secret come from the browser per request (nothing stored). ──
    if (url.pathname.startsWith('/et/')) {
      const ck = env.ETRADE_KEY, cs = env.ETRADE_SECRET;
      if (!ck || !cs) return json({ error: 'E*TRADE keys not configured' }, 500);

      if (url.pathname === '/et/request') {
        const rurl = 'https://api.etrade.com/oauth/request_token';
        const auth = await etAuth('GET', rurl, ck, cs, '', '', { oauth_callback: 'oob' });
        const r = await fetch(rurl, { headers: { Authorization: auth } });
        const txt = await r.text();
        if (!r.ok) return json({ error: 'request_token failed', detail: txt.slice(0, 300) }, 200);
        const p = new URLSearchParams(txt), ot = p.get('oauth_token');
        return json({ oauth_token: ot, oauth_token_secret: p.get('oauth_token_secret'), authorize: 'https://us.etrade.com/e/t/etws/authorize?key=' + enc(ck) + '&token=' + enc(ot) });
      }
      if (url.pathname === '/et/access') {
        const ot = url.searchParams.get('oauth_token'), ots = url.searchParams.get('oauth_token_secret'), verifier = url.searchParams.get('verifier');
        if (!ot || !ots || !verifier) return json({ error: 'missing token/secret/verifier' }, 400);
        const aurl = 'https://api.etrade.com/oauth/access_token';
        const auth = await etAuth('GET', aurl, ck, cs, ot, ots, { oauth_verifier: verifier });
        const r = await fetch(aurl, { headers: { Authorization: auth } });
        const txt = await r.text();
        if (!r.ok) return json({ error: 'access_token failed', detail: txt.slice(0, 300) }, 200);
        const p = new URLSearchParams(txt);
        return json({ oauth_token: p.get('oauth_token'), oauth_token_secret: p.get('oauth_token_secret') });
      }
      if (url.pathname === '/et/portfolio') {
        const at = req.headers.get('X-ET-Token'), ats = req.headers.get('X-ET-Secret');
        if (!at || !ats) return json({ error: 'no token' }, 401);
        const lr = await etGet('https://api.etrade.com/v1/accounts/list.json', ck, cs, at, ats);
        if (lr.status === 401) return json({ error: 'expired' }, 401);
        if (!lr.ok) return json({ error: 'accounts failed', detail: (await lr.text()).slice(0, 300) }, 200);
        const ld = await lr.json();
        const accts = (((ld.AccountListResponse || {}).Accounts || {}).Account) || [];
        const out = [];
        for (const a of accts) {
          if (a.accountStatus === 'CLOSED') continue;
          const idk = a.accountIdKey;
          let total = null, cash = null, dayGain = null;
          try {
            const br = await etGet('https://api.etrade.com/v1/accounts/' + idk + '/balance.json?instType=BROKERAGE&realTimeNAV=true', ck, cs, at, ats);
            if (br.ok) { const comp = ((await br.json()).BalanceResponse || {}).Computed || {}; const rt = comp.RealTimeValues || {}; total = rt.totalAccountValue != null ? rt.totalAccountValue : comp.totalAccountValue; cash = comp.cashAvailableForInvestment; dayGain = rt.totalDayValue; }
          } catch (e) {}
          const positions = [];
          try {
            const pr = await etGet('https://api.etrade.com/v1/accounts/' + idk + '/portfolio.json?count=50&view=COMPLETE', ck, cs, at, ats);
            if (pr.ok) {
              for (const ap of ((await pr.json()).PortfolioResponse || {}).AccountPortfolio || []) {
                for (const pos of ap.Position || []) {
                  positions.push({ sym: (pos.Product || {}).symbol || pos.symbolDescription, qty: pos.quantity, value: pos.marketValue, gain: pos.totalGain, gainPct: pos.totalGainPct, dayGain: pos.daysGain, dayGainPct: pos.daysGainPct });
                }
              }
            }
          } catch (e) {}
          out.push({ name: a.accountDesc || a.accountName || ('…' + String(a.accountId).slice(-4)), type: a.accountType, total, cash, dayGain, positions });
        }
        return json({ accounts: out });
      }
      return json({ error: 'unknown et endpoint' }, 404);
    }

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
      const tk = await msForm({ grant_type: 'refresh_token', client_id: MS_CLIENT, refresh_token: rt, scope: 'Tasks.ReadWrite offline_access openid profile' });
      if (!tk.access_token) return json({ error: 'refresh failed', detail: tk.error_description || tk.error }, 401);
      const at = tk.access_token;
      const me = jwtEmail(tk.id_token || '');
      const lists = ((await (await fetch('https://graph.microsoft.com/v1.0/me/todo/lists', { headers: { Authorization: 'Bearer ' + at } })).json()).value) || [];
      const out = [];
      for (const l of lists.slice(0, 25)) {
        const tasks = ((await (await fetch('https://graph.microsoft.com/v1.0/me/todo/lists/' + l.id + "/tasks?$top=25&$filter=status ne 'completed'", { headers: { Authorization: 'Bearer ' + at } })).json()).value) || [];
        out.push({ id: l.id, name: l.displayName, tasks: tasks.map((t) => ({ id: t.id, title: t.title, due: (t.dueDateTime && t.dueDateTime.dateTime) || null })) });
      }
      return json({ me, lists: out, refresh: tk.refresh_token || rt });
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

    return new Response("Kandy's Planner Worker (stateless). /health /proxy /ms/* /et/request /et/access /et/portfolio", { headers: { ...CORS, 'content-type': 'text/plain' } });
  },
};
