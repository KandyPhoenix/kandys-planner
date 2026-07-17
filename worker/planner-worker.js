// ── Kandy's Planner — Cloudflare Worker ──────────────────────────────
// Stateless relay: news/quotes CORS proxy + Microsoft To Do + E*TRADE.
// It STORES NOTHING user-specific except a push subscription + a small
// server-side "already notified" log, both persisted in the same Firestore
// doc the planner app itself uses (wellness/servicesPlanner). The Microsoft
// refresh token and the E*TRADE access token/secret still live only in the
// browser's localStorage and are sent per-request.
// Deploy: wrangler deploy --config <this dir>/wrangler.toml  (--dry-run first)

import { ApplicationServerKeys, generatePushHTTPRequest } from 'webpush-webcrypto';

const MS_CLIENT = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; // public client
const FIRESTORE_DOC_URL = 'https://firestore.googleapis.com/v1/projects/wellness-tracker-127/databases/(default)/documents/wellness/servicesPlanner';

// ── Firestore auth ───────────────────────────────────────────────────
// This worker used to read AND WRITE the planner doc anonymously, which only
// worked because the Firestore rules were wide open — the same hole that let
// anyone on the internet read Kandy's client names and invoice amounts. Once
// those rules lock, anonymous access 403s and her reminders would die
// silently (a cron failure is invisible).
//
// So it now authenticates with a service account. Firestore's REST API
// authorises IAM identities directly, so an Owner/Editor token satisfies the
// locked rules without needing a Firebase Auth user.
//
// FIREBASE_SA_JSON is a wrangler secret (the service-account key JSON), never
// in the repo. If it's absent the calls fall back to anonymous, which keeps
// this working while the rules are still open.
let _tokCache = { token: null, exp: 0 };

function b64url(buf) {
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
async function firestoreToken(env) {
  if (!env || !env.FIREBASE_SA_JSON) return null;          // rules still open
  const now = Math.floor(Date.now() / 1000);
  if (_tokCache.token && _tokCache.exp > now + 120) return _tokCache.token;

  const sa = JSON.parse(env.FIREBASE_SA_JSON);
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64url(new TextEncoder().encode(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600, iat: now,
  })));
  const key = await crypto.subtle.importKey(
    'pkcs8', pemToArrayBuffer(sa.private_key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${header}.${claim}`));
  const jwt = `${header}.${claim}.${b64url(sig)}`;

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt,
    }),
  });
  if (!r.ok) return null;
  const t = await r.json();
  _tokCache = { token: t.access_token, exp: now + (t.expires_in || 3600) };
  return _tokCache.token;
}
async function firestoreHeaders(env, extra) {
  const h = Object.assign({}, extra || {});
  const t = await firestoreToken(env);
  if (t) h['Authorization'] = 'Bearer ' + t;
  return h;
}

// ── Firestore read/modify/write of the single `json` string field ──
async function getPlannerJson(env) {
  const r = await fetch(FIRESTORE_DOC_URL, { headers: await firestoreHeaders(env) });
  const doc = await r.json();
  return JSON.parse(doc.fields.json.stringValue);
}
async function putPlannerJson(data, env) {
  const body = { fields: { json: { stringValue: JSON.stringify(data) } } };
  await fetch(FIRESTORE_DOC_URL + '?updateMask.fieldPaths=json', {
    method: 'PATCH',
    headers: await firestoreHeaders(env, { 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });
}

// ── Recurring-rule + one-off due-date math, mirrored from index.html instancesIn()/itemsIn() ──
function lastDom(y, m) { return new Date(y, m + 1, 0).getDate(); }
function toISO(d) { return d.toISOString().slice(0, 10); }
function parseISO(s) { const [y, m, d] = s.split('-').map(Number); return new Date(Date.UTC(y, m - 1, d)); }

function dueItemsInRange(data, startISO, endISO) {
  const start = parseISO(startISO), end = parseISO(endISO);
  const skip = data.skip || {}, done = data.done || {};
  const out = [];
  for (const r of (data.rules || [])) {
    if (!r.active) continue;
    const rs = r.start ? parseISO(r.start) : null;
    const ok = (d) => !rs || d >= rs;
    if (r.freq === 'monthly' || r.freq === 'quarterly') {
      const anc = rs || start;
      const ancIdx = anc.getUTCFullYear() * 12 + anc.getUTCMonth();
      const step = r.freq === 'quarterly' ? 3 : 1;
      let cur = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), 1));
      while (cur <= end) {
        const idx = cur.getUTCFullYear() * 12 + cur.getUTCMonth();
        if ((!rs || idx >= ancIdx) && (idx - ancIdx) % step === 0) {
          const day = Math.min(r.dom || 1, lastDom(cur.getUTCFullYear(), cur.getUTCMonth()));
          const dm = new Date(Date.UTC(cur.getUTCFullYear(), cur.getUTCMonth(), day));
          if (dm >= start && dm <= end && ok(dm)) {
            const key = r.id + '|' + toISO(dm);
            if (!skip[key] && !done[key]) out.push({ key, date: toISO(dm), title: r.title, client: r.client, remind: r.remind || 0, amount: r.amount || 0 });
          }
        }
        cur = new Date(Date.UTC(cur.getUTCFullYear(), cur.getUTCMonth() + 1, 1));
      }
    } else if (r.freq === 'yearly') {
      const mo = r.month || 0;
      for (let y = start.getUTCFullYear(); y <= end.getUTCFullYear(); y++) {
        const day = Math.min(r.dom || 1, lastDom(y, mo));
        const dy = new Date(Date.UTC(y, mo, day));
        if (dy >= start && dy <= end && ok(dy)) {
          const key = r.id + '|' + toISO(dy);
          if (!skip[key] && !done[key]) out.push({ key, date: toISO(dy), title: r.title, client: r.client, remind: r.remind || 0, amount: r.amount || 0 });
        }
      }
    }
  }
  for (const o of (data.oneoffs || [])) {
    if (o.done || !o.due) continue;
    const dd = parseISO(o.due);
    if (dd >= start && dd <= end) out.push({ key: o.id, date: o.due, title: o.title, client: o.client, remind: o.remind || 0, amount: o.amount || 0 });
  }
  return out;
}

async function sendPush(env, subscription, payload) {
  if (!subscription || !env.VAPID_PRIVATE_KEY || !env.VAPID_PUBLIC_KEY) return;
  try {
    const applicationServerKeys = await ApplicationServerKeys.fromJSON({
      publicKey: env.VAPID_PUBLIC_KEY,
      privateKey: env.VAPID_PRIVATE_KEY,
    });
    const { headers, body, endpoint } = await generatePushHTTPRequest({
      applicationServerKeys,
      payload: JSON.stringify(payload),
      target: subscription,
      adminContact: 'mailto:' + (env.REMINDER_EMAIL_TO || 'kandyphoenix@hotmail.com'),
      ttl: 60 * 60 * 24,
    });
    const r = await fetch(endpoint, { method: 'POST', headers, body });
    if (!r.ok) console.log('push send failed', r.status, await r.text());
  } catch (e) { console.log('push send failed', e.message); }
}
async function sendEmail(env, subject, html) {
  if (!env.RESEND_API_KEY) return;
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: "Kandy's Planner <hello@phoenixmethodseo.com>",
      to: [env.REMINDER_EMAIL_TO || 'kandyphoenix@hotmail.com'],
      subject,
      html,
    }),
  }).catch((e) => console.log('email send failed', e.message));
}

// ── Daily cron: due-today/overdue summary + N-day-ahead lead-time reminders ──
async function runReminderCheck(env) {
  const data = await getPlannerJson(env);
  const today = new Date(); today.setUTCHours(0, 0, 0, 0);
  const todayISO = toISO(today);
  data.serverNotified = data.serverNotified || {};
  let changed = false;

  const dueToday = dueItemsInRange(data, todayISO, todayISO);
  const overdueWindow = dueItemsInRange(data, toISO(new Date(today.getTime() - 30 * 86400000)), toISO(new Date(today.getTime() - 86400000)));
  const summaryKey = 'summary|' + todayISO;
  if ((dueToday.length || overdueWindow.length) && !data.serverNotified[summaryKey]) {
    data.serverNotified[summaryKey] = true; changed = true;
    const title = '📋 Planner — ' + todayISO;
    const body = (dueToday.length ? dueToday.length + ' due today' : '') + (dueToday.length && overdueWindow.length ? ' · ' : '') + (overdueWindow.length ? overdueWindow.length + ' overdue' : '');
    const listHtml = dueToday.map((i) => `<li><strong>${i.title}</strong> (${i.client}${i.amount ? ', $' + i.amount : ''})</li>`).join('');
    await sendPush(env, data.pushSubscription, { title, body });
    await sendEmail(env, title, `<p>${body}</p>${listHtml ? '<ul>' + listHtml + '</ul>' : ''}`);
  }

  const upcoming = dueItemsInRange(data, toISO(new Date(today.getTime() + 86400000)), toISO(new Date(today.getTime() + 60 * 86400000))).filter((i) => i.remind > 0);
  for (const i of upcoming) {
    const days = Math.round((parseISO(i.date) - today) / 86400000);
    if (days > 0 && days <= i.remind) {
      const leadKey = 'lead|' + i.key + '|' + todayISO;
      if (!data.serverNotified[leadKey]) {
        data.serverNotified[leadKey] = true; changed = true;
        const title = `📅 In ${days} day${days > 1 ? 's' : ''}: ${i.title}`;
        const body = `${i.client} · due ${i.date}${i.amount ? ' · $' + i.amount : ''}`;
        await sendPush(env, data.pushSubscription, { title, body });
        await sendEmail(env, title, `<p>${body}</p>`);
      }
    }
  }

  if (changed) await putPlannerJson(data, env);
}
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

    // ── Push subscription storage (single device) + manual test trigger ──
    if (url.pathname === '/push-subscribe' && req.method === 'POST') {
      const sub = await req.json().catch(() => null);
      if (!sub || !sub.endpoint) return json({ error: 'invalid subscription' }, 400);
      const data = await getPlannerJson(env);
      data.pushSubscription = sub;
      await putPlannerJson(data, env);
      return json({ ok: true });
    }
    if (url.pathname === '/push-test' && req.method === 'POST') {
      const data = await getPlannerJson(env);
      await sendPush(env, data.pushSubscription, { title: '🔔 Test reminder', body: "Push is wired up — you're good." });
      await sendEmail(env, "Test reminder — Kandy's Planner", '<p>Push + email are wired up.</p>');
      return json({ ok: true });
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

    return new Response("Kandy's Planner Worker. /health /proxy /ms/* /et/request /et/access /et/portfolio /push-subscribe /push-test", { headers: { ...CORS, 'content-type': 'text/plain' } });
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runReminderCheck(env));
  },
};
