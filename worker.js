/* Venue dashboard Worker.
   Money figures always come from Xero, ex-GST. Square supplies only the
   count of completed transactions. Read-only everywhere. */

import dashboardHtml from './dashboard.html';

const SESSION_TTL = 60 * 60 * 24 * 30;

function b64url(buf) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function hmacB64(secret, msg) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
}
async function pbkdf2B64(passcode, saltHex) {
  const salt = Uint8Array.from((saltHex.match(/.{2}/g) || []).map((h) => parseInt(h, 16)));
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(passcode), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, 256);
  return b64url(bits);
}
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}
let _sessionKeyCache = null;
async function getSessionKey(env) {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  if (_sessionKeyCache) return _sessionKeyCache;
  let k = await env.TOKENS.get('sys:session_secret');
  if (!k) {
    const b = new Uint8Array(32); crypto.getRandomValues(b);
    k = Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
    await env.TOKENS.put('sys:session_secret', k);
  }
  _sessionKeyCache = k; return k;
}
async function passcodeSet(env) { return !!(await env.TOKENS.get('sys:passcode_hash')); }
async function makeSession(env) {
  const payload = 'v1.' + Math.floor(Date.now() / 1000);
  return payload + '.' + await hmacB64(await getSessionKey(env), payload);
}
async function validSession(env, token) {
  if (!token) return false;
  const i = token.lastIndexOf('.'); if (i < 0) return false;
  const payload = token.slice(0, i);
  if (!timingSafeEqual(token.slice(i + 1), await hmacB64(await getSessionKey(env), payload))) return false;
  const issued = parseInt(payload.split('.')[1], 10);
  return !!issued && (Date.now() / 1000 - issued) <= SESSION_TTL;
}
function getCookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}
async function isLoggedIn(request, env) { return await validSession(env, getCookie(request, 'vd_session')); }
function sessionCookie(token, maxAge) {
  return 'vd_session=' + encodeURIComponent(token) + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + maxAge;
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
function htmlResponse(html) {
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' } });
}

function setupPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Set your password</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>body{font-family:system-ui,sans-serif;background:#0f1720;color:#eee;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
  .box{background:#1b2530;padding:32px;border-radius:12px;max-width:360px;width:100%}
  h1{font-size:20px;margin:0 0 8px} p{color:#9aa5b1;font-size:14px}
  input{width:100%;padding:10px;border-radius:8px;border:1px solid #34404c;background:#0f1720;color:#eee;margin:12px 0;box-sizing:border-box}
  button{width:100%;padding:10px;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
  .err{color:#f87171;font-size:13px;min-height:18px}</style></head>
  <body><div class="box"><h1>Set your dashboard password</h1>
  <p>Choose a password you'll use to open your dashboard. At least 6 characters.</p>
  <input id="p1" type="password" placeholder="New password">
  <input id="p2" type="password" placeholder="Confirm password">
  <div class="err" id="err"></div>
  <button onclick="go()">Save and open my dashboard</button></div>
  <script>
  async function go(){
    const p1=document.getElementById('p1').value, p2=document.getElementById('p2').value;
    const err=document.getElementById('err');
    if(p1.length<6){err.textContent='Please use at least 6 characters.';return;}
    if(p1!==p2){err.textContent='Passwords do not match.';return;}
    const r=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode:p1})});
    if(r.ok){location.href='/';}else{err.textContent='Something went wrong. Try again.';}
  }
  </script></body></html>`;
}
function loginPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>body{font-family:system-ui,sans-serif;background:#0f1720;color:#eee;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
  .box{background:#1b2530;padding:32px;border-radius:12px;max-width:360px;width:100%}
  h1{font-size:20px;margin:0 0 8px}
  input{width:100%;padding:10px;border-radius:8px;border:1px solid #34404c;background:#0f1720;color:#eee;margin:12px 0;box-sizing:border-box}
  button{width:100%;padding:10px;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
  .err{color:#f87171;font-size:13px;min-height:18px}</style></head>
  <body><div class="box"><h1>Your dashboard</h1>
  <input id="p" type="password" placeholder="Password" onkeydown="if(event.key==='Enter')go()">
  <div class="err" id="err"></div>
  <button onclick="go()">Sign in</button></div>
  <script>
  async function go(){
    const p=document.getElementById('p').value;
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode:p})});
    if(r.ok){location.href='/';}else{document.getElementById('err').textContent='Wrong password.';}
  }
  </script></body></html>`;
}

async function apiSetup(env, request) {
  if (await passcodeSet(env)) return json({ ok: false, error: 'exists' }, 403);
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const passcode = String((body && body.passcode) || '');
  if (passcode.length < 6) return json({ ok: false }, 400);
  const saltB = new Uint8Array(16); crypto.getRandomValues(saltB);
  const saltHex = Array.from(saltB).map((x) => x.toString(16).padStart(2, '0')).join('');
  await env.TOKENS.put('sys:passcode_hash', saltHex + '.' + (await pbkdf2B64(passcode, saltHex)));
  const token = await makeSession(env);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie(token, SESSION_TTL) } });
}
async function apiLogin(env, request) {
  if (!(await passcodeSet(env))) return json({ ok: false, error: 'no_passcode' }, 400);
  let body; try { body = await request.json(); } catch (e) { return json({ ok: false }, 400); }
  const passcode = String((body && body.passcode) || '');
  const stored = await env.TOKENS.get('sys:passcode_hash');
  const dot = stored.indexOf('.');
  const okPass = timingSafeEqual(await pbkdf2B64(passcode, stored.slice(0, dot)), stored.slice(dot + 1));
  if (!okPass) return json({ ok: false }, 401);
  const token = await makeSession(env);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie(token, SESSION_TTL) } });
}
function apiLogout() {
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': sessionCookie('', 0) } });
}

/* ---------------- Token store for OAuth (Xero) ---------------- */
async function getTokens(env, source) { const raw = await env.TOKENS.get('tokens:' + source); return raw ? JSON.parse(raw) : null; }
async function saveTokens(env, source, t) { await env.TOKENS.put('tokens:' + source, JSON.stringify(t)); }
async function clearTokens(env, source) { await env.TOKENS.delete('tokens:' + source); }
async function noteSync(env, source) { await env.TOKENS.put('lastSync:' + source, new Date().toISOString()); }
async function lastSync(env, source) { return await env.TOKENS.get('lastSync:' + source); }

const XERO = {
  authorizeUrl: 'https://login.xero.com/identity/connect/authorize',
  tokenUrl: 'https://identity.xero.com/connect/token',
  scopes: 'offline_access accounting.reports.profitandloss.read accounting.settings.read'
};

async function xeroRefresh(env) {
  const t = await getTokens(env, 'accounting');
  if (!t || !t.access_token) { const e = new Error('no tokens'); e.status = 401; throw e; }
  if (t.expires_at && Date.now() < t.expires_at - 60000) return t.access_token;
  if (!t.refresh_token) { const e = new Error('cannot refresh'); e.status = 401; throw e; }
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: t.refresh_token });
  const res = await fetch(XERO.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + btoa((env.ACCOUNTING_CLIENT_ID || '') + ':' + (env.ACCOUNTING_CLIENT_SECRET || '')) },
    body: body.toString()
  });
  if (!res.ok) { const e = new Error('refresh failed'); e.status = 401; throw e; }
  const fresh = await res.json();
  const updated = { ...t, access_token: fresh.access_token, refresh_token: fresh.refresh_token || t.refresh_token, expires_at: Date.now() + ((fresh.expires_in || 1800) * 1000) };
  await saveTokens(env, 'accounting', updated);
  return updated.access_token;
}

async function xeroTenantId(env) {
  const t = await getTokens(env, 'accounting');
  if (t && t.tenant_id) return t.tenant_id;
  const token = await xeroRefresh(env);
  const res = await fetch('https://api.xero.com/connections', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) { const e = new Error('connections failed'); e.status = res.status; throw e; }
  const list = await res.json();
  if (!list.length) { const e = new Error('no tenant'); e.status = 401; throw e; }
  const tenantId = list[0].tenantId, tenantName = list[0].tenantName;
  const cur = await getTokens(env, 'accounting');
  await saveTokens(env, 'accounting', { ...cur, tenant_id: tenantId, tenant_name: tenantName });
  return tenantId;
}

function walkPL(rows, sectionAcc) {
  for (const row of rows || []) {
    if (row.RowType === 'Section') {
      const title = (row.Title || '').toLowerCase();
      let key = null;
      if (title.includes('income') && !title.includes('other')) key = 'income';
      else if (title.includes('cost of sales') || title.includes('cost of goods')) key = 'cogs';
      else if (title.includes('operating expense') || title === 'expenses') key = 'opex';
      if (key) {
        for (const r of row.Rows || []) {
          if (r.RowType === 'Row' && r.Cells && r.Cells.length >= 2) {
            const label = (r.Cells[0].Value || '').toString();
            const amount = parseFloat(r.Cells[r.Cells.length - 1].Value || '0') || 0;
            sectionAcc[key].push({ label, amount });
          }
        }
      }
      walkPL(row.Rows, sectionAcc);
    }
  }
}
const WAGE_RE = /wages|salaries|superannuation|\bsuper\b|payroll|annual leave|long service|workcover/i;

async function xeroPL(env, from, to) {
  const token = await xeroRefresh(env);
  const tenantId = await xeroTenantId(env);
  const url = 'https://api.xero.com/api.xro/2.0/Reports/ProfitAndLoss?fromDate=' + from + '&toDate=' + to;
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + token, 'Xero-Tenant-Id': tenantId, Accept: 'application/json' } });
  if (!res.ok) { const e = new Error('xero pl failed'); e.status = res.status; throw e; }
  const data = await res.json();
  const rows = (data.Reports && data.Reports[0] && data.Reports[0].Rows) || [];
  const acc = { income: [], cogs: [], opex: [] };
  walkPL(rows, acc);
  const sum = (arr) => arr.reduce((a, r) => a + r.amount, 0);
  const revenue = sum(acc.income);
  const cogs = sum(acc.cogs);
  const wageRows = acc.opex.filter((r) => WAGE_RE.test(r.label));
  const wagesSuper = sum(wageRows);
  const opexTotal = sum(acc.opex);
  const overheads = opexTotal - wagesSuper;
  return { revenue, cogs, wagesSuper, overheads, wageLabels: wageRows.map((r) => r.label) };
}

/* ---------------- Square (POS) ---------------- */
async function squareCount(env, from, to) {
  if (!env.POS_API_TOKEN) { const e = new Error('no token'); e.status = 401; throw e; }
  const base = 'https://connect.squareup.com';
  let cursor = null, count = 0, iterations = 0;
  do {
    const params = new URLSearchParams({ begin_time: from + 'T00:00:00+10:00', end_time: to + 'T23:59:59+10:00', sort_order: 'ASC' });
    if (cursor) params.set('cursor', cursor);
    const res = await fetch(base + '/v2/payments?' + params.toString(), {
      headers: { Authorization: 'Bearer ' + env.POS_API_TOKEN, 'Square-Version': '2025-01-23' }
    });
    if (!res.ok) { const e = new Error('square failed'); e.status = res.status; throw e; }
    const data = await res.json();
    for (const p of data.payments || []) { if (p.status === 'COMPLETED') count++; }
    cursor = data.cursor; iterations++;
  } while (cursor && iterations < 20);
  return { count };
}
async function squareStatus(env) {
  if (!env.POS_API_TOKEN) return { connected: false };
  const res = await fetch('https://connect.squareup.com/v2/locations', { headers: { Authorization: 'Bearer ' + env.POS_API_TOKEN, 'Square-Version': '2025-01-23' } });
  if (!res.ok) return { connected: false, error: res.status };
  const data = await res.json();
  const loc = (data.locations || [])[0];
  return { connected: true, org: loc ? loc.name : null, sandbox: false };
}

/* ---------------- OAuth begin/callback (Xero only) ---------------- */
function randomState() { const a = new Uint8Array(16); crypto.getRandomValues(a); return Array.from(a).map((b) => b.toString(16).padStart(2, '0')).join(''); }

async function authStart(env, url) {
  const state = randomState();
  await env.TOKENS.put('oauthstate:accounting', state, { expirationTtl: 600 });
  const redirectUri = url.origin + '/auth/accounting/callback';
  const p = new URLSearchParams({ response_type: 'code', client_id: env.ACCOUNTING_CLIENT_ID || '', redirect_uri: redirectUri, scope: XERO.scopes, state });
  return Response.redirect(XERO.authorizeUrl + '?' + p.toString(), 302);
}
async function authCallback(env, url) {
  const code = url.searchParams.get('code');
  const gotState = url.searchParams.get('state');
  const wantState = await env.TOKENS.get('oauthstate:accounting');
  if (!code || !gotState || gotState !== wantState) {
    return new Response('That authorisation did not complete cleanly. Go back and click Reconnect to try again.', { status: 400 });
  }
  await env.TOKENS.delete('oauthstate:accounting');
  const redirectUri = url.origin + '/auth/accounting/callback';
  const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri });
  const res = await fetch(XERO.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic ' + btoa((env.ACCOUNTING_CLIENT_ID || '') + ':' + (env.ACCOUNTING_CLIENT_SECRET || '')) },
    body: body.toString()
  });
  if (!res.ok) return new Response('The connection could not be finished (Xero said no). Check the redirect address matches exactly.', { status: 502 });
  const t = await res.json();
  await saveTokens(env, 'accounting', { access_token: t.access_token, refresh_token: t.refresh_token || null, expires_at: Date.now() + ((t.expires_in || 1800) * 1000) });
  return Response.redirect(url.origin + '/', 302);
}

/* ---------------- Metrics API ---------------- */
async function accountingStatus(env) {
  const t = await getTokens(env, 'accounting');
  if (!t) return { configured: true, connected: false };
  try {
    const tenantId = await xeroTenantId(env);
    const cur = await getTokens(env, 'accounting');
    const sandbox = (cur.tenant_name || '').toLowerCase().includes('demo company');
    return { configured: true, connected: true, org: cur.tenant_name || null, sandbox, lastSync: await lastSync(env, 'accounting') };
  } catch (err) {
    return { configured: true, connected: false, error: { code: err.status || 0 } };
  }
}
async function slot(env, from, to) {
  const out = { accounting: null, pos: null };
  try { out.accounting = await xeroPL(env, from, to); await noteSync(env, 'accounting'); } catch (e) {}
  if (env.POS_API_TOKEN) { try { out.pos = await squareCount(env, from, to); await noteSync(env, 'pos'); } catch (e) {} }
  return out;
}
async function apiMetrics(env, url) {
  const cur = url.searchParams.get('cur'); const prev = url.searchParams.get('prev'); const yoy = url.searchParams.get('yoy');
  const parseR = (s) => { const m = /^(\d{4}-\d{2}-\d{2}):(\d{4}-\d{2}-\d{2})$/.exec(s || ''); return m ? { from: m[1], to: m[2] } : null; };
  const c = parseR(cur); if (!c) return json({ error: 'bad range' }, 400);
  const p = parseR(prev), y = parseR(yoy);
  const [accStatus, posStatus] = await Promise.all([accountingStatus(env), squareStatus(env)]);
  const periods = {};
  periods.cur = await slot(env, c.from, c.to);
  periods.prev = p ? await slot(env, p.from, p.to) : null;
  periods.yoy = y ? await slot(env, y.from, y.to) : null;
  return json({
    generatedAt: new Date().toISOString(),
    sources: {
      accounting: accStatus,
      pos: { configured: true, connected: !!posStatus.connected, org: posStatus.org || null, sandbox: false, lastSync: await lastSync(env, 'pos') },
      rostering: { configured: false }
    },
    periods
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url); const path = url.pathname;
    if (path === '/favicon.ico') return new Response(null, { status: 204 });
    if (path === '/api/setup' && request.method === 'POST') return apiSetup(env, request);
    if (path === '/api/login' && request.method === 'POST') return apiLogin(env, request);
    if (path === '/api/logout' && request.method === 'POST') return apiLogout();

    const loggedIn = await isLoggedIn(request, env);

    if (path === '/api/bepoz-raw' && request.method === 'POST') {
      const token = url.searchParams.get('token');
      if (!env.BEPOZ_INGEST_TOKEN || token !== env.BEPOZ_INGEST_TOKEN) return json({ error: 'unauthorized' }, 401);
      const body = await request.text();
      const key = 'bepozraw:' + new Date().toISOString();
      await env.TOKENS.put(key, body.slice(0, 500000));
      return json({ ok: true });
    }
    if (path === '/api/bepoz-inbox') {
      if (!loggedIn) return json({ error: 'auth' }, 401);
      const list = await env.TOKENS.list({ prefix: 'bepozraw:' });
      const keys = list.keys.map(k => k.name).sort().reverse().slice(0, 5);
      const items = [];
      for (const k of keys) { items.push({ key: k, value: (await env.TOKENS.get(k) || '').slice(0, 3000) }); }
      return json({ count: list.keys.length, items });
    }

    if (path === '/' || path === '/index.html') {
      if (loggedIn) return htmlResponse(dashboardHtml);
      return htmlResponse((await passcodeSet(env)) ? loginPage() : setupPage());
    }
    if (path === '/api/metrics' && request.method === 'GET') {
      if (!loggedIn) return json({ error: 'auth' }, 401);
      return apiMetrics(env, url);
    }
    if (path === '/auth/accounting/start') { if (!loggedIn) return Response.redirect(url.origin + '/', 302); return authStart(env, url); }
    if (path === '/auth/accounting/callback') { if (!loggedIn) return Response.redirect(url.origin + '/', 302); return authCallback(env, url); }
    if (path === '/api/disconnect' && request.method === 'POST') {
      if (!loggedIn) return json({ error: 'auth' }, 401);
      const source = url.searchParams.get('source');
      if (source === 'accounting') { await clearTokens(env, 'accounting'); return json({ ok: true }); }
      return json({ error: 'unknown source' }, 400);
    }
    return new Response('Not found', { status: 404 });
  }
};
