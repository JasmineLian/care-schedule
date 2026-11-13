/**
 * 居護行程動態表 — 帳號密碼登入（Cloudflare Pages Middleware）
 * 整個網站（畫面 + /api）都要先登入；登入後記住 90 天。
 *
 * Pages 專案 → Settings 需要設定：
 *   Variables and Secrets
 *     USERS          （Text）帳號清單 JSON，用「帳號產生器.html」產生；只存雜湊，不存密碼
 *     SESSION_SECRET （Secret）隨機長字串（至少 32 字）；換掉 = 所有人立刻被登出
 *   Bindings
 *     KV namespace：變數名 AUTH_KV（記錄登入失敗次數，用來鎖帳號）
 *     Service binding：變數名 API → care-schedule-api（給 /api 用）
 *
 * USERS 格式：
 *   {"weishan":{"name":"WeiShan","salt":"…","hash":"…","iter":10000},
 *    "bot":{"name":"每日流程","salt":"…","hash":"…","iter":10000,"disabled":false}}
 *   - 帳號一律小寫；"disabled":true = 停用（已登入的人下一個請求就被踢出）
 *   - 改密碼 = 換掉 salt/hash，該帳號所有裝置的登入立刻失效
 */

const SESSION_COOKIE = 'cs_session';
const NAME_COOKIE = 'cs_user';                 // 只放顯示名稱，給網頁顯示用（不是憑證）
const MAX_AGE = 90 * 24 * 3600;                // 記住 3 個月
const DEFAULT_ITER = 10000;
const USER_FAIL_MAX = 5;                       // 同一帳號錯 5 次鎖 15 分鐘
const IP_FAIL_MAX = 20;                        // 同一 IP 錯 20 次鎖 15 分鐘
const LOCK_TTL = 15 * 60;

const te = new TextEncoder();

/* ---------- 小工具 ---------- */
function b64urlEncode(bytes) {
  let s = '';
  const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64Decode(s) {
  s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function getCookie(request, name) {
  const c = request.headers.get('Cookie') || '';
  for (const part of c.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function safeNext(n) {
  n = String(n || '/');
  return (n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') && !n.startsWith('/login')) ? n : '/';
}
function jsonRes(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {})
  });
}

/* ---------- 設定 ---------- */
let usersCache = { raw: null, map: null };
function getUsers(env) {
  const raw = String(env.USERS || '');
  if (usersCache.raw === raw) return usersCache.map;
  const obj = JSON.parse(raw);                 // 格式錯誤 → 丟例外（外層會回設定錯誤）
  const map = {};
  for (const k of Object.keys(obj)) map[k.trim().toLowerCase()] = obj[k];
  usersCache = { raw, map };
  return map;
}
let keyCache = { secret: null, key: null };
async function hmacKey(env) {
  const secret = String(env.SESSION_SECRET || '');
  if (secret.length < 32) throw new Error('SESSION_SECRET 未設定或太短（至少 32 字）');
  if (keyCache.secret === secret) return keyCache.key;
  const key = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  keyCache = { secret, key };
  return key;
}
function checkConfig(env) {
  if (!env.USERS) throw new Error('USERS 未設定');
  if (!env.AUTH_KV) throw new Error('KV 綁定 AUTH_KV 未設定');
  getUsers(env);
}

/* ---------- 密碼 ---------- */
async function pbkdf2(password, saltBytes, iter) {
  const k = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: iter }, k, 256));
}
async function checkPassword(rec, password) {
  if (!rec || !rec.salt || !rec.hash) {
    await pbkdf2(password, te.encode('dummy-salt-0000'), DEFAULT_ITER);   // 不存在的帳號也花一樣的時間
    return false;
  }
  const got = await pbkdf2(password, b64Decode(rec.salt), Number(rec.iter) || DEFAULT_ITER);
  return sameBytes(got, b64Decode(rec.hash));
}

/* ---------- 登入狀態（簽章 Cookie） ---------- */
async function makeSession(env, user, rec) {
  const payload = { u: user, k: String(rec.hash).slice(0, 12), exp: Math.floor(Date.now() / 1000) + MAX_AGE };
  const p = b64urlEncode(te.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), te.encode(p));
  return p + '.' + b64urlEncode(sig);
}
async function readSession(request, env) {
  const v = getCookie(request, SESSION_COOKIE);
  if (!v) return null;
  const dot = v.indexOf('.');
  if (dot < 1) return null;
  const p = v.slice(0, dot), s = v.slice(dot + 1);
  let ok = false;
  try { ok = await crypto.subtle.verify('HMAC', await hmacKey(env), b64Decode(s), te.encode(p)); } catch (e) { ok = false; }
  if (!ok) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(b64Decode(p))); } catch (e) { return null; }
  if (!payload || typeof payload.exp !== 'number' || payload.exp < Date.now() / 1000) return null;
  const rec = getUsers(env)[payload.u];
  if (!rec || rec.disabled) return null;                         // 帳號被刪除或停用
  if (String(rec.hash || '').slice(0, 12) !== payload.k) return null;   // 密碼改過
  return { user: payload.u, name: String(rec.name || payload.u) };
}
function sessionCookies(token, name) {
  return [
    `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
    `${NAME_COOKIE}=${encodeURIComponent(name)}; Path=/; Max-Age=${MAX_AGE}; Secure; SameSite=Lax`
  ];
}
function clearCookies() {
  return [
    `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
    `${NAME_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Lax`
  ];
}

/* ---------- 失敗次數 / 鎖定（KV） ---------- */
async function getCount(env, key) { return Number(await env.AUTH_KV.get(key)) || 0; }
async function addFail(env, key) {
  const n = (await getCount(env, key)) + 1;
  await env.AUTH_KV.put(key, String(n), { expirationTtl: LOCK_TTL });
  return n;
}

/* ---------- 登入頁 ---------- */
function loginPage(next, msg, status) {
  const html = `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>登入｜居護行程動態表</title>
<style>
body{margin:0;font-family:system-ui,-apple-system,"Microsoft JhengHei",sans-serif;background:#f4f6fa;display:flex;min-height:100vh;align-items:center;justify-content:center}
form{background:#fff;border:1px solid #dde3ee;border-radius:12px;padding:28px 28px 22px;width:300px;box-shadow:0 2px 10px rgba(0,0,0,.04)}
h1{font-size:18px;margin:0 0 18px}
label{display:block;font-size:13px;color:#555;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #ccd3e0;border-radius:8px;font-size:15px}
button{margin-top:18px;width:100%;padding:10px;border:0;border-radius:8px;background:#2f6fdb;color:#fff;font-size:15px;cursor:pointer}
.msg{background:#fdecea;color:#b3261e;border-radius:8px;padding:8px 10px;font-size:13px;margin-bottom:6px}
.note{font-size:12px;color:#888;margin-top:12px;text-align:center}
</style></head><body>
<form method="post" action="/login" autocomplete="on">
<h1>居護行程動態表</h1>
${msg ? `<div class="msg">${escHtml(msg)}</div>` : ''}
<input type="hidden" name="next" value="${escHtml(next)}">
<label for="u">帳號</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">密碼</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">登入</button>
<div class="note">登入後這台電腦會記住 3 個月；共用電腦用完請按「登出」。</div>
</form></body></html>`;
  return new Response(html, {
    status: status || 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' }
  });
}

async function handleLogin(request, env, url) {
  if (request.method === 'GET') return loginPage(safeNext(url.searchParams.get('next')), '');
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) return new Response('Forbidden', { status: 403 });

  const form = await request.formData();
  const user = String(form.get('username') || '').trim().toLowerCase().slice(0, 64);
  const password = String(form.get('password') || '').slice(0, 200);
  const next = safeNext(form.get('next'));
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const kUser = 'fail:u:' + user, kIp = 'fail:ip:' + ip;

  if ((await getCount(env, kUser)) >= USER_FAIL_MAX || (await getCount(env, kIp)) >= IP_FAIL_MAX) {
    return loginPage(next, '嘗試次數過多，請 15 分鐘後再試', 429);
  }

  const rec = getUsers(env)[user];
  const ok = !!user && !!password && !(rec && rec.disabled) && await checkPassword(rec, password);
  if (!ok) {
    await addFail(env, kUser);
    await addFail(env, kIp);
    return loginPage(next, '帳號或密碼錯誤', 401);
  }

  await env.AUTH_KV.delete(kUser);
  const token = await makeSession(env, user, rec);
  const h = new Headers({ Location: next, 'Cache-Control': 'no-store' });
  for (const c of sessionCookies(token, String(rec.name || user))) h.append('Set-Cookie', c);
  return new Response(null, { status: 303, headers: h });
}

function handleLogout() {
  const h = new Headers({ Location: '/login', 'Cache-Control': 'no-store', 'Clear-Site-Data': '"cache"' });
  for (const c of clearCookies()) h.append('Set-Cookie', c);
  return new Response(null, { status: 303, headers: h });
}

/* ---------- 主流程 ---------- */
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  try { checkConfig(env); await hmacKey(env); }
  catch (e) {
    const msg = '登入設定錯誤：' + (e.message || e);
    return path.startsWith('/api') ? jsonRes({ ok: false, error: 'config', message: msg }, 500)
                                   : new Response(msg, { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }

  if (path === '/login') return handleLogin(request, env, url);
  if (path === '/logout') return handleLogout();

  const who = await readSession(request, env);
  if (!who) {
    if (path.startsWith('/api')) {
      return jsonRes({ ok: false, error: 'unauthenticated', message: '登入已逾時或未登入，請重新整理頁面後登入' }, 401);
    }
    return new Response(null, { status: 302, headers: { Location: '/login?next=' + encodeURIComponent(path + url.search), 'Cache-Control': 'no-store' } });
  }

  /* 寫入請求只接受自己網站發出的 */
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const origin = request.headers.get('Origin');
    if (origin && origin !== url.origin) return jsonRes({ ok: false, error: 'origin', message: '不允許的來源' }, 403);
  }

  context.data.user = who.user;
  context.data.name = who.name;

  const res = await next();
  const out = new Response(res.body, res);
  out.headers.set('Cache-Control', 'no-store');
  out.headers.set('X-Frame-Options', 'DENY');
  out.headers.set('Referrer-Policy', 'same-origin');
  return out;
}
