/**
 * 居護行程動態表 — 共用資料庫 API（Cloudflare Worker + Durable Object / SQLite）
 *
 * 取代 Google Apps Script。API 與 Apps Script v7 相容（舊網頁也能讀寫），
 * 另外新增：伺服器端三方合併、每天的變更紀錄與單日還原、護理師名單雲端同步。
 *
 * ═══ 為什麼用 Durable Object ═══
 *  - 所有請求都進同一個物件，一次處理一筆 → 天生排隊，不會兩人同時寫入互相覆蓋
 *  - 資料存在物件內建的 SQLite，讀寫是毫秒級（Apps Script 每次 10~30 秒）
 *  - Workers 免費方案即可使用，不用綁信用卡
 *
 * ═══ API ═══
 *   GET  ?ping=1                         版本／天數
 *   GET  ?index=1                        日期索引＋請假＋護理師名單＋updatedAt
 *   GET  ?org=ivy&ym=2026-09,2026-10     某機構某些月份
 *   GET  （不帶參數）                    全部（舊網頁相容）
 *   GET  ?history=1&org=ivy&date=YYYY-MM-DD   該天的變更紀錄（新到舊）
 *   GET  ?hist=<id>                      某一筆變更的前後內容
 *   POST {mode:"merge", patch, deletes, base, nurseUnlock, user}
 *   POST {mode:"leave", org, add, remove, user}
 *   POST {mode:"nurses", org, cfg, user}
 *   POST {mode:"restoreDay", id, which:"before"|"after", user}
 *   POST {data, user, force?}            舊網頁整包覆蓋（有暴跌防呆與護理師鎖定）
 *   POST {mode:"import", token, key, text}   搬家用（需環境變數 IMPORT_TOKEN）
 *
 * ═══ 護理師鎖定（v7 規則）═══
 *   分區有護理師就是鎖定。沒有在 nurseUnlock 列出 "機構|日期|分區" 的寫入：
 *   改人／清空 → 保留原本；整區被拿掉 → 留下只有護理師的空分區；整天刪除 → 不刪。
 *
 * ═══ 伺服器端三方合併 ═══
 *   新網頁存檔時會一併送上「我開始改之前看到的那一天」(base)。
 *   伺服器比對 base／我的版本／目前資料庫：
 *     別人沒動過 → 直接用我的；兩人都改過 → 以「個案」為單位合併，
 *     我加的加上去、我刪的刪掉，別人做的保留；人數用增減量合併。
 *   全部在物件內一次完成，不會有「檢查完、還沒寫入時別人插隊」的空檔。
 */

const API_VERSION = 'do-v1-20261001';
const ORGS = ['ivy', 'tree'];
const GUARD_RATIO = 0.8;
const GUARD_MIN = 5;
const HISTORY_DAYS = 180;              // 變更紀錄保留天數
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const YM_RE = /^\d{4}-\d{2}$/;

/* ══════════ Worker 入口：CORS ＋ 轉給唯一的 Durable Object ══════════ */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    if (!env.SCHEDULE) {
      return withCors(json({ ok: false, error: 'no-binding', message: 'Durable Object 還沒綁定（請確認 wrangler.jsonc 已部署）' }, 500));
    }
    /* 可選：限制只有自己的網頁能寫入（環境變數 ALLOWED_ORIGINS，逗號分隔） */
    if (request.method === 'POST' && env.ALLOWED_ORIGINS) {
      const origin = request.headers.get('Origin');
      const allow = String(env.ALLOWED_ORIGINS).split(',').map(s => s.trim()).filter(Boolean);
      if (origin && !allow.includes(origin)) {
        return withCors(json({ ok: false, error: 'origin', message: '不允許的來源：' + origin }, 403));
      }
    }
    const stub = env.SCHEDULE.get(env.SCHEDULE.idFromName('main'));
    const res = await stub.fetch(request);
    return withCors(res);
  },
};

function withCors(res) {
  const h = new Headers(res.headers);
  Object.entries(CORS).forEach(([k, v]) => h.set(k, v));
  return new Response(res.body, { status: res.status, headers: h });
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
function raw(text) {
  return new Response(text, {
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/* ══════════ 小工具 ══════════ */
function partName(org, ym) { return `${org}-${ym}.json`; }
function ymsOf(list) {
  const m = {};
  (list || []).forEach(d => { m[d.slice(0, 7)] = true; });
  return Object.keys(m).sort();
}
function stableStr(v) {
  if (Array.isArray(v)) return '[' + v.map(stableStr).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stableStr(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}
function same(a, b) { return stableStr(a) === stableStr(b); }
function clone(o) { return o === undefined ? undefined : JSON.parse(JSON.stringify(o)); }
function pkey(p) { return (p && typeof p === 'object') ? String(p.name || '') : String(p); }

/* ══════════ 護理師鎖定 ══════════ */
function lockedZones(day) {
  const out = {};
  if (!day || typeof day !== 'object') return out;
  Object.keys(day).forEach(z => { const r = day[z]; if (r && typeof r === 'object' && r.nurse) out[z] = String(r.nurse); });
  return out;
}
function protectDay(org, d, oldDay, newDay, unlock, kept) {
  const locked = lockedZones(oldDay);
  Object.keys(locked).forEach(z => {
    if (unlock[`${org}|${d}|${z}`]) return;
    const nr = newDay[z];
    if (nr && typeof nr === 'object') {
      if (nr.nurse !== locked[z]) { kept.push({ org, date: d, zone: z, nurse: locked[z], incoming: nr.nurse || '' }); nr.nurse = locked[z]; }
    } else {
      kept.push({ org, date: d, zone: z, nurse: locked[z], incoming: '(整區移除)' });
      newDay[z] = { count: 0, tags: [], nurse: locked[z] };
    }
  });
  return newDay;
}
function canDeleteDay(org, d, oldDay, unlock, kept) {
  const locked = lockedZones(oldDay);
  const blocked = Object.keys(locked).filter(z => !unlock[`${org}|${d}|${z}`]);
  blocked.forEach(z => kept.push({ org, date: d, zone: z, nurse: locked[z], incoming: '(整天刪除)' }));
  return blocked.length === 0;
}

/* ══════════ 三方合併 ══════════ */
/** 分區層級：b=開始改之前、m=我的、c=資料庫目前 */
function mergeZone(b, m, c, notes, label) {
  b = b || { count: 0, tags: [], nurse: '' };
  const out = clone(c);
  out.tags = out.tags || [];
  const pairs = z => {
    const map = new Map();
    (z.tags || []).forEach(t => (t.people || []).forEach(p => map.set(t.name + '\u0001' + pkey(p), { tag: t, p })));
    return map;
  };
  const B = pairs(b), M = pairs(m);
  /* 我刪掉的個案 → 從目前資料移除 */
  B.forEach((v, k) => {
    if (M.has(k)) return;
    const [tn, pk] = k.split('\u0001');
    const t = out.tags.find(x => x.name === tn);
    if (t && t.people) t.people = t.people.filter(p => pkey(p) !== pk);
  });
  /* 我新增或修改過的個案 → 加到目前資料（同名就以我的為準） */
  M.forEach((v, k) => {
    const bv = B.get(k);
    if (bv && same(bv.p, v.p)) return;                      // 我沒動過
    const [tn, pk] = k.split('\u0001');
    let t = out.tags.find(x => x.name === tn);
    if (!t) {
      t = { name: tn, people: [] };
      if (v.tag.isInst) { t.isInst = true; if (v.tag.qty != null) t.qty = v.tag.qty; }
      out.tags.push(t);
    }
    t.people = t.people || [];
    const i = t.people.findIndex(p => pkey(p) === pk);
    if (i >= 0) t.people[i] = clone(v.p); else t.people.push(clone(v.p));
  });
  /* 標籤本身（機構標籤的代表人數、沒有個案的空標籤） */
  const bTags = new Map((b.tags || []).map(t => [t.name, t])), mTags = new Map((m.tags || []).map(t => [t.name, t]));
  mTags.forEach((mt, name) => {
    const bt = bTags.get(name);
    let t = out.tags.find(x => x.name === name);
    if (!t && !bt) { t = { name, people: [] }; if (mt.isInst) t.isInst = true; out.tags.push(t); }
    if (t && (!bt || bt.qty !== mt.qty) && mt.qty != null) t.qty = mt.qty;
  });
  bTags.forEach((bt, name) => {
    if (mTags.has(name)) return;                            // 我把整個標籤移除了
    const i = out.tags.findIndex(x => x.name === name);
    if (i >= 0 && !(out.tags[i].people || []).length) out.tags.splice(i, 1);
  });
  /* 人數：用增減量合併（兩人各加一人 → 兩人都算） */
  const bc = b.count || 0, mc = m.count || 0, cc = c.count || 0;
  if (mc !== bc) out.count = (cc === bc) ? mc : Math.max(0, cc + (mc - bc));
  /* 護理師：我有改才用我的（鎖定規則另外處理） */
  if ((m.nurse || '') !== (b.nurse || '')) {
    if ((c.nurse || '') !== (b.nurse || '') && (c.nurse || '') !== (m.nurse || '')) notes.push(`${label} 區護理師兩人同時改`);
    out.nurse = m.nurse || '';
  }
  notes.push(`${label} 區已合併兩人的修改`);
  return out;
}
/** 一天：回傳合併後的一天 */
function mergeDay(base, mine, cur, notes, label) {
  base = base || {}; mine = mine || {}; cur = cur || {};
  const out = {};
  const zs = new Set([...Object.keys(base), ...Object.keys(mine), ...Object.keys(cur)]);
  zs.forEach(z => {
    const b = base[z], m = mine[z], c = cur[z];
    let v;
    if (same(m, b)) v = c;                                  // 我沒動 → 用目前的
    else if (same(c, b) || same(c, m)) v = m;               // 別人沒動 → 用我的
    else if (m === undefined) { v = c; notes.push(`${label} ${z} 區：別人剛改過，刪除已取消`); }
    else if (c === undefined) { v = m; notes.push(`${label} ${z} 區：別人剛刪除，已用你的版本保留`); }
    else v = mergeZone(b, m, c, notes, `${label} ${z}`);
    if (v !== undefined) out[z] = clone(v);
  });
  return out;
}

/** 變更摘要（存進紀錄，前端直接顯示） */
function summarize(before, after) {
  const out = [];
  if (!before && after) out.push('新增這一天');
  if (before && !after) { out.push('刪除這一天'); return out; }
  before = before || {}; after = after || {};
  const zs = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  zs.forEach(z => {
    const b = before[z], a = after[z];
    if (same(a, b)) return;
    if (!b) { out.push(`${z}區 新增${a.nurse ? '（' + a.nurse + '）' : ''}`); return; }
    if (!a) { out.push(`${z}區 刪除${b.nurse ? '（' + b.nurse + '）' : ''}`); return; }
    const parts = [];
    if ((b.nurse || '') !== (a.nurse || '')) parts.push(`護理師 ${b.nurse || '（空）'}→${a.nurse || '（空）'}`);
    if ((b.count || 0) !== (a.count || 0)) parts.push(`人數 ${b.count || 0}→${a.count || 0}`);
    const names = r => new Set((r.tags || []).flatMap(t => (t.people || []).map(pkey)));
    const bn = names(b), an = names(a);
    const add = [...an].filter(x => !bn.has(x)), del = [...bn].filter(x => !an.has(x));
    if (add.length) parts.push('加入 ' + add.slice(0, 6).join('、') + (add.length > 6 ? ` 等${add.length}人` : ''));
    if (del.length) parts.push('移出 ' + del.slice(0, 6).join('、') + (del.length > 6 ? ` 等${del.length}人` : ''));
    if (!parts.length) parts.push('內容調整');
    out.push(`${z}區 ` + parts.join('，'));
  });
  return out;
}

/* ══════════ Durable Object ══════════ */
export class ScheduleDB {
  constructor(state, env) {
    this.state = state;
    this.env = env || {};
    this.sql = state.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS parts (name TEXT PRIMARY KEY, text TEXT, at INTEGER DEFAULT 0)`);
    this._clock = 0;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS hist (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, user TEXT, org TEXT, date TEXT,
      action TEXT, before TEXT, after TEXT, summary TEXT)`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS hist_day ON hist(org, date, id)`);
    this.sql.exec(`CREATE INDEX IF NOT EXISTS hist_ts ON hist(ts)`);
  }

  /* ── 儲存 ── */
  kvGet(k, dflt) {
    const r = this.sql.exec(`SELECT v FROM kv WHERE k = ?`, k).toArray();
    return r.length ? r[0].v : dflt;
  }
  kvSet(k, v) { this.sql.exec(`INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v); }
  partGet(name) {
    const r = this.sql.exec(`SELECT text FROM parts WHERE name = ?`, name).toArray();
    return r.length ? r[0].text : '{}';
  }
  partSet(name, text) {
    if (text === '{}') { this.sql.exec(`DELETE FROM parts WHERE name = ?`, name); return; }
    this._clock = Math.max(Date.now(), this._clock + 1);
    this.sql.exec(`INSERT INTO parts (name, text, at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET text = excluded.text, at = excluded.at`, name, text, this._clock);
  }
  /** 每個月份檔最後修改時間：網頁輪詢時只重抓有變的月份 */
  partTimes() {
    const out = {};
    this.sql.exec(`SELECT name, at FROM parts`).toArray().forEach(r => { out[r.name.replace(/\.json$/, '')] = r.at || 0; });
    return out;
  }
  readIdx() {
    try {
      const j = JSON.parse(this.kvGet('idx.json', '{}'));
      if (!j.days) j.days = { ivy: [], tree: [] };
      ORGS.forEach(o => { if (!j.days[o]) j.days[o] = []; });
      j.total = j.days.ivy.length + j.days.tree.length;
      return j;
    } catch (e) { return { updatedAt: 0, user: '', days: { ivy: [], tree: [] }, total: 0 }; }
  }
  writeIdx(idx) {
    idx.total = idx.days.ivy.length + idx.days.tree.length;
    this.kvSet('idx.json', JSON.stringify(idx));
  }
  readLeave() {
    try { const j = JSON.parse(this.kvGet('leave.json', '{}')); ORGS.forEach(o => { if (!j[o]) j[o] = {}; }); return j; }
    catch (e) { return { ivy: {}, tree: {} }; }
  }
  readNurses() {
    try {
      const j = JSON.parse(this.kvGet('nurses.json', '{}'));
      ORGS.forEach(o => { const v = j[o] || {}; j[o] = { add: Array.isArray(v.add) ? v.add : [], del: Array.isArray(v.del) ? v.del : [] }; });
      return j;
    } catch (e) { return { ivy: { add: [], del: [] }, tree: { add: [], del: [] } }; }
  }
  addHist(user, org, date, action, before, after) {
    const sum = summarize(before, after);
    this.sql.exec(`INSERT INTO hist (ts, user, org, date, action, before, after, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      Date.now(), user, org, date, action,
      before === undefined ? null : JSON.stringify(before),
      after === undefined ? null : JSON.stringify(after),
      JSON.stringify(sum));
  }
  pruneHist() {
    this.sql.exec(`DELETE FROM hist WHERE ts < ?`, Date.now() - HISTORY_DAYS * 86400000);
  }
  bump(idx, user) { idx.updatedAt = Math.max(Date.now(), (idx.updatedAt || 0) + 1); idx.user = user; }

  /* ── 入口 ── */
  async fetch(request) {
    try {
      if (request.method === 'GET') return this.handleGet(new URL(request.url).searchParams);
      if (request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ ok: false, error: 'bad-json', message: '內容不是 JSON' }, 400); }
        return this.handlePost(body || {});
      }
      return json({ ok: false, error: 'method', message: '只接受 GET / POST' }, 405);
    } catch (err) {
      return json({ ok: false, error: 'exception', message: String(err && err.message || err) }, 500);
    }
  }

  /* ══════════ GET ══════════ */
  handleGet(p) {
    if (p.get('ping') === '1') {
      const idx = this.readIdx();
      return json({ ok: true, v: API_VERSION, days: idx.total, updatedAt: idx.updatedAt || 0 });
    }
    if (p.get('index') === '1') {
      const idx = this.readIdx();
      return json({
        ok: true, v: API_VERSION, updatedAt: idx.updatedAt || 0, user: idx.user || '',
        days: idx.days, total: idx.total,
        leave: this.readLeave(), leaveUpdatedAt: idx.leaveUpdatedAt || 0,
        nurses: this.readNurses(),
        mt: this.partTimes(),
      });
    }
    if (p.get('leave') === '1') {
      const idx = this.readIdx();
      return json({ ok: true, v: API_VERSION, leave: this.readLeave(), leaveUpdatedAt: idx.leaveUpdatedAt || 0 });
    }
    if (p.get('history') === '1') {
      const org = p.get('org'), date = p.get('date');
      if (!ORGS.includes(org) || !DAY_RE.test(date || '')) return json({ ok: false, error: 'bad-param', message: '需要 org 與 date' }, 400);
      const rows = this.sql.exec(`SELECT id, ts, user, action, summary FROM hist WHERE org = ? AND date = ? ORDER BY id DESC LIMIT 60`, org, date).toArray();
      return json({ ok: true, org, date, items: rows.map(r => ({ id: r.id, ts: r.ts, user: r.user, action: r.action, summary: JSON.parse(r.summary || '[]') })) });
    }
    if (p.get('hist')) {
      const r = this.sql.exec(`SELECT * FROM hist WHERE id = ?`, Number(p.get('hist'))).toArray()[0];
      if (!r) return json({ ok: false, error: 'not-found', message: '找不到這筆紀錄' }, 404);
      return json({ ok: true, id: r.id, ts: r.ts, user: r.user, org: r.org, date: r.date, action: r.action,
        before: r.before ? JSON.parse(r.before) : null, after: r.after ? JSON.parse(r.after) : null,
        summary: JSON.parse(r.summary || '[]') });
    }
    const org = p.get('org');
    if (ORGS.includes(org)) {
      const idx = this.readIdx();
      const yms = (p.get('ym') ? p.get('ym').split(',') : ymsOf(idx.days[org])).map(x => x.trim()).filter(x => YM_RE.test(x));
      const chunks = yms.map(ym => this.partGet(partName(org, ym))).map(t => (t && t.length > 2) ? t.slice(1, -1) : '').filter(Boolean);
      return raw(`{"ok":true,"org":"${org}","ym":${JSON.stringify(p.get('ym') || '')},"updatedAt":${idx.updatedAt || 0},` +
        `"user":${JSON.stringify(idx.user || '')},"part":{${chunks.join(',')}}}`);
    }
    const idx = this.readIdx();
    const parts = ORGS.map(o => {
      const inner = ymsOf(idx.days[o]).map(ym => this.partGet(partName(o, ym))).map(t => (t && t.length > 2) ? t.slice(1, -1) : '').filter(Boolean);
      return `"${o}":{${inner.join(',')}}`;
    });
    return raw(`{"data":{${parts.join(',')}},"updatedAt":${idx.updatedAt || 0},"user":${JSON.stringify(idx.user || '')}}`);
  }

  /* ══════════ POST ══════════ */
  handlePost(body) {
    const user = String(body.user || '').slice(0, 30);

    if (body.mode === 'import') {
      if (!this.env.IMPORT_TOKEN || body.token !== this.env.IMPORT_TOKEN) {
        return json({ ok: false, error: 'unauthorized', message: 'IMPORT_TOKEN 不正確（或尚未設定）' }, 403);
      }
      if (!body.key || typeof body.text !== 'string') return json({ ok: false, error: 'bad-import', message: '需要 key 與 text' }, 400);
      try { JSON.parse(body.text); } catch (e) { return json({ ok: false, error: 'bad-import', message: body.key + ' 不是合法 JSON' }, 400); }
      if (['idx.json', 'leave.json', 'nurses.json'].includes(body.key)) this.kvSet(body.key, body.text);
      else if (/^(ivy|tree)-\d{4}-\d{2}\.json$/.test(body.key)) this.partSet(body.key, body.text);
      else return json({ ok: false, error: 'bad-import', message: '不認得的檔名：' + body.key }, 400);
      return json({ ok: true, mode: 'import', key: body.key, bytes: body.text.length });
    }

    const idx = this.readIdx();

    if (body.mode === 'leave') {
      const org = body.org;
      if (!ORGS.includes(org)) return json({ ok: false, error: 'bad-org', message: '機構代碼不正確' });
      const lv = this.readLeave();
      let added = 0, removed = 0;
      (body.add || []).forEach(x => {
        if (!x || !DAY_RE.test(x.date) || !x.name) return;
        (lv[org][x.date] = lv[org][x.date] || {})[String(x.name)] = String(x.note || '');
        added++;
      });
      (body.remove || []).forEach(x => {
        if (!x || !x.date || !x.name) return;
        if (lv[org][x.date] && lv[org][x.date][x.name] !== undefined) {
          delete lv[org][x.date][x.name];
          if (!Object.keys(lv[org][x.date]).length) delete lv[org][x.date];
          removed++;
        }
      });
      this.kvSet('leave.json', JSON.stringify(lv));
      idx.leaveUpdatedAt = Date.now();
      this.bump(idx, user);
      this.writeIdx(idx);
      let total = 0; ORGS.forEach(o => Object.keys(lv[o]).forEach(d => { total += Object.keys(lv[o][d]).length; }));
      return json({ ok: true, mode: 'leave', updatedAt: idx.updatedAt, leaveUpdatedAt: idx.leaveUpdatedAt, added, removed, totalLeave: total, leave: lv });
    }

    if (body.mode === 'nurses') {
      const org = body.org;
      if (!ORGS.includes(org)) return json({ ok: false, error: 'bad-org', message: '機構代碼不正確' });
      const cfg = body.cfg || {};
      const ns = this.readNurses();
      const clean = a => [...new Set((Array.isArray(a) ? a : []).map(x => String(x).trim()).filter(Boolean))].slice(0, 200);
      ns[org] = { add: clean(cfg.add), del: clean(cfg.del) };
      this.kvSet('nurses.json', JSON.stringify(ns));
      this.bump(idx, user);
      this.writeIdx(idx);
      return json({ ok: true, mode: 'nurses', updatedAt: idx.updatedAt, nurses: ns });
    }

    if (body.mode === 'restoreDay') {
      const prevUpdatedAt = idx.updatedAt || 0;
      const r = this.sql.exec(`SELECT * FROM hist WHERE id = ?`, Number(body.id)).toArray()[0];
      if (!r) return json({ ok: false, error: 'not-found', message: '找不到這筆紀錄' });
      const ver = body.which === 'after' ? r.after : r.before;
      let target = ver ? JSON.parse(ver) : null;
      const name = partName(r.org, r.date.slice(0, 7));
      const obj = JSON.parse(this.partGet(name));
      const before = obj[r.date];
      /* 還原也遵守護理師鎖定：目前已指定的護理師不會被舊版本蓋掉 */
      const kept = [];
      if (target) target = protectDay(r.org, r.date, before, target, {}, kept);
      else if (before && !canDeleteDay(r.org, r.date, before, {}, kept)) target = protectDay(r.org, r.date, before, {}, {}, []);
      if (target) obj[r.date] = target; else delete obj[r.date];
      this.partSet(name, JSON.stringify(obj));
      this.addHist(user, r.org, r.date, 'restore', before, target || undefined);
      this.syncIdxMonth(idx, r.org, r.date.slice(0, 7), obj);
      this.bump(idx, user);
      this.writeIdx(idx);
      return json({ ok: true, mode: 'restoreDay', org: r.org, date: r.date, day: target, updatedAt: idx.updatedAt, prevUpdatedAt, days: idx.total, nurseKept: kept, mt: this.partTimes() });
    }

    if (body.mode === 'merge') return this.doMerge(body, user, idx);
    return this.doFull(body, user, idx);
  }

  syncIdxMonth(idx, org, ym, obj) {
    const keep = {};
    idx.days[org].forEach(d => { if (d.slice(0, 7) !== ym) keep[d] = true; });
    Object.keys(obj).forEach(d => { keep[d] = true; });
    idx.days[org] = Object.keys(keep).sort();
  }

  doMerge(body, user, idx) {
    const patch = body.patch || {};
    const bases = body.base || null;              // 新網頁才有；舊網頁沒有就照舊直接覆蓋
    const unlock = {};
    (body.nurseUnlock || []).forEach(k => { unlock[String(k)] = true; });
    const groups = {};
    const grp = (org, d) => {
      const k = `${org}|${d.slice(0, 7)}`;
      return groups[k] || (groups[k] = { org, ym: d.slice(0, 7), set: {}, del: [] });
    };
    ORGS.forEach(org => {
      const pp = patch[org];
      if (!pp || typeof pp !== 'object') return;
      Object.keys(pp).forEach(d => { if (DAY_RE.test(d) && pp[d] != null && typeof pp[d] === 'object') grp(org, d).set[d] = pp[d]; });
    });
    (body.deletes || []).forEach(k => {
      const a = String(k).split('|');
      if (a.length === 2 && ORGS.includes(a[0]) && DAY_RE.test(a[1])) grp(a[0], a[1]).del.push(a[1]);
    });
    const keys = Object.keys(groups);
    if (!keys.length) return json({ ok: true, mode: 'merge', noop: true, updatedAt: idx.updatedAt, days: idx.total, applied: 0, deleted: 0, result: {} });

    const prevUpdatedAt = idx.updatedAt || 0;
    let applied = 0, deleted = 0, changed = 0;
    const touched = [], kept = [], notes = [], result = { ivy: {}, tree: {} };
    for (const k of keys) {
      const g = groups[k];
      const name = partName(g.org, g.ym);
      const obj = JSON.parse(this.partGet(name));
      let dirty = false;
      for (const d of Object.keys(g.set)) {
        const cur = obj[d];
        const hasBase = !!(bases && bases[g.org] && Object.prototype.hasOwnProperty.call(bases[g.org], d));
        const base = hasBase ? bases[g.org][d] : undefined;
        let next;
        if (!hasBase || same(cur, base) || (cur === undefined && base == null)) next = clone(g.set[d]);
        else next = mergeDay(base || {}, g.set[d], cur, notes, `${g.org === 'ivy' ? '常春藤' : '長青樹'} ${d}`);
        next = protectDay(g.org, d, cur, next, unlock, kept);
        applied++; touched.push(`${g.org}|${d}`);
        result[g.org][d] = next;
        if (same(cur, next)) continue;
        this.addHist(user, g.org, d, 'edit', cur, next);
        obj[d] = next; dirty = true; changed++;
      }
      for (const d of g.del) {
        if (!Object.prototype.hasOwnProperty.call(obj, d)) { result[g.org][d] = null; continue; }
        const cur = obj[d];
        const base = bases && bases[g.org] ? bases[g.org][d] : undefined;
        if (base !== undefined && base !== null && !same(cur, base)) {
          notes.push(`${g.org === 'ivy' ? '常春藤' : '長青樹'} ${d}：別人剛改過，整天刪除已取消`);
          result[g.org][d] = cur; continue;
        }
        if (!canDeleteDay(g.org, d, cur, unlock, kept)) { result[g.org][d] = cur; continue; }
        this.addHist(user, g.org, d, 'delete', cur, undefined);
        delete obj[d]; deleted++; dirty = true; changed++;
        touched.push(`-${g.org}|${d}`);
        result[g.org][d] = null;
      }
      if (dirty) { this.partSet(name, JSON.stringify(obj)); this.syncIdxMonth(idx, g.org, g.ym, obj); }
    }
    if (changed) {
      this.bump(idx, user);
      this.writeIdx(idx);
      this.pruneHist();
    }
    return json({
      ok: true, mode: 'merge', updatedAt: idx.updatedAt, prevUpdatedAt, applied, deleted, days: idx.total, touched,
      nurseKept: kept, conflicts: [...new Set(notes)], result, mt: this.partTimes(),
    });
  }

  doFull(body, user, idx) {
    const next = body.data || { ivy: {}, tree: {} };
    let nNew = 0;
    ORGS.forEach(o => { nNew += Object.keys(next[o] || {}).length; });
    if (!body.force && idx.total >= GUARD_MIN && nNew < idx.total * GUARD_RATIO) {
      return json({
        ok: false, error: 'shrink-guard', current: idx.total, incoming: nNew, days: idx.total,
        message: `拒絕寫入：資料庫目前有 ${idx.total} 天，送上來的只有 ${nNew} 天，會刪掉 ${idx.total - nNew} 天。`,
      });
    }
    const unlock = {};
    (body.nurseUnlock || []).forEach(k => { unlock[String(k)] = true; });
    const kept = [];
    for (const o of ORGS) {
      const src = next[o] || {};
      const byYm = {};
      Object.keys(src).forEach(d => { if (DAY_RE.test(d)) (byYm[d.slice(0, 7)] = byYm[d.slice(0, 7)] || {})[d] = src[d]; });
      ymsOf(idx.days[o]).forEach(ym => { if (!byYm[ym]) byYm[ym] = {}; });
      for (const ym of Object.keys(byYm)) {
        const name = partName(o, ym);
        const oldObj = JSON.parse(this.partGet(name));
        const newObj = byYm[ym];
        Object.keys(oldObj).forEach(d => {
          if (newObj[d]) newObj[d] = protectDay(o, d, oldObj[d], newObj[d], unlock, kept);
          else if (!canDeleteDay(o, d, oldObj[d], unlock, kept)) newObj[d] = oldObj[d];
        });
        new Set([...Object.keys(oldObj), ...Object.keys(newObj)]).forEach(d => {
          if (!same(oldObj[d], newObj[d])) this.addHist(user, o, d, 'full', oldObj[d], newObj[d]);
        });
        this.partSet(name, JSON.stringify(newObj));
        this.syncIdxMonth(idx, o, ym, newObj);
      }
    }
    this.bump(idx, user);
    this.writeIdx(idx);
    this.pruneHist();
    return json({ ok: true, mode: 'full', updatedAt: idx.updatedAt, days: idx.total, nurseKept: kept });
  }
}

/* 給測試用 */
export const _internal = { mergeDay, mergeZone, summarize, protectDay, same };
