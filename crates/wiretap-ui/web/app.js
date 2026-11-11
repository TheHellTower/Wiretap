'use strict';
// Wiretap UI. Dependency-free. Captured data is untrusted: it is only ever inserted with
// textContent / value (never innerHTML), and the server sends a strict CSP.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function clear(node) { while (node.firstChild) node.firstChild.remove(); return node; }

async function api(path, body) {
  const init = body === undefined ? {} : body === null ? { method: 'POST' } : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const r = await fetch(path, init);
  if (!r.ok) {
    let msg = r.status + ' ' + r.statusText;
    try { msg = (await r.json()).error || msg; } catch { /* not JSON */ }
    throw new Error(msg);
  }
  return (r.headers.get('content-type') || '').includes('json') ? r.json() : r.arrayBuffer();
}

function toast(text, kind = '') {
  const t = el('div', 'toast ' + kind, text);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 7000 : 3500);
}

const pad = (n, w = 2) => String(n).padStart(w, '0');
function clock(us) {
  const d = new Date(Math.floor(us / 1000));
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}
function fullTime(us) { return new Date(Math.floor(us / 1000)).toLocaleString(); }
function bytes(n) {
  if (n === undefined || n === null || Number.isNaN(n)) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}
function header(headers, name) {
  const h = (headers || []).find(x => x.name.toLowerCase() === name);
  return h ? h.value : '';
}
function endpoint(e) {
  if (!e) return '';
  const ip = e.ip.includes(':') ? `[${e.ip}]` : e.ip;
  return e.port === null || e.port === undefined ? e.ip : `${ip}:${e.port}`;
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
// Runs `fn` at most once per `ms` however often it is asked: live lists must keep updating under
// constant traffic, where a debounce would wait for a quiet moment that never comes.
function throttle(fn, ms) { let t = null; return () => { if (t === null) t = setTimeout(() => { t = null; fn(); }, ms); }; }
function hostOf(url) {
  const rest = url.includes('://') ? url.split('://')[1] : url;
  const auth = rest.split(/[/?#]/)[0].split('@').pop();
  return auth.startsWith('[') ? auth.slice(1, auth.indexOf(']')) : auth.split(':')[0];
}

// ---------------------------------------------------------------------------------------------
// State

const S = {
  state: null,
  session: 'live',          // 'live' or a stored session id
  sessions: [],
  flows: new Map(),         // id -> row
  flowOrder: [],
  tlsRows: 0,               // flows that are HTTPS connections (metadata only)
  conns: new Map(),
  connOrder: [],
  rules: [],
  rulesDirty: false,
  ruleSel: -1,
  matchSet: null,
  selected: null,
  tabs: { req: 'headers', res: 'headers' },
  bodies: new Map(),
  ws: new Map(),            // flow id -> { list, ids, sent, bytes, count }: WebSocket/SSE messages
  meta: new Map(),          // flow id -> { tls, relay } of a connection relayed without decryption
  wsSel: null,              // selected message event id
  wsStick: true,            // the message list follows new messages (scrolled to the end)
  wsTop: 0,
  wsPending: false,
  resync: false,            // the live feed had a gap: reload this run's data on reconnect
};
// Messages kept in memory per stream (the newest; counts cover all of them).
const MAX_MESSAGES = 20000;

// ---------------------------------------------------------------------------------------------
// Virtualized table

class VTable {
  constructor(root, columns, onSelect) {
    this.root = root; this.columns = columns; this.onSelect = onSelect;
    this.rows = []; this.sel = null; this.height = 28;
    const template = columns.map(c => c.w).join(' ');
    this.head = el('div', 'thead'); this.head.style.gridTemplateColumns = template;
    for (const c of columns) this.head.append(el('span', '', c.title));
    this.body = el('div', 'tbody'); this.body.tabIndex = 0;
    this.spacer = el('div'); this.body.append(this.spacer);
    this.pool = []; this.template = template;
    root.append(this.head, this.body);
    this.empty = el('div', 'empty'); root.append(this.empty);
    this.body.addEventListener('scroll', () => this.render());
    new ResizeObserver(() => this.render()).observe(this.body);
    this.body.addEventListener('click', e => {
      const tr = e.target.closest('.tr');
      if (tr) this.select(this.rows[Number(tr.dataset.i)]);
    });
    this.body.addEventListener('keydown', e => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      const i = this.rows.indexOf(this.sel) + (e.key === 'ArrowDown' ? 1 : -1);
      if (i >= 0 && i < this.rows.length) { this.select(this.rows[i]); this.reveal(i); }
    });
  }
  setEmpty(node) { clear(this.empty).append(node); }
  setRows(rows) {
    const atBottom = this.body.scrollTop + this.body.clientHeight >= this.body.scrollHeight - this.height * 2;
    this.rows = rows;
    this.spacer.style.height = rows.length * this.height + 'px';
    this.empty.classList.toggle('hidden', rows.length > 0);
    this.body.classList.toggle('hidden', rows.length === 0);
    if (atBottom && S.follow !== false) this.body.scrollTop = this.body.scrollHeight;
    this.render();
  }
  reveal(i) {
    const top = i * this.height, b = this.body;
    if (top < b.scrollTop) b.scrollTop = top;
    else if (top + this.height > b.scrollTop + b.clientHeight) b.scrollTop = top + this.height - b.clientHeight;
  }
  select(row) { this.sel = row; this.render(); this.onSelect(row); }
  render() {
    const b = this.body, first = Math.max(0, Math.floor(b.scrollTop / this.height) - 4);
    const count = Math.ceil(b.clientHeight / this.height) + 8;
    const now = performance.now();
    for (let k = 0; k < count; k++) {
      const i = first + k, row = this.rows[i];
      let tr = this.pool[k];
      if (!tr) {
        tr = el('div', 'tr'); tr.style.gridTemplateColumns = this.template;
        for (let c = 0; c < this.columns.length; c++) tr.append(el('span'));
        this.pool[k] = tr; b.append(tr);
      }
      if (!row) { tr.classList.add('hidden'); continue; }
      tr.classList.remove('hidden');
      tr.dataset.i = i;
      tr.style.top = i * this.height + 'px';
      tr.className = 'tr' + (row === this.sel ? ' sel' : '') + (now - row.added < 900 ? ' fresh' : '') + (row.mark ? ' hl-' + row.mark : '');
      this.columns.forEach((c, ci) => {
        const span = tr.children[ci];
        span.className = c.cls ? c.cls(row) : '';
        const value = c.text(row);
        if (c.badge) {
          clear(span).append(document.createTextNode(value));
          const badge = c.badge(row);
          if (badge) span.append(el('span', 'badge ' + badge[0], badge[1]));
        } else if (span.textContent !== value) span.textContent = value;
        if (c.tip) span.title = c.tip(row);
      });
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Traffic

function source(flow) {
  if (flow.tags && flow.tags.includes('auto-reply')) return 'auto';
  return flow.source === 'driver' ? 'driver' : 'proxy';
}
function typeOf(flow) {
  if (flow.tls) return 'encrypted' + (flow.tls.alpn ? ' · ' + flow.tls.alpn : '');
  if (flow.relay) return 'tcp';
  if (tagged(flow, 'h2-connection')) return 'http/2 connection';
  if (tagged(flow, 'websocket')) return 'websocket';
  return header(flow.response && flow.response.headers, 'content-type').split(';')[0].trim();
}
function sizeOf(flow) {
  if (flow.relay && flow.relay.received) return Number(flow.relay.received);
  const r = flow.response;
  if (!r) return undefined;
  if (r.body) return r.body.size;
  const cl = header(r.headers, 'content-length');
  return cl ? Number(cl) : undefined;
}
const dev = () => !!(S.state && S.state.dev);
const tagged = (flow, tag) => !!(flow.tags && flow.tags.includes(tag));
function badgeOf(flow) {
  if (tagged(flow, 'auto-reply')) return ['auto', 'AUTO'];
  if (tagged(flow, 'redirect')) return ['auto', 'REDIRECT'];
  if (tagged(flow, 'websocket')) return ['tunnel', 'WEBSOCKET'];
  if (tagged(flow, 'proxy-error')) return ['err', 'ERROR'];
  if (tagged(flow, 'client-gone')) return ['tunnel', 'CANCELED'];
  if (tagged(flow, 'pinned')) return ['tunnel', 'PINNED'];
  if (tagged(flow, 'refused')) return ['tunnel', 'REFUSED'];
  if (tagged(flow, 'passthrough')) return ['tunnel', dev() ? 'PASSTHROUGH' : 'ENCRYPTED'];
  if (tagged(flow, 'h2-connection')) return ['tunnel', 'H2 CONNECTION'];
  if (tagged(flow, 'tunnel')) return ['tunnel', dev() ? 'TUNNEL' : 'ENCRYPTED'];
  return null;
}
/** Diagnostic rows (not requests) shown only in developer mode. */
const diagnostic = flow => ['tls-error', 'no-request', 'client-closed', 'h2-connection'].some(t => tagged(flow, t));
// A failed gRPC call answers HTTP 200 and puts its result in trailers (grpc-status): show that.
const grpcStatus = flow => (tagged(flow, 'grpc') && flow.response && header(flow.response.headers, 'grpc-status')) || '';
function statusText(flow) {
  const g = grpcStatus(flow);
  if (g && g !== '0') return 'gRPC ' + g;
  if (flow.response) return String(flow.response.status);
  if (flow.tls || tagged(flow, 'tunnel') || tagged(flow, 'h2-connection')) return '';
  return flow.timing.response_complete ? '—' : '…';
}
// Requests show their HTTP version; connection rows show what they carry (their CONNECT line is a
// placeholder, not an HTTP/1.1 request).
function versionOf(flow) {
  if (tagged(flow, 'h2-connection')) return 'HTTP/2';
  if (flow.relay || tagged(flow, 'tunnel')) return (flow.tls && flow.tls.version) || (flow.relay && flow.relay.reason === 'opaque' ? 'TCP' : 'TLS');
  return flow.request.version;
}

const flowTable = new VTable($('#flows'), [
  { title: '#', w: '52px', text: r => r.n, cls: () => 'mono dim' },
  { title: 'Method', w: '84px', text: r => r.flow.request.method, cls: r => 'mono m-' + r.flow.request.method },
  { title: 'Version', w: '76px', text: r => versionOf(r.flow), cls: () => 'mono' },
  { title: 'URL', w: 'minmax(260px, 1fr)', text: r => r.flow.request.url, tip: r => r.flow.request.url, cls: () => 'mono',
    badge: r => badgeOf(r.flow) },
  { title: 'Status', w: '64px', text: r => statusText(r.flow), cls: r => 'mono s' + (grpcStatus(r.flow) > '0' ? '5' : r.flow.response ? String(r.flow.response.status)[0] : '0'),
    tip: r => grpcStatus(r.flow) ? `HTTP ${r.flow.response.status}, gRPC status ${grpcStatus(r.flow)}` : '' },
  { title: 'Type', w: '170px', text: r => typeOf(r.flow) },
  { title: 'Size', w: '78px', text: r => bytes(sizeOf(r.flow)), cls: () => 'mono' },
  { title: 'Application', w: '150px', text: r => (r.flow.process && r.flow.process.name) || '', cls: () => 'app',
    tip: r => r.flow.process ? `${r.flow.process.path || r.flow.process.name || ''} (PID ${r.flow.process.pid})` : '' },
  { title: 'Time', w: '100px', text: r => clock(r.flow.timing.started), cls: () => 'mono' },
], row => showDetails(row));

// Search: free text plus field:value terms (wildcards * ?, prefix - to negate).
function compileTerm(raw) {
  let neg = false, tok = raw;
  if (tok.startsWith('-') && tok.length > 1) { neg = true; tok = tok.slice(1); }
  const i = tok.indexOf(':');
  const key = i > 0 ? tok.slice(0, i).toLowerCase() : '';
  const value = (i > 0 ? tok.slice(i + 1) : tok).replace(/\*+/g, '*');
  const stars = (value.match(/\*/g) || []).length;
  const pattern = value.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, stars > 8 ? '' : '.*').replace(/\?/g, '.');
  return { neg, key, value: value.toLowerCase(), re: new RegExp(pattern, 'i') };
}
function termMatches(t, flow) {
  const req = flow.request, res = flow.response;
  const app = (flow.process && flow.process.name) || '';
  switch (t.key) {
    case 'app': case 'process': return t.re.test(app);
    case 'host': case 'domain': return t.re.test(hostOf(req.url));
    case 'method': return t.re.test(req.method);
    case 'url': return t.re.test(req.url);
    case 'type': return t.re.test(typeOf(flow));
    case 'source': return t.re.test(source(flow));
    case 'status': {
      if (!res) return t.value === 'none';
      const s = String(res.status);
      return /^[1-9]xx$/.test(t.value) ? s[0] === t.value[0] : t.re.test(s);
    }
    case 'header': return [...req.headers, ...(res ? res.headers : [])].some(h => t.re.test(h.name + ': ' + h.value));
    default: return [req.url, app, req.method, res ? String(res.status) : ''].some(v => t.re.test(v));
  }
}

function filteredFlows() {
  const terms = $('#search').value.trim().split(/\s+/).filter(Boolean).map(compileTerm);
  const f = { app: $('#f-app').value, host: $('#f-host').value, method: $('#f-method').value, status: $('#f-status').value, type: $('#f-type').value, src: $('#f-source').value };
  const out = [];
  for (const id of S.flowOrder) {
    const row = S.flows.get(id), flow = row.flow;
    if (S.matchSet && !S.matchSet.has(id)) continue;
    if (!dev() && diagnostic(flow)) continue;
    if (f.app && ((flow.process && flow.process.name) || '') !== f.app) continue;
    if (f.host && hostOf(flow.request.url) !== f.host) continue;
    if (f.method && flow.request.method !== f.method) continue;
    if (f.type && typeOf(flow) !== f.type) continue;
    if (f.src && source(flow) !== f.src) continue;
    if (f.status) {
      if (f.status === 'none' ? !!flow.response : !flow.response || String(flow.response.status)[0] !== f.status[0]) continue;
    }
    if (!terms.every(t => termMatches(t, flow) !== t.neg)) continue;
    out.push(row);
  }
  return out;
}

const facets = { app: new Set(), host: new Set(), method: new Set(), type: new Set(), capp: new Set() };
function addFacet(kind, value, select) {
  if (!value || facets[kind].has(value)) return;
  facets[kind].add(value);
  const opts = [...facets[kind]].sort((a, b) => a.localeCompare(b));
  const keep = select.value, first = select.options[0].cloneNode(true);
  clear(select).append(first);
  for (const v of opts) select.append(el('option', '', v));
  select.value = keep;
}

const refreshFlows = throttle(() => {
  const rows = filteredFlows();
  flowTable.setRows(rows);
  $('#f-count').textContent = rows.length === S.flowOrder.length ? `${rows.length}` : `${rows.length} of ${S.flowOrder.length}`;
  setChip('#chip-http', S.flowOrder.length - S.tlsRows);
  updateCounts();
}, 60);

// Updates of the selected request redraw its details at most once per frame.
let detailsPending = false;
function scheduleDetails() {
  if (detailsPending) return;
  detailsPending = true;
  requestAnimationFrame(() => { detailsPending = false; if (S.selected) showDetails(S.flows.get(S.selected.flow.id) || S.selected); });
}
const beforeClear = t => S.session === 'live' && S.clearedAt > 0 && t < S.clearedAt;
function onFlow(flow) {
  if (!flow.request || (!S.flows.has(flow.id) && beforeClear(flow.timing.started))) return;
  facetCache = null;
  withMeta(flow);
  let row = S.flows.get(flow.id);
  if (row) row.flow = flow;
  else {
    row = { flow, n: S.flowOrder.length + 1, added: performance.now(), tls: false };
    S.flows.set(flow.id, row);
    S.flowOrder.push(flow.id);
  }
  if (!!flow.tls !== row.tls) { row.tls = !!flow.tls; S.tlsRows += row.tls ? 1 : -1; }
  addFacet('app', flow.process && flow.process.name, $('#f-app'));
  addFacet('host', hostOf(flow.request.url), $('#f-host'));
  addFacet('method', flow.request.method, $('#f-method'));
  addFacet('type', typeOf(flow), $('#f-type'));
  if (S.selected && S.selected.flow.id === flow.id) scheduleDetails();
  refreshFlows();
  if (S.view === 'rules') renderRuleList();
}

// Details panes
function kv(container, rows, filter) {
  const grid = el('div', 'kv');
  const f = (filter || '').toLowerCase();
  for (const [k, v, first] of rows) {
    if (f && !first && !(k + ' ' + v).toLowerCase().includes(f)) continue;
    grid.append(el('span', first ? 'k first' : 'k', k), el('span', first ? 'first' : '', v));
  }
  container.append(grid);
}
function rawText(flow, which) {
  const m = flow[which];
  const line = which === 'request' ? `${m.method} ${m.url} ${m.version}` : `${m.version} ${m.status} ${m.reason}`;
  return [line, ...m.headers.map(h => `${h.name}: ${h.value}`)].join('\r\n') + '\r\n\r\n';
}
function hexdump(buf) {
  const b = new Uint8Array(buf), lines = [];
  for (let i = 0; i < Math.min(b.length, 65536); i += 16) {
    const row = b.subarray(i, i + 16);
    const hex = [...row].map(x => x.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...row].map(x => (x >= 32 && x < 127 ? String.fromCharCode(x) : '.')).join('');
    lines.push(i.toString(16).padStart(8, '0') + '  ' + hex.padEnd(48) + '  ' + ascii);
  }
  return lines.join('\n');
}
// What a binary body is, from its leading bytes (file signatures) and a Content-Range: binary
// is not encrypted, and a range of a file starts mid-file.
const SIGNATURES = [[[0x89, 0x50, 0x4e, 0x47], 'a PNG image'], [[0xff, 0xd8, 0xff], 'a JPEG image'], [[0x47, 0x49, 0x46, 0x38], 'a GIF image'],
  [[0x25, 0x50, 0x44, 0x46], 'a PDF document'], [[0x50, 0x4b, 0x03, 0x04], 'a ZIP archive'], [[0x43, 0x72, 0x32, 0x34], 'a Chrome extension package (CRX, a signed ZIP)'],
  [[0x1f, 0x8b], 'gzip data'], [[0x28, 0xb5, 0x2f, 0xfd], 'Zstandard data'], [[0x00, 0x61, 0x73, 0x6d], 'a WebAssembly module'],
  [[0x4d, 0x5a], 'a Windows executable'], [[0x52, 0x49, 0x46, 0x46], 'a RIFF file (WebP, WAV or AVI)'], [[0x4d, 0x53, 0x43, 0x46], 'a cabinet (.cab) archive']];
function binaryNote(buf, headers) {
  const b = new Uint8Array(buf), at = (sig, i) => sig.every((x, k) => b[i + k] === x);
  const parts = [];
  const range = /bytes (\d+)-(\d+)\/(\d+|\*)/i.exec(header(headers, 'content-range'));
  if (range) parts.push(`Bytes ${Number(range[1]).toLocaleString()}–${Number(range[2]).toLocaleString()} of ${range[3] === '*' ? 'an unknown size' : Number(range[3]).toLocaleString()}: part of a file (a range request), so it starts mid-file.`);
  const known = SIGNATURES.find(([sig]) => at(sig, 0));
  if (known) parts.push(`Starts like ${known[1]}.`);
  else if (b.length > 8 && at([0x66, 0x74, 0x79, 0x70], 4)) parts.push('Starts like an MP4/QuickTime media file.');
  else {
    const zip = b.slice(0, 65536).findIndex((_, i) => at([0x50, 0x4b, 0x03, 0x04], i));
    if (zip > 0) parts.push(`Contains ZIP entries (the first "PK\\3\\4" header at 0x${zip.toString(16)}); entry data is usually compressed.`);
  }
  return parts.length ? parts.join(' ') + ' Binary data, not encryption.' : '';
}
// The body as text (or a hex dump) plus a note when it could not be fully decoded. The server
// undoes gzip, deflate, br and zstd content codings.
async function loadBody(ref, headers) {
  const coding = header(headers, 'content-encoding').toLowerCase().split(',').map(s => s.trim()).filter(s => s && s !== 'identity').join(',');
  const key = ref.id + '|' + coding;
  let entry = S.bodies.get(key);
  if (!entry) {
    const r = await fetch('/api/payloads/' + ref.id + (/^[a-z0-9,-]{1,64}$/.test(coding) ? '?coding=' + coding : ''));
    if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
    entry = { buf: await r.arrayBuffer(), error: r.headers.get('x-wiretap-decode-error'), partial: r.headers.get('x-wiretap-decoded') === 'partial' };
    if (S.bodies.size > 64) S.bodies.delete(S.bodies.keys().next().value);
    S.bodies.set(key, entry);
  }
  let text = null;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(entry.buf); } catch { /* binary */ }
  // A body that is already readable text despite its Content-Encoding (bodies imported from
  // browser HAR files are stored decoded) needs no note.
  const note = entry.partial ? `Partly decoded (${coding}): ${entry.error}.`
    : entry.error && text === null ? `Not decoded (${coding}): ${entry.error}.` : '';
  if (text === null) return { text: hexdump(entry.buf), note: [note, binaryNote(entry.buf, headers)].filter(Boolean).join(' ') };
  if (/json/i.test(header(headers, 'content-type'))) { try { text = JSON.stringify(JSON.parse(text), null, 2); } catch { /* not JSON */ } }
  return { text: text.length > 2_000_000 ? text.slice(0, 2_000_000) + '\n… (truncated for display)' : text, note };
}
function renderPane(which) {
  const pane = $(which === 'req' ? '#pane-req' : '#pane-res');
  const body = clear($('.pane-body', pane));
  const tab = S.tabs[which];
  $$('.tabs button', pane).forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  if (which === 'res') {
    $('#details .panes').classList.toggle('ws', tab === 'messages');
    $('.pane-filter', pane).placeholder = tab === 'messages' ? 'Filter messages' : 'Filter headers';
  }
  const row = S.selected;
  if (!row) { body.append(el('div', 'note', 'Select a request to inspect it.')); return; }
  const flow = row.flow, key = which === 'req' ? 'request' : 'response', m = flow[key];
  if ((flow.tls || flow.relay) && tab !== 'info') {
    const t = flow.tls || {}, r = flow.relay || {};
    const rows = !flow.tls ? [['TCP', 'Relayed untouched', true]]
      : which === 'req'
        ? [['TLS', 'Client hello', true], ['Server name', t.sni || '—'], ['Versions offered', t.versions_offered || '—'], ['ALPN offered', t.alpn_offered || '—']]
        : [['TLS', 'Server hello', true], ['Version', t.version || 'not seen yet'], ['Cipher suite', t.cipher_suite || '—'], ['ALPN selected', t.alpn || '—'],
          ...(t.certificate ? [['Certificate', t.certificate], ['Issued by', t.issuer || '—'], ['Valid', t.valid || '—']] : []),
          ...(t.chain ? [['Chain', t.chain]] : [])];
    const count = which === 'req' ? r.sent : r.received;
    if (count) rows.push([which === 'req' ? 'Sent' : 'Received', bytes(Number(count))]);
    kv(body, rows);
    body.append(el('div', 'note', untouched(flow)));
    return;
  }
  if (tab === 'messages') { renderMessages(body, flow); return; }
  if (tab === 'info') {
    const p = flow.process || {};
    const t = flow.timing;
    kv(body, [
      ['Application', p.name || '—'], ['Process ID', p.pid ?? '—'], ['Image path', p.path || '—'],
      ['Client', endpoint(flow.client) || '—'], ['Server', endpoint(flow.server) || '—'],
      ['Source', { driver: 'Kernel driver (WFP)', explicit_proxy: 'Wiretap proxy', transparent_proxy: 'Wiretap proxy (captured)' }[flow.source] || flow.source],
      ['Started', fullTime(t.started)],
      ['Response after', t.response_started ? ((t.response_started - t.started) / 1000).toFixed(1) + ' ms' : '—'],
      ['Completed after', t.response_complete ? ((t.response_complete - t.started) / 1000).toFixed(1) + ' ms' : '—'],
      ['Tags', (flow.tags || []).join(', ') || '—'], ['Flow ID', flow.id],
    ]);
    return;
  }
  if (!m) { body.append(el('div', 'note', which === 'res' ? 'No response captured yet.' : 'No request.')); return; }
  if (tab === 'headers') {
    const first = which === 'req' ? [`${m.method}`, `${m.url} ${m.version}`, true] : [`${m.version}`, `${m.status} ${m.reason}`, true];
    kv(body, [first, ...m.headers.map(h => [h.name, h.value])], $('.pane-filter', pane).value);
  } else if (tab === 'raw') {
    body.append(el('pre', 'code', rawText(flow, key)));
  } else if (!m.body) {
    body.append(el('div', 'note', flow.source === 'driver'
      ? 'Body not captured: driver capture records message heads. Send traffic through the Wiretap proxy to record bodies.'
      : 'No body.'));
  } else {
    const pre = el('pre', 'code', 'Loading…');
    body.append(pre);
    if (m.body.stored < m.body.size) body.prepend(el('div', 'note', `Showing the first ${bytes(m.body.stored)} of ${bytes(m.body.size)}.`));
    loadBody(m.body, m.headers).then(({ text, note }) => {
      pre.textContent = text;
      if (note) pre.before(el('div', 'note', note));
    }, e => { pre.textContent = 'Cannot load body: ' + e.message; });
  }
}
function showDetails(row) {
  const changed = (S.selected && S.selected.flow.id) !== (row && row.flow.id);
  S.selected = row || null;
  const streaming = f => tagged(f, 'websocket') || tagged(f, 'sse') || tagged(f, 'grpc');
  if (changed && row && streaming(row.flow)) { S.tabs.res = 'messages'; S.wsSel = null; S.wsStick = true; }
  const has = !!row, http = has && !row.flow.tls && !row.flow.relay;
  $('#act-url').disabled = !has;
  ['#act-rule', '#act-curl'].forEach(id => { $(id).disabled = !http; });
  $('#sel-title').textContent = has ? `${row.flow.request.method} ${row.flow.request.url}`.trim() : 'Select a request';
  // The Messages tab exists for WebSocket, Server-Sent Events and gRPC flows only.
  const wsTab = $('#pane-res .tabs [data-tab=messages]'), ws = has && streaming(row.flow);
  wsTab.hidden = !ws;
  if (ws) wsTab.textContent = `Messages (${(S.ws.get(row.flow.id) || { count: 0 }).count})`;
  if (!ws && S.tabs.res === 'messages') S.tabs.res = 'headers';
  renderPane('req'); renderPane('res');
}
for (const which of ['req', 'res']) {
  const pane = $(which === 'req' ? '#pane-req' : '#pane-res');
  $('.tabs', pane).addEventListener('click', e => { const t = e.target.closest('button'); if (t) { S.tabs[which] = t.dataset.tab; renderPane(which); } });
  $('.pane-filter', pane).addEventListener('input', debounce(() => renderPane(which), 80));
}
const shellQuote = s => "'" + s.replace(/'/g, "'\\''") + "'";
$('#act-url').addEventListener('click', () => navigator.clipboard.writeText(S.selected.flow.request.url).then(() => toast('URL copied', 'ok')));
$('#act-curl').addEventListener('click', () => copy(curlOf(S.selected.flow.request), 'cURL command copied'));
$('#act-rule').addEventListener('click', async () => {
  try {
    const rule = await api('/api/rules/from-flow', { flow: S.selected.flow.id });
    S.rules.unshift(rule);
    S.rulesDirty = true; S.ruleSel = 0;
    setView('rules');
    toast('Auto-reply created from the original response. Edit it, then Save.', 'ok');
  } catch (e) { toast('Cannot create rule: ' + e.message, 'err'); }
});

// Resizable split between table and details
(() => {
  const split = $('#split'), details = $('#details');
  split.addEventListener('pointerdown', e => {
    split.setPointerCapture(e.pointerId); split.classList.add('drag');
    const view = $('#view-traffic').getBoundingClientRect();
    const move = ev => { details.style.flexBasis = Math.min(Math.max(view.bottom - ev.clientY, 140), view.height - 160) + 'px'; };
    const up = () => { split.classList.remove('drag'); split.removeEventListener('pointermove', move); };
    split.addEventListener('pointermove', move);
    split.addEventListener('pointerup', up, { once: true });
  });
})();

// ---------------------------------------------------------------------------------------------
// Connections

const connTable = new VTable($('#conns'), [
  { title: 'Time', w: '100px', text: r => clock(r.time), cls: () => 'mono' },
  { title: 'Application', w: '160px', text: r => r.app, cls: () => 'app', tip: r => `${r.path || r.app} (PID ${r.pid ?? '?'})` },
  { title: 'Protocol', w: '90px', text: r => r.proto, cls: () => 'mono' },
  { title: 'Direction', w: '86px', text: r => r.dir },
  { title: 'Local', w: '200px', text: r => r.local, cls: () => 'mono' },
  { title: 'Remote', w: '220px', text: r => r.remote, cls: () => 'mono' },
  { title: 'Server name', w: 'minmax(180px, 1fr)', text: r => r.sni, cls: () => 'mono' },
  { title: 'TLS', w: '150px', text: r => r.tls },
  { title: 'ALPN', w: '130px', text: r => r.alpn, cls: () => 'mono' },
], () => {});

// Why a connection was relayed without decryption (the proxy's `relay.reason`).
function untouched(flow) {
  const r = flow.relay || {}, app = (flow.process && flow.process.name) || 'The app';
  switch (r.reason) {
    case 'pinned': return `Pinned by the app: ${app} accepts only its own certificates, so Wiretap relays it untouched (decrypting would break it). The clear-text part of the handshake is shown above.`;
    case 'refused': return `${app} refused the Wiretap certificate for this server (it pins its certificates or uses its own trust store, like Firefox), so its connections here are relayed untouched.`;
    case 'service': return `${app} runs as a Windows service (or another user), which does not trust the Wiretap root: Windows trusts it for your account only. Its connections are relayed untouched so they keep working.`;
    case 'protocol': return `Relayed untouched: ${app} offers only ${(flow.tls && flow.tls.alpn_offered) || 'protocols'} here, which Wiretap does not decrypt yet.`;
    case 'unverified': return `Relayed untouched: Wiretap could not verify this server${r.detail ? ` (${r.detail})` : ''}, so ${app} meets it directly and decides itself.`;
    case 'opaque': return 'Neither HTTP nor TLS: relayed untouched.';
    case 'off': return 'HTTPS decryption was off for this connection. Turn it on in the toolbar to see the requests inside.';
    default: return S.state && S.state.https
      ? 'Encrypted and relayed untouched: this app does not trust the Wiretap certificate, or uses a protocol Wiretap does not decrypt yet.'
      : 'Encrypted. Turn on HTTPS decryption in the toolbar to see the requests inside.';
  }
}
// A connection the proxy relayed without decryption is described by events of its flow (the
// clear-text TLS handshake, then the bytes each way): merged, they show on its row.
function onMeta(e) {
  const id = e.metadata.flow_id, m = S.meta.get(id) || { tls: null, relay: {} };
  for (const [k, v] of Object.entries(e.metadata.attributes || {})) {
    if (k.startsWith('tls.')) (m.tls ||= {})[k.slice(4)] = v;
    else if (k.startsWith('relay.')) m.relay[k.slice(6)] = v;
  }
  S.meta.set(id, m);
  const row = S.flows.get(id);
  if (row) onFlow(row.flow);
}
function withMeta(flow) {
  const m = S.meta.get(flow.id);
  if (m) { if (m.tls) flow.tls = m.tls; flow.relay = m.relay; }
}

function onEvent(e) {
  if (beforeClear(e.timestamp)) return;
  if (e.metadata.flow_id) { if (['websocket', 'sse', 'grpc'].includes(e.protocol)) onMessage(e); else onMeta(e); return; }
  const local = endpoint(e.local_endpoint), remote = endpoint(e.remote_endpoint);
  const key = `${e.process ? e.process.pid : ''}|${local}|${remote}`;
  let row = S.conns.get(key);
  if (!row) {
    row = { time: e.timestamp, app: (e.process && e.process.name) || '', pid: e.process && e.process.pid, path: e.process && e.process.path,
      proto: e.protocol.toUpperCase(), dir: e.direction, local, remote, sni: '', tls: '', alpn: '', added: performance.now() };
    S.conns.set(key, row); S.connOrder.push(key);
    addFacet('capp', row.app, $('#c-app'));
  }
  const a = e.metadata.attributes || {};
  if (e.protocol === 'tls') {
    row.proto = 'TLS';
    if (a['tls.sni']) row.sni = a['tls.sni'];
    if (a['tls.version']) row.tls = `${a['tls.version']} · ${a['tls.cipher_suite'] || ''}`;
    else if (a['tls.versions_offered'] && !row.tls) row.tls = 'offers ' + a['tls.versions_offered'];
    if (a['tls.alpn']) row.alpn = a['tls.alpn'];
    else if (a['tls.alpn_offered'] && !row.alpn) row.alpn = a['tls.alpn_offered'];
    // The driver's TLS rows stand for requests it cannot read; the proxy's TLS details describe
    // a connection whose decrypted requests are already in the list.
    if (e.source === 'driver') onFlow(tlsFlow(key, e, a));
  }
  refreshConns();
}

// A message's size: on the wire for gRPC (its payload is the readable view), else the payload's.
const msgSize = e => e.protocol === 'grpc' ? Number(e.metadata.attributes.size || 0) : (e.payload ? e.payload.size : 0);
// WebSocket and SSE messages belong to their flow and show in its Messages tab, in time order.
function onMessage(e) {
  const id = e.metadata.flow_id;
  let m = S.ws.get(id);
  if (!m) { m = { list: [], ids: new Set(), sent: 0, bytes: 0, count: 0 }; S.ws.set(id, m); }
  // Known already (a reload after a gap in the live feed), or older than those still kept.
  const list = m.list, trimmed = m.count > list.length;
  if (m.ids.has(e.id) || (trimmed && list.length && e.timestamp < list[0].timestamp)) return;
  m.ids.add(e.id); m.count++;
  if (!list.length || e.timestamp >= list[list.length - 1].timestamp) list.push(e);
  else { // missed during a gap, reloaded after newer ones arrived
    let lo = 0, hi = list.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid].timestamp <= e.timestamp) lo = mid + 1; else hi = mid; }
    list.splice(lo, 0, e);
    m.reordered = true; // an open list cannot just append: redraw it
  }
  if (e.direction === 'outbound') m.sent++;
  m.bytes += msgSize(e);
  if (m.list.length > MAX_MESSAGES) for (const old of m.list.splice(0, m.list.length - MAX_MESSAGES)) m.ids.delete(old.id);
  // Shown at most 10 times a second, however fast messages come: appended to the open list.
  if (!S.wsPending && S.selected && S.selected.flow.id === id) {
    S.wsPending = true;
    setTimeout(() => {
      S.wsPending = false;
      if (!S.selected) return;
      if (S.tabs.res !== 'messages' || !updateMessages(S.selected.flow.id)) showDetails(S.selected);
    }, 100);
  }
}
// The open Messages tab, brought up to date in place: new messages appended (older ones dropped
// past 1,000), counts refreshed, the scroll position kept. False when it must be redrawn instead
// (another flow or filter, messages inserted out of order).
function updateMessages(flowId) {
  const rows = $('#pane-res .ws-list'), m = S.ws.get(flowId);
  const filter = $('#pane-res .pane-filter').value.toLowerCase();
  if (!rows || !m || m.reordered || rows.dataset.flow !== flowId || rows.dataset.filter !== filter) return false;
  const list = m.list;
  let i = list.length - 1;
  while (i >= 0 && list[i].id !== rows.dataset.last) i--;
  if (i < 0) return false; // the shown tail fell off the kept messages
  const fresh = list.slice(i + 1).filter(e => messageMatches(e, filter));
  for (const e of fresh) rows.append(messageRow(e));
  if (fresh.length) rows.dataset.last = fresh[fresh.length - 1].id;
  const shown = rows.querySelectorAll('.ws-row');
  for (let k = 0; k < shown.length - 1000; k++) shown[k].remove();
  const count = $('#pane-res .ws-count');
  if (count) count.textContent = messageCounts(m);
  const tab = $('#pane-res .tabs [data-tab=messages]');
  if (tab) tab.textContent = `Messages (${m.count})`;
  if (S.wsStick) rows.scrollTop = rows.scrollHeight;
  return true;
}
const messageCounts = m => `${m.count} message${m.count === 1 ? '' : 's'} · ↑ ${m.sent} sent · ↓ ${m.count - m.sent} received · ${bytes(m.bytes)}`;
const messageMatches = (e, filter) => !filter || JSON.stringify(e.metadata.attributes).toLowerCase().includes(filter);
// One row of the Messages tab.
function messageRow(e) {
  const a = e.metadata.attributes || {}, out = e.direction === 'outbound';
  const grpc = e.protocol === 'grpc';
  // gRPC: each message (its protobuf or JSON view), then the call's status.
  const kind = a.error ? 'error' : grpc ? (a.status ? 'status' : ['message', a.compressed, a.shown].filter(Boolean).join(' · '))
    : [a.opcode || a.event, a.id && `id ${a.id}`, a.wire_size && 'deflate', a.frames && `${a.frames} frames`].filter(Boolean).join(' · ');
  const data = a.error || (a.status ? [a.status, a['grpc-message']].filter(Boolean).join(' · ')
    : a.opcode === 'close' ? `Close ${a.close_code || ''} ${a.close_reason || ''}`.trim() : a.preview || '');
  const row = el('div', `ws-row ${out ? 'out' : 'in'}` + (S.wsSel === e.id ? ' sel' : '') + (a.error || a.problem || (a.status && !a.status.startsWith('0 ')) ? ' bad' : ''));
  row.append(el('span', 'dir', out ? '↑' : '↓'), el('span', 'data', data), el('span', 'kind', kind),
    el('span', 'len', e.payload || a.size ? bytes(msgSize(e)) : ''), el('span', 'time', clock(e.timestamp)));
  row.title = [out ? 'Sent by the client' : 'Received from the server', a.problem].filter(Boolean).join(' · ');
  row.addEventListener('click', () => { S.wsSel = e.id; renderPane('res'); });
  return row;
}
// Like the Messages tab of browser developer tools: a live list (sent ↑, received ↓) that follows
// new messages unless scrolled up, and the selected message in full below.
function renderMessages(container, flow) {
  const m = S.ws.get(flow.id) || { list: [], sent: 0, bytes: 0, count: 0 }, list = m.list;
  // Open until either end closes it; streams of earlier runs ended with their run.
  const open = !flow.timing.response_complete && !!S.state && flow.session_id === S.state.session;
  const status = el('div', 'ws-status');
  status.append(el('span', open ? 'pill on' : 'pill', open ? 'Open' : 'Closed'), el('span', 'ws-count', messageCounts(m)));
  container.append(status);
  if (!list.length) { container.append(el('div', 'note', open ? 'Waiting for messages…' : 'No messages.')); return; }
  m.reordered = false;
  // The newest 1,000 matching messages, oldest first, without scanning the whole list.
  const filter = $('#pane-res .pane-filter').value.toLowerCase(), shown = [];
  for (let i = list.length - 1; i >= 0 && shown.length < 1000; i--) {
    if (messageMatches(list[i], filter)) shown.push(list[i]);
  }
  shown.reverse();
  const rows = el('div', 'ws-list');
  // What is shown, so live updates can append to it (see updateMessages).
  rows.dataset.flow = flow.id; rows.dataset.filter = filter; rows.dataset.last = list[list.length - 1].id;
  const n = shown.length.toLocaleString(), all = m.count.toLocaleString();
  if (filter) rows.append(el('div', 'note', shown.length === 1000 ? `Showing the last 1,000 matches of ${all} messages.` : `${n} of ${all} messages match.`));
  else if (m.count > shown.length) rows.append(el('div', 'note', `Showing the last ${n} of ${all} messages.`));
  for (const e of shown) rows.append(messageRow(e));
  rows.addEventListener('scroll', () => { S.wsStick = rows.scrollHeight - rows.scrollTop - rows.clientHeight < 24; S.wsTop = rows.scrollTop; });
  container.append(rows);
  rows.scrollTop = S.wsStick ? rows.scrollHeight : S.wsTop;
  const sel = S.wsSel && list.find(e => e.id === S.wsSel);
  if (!sel) return;
  const pre = el('pre', 'code ws-payload', sel.payload ? 'Loading…' : 'No payload.');
  container.append(pre);
  if (sel.payload) {
    const sa = sel.metadata.attributes, readable = sa.opcode === 'text' || sel.protocol === 'sse' || (sel.protocol === 'grpc' && sa.shown !== 'bytes');
    const type = readable ? (sa.shown === 'protobuf' ? 'text/plain' : 'application/json') : '';
    loadBody(sel.payload, [{ name: 'content-type', value: type }])
      .then(({ text }) => { pre.textContent = text; }, err => { pre.textContent = 'Cannot load the message: ' + err.message; });
  }
}
// HTTPS connections also join the traffic list, live, as metadata-only rows: the driver sees
// the handshake (server name, version, ALPN) but not the encrypted requests, so the method stays
// empty until TLS interception decrypts them.
function tlsFlow(key, e, a) {
  const id = 'tls:' + key, prev = S.flows.get(id), tls = { ...(prev && prev.flow.tls) };
  for (const [k, v] of Object.entries(a)) if (k.startsWith('tls.')) tls[k.slice(4)] = v;
  const inbound = e.direction === 'inbound';
  const client = inbound ? e.remote_endpoint : e.local_endpoint, server = inbound ? e.local_endpoint : e.remote_endpoint;
  const port = server && server.port, name = tls.sni || (server ? server.ip : '?');
  return {
    id, session_id: e.session_id, source: 'driver', process: e.process, client, server, tls, tags: ['tls'], response: null,
    request: { method: '', url: `https://${name.includes(':') ? `[${name}]` : name}${port && port !== 443 ? ':' + port : ''}`, version: tls.version || 'TLS', headers: [] },
    timing: { started: prev ? prev.flow.timing.started : e.timestamp,
      response_started: (prev && prev.flow.timing.response_started) || (a['tls.version'] ? e.timestamp : null) },
  };
}
const refreshConns = throttle(() => {
  const app = $('#c-app').value, proto = $('#c-proto').value;
  const terms = $('#search').value.trim().split(/\s+/).filter(Boolean).map(compileTerm);
  const rows = S.connOrder.map(k => S.conns.get(k)).filter(r => (!app || r.app === app) && (!proto || r.proto === proto)
    && terms.every(t => [r.app, r.sni, r.remote, r.local, r.proto].some(v => t.re.test(v)) !== t.neg));
  connTable.setRows(rows);
  $('#c-count').textContent = rows.length;
  setChip('#chip-conn', S.connOrder.length);
  setChip('#chip-tls', S.connOrder.filter(k => S.conns.get(k).proto === 'TLS').length);
  updateCounts();
}, 80);

function setChip(sel, n) {
  const b = $(sel + ' b');
  if (b.textContent === String(n)) return;
  b.textContent = n; b.classList.remove('bump'); void b.offsetWidth; b.classList.add('bump');
}
function updateCounts() { $('#st-counts').textContent = `${S.flowOrder.length - S.tlsRows} requests · ${S.connOrder.length} connections`; }

// ---------------------------------------------------------------------------------------------
// Auto-reply rules

const TEXT_FIELDS = ['method', 'url', 'host', 'path', 'query', 'body', 'content_type', 'process', 'client_ip', 'server_ip'];
const FIELDS = [...TEXT_FIELDS.slice(0, 5), 'header', 'cookie', ...TEXT_FIELDS.slice(5), 'server_port'];
const OPS = ['equals', 'contains', 'starts_with', 'ends_with', 'wildcard'];
const label = s => s.replace(/_/g, ' ');

function leafToRow(c) {
  let not = false;
  if (c.not) { not = true; c = c.not; }
  const field = Object.keys(c)[0], v = c[field];
  if (TEXT_FIELDS.includes(field)) return { not, field, name: '', op: v.op, value: v.value, cs: !!v.case_sensitive };
  if (field === 'header' || field === 'cookie') {
    return v.value ? { not, field, name: v.name, op: v.value.op, value: v.value.value, cs: !!v.value.case_sensitive } : { not, field, name: v.name, op: 'exists', value: '', cs: false };
  }
  if (field === 'server_port') return { not, field, name: '', op: 'equals', value: String(v), cs: false };
  return null;
}
function fromCondition(c) {
  const mode = c.all ? 'all' : c.any ? 'any' : null;
  const leaves = mode ? c[mode] : [c];
  const rows = leaves.map(leafToRow);
  return rows.every(Boolean) && rows.every(r => !(r.field === 'all' || r.field === 'any')) ? { mode: mode || 'all', rows } : null;
}
function rowToLeaf(r) {
  let leaf;
  const text = { op: r.op, value: r.value };
  if (r.cs) text.case_sensitive = true;
  if (r.field === 'server_port') leaf = { server_port: Number(r.value) || 0 };
  else if (r.field === 'header' || r.field === 'cookie') leaf = { [r.field]: { name: r.name, value: r.op === 'exists' ? null : text } };
  else leaf = { [r.field]: text };
  return r.not ? { not: leaf } : leaf;
}
const toCondition = b => ({ [b.mode]: b.rows.map(rowToLeaf) });

function hits(rule) {
  const tag = 'rule:' + rule.id;
  let n = 0;
  for (const row of S.flows.values()) if (row.flow.tags && row.flow.tags.includes(tag)) n++;
  return n;
}

// Rule groups are shared as `.wtrr` files ("Wiretap redirect rules"), named after the domain.
const WTRR = 'wiretap.rules';
function ruleHost(c) {
  if (!c || typeof c !== 'object') return '';
  if (c.host && c.host.value) return c.host.value.replace(/^\*\.?/, '');
  if (c.url && c.url.value && c.url.value.includes('://')) return hostOf(c.url.value);
  for (const k of ['all', 'any']) for (const child of c[k] || []) { const h = ruleHost(child); if (h) return h; }
  return '';
}
function domainOf(host) {
  if (!host || /^[\d.]+$/.test(host) || host.includes(':')) return host;
  return host.split('.').filter(Boolean).slice(-2).join('.');
}
function groupFile(name, rules) {
  const domain = rules.map(r => domainOf(ruleHost(r.condition))).find(Boolean);
  return ((domain || name || 'rules').replace(/[^\w.-]+/g, '_')) + '.wtrr';
}
function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = el('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
function exportRules(group, rules) {
  download(groupFile(group, rules), JSON.stringify({ format: WTRR, version: 1, group, rules }, null, 2));
  toast(`Exported ${rules.length} rule(s).`, 'ok');
}
const groupName = r => r.group || '';
const describe = r => r.redirect ? `redirects to ${r.redirect.to}` : `replies ${(r.response && r.response.status) || 200}`;

function renderRuleList() {
  const list = clear($('#r-list'));
  let current = null;
  S.rules.forEach((rule, i) => {
    if (groupName(rule) !== current) {
      current = groupName(rule);
      const members = S.rules.filter(r => groupName(r) === current);
      const head = el('li', 'group');
      const sw = el('input', 'switch'); sw.type = 'checkbox'; sw.checked = members.every(r => r.enabled); sw.title = 'Enable or disable the whole group';
      sw.addEventListener('click', e => { e.stopPropagation(); members.forEach(r => { r.enabled = sw.checked; }); markDirty(); renderRuleList(); });
      const name = el('div', 'grow'); name.append(el('div', 'name', current || 'Ungrouped'), el('div', 'meta', `${members.length} rule(s)`));
      const exp = el('button', 'x', '⤓'); exp.title = 'Export this group (.wtrr)';
      exp.addEventListener('click', e => { e.stopPropagation(); exportRules(current, members); });
      head.append(sw, name, exp);
      if (current) {
        const del = el('button', 'x', '×'); del.title = 'Delete this group';
        del.addEventListener('click', async e => {
          e.stopPropagation();
          if (!await ask('Delete this group?', `All ${members.length} rule(s) of “${current}” are removed when you save.`, 'Delete')) return;
          S.rules = S.rules.filter(r => groupName(r) !== current); S.ruleSel = -1; markDirty(); renderRules();
        });
        head.append(del);
      }
      list.append(head);
    }
    const li = el('li', (i === S.ruleSel ? 'sel ' : '') + (rule.enabled ? '' : 'off'));
    const sw = el('input', 'switch'); sw.type = 'checkbox'; sw.checked = rule.enabled; sw.title = 'Enabled';
    sw.addEventListener('click', e => { e.stopPropagation(); rule.enabled = sw.checked; markDirty(); renderRuleList(); });
    const text = el('div');
    text.append(el('div', 'name', rule.name), el('div', 'meta', `#${i + 1} · ${describe(rule)} · ${hits(rule)} hits`));
    const move = el('div', 'row');
    for (const [sym, d] of [['↑', -1], ['↓', 1]]) {
      const b = el('button', 'x', sym); b.title = d < 0 ? 'Higher priority' : 'Lower priority';
      b.addEventListener('click', e => {
        e.stopPropagation();
        const j = i + d; if (j < 0 || j >= S.rules.length) return;
        [S.rules[i], S.rules[j]] = [S.rules[j], S.rules[i]]; S.ruleSel = j; markDirty(); renderRules();
      });
      move.append(b);
    }
    li.append(sw, text, move);
    li.addEventListener('click', () => { S.ruleSel = i; renderRules(); });
    list.append(li);
  });
  if (!S.rules.length) list.append(el('li', 'empty-rules', 'No rules yet.'));
}

function markDirty() {
  S.rulesDirty = true;
  const save = $('#r-save');
  if (save) save.disabled = false;
}

function renderRuleEditor() {
  const ed = clear($('#r-editor'));
  const rule = S.rules[S.ruleSel];
  if (!rule) {
    // Deleting the last rule still has to be saved: offer it here too.
    if (S.rulesDirty) { const save = el('button', 'btn primary small', 'Save rules'); save.id = 'r-save'; save.addEventListener('click', saveRules); const row = el('div', 'row'); row.append(el('span', 'grow'), save); ed.append(row); }
    ed.append(el('div', 'empty', 'Select a rule, or pick a request in Traffic and choose “Create auto-reply”: the response starts as the original one.'));
    return;
  }
  const head = el('div', 'row');
  const title = el('h2', '', rule.name);
  const save = el('button', 'btn primary small', S.rulesDirty ? 'Save rules' : 'Saved'); save.id = 'r-save'; save.disabled = !S.rulesDirty;
  save.addEventListener('click', saveRules);
  const test = el('button', 'btn small', 'Test on session'); test.addEventListener('click', () => testRule(rule));
  const dup = el('button', 'btn small ghost', 'Duplicate');
  dup.addEventListener('click', () => { const copy = structuredClone(rule); copy.id = crypto.randomUUID(); copy.name += ' (copy)'; S.rules.splice(S.ruleSel + 1, 0, copy); S.ruleSel++; markDirty(); renderRules(); });
  const del = el('button', 'btn small ghost danger', 'Delete');
  del.addEventListener('click', async () => { if (await ask('Delete this rule?', `“${rule.name}” is removed when you save.`, 'Delete')) { S.rules.splice(S.ruleSel, 1); S.ruleSel = Math.min(S.ruleSel, S.rules.length - 1); markDirty(); renderRules(); } });
  head.append(title, el('span', 'grow'), test, dup, del, save);
  ed.append(head);

  const field = (name, input) => { const f = el('div', 'field'); f.append(el('label', '', name), input); return f; };
  const nameIn = el('input', 'input'); nameIn.value = rule.name;
  nameIn.addEventListener('input', () => { rule.name = nameIn.value; title.textContent = rule.name; markDirty(); renderRuleList(); });
  const groupIn = el('input', 'input'); groupIn.value = rule.group || ''; groupIn.placeholder = 'none (e.g. example.com)';
  const groups = el('datalist'); groups.id = 'r-groups';
  for (const g of new Set(S.rules.map(groupName).filter(Boolean))) groups.append(el('option', '', g));
  groupIn.setAttribute('list', 'r-groups');
  groupIn.addEventListener('change', () => { rule.group = groupIn.value.trim(); markDirty(); renderRuleList(); });
  const action = el('select');
  for (const [v, t] of [['reply', 'Auto-reply: Wiretap answers'], ['redirect', 'Redirect: send to another server']]) { const o = el('option', '', t); o.value = v; action.append(o); }
  action.value = rule.redirect ? 'redirect' : 'reply';
  action.addEventListener('change', () => {
    rule.redirect = action.value === 'redirect' ? (rule.redirect || { to: 'http://localhost:3000', keep_host: false }) : undefined;
    if (!rule.redirect) delete rule.redirect;
    markDirty(); renderRules();
  });
  const meta = el('div', 'row'); meta.append(field('Name', nameIn), field('Group', groupIn), field('Action', action), groups);
  ed.append(meta);

  // Conditions
  const cbox = el('div', 'box');
  const ch = el('h4', '', 'When the request matches');
  const advanced = el('label', 'inline'); const advIn = el('input'); advIn.type = 'checkbox'; advanced.append(advIn, 'Advanced (JSON)');
  ch.append(el('span', 'grow'), advanced);
  cbox.append(ch);
  const builder = fromCondition(rule.condition);
  const area = el('div');
  cbox.append(area);
  const renderBuilder = b => {
    clear(area);
    const mode = el('select'); for (const m of [['all', 'ALL of'], ['any', 'ANY of']]) { const o = el('option', '', m[1]); o.value = m[0]; mode.append(o); }
    mode.value = b.mode;
    mode.addEventListener('change', () => { b.mode = mode.value; rule.condition = toCondition(b); markDirty(); });
    const top = el('div', 'row'); top.append(el('span', 'inline', 'Match'), mode, el('span', 'inline', 'these conditions (none = every request)'));
    area.append(top, el('div', 'note'));
    b.rows.forEach((r, i) => {
      const line = el('div', 'cond');
      const not = el('label', 'inline'); const notIn = el('input'); notIn.type = 'checkbox'; notIn.checked = r.not; not.append(notIn, 'NOT');
      const f = el('select'); for (const x of FIELDS) { const o = el('option', '', label(x)); o.value = x; f.append(o); } f.value = r.field;
      const name = el('input', 'input'); name.placeholder = r.field === 'cookie' ? 'cookie name' : 'header name'; name.value = r.name;
      name.classList.toggle('hidden', r.field !== 'header' && r.field !== 'cookie');
      const op = el('select'); for (const x of [...OPS, 'exists']) { const o = el('option', '', label(x)); o.value = x; op.append(o); } op.value = r.op;
      const value = el('input', 'input mono'); value.value = r.value; value.placeholder = r.field === 'server_port' ? 'port' : 'value (wildcard: * ?)';
      const cs = el('label', 'inline'); const csIn = el('input'); csIn.type = 'checkbox'; csIn.checked = r.cs; cs.append(csIn, 'Aa'); cs.title = 'Case-sensitive';
      const x = el('button', 'x', '×'); x.title = 'Remove condition';
      const sync = () => {
        Object.assign(r, { not: notIn.checked, field: f.value, name: name.value, op: op.value, value: value.value, cs: csIn.checked });
        if (r.field === 'server_port') r.op = 'equals';
        rule.condition = toCondition(b); markDirty();
      };
      [notIn, f, op, csIn].forEach(n => n.addEventListener('change', () => { sync(); renderBuilder(b); }));
      [name, value].forEach(n => n.addEventListener('input', sync));
      x.addEventListener('click', () => { b.rows.splice(i, 1); rule.condition = toCondition(b); markDirty(); renderBuilder(b); });
      line.append(not, f, name, op, value, cs, el('span'), x);
      area.append(line);
    });
    const add = el('button', 'btn small ghost', '+ Add condition');
    add.addEventListener('click', () => { b.rows.push({ not: false, field: 'url', name: '', op: 'contains', value: '', cs: false }); renderBuilder(b); });
    area.append(add);
  };
  const renderJson = () => {
    clear(area);
    const ta = el('textarea'); ta.value = JSON.stringify(rule.condition, null, 2); ta.spellcheck = false;
    const status = el('div', 'note', 'Full condition language: all, any, not, method, url, host, path, query, header, cookie, body, content_type, process, client_ip, server_ip, server_port.');
    ta.addEventListener('input', () => { try { rule.condition = JSON.parse(ta.value); status.textContent = 'Valid JSON (validated on save).'; markDirty(); } catch (e) { status.textContent = 'Invalid JSON: ' + e.message; } });
    area.append(ta, status);
  };
  advIn.checked = !builder;
  advIn.addEventListener('change', () => {
    if (advIn.checked) renderJson();
    else { const b = fromCondition(rule.condition); if (b) renderBuilder(b); else { advIn.checked = true; toast('This condition is too complex for the builder; edit it as JSON.', 'err'); } }
  });
  if (builder) renderBuilder(builder); else renderJson();
  ed.append(cbox);

  if (rule.redirect) {
    const red = rule.redirect;
    const dbox = el('div', 'box');
    dbox.append(el('h4', '', 'Send it to'));
    const to = el('input', 'input mono'); to.value = red.to; to.placeholder = 'http://localhost:3000';
    to.addEventListener('input', () => { red.to = to.value.trim(); markDirty(); renderRuleList(); });
    const keep = el('label', 'inline'); const keepIn = el('input'); keepIn.type = 'checkbox'; keepIn.checked = !!red.keep_host; keep.append(keepIn, 'Keep the original Host header');
    keepIn.addEventListener('change', () => { red.keep_host = keepIn.checked; markDirty(); });
    dbox.append(field('Server (scheme, host and port; a path becomes a prefix)', to), keep,
      el('div', 'note', 'The path and query are kept: https://api.example.com/v1/users?id=7 → http://localhost:3000/v1/users?id=7. Redirects are checked before auto-replies, and the original server is never contacted.'));
    ed.append(dbox);
    return;
  }

  // Response
  rule.response = rule.response || { status: 200, reason: 'OK', headers: [], body: { kind: 'empty' }, delay_ms: 0 };
  const r = rule.response;
  const rbox = el('div', 'box');
  rbox.append(el('h4', '', 'Reply with'));
  const status = el('input', 'input status-in mono'); status.type = 'number'; status.min = 200; status.max = 999; status.value = r.status;
  const reason = el('input', 'input reason-in'); reason.value = r.reason;
  const delay = el('input', 'input delay-in mono'); delay.type = 'number'; delay.min = 0; delay.max = 60000; delay.value = r.delay_ms || 0;
  status.addEventListener('input', () => { r.status = Number(status.value); markDirty(); renderRuleList(); });
  reason.addEventListener('input', () => { r.reason = reason.value; markDirty(); });
  delay.addEventListener('input', () => { r.delay_ms = Number(delay.value) || 0; markDirty(); });
  const line = el('div', 'row'); line.append(el('span', 'inline', 'Status'), status, el('span', 'inline', 'Reason'), reason, el('span', 'inline', 'Delay (ms)'), delay);
  rbox.append(line, el('div', 'note', 'Headers (Content-Length and Connection are set automatically):'));
  const hdrs = el('div');
  const renderHeaders = () => {
    clear(hdrs);
    r.headers.forEach((h, i) => {
      const row = el('div', 'hdr');
      const n = el('input', 'input mono'); n.value = h.name; n.placeholder = 'Name';
      const v = el('input', 'input mono'); v.value = h.value; v.placeholder = 'Value ({{request.header.X}} allowed)';
      const x = el('button', 'x', '×');
      n.addEventListener('input', () => { h.name = n.value; markDirty(); });
      v.addEventListener('input', () => { h.value = v.value; markDirty(); });
      x.addEventListener('click', () => { r.headers.splice(i, 1); markDirty(); renderHeaders(); });
      row.append(n, v, x); hdrs.append(row);
    });
    const add = el('button', 'btn small ghost', '+ Add header');
    add.addEventListener('click', () => { r.headers.push({ name: '', value: '' }); renderHeaders(); });
    hdrs.append(add);
  };
  renderHeaders();
  rbox.append(hdrs);
  const kind = el('select'); for (const k of [['empty', 'Empty body'], ['text', 'Text body'], ['base64', 'Binary (base64)']]) { const o = el('option', '', k[1]); o.value = k[0]; kind.append(o); }
  kind.value = r.body.kind;
  const bodyArea = el('textarea'); bodyArea.spellcheck = false;
  const syncBodyArea = () => {
    bodyArea.classList.toggle('hidden', r.body.kind === 'empty');
    bodyArea.value = r.body.kind === 'text' ? r.body.text : r.body.kind === 'base64' ? r.body.data : '';
  };
  kind.addEventListener('change', () => {
    r.body = kind.value === 'text' ? { kind: 'text', text: '' } : kind.value === 'base64' ? { kind: 'base64', data: '' } : { kind: 'empty' };
    markDirty(); syncBodyArea();
  });
  bodyArea.addEventListener('input', () => { if (r.body.kind === 'text') r.body.text = bodyArea.value; else if (r.body.kind === 'base64') r.body.data = bodyArea.value.trim(); markDirty(); });
  syncBodyArea();
  const brow = el('div', 'row'); brow.append(el('span', 'inline', 'Body'), kind);
  rbox.append(el('div', 'note'), brow, bodyArea,
    el('div', 'note', 'Variables: {{request.method}} {{request.url}} {{request.host}} {{request.path}} {{request.query}} {{request.body}} {{request.header.NAME}}'));
  ed.append(rbox);
}

function renderRules() { renderRuleList(); renderRuleEditor(); }

async function loadRules() { try { S.rules = await api('/api/rules'); S.rulesDirty = false; } catch (e) { toast('Cannot load rules: ' + e.message, 'err'); } }
async function saveRules() {
  try {
    await api('/api/rules', S.rules);
    S.rulesDirty = false;
    toast(`${S.rules.length} rule(s) saved and active.`, 'ok');
    renderRules();
  } catch (e) { toast('Not saved: ' + e.message, 'err'); }
}
async function testRule(rule) {
  const session = S.session === 'live' ? S.state && S.state.session : S.session;
  if (!session) { toast('Open a session first (Sessions view).', 'err'); return; }
  try {
    const ids = await api('/api/rules/test', { rule, session });
    S.matchSet = new Set(ids);
    const banner = $('#match-banner');
    banner.classList.remove('hidden');
    $('span', banner).textContent = `${ids.length} request(s) match “${rule.name}”`;
    setView('traffic'); refreshFlows();
  } catch (e) { toast('Test failed: ' + e.message, 'err'); }
}
$('#match-clear').addEventListener('click', () => { S.matchSet = null; $('#match-banner').classList.add('hidden'); refreshFlows(); });
$('#r-new').addEventListener('click', () => {
  S.rules.unshift({ id: crypto.randomUUID(), name: 'New rule', enabled: true, condition: { all: [{ url: { op: 'contains', value: '/api/' } }] },
    response: { status: 200, reason: 'OK', headers: [{ name: 'Content-Type', value: 'application/json' }], body: { kind: 'text', text: '{"mocked": true}' }, delay_ms: 0 } });
  S.ruleSel = 0; markDirty(); renderRules();
});
$('#r-export').addEventListener('click', () => exportRules('', S.rules));
$('#r-import').addEventListener('click', () => $('#r-file').click());
$('#r-file').addEventListener('change', async e => {
  const file = e.target.files[0]; e.target.value = '';
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    // A `.wtrr` file (one group), or a plain rule array (older exports).
    const wrapped = data && !Array.isArray(data) && data.format === WTRR;
    const rules = wrapped ? data.rules : data;
    if (!Array.isArray(rules)) throw new Error('not a Wiretap rules file');
    const group = wrapped ? String(data.group || '') : '';
    const taken = new Set(S.rules.filter(r => !group || groupName(r) !== group).map(r => r.id));
    for (const r of rules) {
      if (wrapped && group) r.group = group;
      if (!r.id || taken.has(r.id)) r.id = crypto.randomUUID();
      taken.add(r.id);
    }
    // Importing a group again replaces it (shared files update in place).
    if (group) S.rules = S.rules.filter(r => groupName(r) !== group);
    S.rules.push(...rules); S.ruleSel = S.rules.length - rules.length; markDirty(); renderRules();
    toast(`${rules.length} rule(s) imported${group ? ` into “${group}”` : ''}. Review, then Save.`, 'ok');
  } catch (err) { toast('Import failed: ' + err.message, 'err'); }
});

// ---------------------------------------------------------------------------------------------
// Sessions, system, views

async function loadSessions() {
  try { S.sessions = await api('/api/sessions'); } catch (e) { toast('Cannot list sessions: ' + e.message, 'err'); }
  const sel = $('#session'), keep = S.session;
  clear(sel);
  const live = el('option', '', '● Live'); live.value = 'live'; sel.append(live);
  for (const s of S.sessions) { const o = el('option', '', `${s.name}`); o.value = s.id; sel.append(o); }
  sel.value = [...sel.options].some(o => o.value === keep) ? keep : 'live';
  if (S.view === 'sessions') renderSessions();
}
// HAR 1.2 files (browser developer tools, other debuggers) import as new sessions.
const harFile = el('input'); harFile.type = 'file'; harFile.accept = '.har,application/json'; harFile.hidden = true;
document.body.append(harFile);
harFile.addEventListener('change', async () => {
  const file = harFile.files[0]; harFile.value = '';
  if (!file) return;
  try {
    const r = await fetch('/api/har', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: await file.text() });
    const result = await r.json();
    if (!r.ok) throw new Error(result.error || r.statusText);
    await loadSessions(); await openSession(result.session.id); setView('traffic');
    toast(`${result.imported} request(s) imported from ${file.name}${result.skipped ? `, ${result.skipped} skipped (not valid)` : ''}.`, 'ok');
  } catch (e) { toast('HAR import failed: ' + e.message, 'err'); }
});

function renderSessions() {
  const list = clear($('#s-list'));
  const tools = el('div', 'row');
  const importHar = el('button', 'btn small', 'Import HAR…'); importHar.addEventListener('click', () => harFile.click());
  tools.append(importHar, el('span', 'note', 'HAR files from browsers and other tools open as new sessions.'));
  list.append(tools);
  if (!S.sessions.length) list.append(el('div', 'empty', 'No sessions yet. Start a capture or open a browser.'));
  for (const s of S.sessions) {
    const card = el('div', 'card' + (s.id === S.session ? ' current' : ''));
    const open = el('button', 'btn small', 'Open'); open.addEventListener('click', () => openSession(s.id));
    const del = el('button', 'btn small ghost danger', 'Delete');
    del.addEventListener('click', async () => {
      if (!await ask('Delete this session?', `“${s.name}” and all its requests, connections and bodies are deleted.`, 'Delete')) return;
      try { await api(`/api/sessions/${s.id}/delete`, null); if (S.session === s.id) await openSession('live'); await loadSessions(); toast('Session deleted', 'ok'); } catch (e) { toast(e.message, 'err'); }
    });
    const har = el('a', 'btn small ghost', 'Export HAR'); har.href = `/api/sessions/${s.id}/har`; har.download = (s.name || 'session').replace(/[^\w-]+/g, '_') + '.har';
    const row = el('div', 'row'); row.append(open, har, del);
    card.append(el('div', 't', s.name), el('div', 'd', `${fullTime(s.created)} · ${s.id.slice(0, 8)}`), row);
    list.append(card);
  }
}
function resetData() {
  facetCache = null;
  S.flows.clear(); S.flowOrder = []; S.tlsRows = 0; S.conns.clear(); S.connOrder = []; S.selected = null; S.matchSet = null; S.ws.clear(); S.meta.clear(); S.wsSel = null;
  for (const k of Object.keys(facets)) facets[k].clear();
  for (const id of ['#f-app', '#f-host', '#f-method', '#f-type', '#c-app']) { const s = $(id); const first = s.options[0]; clear(s).append(first); }
  $('#match-banner').classList.add('hidden');
  showDetails(null); refreshFlows(); refreshConns();
}
// Loads a stored session's flows and events; rows and messages already shown merge by id.
async function loadStored(id) {
  for (const [kind, handler] of [['flows', onFlow], ['events', onEvent]]) {
    let after = null;
    do {
      const page = await api(`/api/sessions/${id}/${kind}` + (after ? `?after=${after}` : ''));
      page.items.forEach(item => handler(item));
      after = page.next;
    } while (after);
  }
  // Flows and events load separately: interleave HTTP and HTTPS rows by time.
  const started = id => S.flows.get(id).flow.timing.started;
  S.flowOrder.sort((x, y) => started(x) - started(y));
  S.flowOrder.forEach((id, i) => { S.flows.get(id).n = i + 1; });
  refreshFlows();
  if (S.selected) showDetails(S.flows.get(S.selected.flow.id) || null);
}
async function openSession(id) {
  S.session = id; $('#session').value = id; S.clearedAt = 0;
  resetData();
  if (id === 'live') return;
  try { await loadStored(id); } catch (e) { toast('Cannot load session: ' + e.message, 'err'); }
  if (S.view === 'sessions') renderSessions();
}
// After a gap in the live feed (a reconnect, or a browser too slow to keep up), what was missed
// is reloaded from storage.
async function resync() {
  const id = S.session === 'live' ? S.state.session : S.session;
  if (id !== S.state.session) return; // an earlier session: nothing new arrives
  try { await loadStored(id); } catch { /* not stored yet: nothing was missed */ }
}

function renderSystem() {
  const st = S.state; const sys = clear($('#sys'));
  if (!st) return;
  const p = st.platform;
  const yes = (v, good = true) => { const s = el('span', v === null || v === undefined ? 'no' : (v === good ? 'yes' : 'warnc'), v === null || v === undefined ? 'unknown' : v ? 'yes' : 'no'); return s; };
  const port = st.proxy ? st.proxy.port : 8899;
  let root = 'created when HTTPS decryption is turned on';
  if (st.https) { root = el('a', 'link', 'Download wiretap-root.cer'); root.href = '/api/tls/root.cer'; root.download = 'wiretap-root.cer'; }
  const box = (title, rows) => { const b = el('div', 'box'); b.append(el('h4', '', title)); const g = el('div', 'kv'); for (const [k, v] of rows) { g.append(el('span', 'k', k)); const c = el('span'); c.append(typeof v === 'string' ? document.createTextNode(v) : v); g.append(c); } b.append(g); return b; };
  const devSwitch = el('label', 'inline'); const devIn = el('input', 'switch'); devIn.type = 'checkbox'; devIn.checked = !!st.dev;
  devSwitch.append(devIn, 'Show diagnostics: connection-level rows, the Connections view and system internals');
  devIn.addEventListener('change', async () => { try { setState(await api('/api/prefs', { dev: devIn.checked })); } catch (e) { toast(e.message, 'err'); } });
  sys.append(box('Developer mode', [['Diagnostics', devSwitch]]));
  if (!st.dev) { sys.append(
    box('Proxy', [['State', st.proxy ? `always on, 127.0.0.1:${st.proxy.port}` : 'unavailable'], ['Active rules', String(st.rules)]]),
    box('HTTPS decryption', [['State', st.https ? 'on' : 'off'], ['Root certificate', root]]));
    return;
  }
  sys.append(
    box('Windows', [['Version', p.windows], ['Support', p.support], ['Administrator', yes(p.elevated)], ['Test signing', yes(p.test_signing, false)], ['Memory integrity', yes(p.memory_integrity)], ['Secure Boot', yes(p.secure_boot)]]),
    box('Driver', [['Service', p.driver], ['Capture', st.capture], ['After a capture', 'stays loaded without filters until Windows restarts (redirected connections may still hold its memory)']]),
    box('Proxy', [['State', st.proxy ? `always on, 127.0.0.1:${st.proxy.port}` : 'unavailable'], ['Use from curl', `curl -x http://127.0.0.1:${port} https://example.com/`], ['Use from any browser', `proxy server 127.0.0.1:${port}, or Open browser above`], ['Active rules', String(st.rules)]]),
    box('HTTPS decryption', [['State', st.https ? 'on: HTTPS through the proxy is decrypted' : 'off: HTTPS is tunnelled unread'], ['Root certificate', root], ['Server certificates', 'verified against the Windows trust store'], ['Other browsers / devices', 'import the root certificate there (Firefox: Settings › Certificates)']]),
    box('Storage', [['Database', st.db], ['Version', st.version]]),
  );
}

function setView(view) {
  S.view = view;
  $$('.rail button').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + view));
  if (view === 'rules') renderRules();
  if (view === 'sessions') loadSessions().then(renderSessions);
  if (view === 'system') renderSystem();
  if (view === 'traffic') flowTable.render();
  if (view === 'connections') connTable.render();
}
$$('.rail button').forEach(b => b.addEventListener('click', () => setView(b.dataset.view)));

// ---------------------------------------------------------------------------------------------
// Live state

let captureSince = null;
function setState(st) {
  const prev = S.state; S.state = st;
  document.body.classList.toggle('dev', !!st.dev);
  if (prev && prev.dev !== st.dev) { refreshFlows(); if (!st.dev && S.view === 'connections') setView('traffic'); }
  const cap = $('#capture');
  cap.classList.toggle('on', st.capture === 'running');
  cap.classList.toggle('wait', st.capture === 'starting');
  $('.label', cap).textContent = st.capture === 'running' ? 'Stop capture' : st.capture === 'starting' ? 'Starting…' : 'Start capture';
  cap.title = st.capture === 'running' ? 'Stop capturing: new connections go straight to their servers, open ones (WebSockets, streams) go on until they end' : 'Load the driver and capture all connections (asks for administrator approval)';
  const pill = $('#st-capture');
  pill.className = 'pill' + (st.capture === 'running' ? ' on' : '');
  if (st.capture === 'running' && (!prev || prev.capture !== 'running')) captureSince = Date.now();
  if (st.capture !== 'running') captureSince = null;
  pill.textContent = st.capture === 'running' ? 'Capturing' : st.capture === 'starting' ? 'Waiting for approval…' : 'Not capturing';
  const hs = $('#https');
  hs.classList.toggle('on', st.https);
  $('.label', hs).textContent = st.https ? 'HTTPS decrypted' : 'HTTPS decryption';
  const pp = $('#st-proxy');
  pp.className = 'pill' + (st.proxy ? ' ok' : '');
  pp.textContent = st.proxy ? `Proxy 127.0.0.1:${st.proxy.port} · HTTPS ${st.https ? 'decrypted' : 'tunnelled'} · ${st.rules} rule(s)` : 'Proxy unavailable';
  const msg = $('#st-msg');
  msg.textContent = st.error || ''; msg.className = st.error ? 'err' : '';
  if (prev && prev.error !== st.error && st.error) toast(st.error, 'err');
  if (S.view === 'system') renderSystem();
}
setInterval(() => {
  if (captureSince) {
    const s = Math.floor((Date.now() - captureSince) / 1000);
    $('#st-capture').textContent = `Capturing ${pad(Math.floor(s / 60))}:${pad(s % 60)}`;
  }
}, 1000);

function belongs(sessionId) { return S.session === 'live' || S.session === sessionId; }
// Live messages are handled in slices of at most 8 ms per frame, in arrival order: a burst of
// traffic never freezes the window, and the lists update between slices.
const inbox = []; let inboxAt = 0, draining = false;
function drainInbox() {
  const end = performance.now() + 8;
  while (inboxAt < inbox.length && performance.now() < end) liveMessage(inbox[inboxAt++]);
  if (inboxAt < inbox.length) { nextSlice(); return; }
  inbox.length = 0; inboxAt = 0; draining = false;
}
// Animation frames pause while the window is hidden: then timers keep the queue short.
const nextSlice = () => (document.hidden ? setTimeout(drainInbox, 50) : requestAnimationFrame(drainInbox));
function connectLive() {
  const es = new EventSource('/api/live');
  es.onmessage = ev => { inbox.push(ev.data); if (!draining) { draining = true; nextSlice(); } };
  es.onerror = () => { S.resync = true; $('#st-msg').textContent = 'Reconnecting…'; };
}
function liveMessage(data) {
  let m; try { m = JSON.parse(data); } catch { return; }
  if (m.state) { setState(m.state); if (S.resync) { S.resync = false; resync(); } }
  else if (m.session) { loadSessions(); }
  else if (m.event) { if (belongs(m.event.session_id)) onEvent(m.event); }
  else if (m.flow) { if (belongs(m.flow.session_id)) onFlow(m.flow); }
}

$('#capture').addEventListener('click', async () => {
  const running = S.state && S.state.capture !== 'idle';
  try {
    if (running) { setState(await api('/api/capture/stop', null)); return; }
    if (S.session !== 'live') await openSession('live');
    setState(await api('/api/capture/start', null));
    toast('Approve the administrator prompt to load the driver.');
  } catch (e) { toast(e.message, 'err'); }
});
$('#https').addEventListener('click', async () => {
  const on = S.state && S.state.https;
  if (on && !await ask('Turn HTTPS decryption off?', 'The Wiretap root certificate is removed from Windows (Windows asks you to confirm) and its keys are deleted.', 'Turn off')) return;
  const b = $('#https'); b.disabled = true;
  if (!on) toast('Windows asks you to confirm the Wiretap root certificate. Choose Yes to decrypt HTTPS.');
  try {
    setState(await api(on ? '/api/tls/disable' : '/api/tls/enable', null));
    toast(on ? 'HTTPS decryption is off' : 'HTTPS decryption is on', 'ok');
  } catch (e) { toast(e.message, 'err'); } finally { b.disabled = false; }
});
$('#browser').addEventListener('click', async () => {
  try {
    await api('/api/browser', null);
    toast(S.state && S.state.https ? 'Browser opened: its traffic, HTTPS included, appears here.' : 'Browser opened. Turn on HTTPS decryption to read HTTPS too.', 'ok');
  } catch (e) { toast(e.message, 'err'); }
});
// Clear hides what came before, for good: late updates of those requests (a stream ending, a
// reload after a reconnect) do not bring them back.
$('#clear').addEventListener('click', () => { resetData(); S.clearedAt = Date.now() * 1000; });
$('#session').addEventListener('change', e => openSession(e.target.value));
for (const id of ['#f-app', '#f-host', '#f-method', '#f-status', '#f-type', '#f-source']) $(id).addEventListener('change', refreshFlows);
for (const id of ['#c-app', '#c-proto']) $(id).addEventListener('change', refreshConns);
$('#search').addEventListener('input', () => { refreshFlows(); refreshConns(); });
document.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key.toLowerCase() === 'f') { e.preventDefault(); $('#search').focus(); }
});

// ---------------------------------------------------------------------------------------------
// Search autocomplete: filter keys, then the values present in the logged requests.

const KEYS = [
  ['app', 'Application (process)'], ['host', 'Domain'], ['method', 'HTTP method'], ['status', 'Status (200, 4xx…)'],
  ['type', 'Content type'], ['url', 'Anything in the URL'], ['header', 'A header name or value'], ['source', 'Where it was captured'],
];
let facetCache = null;
function facetValues(key) {
  if (!facetCache) {
    facetCache = {};
    const add = (k, v) => { if (!v) return; const m = facetCache[k] || (facetCache[k] = new Map()); m.set(v, (m.get(v) || 0) + 1); };
    for (const { flow } of S.flows.values()) {
      if (!dev() && diagnostic(flow)) continue;
      add('app', flow.process && flow.process.name); add('host', hostOf(flow.request.url)); add('method', flow.request.method);
      add('type', typeOf(flow)); add('source', source(flow));
      if (flow.response) { add('status', String(flow.response.status)); add('status', String(flow.response.status)[0] + 'xx'); }
      for (const h of [...flow.request.headers, ...(flow.response ? flow.response.headers : [])]) add('header', h.name.toLowerCase());
    }
  }
  return [...(facetCache[key] || new Map())].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
}
const suggest = el('div', 'suggest hidden');
$('.search').append(suggest);
let suggestions = [], suggestAt = 0;
/** The word under the caret: [start, end, text]. */
function caretWord(input) {
  const v = input.value, at = input.selectionStart ?? v.length;
  const start = v.lastIndexOf(' ', at - 1) + 1, end = v.indexOf(' ', at) < 0 ? v.length : v.indexOf(' ', at);
  return [start, end, v.slice(start, end)];
}
function renderSuggest() {
  clear(suggest);
  suggest.classList.toggle('hidden', !suggestions.length);
  suggestions.forEach((s, i) => {
    const row = el('div', 'item' + (i === suggestAt ? ' on' : ''));
    row.append(el('span', 'mono', s.label), el('span', 'grow'), el('span', 'meta', s.meta));
    row.addEventListener('pointerdown', e => { e.preventDefault(); applySuggestion(s); });
    suggest.append(row);
  });
}
function updateSuggest() {
  const input = $('#search');
  const [, , word] = caretWord(input);
  const neg = word.startsWith('-') ? '-' : '', bare = neg ? word.slice(1) : word;
  const colon = bare.indexOf(':');
  if (colon < 0) {
    const q = bare.toLowerCase();
    suggestions = KEYS.filter(([k]) => k.startsWith(q)).map(([k, d]) => ({ label: `${neg}${k}:`, meta: d, insert: `${neg}${k}:`, more: true }));
  } else {
    const key = bare.slice(0, colon).toLowerCase(), q = bare.slice(colon + 1).toLowerCase();
    suggestions = facetValues(key).filter(([v]) => String(v).toLowerCase().includes(q)).slice(0, 8)
      .map(([v, n]) => ({ label: `${neg}${key}:${v}`, meta: `${n}`, insert: `${neg}${key}:${token(String(v))} ` }));
  }
  if (suggestions.length === 1 && suggestions[0].label === word) suggestions = [];
  suggestAt = 0; renderSuggest();
}
function applySuggestion(s) {
  const input = $('#search');
  const [start, end] = caretWord(input);
  input.value = input.value.slice(0, start) + s.insert + input.value.slice(end);
  const caret = start + s.insert.length;
  input.setSelectionRange(caret, caret);
  refreshFlows(); refreshConns();
  if (s.more) updateSuggest(); else { suggestions = []; renderSuggest(); }
}
$('#search').addEventListener('focus', updateSuggest);
$('#search').addEventListener('input', updateSuggest);
$('#search').addEventListener('blur', () => { suggestions = []; renderSuggest(); });
$('#search').addEventListener('keydown', e => {
  if (!suggestions.length) return;
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); suggestAt = (suggestAt + (e.key === 'ArrowDown' ? 1 : suggestions.length - 1)) % suggestions.length; renderSuggest(); }
  else if (e.key === 'Tab' || e.key === 'Enter') { e.preventDefault(); applySuggestion(suggestions[suggestAt]); }
  else if (e.key === 'Escape') { suggestions = []; renderSuggest(); }
});

// ---------------------------------------------------------------------------------------------
// Wiretap's own context menus and dialogs: the browser's never show.

const menu = el('div', 'menu hidden');
document.body.append(menu);
function closeMenu() { menu.classList.add('hidden'); clear(menu); }
function buildMenu(items, root) {
  for (const it of items) {
    if (it === '-') { root.append(el('div', 'sep')); continue; }
    const row = el('div', 'item' + (it.disabled ? ' off' : '') + (it.items ? ' sub' : ''));
    if (it.swatch) { const s = el('i', 'swatch'); s.style.background = it.swatch; row.append(s); }
    row.append(el('span', 'grow', it.label));
    if (it.key) row.append(el('span', 'key', it.key));
    if (it.items) { const sub = el('div', 'menu submenu'); buildMenu(it.items, sub); row.append(sub); }
    else if (!it.disabled) row.addEventListener('click', () => { closeMenu(); Promise.resolve(it.run()).catch(e => toast(e.message, 'err')); });
    root.append(row);
  }
}
function openMenu(x, y, items) {
  clear(menu); buildMenu(items, menu); menu.classList.remove('hidden');
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 4)) + 'px';
  menu.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 4)) + 'px';
  menu.classList.toggle('flip', x + r.width * 2 > innerWidth);
}
const copy = (text, what) => navigator.clipboard.writeText(text).then(() => toast(what, 'ok'));
function curlOf(r) {
  return ['curl', '-X', r.method, shellQuote(r.url), ...r.headers.filter(h => !/^(host|content-length)$/i.test(h.name)).flatMap(h => ['-H', shellQuote(`${h.name}: ${h.value}`)])].join(' ');
}
function setFilter(id, value) { const s = $(id); if (![...s.options].some(o => o.value === value)) s.append(el('option', '', value)); s.value = value; refreshFlows(); }
function addTerm(term) { const s = $('#search'); s.value = (s.value.trim() + ' ' + term).trim(); refreshFlows(); refreshConns(); }
const token = v => v.replace(/\s/g, '?');
const MARKS = [['Red', 'red', '#f87171'], ['Amber', 'amber', '#fbbf24'], ['Green', 'green', '#34d399'], ['Blue', 'blue', '#60a5fa'], ['Violet', 'violet', '#a78bfa']];
function removeRows(ids) {
  const gone = new Set(ids);
  S.flowOrder = S.flowOrder.filter(id => !gone.has(id));
  for (const id of gone) { if (S.flows.get(id) && S.flows.get(id).tls) S.tlsRows--; S.flows.delete(id); S.meta.delete(id); }
  if (S.selected && gone.has(S.selected.flow.id)) showDetails(null);
  refreshFlows();
}
async function saveBody(f) {
  const buf = await api('/api/payloads/' + f.response.body.id);
  const name = (f.request.url.split(/[?#]/)[0].split('/').pop() || 'response') || 'response';
  const a = el('a'); a.href = URL.createObjectURL(new Blob([buf])); a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}
function flowMenu(row) {
  const f = row.flow, r = f.request, host = hostOf(r.url), app = (f.process && f.process.name) || '';
  const http = !f.tls && !f.relay, body = f.response && f.response.body;
  return [
    { label: 'Copy', items: [
      { label: 'URL', run: () => copy(r.url, 'URL copied') },
      { label: 'As cURL', disabled: !http, run: () => copy(curlOf(r), 'cURL command copied') },
      { label: 'Request headers', disabled: !http, run: () => copy(rawText(f, 'request'), 'Request headers copied') },
      { label: 'Response headers', disabled: !f.response, run: () => copy(rawText(f, 'response'), 'Response headers copied') },
      { label: 'Response body', disabled: !body, run: async () => copy((await loadBody(body, f.response.headers)).text, 'Response body copied') },
    ] },
    { label: 'Show only', items: [
      { label: 'This host  ' + host, run: () => setFilter('#f-host', host) },
      { label: 'This application  ' + (app || '—'), disabled: !app, run: () => setFilter('#f-app', app) },
      { label: 'This method  ' + (r.method || '—'), disabled: !r.method, run: () => setFilter('#f-method', r.method) },
    ] },
    { label: 'Filter out', items: [
      { label: 'This host  ' + host, run: () => addTerm('-host:' + token(host)) },
      { label: 'This application  ' + (app || '—'), disabled: !app, run: () => addTerm('-app:' + token(app)) },
      { label: 'This URL', run: () => addTerm('-url:' + token(r.url.split('?')[0])) },
    ] },
    { label: 'Highlight', items: [...MARKS.map(([label, cls, swatch]) => ({ label, swatch, run: () => { row.mark = cls; flowTable.render(); } })), '-', { label: 'None', run: () => { row.mark = null; flowTable.render(); } }] },
    '-',
    { label: 'Create auto-reply', disabled: !http, run: () => $('#act-rule').click() },
    { label: 'Redirect this host…', disabled: !host, run: () => {
      S.rules.unshift({ id: crypto.randomUUID(), name: `Redirect ${host}`, enabled: true, group: domainOf(host),
        condition: { host: { op: 'equals', value: host } }, redirect: { to: 'http://localhost:3000', keep_host: false } });
      S.ruleSel = 0; markDirty(); setView('rules');
      toast('Set the target server, then Save.', 'ok');
    } },
    { label: 'Save response body…', disabled: !body, run: () => saveBody(f) },
    '-',
    { label: 'Remove from list', key: 'Del', run: () => removeRows([f.id]) },
    { label: 'Clear', key: 'Ctrl+L', run: resetData },
  ];
}
document.addEventListener('contextmenu', e => {
  if (e.target.closest('input, textarea, select')) return; // text fields keep cut/copy/paste
  e.preventDefault();
  const tr = e.target.closest('#flows .tr');
  const row = tr && flowTable.rows[Number(tr.dataset.i)];
  if (row) { flowTable.select(row); openMenu(e.clientX, e.clientY, flowMenu(row)); return; }
  const text = String(getSelection());
  if (text) openMenu(e.clientX, e.clientY, [{ label: 'Copy', key: 'Ctrl+C', run: () => copy(text, 'Copied') }]);
  else closeMenu();
});
document.addEventListener('pointerdown', e => { if (!menu.contains(e.target)) closeMenu(); });
addEventListener('blur', closeMenu);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeMenu();
  if (e.target.closest('input, textarea, select')) return;
  if (e.key === 'Delete' && S.selected && S.view === 'traffic') removeRows([S.selected.flow.id]);
  if (e.ctrlKey && e.key.toLowerCase() === 'l') { e.preventDefault(); resetData(); }
});

/** In-app confirmation (never the browser's dialogs). Resolves true for `yes`. */
function ask(title, text, yes) {
  return new Promise(done => {
    const shade = el('div', 'shade'), box = el('div', 'dialog');
    const ok = el('button', 'btn', yes), cancel = el('button', 'btn ghost', 'Cancel'), row = el('div', 'row');
    const end = v => { shade.remove(); done(v); };
    ok.addEventListener('click', () => end(true)); cancel.addEventListener('click', () => end(false));
    shade.addEventListener('pointerdown', e => { if (e.target === shade) end(false); });
    row.append(cancel, ok); box.append(el('h4', '', title), el('p', '', text), row); shade.append(box);
    document.body.append(shade); ok.focus();
  });
}

function emptyState(title, text) { const d = el('div'); d.append(el('div', 'big', title), el('div', '', text)); return d; }
flowTable.setEmpty(emptyState('No traffic yet', 'Start a capture to see every connection with its application, or click Open browser: everything it loads appears here with full requests, responses and bodies.'));
connTable.setEmpty(emptyState('No connections yet', 'Connections appear here while a capture runs, with TLS server names and versions.'));

(async function init() {
  try { setState(await api('/api/state')); } catch (e) { toast(e.message, 'err'); }
  await Promise.all([loadSessions(), loadRules()]);
  connectLive();
  // Live by default (the proxy is always recording); deep links open a stored session.
  const link = new URLSearchParams(location.hash.slice(1));
  const wanted = link.get('session');
  if (wanted && S.sessions.some(s => s.id === wanted)) await openSession(wanted);
  showDetails(link.get('flow') ? S.flows.get(link.get('flow')) || null : null);
  if (S.selected) { flowTable.sel = S.selected; flowTable.render(); }
  if (link.get('rule')) S.ruleSel = Number(link.get('rule'));
  if (link.get('view')) setView(link.get('view'));
})();
