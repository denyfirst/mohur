// The Mohur window. It draws what the engine reports and asks it to act; it
// has no keys and no network. Every text from elsewhere is set as text.
const m = window.mohur;
const $ = (id) => document.getElementById(id);
const SVG = 'http://www.w3.org/2000/svg';
let snap = { joined: false };
let current = null;
let checked = null;
// Messages already on screen, so only new ones animate in.
let drawnFor = null;
const drawn = new Set();

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('data-') || k.startsWith('aria-') || k === 'type' || k === 'title' || k === 'datetime') n.setAttribute(k, v);
    else n[k] = v;
  }
  for (const c of kids) if (c != null) n.append(c);
  return n;
}

// icon draws one of the symbols in index.html.
function icon(name, cls = 'i') {
  const s = document.createElementNS(SVG, 'svg');
  s.setAttribute('class', cls);
  s.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG, 'use');
  use.setAttribute('href', '#' + name);
  s.append(use);
  return s;
}

const initials = (name) => name.split(/\s+/).map((w) => w[0] || '').join('').slice(0, 2).toUpperCase();
// Each person keeps one of eight colours, picked from their address.
function hue(address) {
  // FNV-1a, then a final mix: addresses share their domain, so the low bits
  // of a plain hash would hand most people at one company the same colour.
  let h = 0x811c9dc5;
  for (const c of address) h = Math.imul(h ^ c.codePointAt(0), 0x01000193);
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b);
  h ^= h >>> 16;
  return String((h >>> 0) % 8);
}
function avatar(target, p) {
  target.textContent = initials(p.name);
  target.dataset.hue = hue(p.address);
  return target;
}
const time = (t) => new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
const day = (t) => new Date(t).toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' });
function short(t) {
  if (!t) return '';
  const d = new Date(t);
  return d.toDateString() === new Date().toDateString() ? time(t) : d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}
function size(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(0) + ' KB';
  return (n / 1024 / 1024).toFixed(1) + ' MB';
}
const statusWords = { sending: 'Sending…', sent: 'Sent', delivered: 'Delivered', waiting: 'Waiting for their server', failed: 'Not sent' };
const statusIcons = { sending: 'i-clock', waiting: 'i-clock', sent: 'i-check', delivered: 'i-checks', failed: 'i-alert' };

async function refresh() {
  snap = await m.state();
  delete document.body.dataset.loading;
  $('join').hidden = snap.joined;
  $('app').hidden = !snap.joined;
  if (!snap.joined) {
    document.title = 'Mohur';
    $('join-invite').focus();
    return;
  }
  $('me-name').textContent = snap.me.name;
  $('me-org').textContent = snap.me.org;
  $('me-org').title = snap.me.address;
  avatar($('me-avatar'), snap.me);
  // The server asks an app too old for it to update; until then it says so.
  const outdated = Boolean(snap.outdated);
  $('status').toggleAttribute('data-online', snap.online && !outdated);
  $('status').toggleAttribute('data-outdated', outdated);
  $('status-text').textContent = outdated ? 'Update needed' : snap.online ? 'Connected' : 'Connecting…';
  $('update-bar').hidden = !outdated;
  $('update-text').textContent = snap.outdated || '';
  const unread = snap.people.reduce((n, p) => n + (p.unread || 0), 0);
  document.title = unread ? `(${unread}) Mohur` : 'Mohur';
  drawPeople();
  drawConversation();
  markSeen();
}

// markSeen tells the engine the open conversation was read, when the window
// is actually in front of the person.
function markSeen() {
  if (!snap.joined || !current || !document.hasFocus()) return;
  const p = snap.people.find((x) => x.address === current);
  if (p && p.unread) m.read(p.address).catch(() => {});
}

function drawPeople() {
  const q = $('search').value.trim().toLowerCase();
  const list = $('people');
  list.replaceChildren();
  const people = snap.people.filter((p) => !q || p.name.toLowerCase().includes(q) || p.address.includes(q) || p.org.toLowerCase().includes(q));
  const groups = new Map();
  for (const p of people.sort((a, b) => (b.lastAt - a.lastAt) || a.name.localeCompare(b.name))) {
    const key = p.own ? snap.me.org : p.org;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(p);
  }
  const order = [...groups.keys()].sort((a, b) => (a === snap.me.org) - (b === snap.me.org) || a.localeCompare(b));
  for (const g of order) {
    const own = g === snap.me.org;
    const items = groups.get(g);
    list.append(el('p', { class: 'group', title: own ? 'Your colleagues' : 'A partner, verified by its domain' },
      own ? null : icon('i-verified'), g, el('span', { class: 'count' }, String(items.length))));
    for (const p of items) {
      const preview = el('span', { class: 'preview' }, p.lastOut ? el('span', { class: 'you' }, 'You: ') : null, p.last || p.address);
      const b = el('button', { type: 'button', class: 'person', 'aria-current': String(p.address === current) },
        avatar(el('span', { class: 'avatar', 'aria-hidden': 'true' }), p),
        el('span', { class: 'who' },
          el('span', { class: 'line' }, el('strong', {}, p.name), el('time', {}, short(p.lastAt))),
          el('span', { class: 'line' }, preview,
            p.blocked ? el('span', { class: 'tag' }, 'Blocked')
              : p.unread ? el('span', { class: 'badge', 'aria-label': `${p.unread} unread` }, p.unread > 99 ? '99+' : String(p.unread)) : null)));
      if (p.unread) b.dataset.unread = '';
      if (p.blocked) b.dataset.blocked = '';
      b.addEventListener('click', () => {
        current = p.address;
        drawPeople();
        drawConversation(true);
        markSeen();
        $('text').focus();
      });
      list.append(b);
    }
  }
  if (!people.length) {
    list.append(el('p', { class: 'empty-list' }, q ? 'No one matches.' : "No one to write to yet. Colleagues appear here when they join, and a partner's people once your admin lets you write to them."));
  }
}

// Messages from one side a few minutes apart sit together as one group.
function together(a, b) {
  return Boolean(a && b) && a.dir === b.dir && a.dir !== 'system' && Math.abs(b.at - a.at) < 3 * 60 * 1000 && day(a.at) === day(b.at);
}

function meta(msg) {
  const words = msg.dir === 'out' ? statusWords[msg.status] || '' : '';
  const out = el('span', { class: 'meta' }, time(msg.at));
  if (msg.dir === 'out' && statusIcons[msg.status]) {
    out.title = words;
    out.append(icon(statusIcons[msg.status]));
    if (msg.status === 'failed') out.append(words);
    else out.append(el('span', { class: 'visually-hidden' }, words));
  }
  return out;
}

function drawConversation(scroll) {
  const p = snap.people.find((x) => x.address === current);
  $('conv-empty').hidden = Boolean(p);
  $('conv-head').hidden = !p;
  $('messages').hidden = !p;
  $('composer').hidden = !p || p.blocked;
  $('blocked-bar').hidden = !p || !p.blocked;
  closeMenu();
  if (!p) return;
  const first = p.name.split(/\s+/)[0];
  $('blocked-text').textContent = `You blocked ${p.name}. They are not told, and nothing they send is kept.`;
  $('menu-block-text').textContent = p.blocked ? `Unblock ${first}` : `Block ${first}`;
  $('menu-block').toggleAttribute('data-blocked', Boolean(p.blocked));
  $('conv-chip').toggleAttribute('data-blocked', Boolean(p.blocked));
  avatar($('conv-avatar'), p);
  $('conv-name').textContent = p.name;
  $('conv-addr').textContent = `${p.address} · ${p.org}`;
  $('conv-chip-text').textContent = p.blocked ? 'Blocked' : 'Verified by ' + p.domain;
  const box = $('messages');
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const opened = drawnFor !== p.address;
  if (opened) { drawnFor = p.address; drawn.clear(); }
  box.replaceChildren(el('li', { class: 'e2e' }, icon('i-lock'),
    `Encrypted end to end. Only you and ${p.name} can read these messages; no server can.`));
  const list = snap.convs[p.address] || [];
  let lastDay = '';
  list.forEach((msg, i) => {
    const d = day(msg.at);
    if (d !== lastDay) { box.append(el('li', { class: 'day' }, d)); lastDay = d; }
    if (msg.dir === 'system') { box.append(el('li', { class: 'msg system' }, msg.text)); return; }
    let cls = 'msg ' + msg.dir;
    if (together(list[i - 1], msg)) cls += ' cont';
    if (together(msg, list[i + 1])) cls += ' more';
    if (!opened && !drawn.has(msg.id)) cls += ' new';
    drawn.add(msg.id);
    let body;
    if (msg.kind === 'file') {
      body = el('div', { class: 'file' }, icon('i-file'), el('div', {}, el('strong', {}, msg.file.name), el('span', { class: 'size' }, size(msg.file.size))));
      if (msg.dir === 'in') {
        const save = el('button', { type: 'button', class: 'secondary' }, 'Save');
        save.addEventListener('click', async () => {
          save.disabled = true;
          save.textContent = 'Checking…';
          try { await m.saveFile(p.address, msg.id); save.textContent = 'Saved'; } catch (e) { save.textContent = 'Save'; alertIn(e.message); }
          save.disabled = false;
        });
        body.append(save);
      }
    } else {
      body = el('span', { class: 'text' }, msg.text);
    }
    box.append(el('li', { class: cls, 'data-status': msg.status || '' }, body, meta(msg)));
  });
  if (scroll || atBottom || opened) box.scrollTop = box.scrollHeight;
}

function alertIn(text) {
  $('messages').append(el('li', { class: 'msg system' }, text));
  $('messages').scrollTop = $('messages').scrollHeight;
}

let toastTimer;
function toast(text, kind) {
  const t = $('toast');
  t.replaceChildren(icon(kind === 'bad' ? 'i-alert' : 'i-check'), text);
  if (kind) t.dataset.kind = kind;
  else delete t.dataset.kind;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, kind === 'bad' ? 6000 : 2500);
}

// ── The conversation menu: report and block ──

function closeMenu() {
  $('conv-menu').hidden = true;
  $('conv-more').setAttribute('aria-expanded', 'false');
}

function openReport() {
  const p = snap.people.find((x) => x.address === current);
  if (!p) return;
  closeMenu();
  $('report-form').reset();
  $('report-title').textContent = 'Report ' + p.name + ' to your admin';
  $('report-block-text').textContent = 'Also block ' + p.name.split(/\s+/)[0] + ' on this computer';
  $('report-block').checked = !p.blocked;
  $('report-block').parentElement.hidden = Boolean(p.blocked);
  $('report-notice').textContent = '';
  delete $('report-notice').dataset.kind;
  $('report-dialog').showModal();
}

async function sendReport(ev) {
  ev.preventDefault();
  const p = snap.people.find((x) => x.address === current);
  const reason = ($('report-form').querySelector('input[name=reason]:checked') || {}).value;
  if (!p) return;
  if (!reason) { $('report-notice').textContent = 'Choose a reason.'; $('report-notice').dataset.kind = 'bad'; return; }
  $('report-send').disabled = true;
  try {
    await m.report(p.address, reason, $('report-note').value);
    if ($('report-block').checked && !p.blocked) await m.block(p.address);
    $('report-dialog').close();
    toast('Report sent to your admin.');
  } catch (e) {
    $('report-notice').textContent = e.message;
    $('report-notice').dataset.kind = 'bad';
  }
  $('report-send').disabled = false;
}

async function toggleBlock() {
  const p = snap.people.find((x) => x.address === current);
  closeMenu();
  if (!p) return;
  try {
    if (p.blocked) { await m.unblock(p.address); toast(p.name + ' is unblocked.'); }
    else { await m.block(p.address); toast(p.name + ' is blocked on this computer.'); }
  } catch (e) { toast(e.message, 'bad'); }
}

// ── The privacy page and terms of use, as shipped with the app ──

const policyTags = { h1: 'h1', h2: 'h2', h3: 'h3', p: 'p' };

function inlineNodes(parts) {
  return parts.map((p) => {
    if (p.t === 'b') return el('strong', {}, p.v);
    if (p.t === 'code') return el('code', {}, p.v);
    if (p.t === 'link') {
      const where = p.href.replace(/^https:\/\//, '').replace(/\/$/, '');
      return el('span', { title: p.href }, p.v, where === p.v ? null : el('span', { class: 'url' }, ` (${where})`));
    }
    return document.createTextNode(p.v);
  });
}

async function openPolicy(name) {
  try {
    const blocks = await m.policy(name);
    const nodes = blocks.map((b, i) => (b.t === 'ul'
      ? el('ul', {}, ...b.items.map((item) => el('li', {}, ...inlineNodes(item))))
      : policyTags[b.t] && el(policyTags[b.t], i === 0 ? { id: 'policy-title' } : {}, ...inlineNodes(b.inline))));
    $('policy-body').replaceChildren(...nodes.filter(Boolean));
    $('policy-dialog').showModal();
    $('policy-body').scrollTop = 0;
  } catch (e) {
    if (snap.joined) toast(e.message, 'bad');
    else { $('join-notice').textContent = e.message; $('join-notice').dataset.kind = 'bad'; }
  }
}

function wire() {
  document.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-policy]');
    if (b) openPolicy(b.dataset.policy);
  });
  $('policy-close').addEventListener('click', () => $('policy-dialog').close());
  $('join-invite').addEventListener('input', () => {
    checked = null;
    $('join-found').hidden = true;
    $('join-submit').textContent = 'Check invite';
    $('join-notice').textContent = '';
  });
  $('join-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const text = $('join-invite').value;
    const notice = $('join-notice');
    $('join-submit').disabled = true;
    try {
      if (!checked) {
        notice.textContent = 'Checking the organization…';
        delete notice.dataset.kind;
        checked = await m.previewInvite(text);
        $('join-org').textContent = checked.name;
        $('join-domain').textContent = checked.domain;
        $('join-found').hidden = false;
        $('join-submit').textContent = 'Join ' + checked.name;
        notice.textContent = '';
      } else {
        notice.textContent = 'Making your keys and joining…';
        await m.join(text);
        await refresh();
      }
    } catch (e) {
      notice.textContent = e.message;
      notice.dataset.kind = 'bad';
      checked = null;
      $('join-found').hidden = true;
      $('join-submit').textContent = 'Check invite';
    }
    $('join-submit').disabled = false;
  });

  // Refresh reads colleagues and partners' people again at once. The list
  // also updates by itself; this is for when someone wants to be sure.
  $('refresh').addEventListener('click', async () => {
    const b = $('refresh');
    if (b.hasAttribute('data-busy')) return;
    b.setAttribute('data-busy', '');
    b.disabled = true;
    const started = Date.now();
    let failed = false;
    try { await m.refresh(); } catch { failed = true; }
    // Keep the turn visible for a moment, so the click reads as done.
    await new Promise((r) => setTimeout(r, Math.max(0, 700 - (Date.now() - started))));
    b.removeAttribute('data-busy');
    b.disabled = false;
    if (failed) toast('Your server could not be reached. Try again in a moment.', 'bad');
    else toast('The list is up to date.');
  });

  $('search').addEventListener('input', drawPeople);
  const text = $('text');
  const grow = () => { text.style.height = 'auto'; text.style.height = Math.min(text.scrollHeight, 200) + 'px'; };
  const ready = () => { $('send').disabled = !text.value.trim(); };
  text.addEventListener('input', () => { grow(); ready(); });
  text.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); $('composer').requestSubmit(); }
  });
  $('composer').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const value = text.value;
    if (!value.trim() || !current) return;
    text.value = '';
    grow();
    ready();
    try { await m.send(current, value); } catch (e) { text.value = value; ready(); alertIn(e.message); }
  });
  $('attach').addEventListener('click', async () => {
    if (!current) return;
    try { await m.sendFile(current); } catch (e) { alertIn(e.message); }
  });
  $('conv-more').addEventListener('click', (ev) => {
    ev.stopPropagation();
    const open = $('conv-menu').hidden;
    $('conv-menu').hidden = !open;
    $('conv-more').setAttribute('aria-expanded', String(open));
    if (open) $('menu-report').focus();
  });
  document.addEventListener('click', (ev) => { if (!ev.target.closest('.more')) closeMenu(); });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && !$('conv-menu').hidden) { closeMenu(); $('conv-more').focus(); } });
  $('menu-report').addEventListener('click', openReport);
  $('menu-block').addEventListener('click', toggleBlock);
  $('unblock').addEventListener('click', toggleBlock);
  $('report-form').addEventListener('submit', sendReport);
  $('report-cancel').addEventListener('click', () => $('report-dialog').close());
  window.addEventListener('focus', markSeen);
  m.onUpdate(() => refresh().catch(() => {}));
}

wire();
refresh().catch((e) => { delete document.body.dataset.loading; document.body.textContent = e.message; });
