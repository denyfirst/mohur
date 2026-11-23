// The Mohur window. It draws what the engine reports and asks it to act; it
// has no keys and no network. Every text from elsewhere is set as text.
const m = window.mohur;
const $ = (id) => document.getElementById(id);
let snap = { joined: false };
let current = null;
let checked = null;

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

const initials = (name) => name.split(/\s+/).map((w) => w[0] || '').join('').slice(0, 2).toUpperCase();
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

async function refresh() {
  snap = await m.state();
  delete document.body.dataset.loading;
  $('join').hidden = snap.joined;
  $('app').hidden = !snap.joined;
  if (!snap.joined) {
    $('join-invite').focus();
    return;
  }
  $('me-name').textContent = snap.me.name;
  $('me-org').textContent = `${snap.me.org} · ${snap.me.address}`;
  $('status').toggleAttribute('data-online', snap.online);
  $('status-text').textContent = snap.online ? 'Connected' : 'Connecting…';
  drawPeople();
  drawConversation();
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
    list.append(el('p', { class: 'group' }, g));
    for (const p of groups.get(g)) {
      const b = el('button', { type: 'button', class: 'person', 'aria-current': String(p.address === current) },
        el('span', { class: 'avatar', 'aria-hidden': 'true' }, initials(p.name)),
        el('span', {}, el('strong', {}, p.name), el('span', { class: 'sub' }, p.last || p.address)),
        el('time', {}, short(p.lastAt)));
      b.addEventListener('click', () => { current = p.address; drawPeople(); drawConversation(true); $('text').focus(); });
      list.append(b);
    }
  }
  if (!people.length) {
    list.append(el('p', { class: 'empty-list' }, q ? 'No one matches.' : 'No one to write to yet. Colleagues appear here when they join, and a partner's people once your admin lets you write to them.'));
  }
}

function drawConversation(scroll) {
  const p = snap.people.find((x) => x.address === current);
  $('conv-empty').hidden = Boolean(p);
  $('conv-head').hidden = !p;
  $('messages').hidden = !p;
  $('composer').hidden = !p;
  if (!p) return;
  $('conv-avatar').textContent = initials(p.name);
  $('conv-name').textContent = p.name;
  $('conv-addr').textContent = `${p.address} · ${p.org}`;
  $('conv-chip-text').textContent = 'Verified by ' + p.domain;
  const box = $('messages');
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  box.replaceChildren();
  let lastDay = '';
  for (const msg of snap.convs[p.address] || []) {
    const d = day(msg.at);
    if (d !== lastDay) { box.append(el('li', { class: 'day' }, d)); lastDay = d; }
    if (msg.dir === 'system') { box.append(el('li', { class: 'msg system' }, msg.text)); continue; }
    const meta = el('span', { class: 'meta' }, time(msg.at) + (msg.dir === 'out' ? ' · ' + (statusWords[msg.status] || '') : ''));
    let body;
    if (msg.kind === 'file') {
      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      icon.setAttribute('viewBox', '0 0 24 24');
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5');
      icon.append(path);
      body = el('div', { class: 'file' }, icon, el('div', {}, el('strong', {}, msg.file.name), el('span', { class: 'size' }, size(msg.file.size))));
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
      body = document.createTextNode(msg.text);
    }
    box.append(el('li', { class: 'msg ' + msg.dir, 'data-status': msg.status || '' }, body, meta));
  }
  if (scroll || atBottom) box.scrollTop = box.scrollHeight;
}

function alertIn(text) {
  $('messages').append(el('li', { class: 'msg system' }, text));
  $('messages').scrollTop = $('messages').scrollHeight;
}

function wire() {
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

  $('search').addEventListener('input', drawPeople);
  const text = $('text');
  const grow = () => { text.style.height = 'auto'; text.style.height = Math.min(text.scrollHeight, 200) + 'px'; };
  text.addEventListener('input', grow);
  text.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); $('composer').requestSubmit(); }
  });
  $('composer').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const value = text.value;
    if (!value.trim() || !current) return;
    text.value = '';
    grow();
    try { await m.send(current, value); } catch (e) { text.value = value; alertIn(e.message); }
  });
  $('attach').addEventListener('click', async () => {
    if (!current) return;
    try { await m.sendFile(current); } catch (e) { alertIn(e.message); }
  });
  m.onUpdate(() => refresh().catch(() => {}));
}

wire();
refresh().catch((e) => { delete document.body.dataset.loading; document.body.textContent = e.message; });
