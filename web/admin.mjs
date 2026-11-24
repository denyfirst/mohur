// Mohur admin pages. One document; this script shows the view for the path
// and talks to /admin/api. Text from the server is always set as text.

const $ = (id) => document.getElementById(id);
let state = {};
let setupCode = '';
let resetCode = '';

async function api(path, body) {
  const init = { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Mohur': '1' }, credentials: 'same-origin' };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  document.body.dataset.busy = '';
  try {
    const res = await fetch('/admin/api/' + path, init);
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && path !== 'signin') {
      await load();
      throw new Error(data.error || 'Sign in again.');
    }
    if (!res.ok) throw new Error(data.error || 'Something went wrong. Try again.');
    return data;
  } finally {
    delete document.body.dataset.busy;
  }
}

function notice(scope, text, kind) {
  const el = scope.querySelector('[data-notice], [data-dialog-notice]');
  if (!el) return;
  el.textContent = text || '';
  if (kind) el.dataset.kind = kind; else delete el.dataset.kind;
}

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('data-') || k.startsWith('aria-') || k === 'type' || k === 'href') n.setAttribute(k, v);
    else n[k] = v;
  }
  for (const c of children) if (c !== null && c !== undefined) n.append(c);
  return n;
}

function pill(text, kind) { return el('span', { class: 'pill', 'data-kind': kind }, text); }

function when(unix) {
  return new Date(unix * 1000).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

function drawQR(svg, rows) {
  svg.replaceChildren();
  const n = rows.length;
  svg.setAttribute('viewBox', `-2 -2 ${n + 4} ${n + 4}`);
  const ns = 'http://www.w3.org/2000/svg';
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      if (row[x] !== '1') continue;
      const r = document.createElementNS(ns, 'rect');
      r.setAttribute('x', x); r.setAttribute('y', y); r.setAttribute('width', 1.02); r.setAttribute('height', 1.02);
      svg.append(r);
    }
  });
}

// ── Views ────────────────────────────────────────────────────────────────

const pages = { '/': 'overview', '/people': 'people', '/partners': 'partners', '/reports': 'reports', '/domain': 'domain' };

function showOnly(id) {
  for (const v of ['setup', 'signin', 'reset', 'workspace']) $(v).hidden = v !== id;
  delete document.body.dataset.loading;
}

async function load() {
  state = await api('state');
  if (state.setup) {
    showOnly('setup');
    if (location.pathname !== '/setup') history.replaceState(null, '', '/setup');
    return;
  }
  if (!state.admin) {
    if (location.pathname === '/reset') {
      showOnly('reset');
      if (!$('reset-code').hidden) $('reset-code-input').focus();
      return;
    }
    showOnly('signin');
    if (location.pathname !== '/signin') history.replaceState(null, '', '/signin');
    $('signin-user').focus();
    return;
  }
  showOnly('workspace');
  if (!pages[location.pathname]) history.replaceState(null, '', state.org && !state.org.dnsChecked ? '/domain' : '/');
  $('rail-org').textContent = state.org ? `${state.org.name} · ${state.org.domain}` : '';
  $('rail-admin').textContent = state.admin;
  $('rail-domain-warn').hidden = Boolean(state.org && state.org.dnsChecked);
  openReports(state.openReports || 0);
  await route();
}

async function route() {
  const page = pages[location.pathname] || 'overview';
  for (const p of Object.values(pages)) $('page-' + p).hidden = p !== page;
  for (const a of document.querySelectorAll('.rail-item')) {
    if (a.dataset.page === page) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  }
  document.querySelector('.rail').removeAttribute('data-open');
  document.title = (page === 'overview' ? 'Overview' : page[0].toUpperCase() + page.slice(1)) + ' · Mohur';
  try {
    if (page === 'overview') await overview();
    if (page === 'people') await people();
    if (page === 'partners') await partners();
    if (page === 'reports') await reports();
    if (page === 'domain') domain();
  } catch (e) {
    notice($('page-' + page), e.message, 'bad');
  }
}

async function overview() {
  const o = state.org;
  $('ov-name').textContent = o.name;
  $('ov-domain').textContent = o.domain;
  $('ov-server').textContent = 'https://' + o.server;
  const [ppl, prt] = await Promise.all([api('people'), api('partners')]);
  const active = ppl.filter((p) => p.state === 'active').length;
  const invited = ppl.length - active;
  const connected = prt.filter((p) => p.state === 'connected').length;
  const waiting = prt.filter((p) => p.state === 'incoming').length;
  $('ov-people').textContent = active;
  $('ov-people-sub').textContent = invited ? `${invited} invited, not joined yet` : 'using Mohur';
  $('ov-partners').textContent = connected;
  $('ov-partners-sub').textContent = waiting ? `${waiting} waiting for your answer` : 'connected';
  step('ov-step-domain', Boolean(o.dnsChecked), o.dnsChecked ? 'Verified' : 'Not yet');
  step('ov-step-people', active > 0, active ? `${active} joined` : invited ? 'Invited' : 'Not yet');
  step('ov-step-partners', connected > 0, connected ? `${connected} connected` : waiting ? `${waiting} waiting` : 'Not yet');
  requests(prt);
}

function step(id, done, text) {
  const card = $(id);
  if (done) card.dataset.done = ''; else delete card.dataset.done;
  const p = card.querySelector('[data-pill]');
  p.textContent = text;
  p.dataset.kind = done ? 'good' : 'none';
}

function requests(prt) {
  const n = prt.filter((p) => p.state === 'incoming' || p.state === 'key-changed').length;
  $('rail-requests').hidden = n === 0;
  $('rail-requests').textContent = n;
}

// writesWith says, for one person, whom they can write to, and with which
// chosen partners once the connection is made.
function writesWith(p) {
  const now = p.partners || [];
  const later = (p.partnerDomains || []).map((d) => partnerChoices.find((c) => c.domain === d))
    .filter((c) => c && c.state !== 'connected').map((c) => c.name);
  const words = now.length ? 'Writes with ' + listWords(['colleagues', ...now]) : later.length ? 'Writes with colleagues' : 'Writes with colleagues only';
  return later.length ? `${words} · ${listWords(later)} once connected` : words;
}

function listWords(items) {
  if (items.length <= 1) return items.join('');
  if (items.length > 4) return items.slice(0, 3).join(', ') + ' and ' + (items.length - 3) + ' more';
  return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
}

// choiceWord says where a partner stands, next to its name in a picker.
const choiceWords = { outgoing: 'waiting for them', incoming: 'wants to connect', 'key-changed': 'key changed' };

// pickList fills a list of checkboxes: items are [value, label, note].
function pickList(ul, name, items, checked, empty) {
  ul.replaceChildren();
  for (const [value, label, note] of items) {
    const box = el('input', { type: 'checkbox', name, value });
    box.checked = checked.includes(value);
    ul.append(el('li', {}, el('label', {}, box, el('span', {}, label), el('span', { class: 'sub' }, note || ''))));
  }
  if (!items.length) ul.append(el('li', { class: 'none' }, empty));
}

const picked = (ul) => [...ul.querySelectorAll('input:checked')].map((b) => b.value);
const partnerItems = (choices) => choices.map((c) => [c.domain, c.name, choiceWords[c.state] || c.domain]);

let partnerChoices = [];

async function people() {
  $('people-title').textContent = 'People in ' + state.org.name;
  const [list, choices] = await Promise.all([api('people'), api('partners/choices')]);
  partnerChoices = choices;
  const ul = $('people-list');
  ul.replaceChildren();
  $('people-empty').hidden = list.length > 0;
  for (const p of list) {
    const initials = p.name.split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase();
    const side = el('div', { class: 'row-side' });
    if (p.state === 'active') {
      side.append(pill('Joined', 'good'));
      side.append(el('button', { type: 'button', class: 'secondary small', onclick: () => resetDevice(p) }, 'New device'));
    } else {
      const expired = p.inviteExpires && p.inviteExpires * 1000 < Date.now();
      side.append(pill(expired ? 'Invite expired' : 'Invited', expired ? 'warn' : 'none'));
      side.append(el('button', { type: 'button', class: 'secondary small', onclick: () => openInvite(p) }, 'New invite'));
    }
    side.append(el('button', { type: 'button', class: 'secondary small', onclick: () => removePerson(p) }, 'Remove'));
    const sub = p.state === 'active' ? `${p.address} · ${p.device} · joined ${when(p.joined)}` : `${p.address} · invite works until ${when(p.inviteExpires)}`;
    const writes = el('span', { class: 'access-line' }, writesWith(p));
    if (choices.length) writes.append(el('button', { type: 'button', class: 'link-button', onclick: () => openPerson(p) }, 'Change partners'));
    ul.append(el('li', { class: 'row' }, el('span', { class: 'avatar', 'aria-hidden': 'true' }, initials),
      el('div', { class: 'row-main' }, el('strong', {}, p.name), el('span', { class: 'sub' }, sub), writes), side));
  }
}

let personFor = null;
function openPerson(p) {
  personFor = p;
  const d = $('person-dialog');
  $('person-title').textContent = `Partners ${p.name} can write with`;
  pickList($('person-partners'), 'partners', partnerItems(partnerChoices), p.partnerDomains || [], 'No partners yet.');
  notice(d, '');
  d.showModal();
}

function openInvite(person) {
  const d = $('invite-dialog');
  $('invite-form').hidden = false;
  $('invite-made').hidden = true;
  $('invite-form').reset();
  notice(d, '');
  $('invite-domain').textContent = '@' + state.org.domain;
  $('invite-title').textContent = 'Invite someone to ' + state.org.name;
  if (person) {
    $('invite-name').value = person.name;
    $('invite-user').value = person.username;
  }
  pickList($('invite-partners'), 'partners', partnerItems(partnerChoices), person ? person.partnerDomains || [] : [], '');
  $('invite-partners-box').hidden = partnerChoices.length === 0;
  d.showModal();
  (person ? $('invite-form').querySelector('[type=submit]') : $('invite-name')).focus();
}

function showInvite(name, res) {
  $('invite-form').hidden = true;
  $('invite-made').hidden = false;
  $('invite-made-hint').textContent = `Send this to ${name} in any way you like. ${name.split(/\s+/)[0]} opens Mohur on their own computer and pastes it there. You do not need to approve anything. It works once, until ${when(res.expires)}.`;
  $('invite-code').textContent = res.invite;
}

async function resetDevice(p) {
  if (!await confirmAction(`New device for ${p.name}?`, `Their current device stops working at once. Use this when ${p.name} has a new or lost computer. Their partners will see that the device changed.`, 'Reset device')) return;
  try {
    const res = await api('people/reset', { username: p.username });
    await people();
    openInvite();
    showInvite(p.name, res);
  } catch (e) { notice($('page-people'), e.message, 'bad'); }
}

async function removePerson(p) {
  if (!await confirmAction(`Remove ${p.name}?`, 'They can no longer send or receive messages. Messages already on their computer stay there.', 'Remove')) return;
  try {
    await api('people/remove', { username: p.username });
    await people();
    notice($('page-people'), `${p.name} was removed.`);
  } catch (e) { notice($('page-people'), e.message, 'bad'); }
}

// ── Reports ──────────────────────────────────────────────────────────────

function openReports(n) {
  $('rail-reports').hidden = n === 0;
  $('rail-reports').textContent = n;
}

async function reports() {
  const list = await api('reports');
  openReports(list.filter((r) => !r.closed).length);
  const ul = $('report-list');
  ul.replaceChildren();
  $('report-empty').hidden = list.length > 0;
  for (const r of list) {
    const about = r.aboutName ? `${r.aboutName} (${r.about})` : r.about;
    const where = r.aboutHere ? 'one of your people' : r.aboutOrg ? 'at ' + r.aboutOrg : 'at ' + r.about.split('@')[1];
    const main = el('div', { class: 'row-main' },
      el('strong', {}, `${r.fromName} reported ${about}`),
      el('span', { class: 'sub' }, `${r.reasonText} · ${where} · ${when(r.at)}`));
    if (r.note) main.append(el('blockquote', { class: 'report-note' }, r.note));
    main.append(el('span', { class: 'access-line' }, r.aboutHere
      ? 'You can remove this person on the People page.'
      : `You can stop your people writing with ${r.aboutOrg || 'this partner'}, or disconnect it, on the Partners page.`));
    const side = el('div', { class: 'row-side' });
    if (r.closed) {
      side.append(pill('Handled', 'good'));
      main.append(el('span', { class: 'sub' }, `Handled by ${r.closedBy} on ${when(r.closed)}`));
    } else {
      side.append(pill('Open', 'warn'));
      side.append(el('a', { class: 'button secondary small', href: r.aboutHere ? '/people' : '/partners', 'data-link': '' }, r.aboutHere ? 'People' : 'Partners'));
      side.append(el('button', { type: 'button', class: 'small', onclick: () => closeReport(r) }, 'Mark handled'));
    }
    const li = el('li', { class: 'row' }, el('span', { class: 'avatar', 'aria-hidden': 'true' }, '!'), main, side);
    if (!r.closed) li.dataset.attention = '';
    ul.append(li);
  }
}

async function closeReport(r) {
  try {
    await api('reports/close', { id: r.id });
    await reports();
    notice($('page-reports'), 'Marked handled.');
  } catch (e) { notice($('page-reports'), e.message, 'bad'); }
}

const stateWords = {
  connected: ['Connected', 'good'],
  outgoing: ['Waiting for them', 'none'],
  incoming: ['Wants to connect', 'warn'],
  'key-changed': ['Key changed', 'bad'],
};

function theirsWords(p) {
  if (p.state !== 'connected' || p.theirs === undefined) return '';
  if (p.theirs === 0) return ' · you see none of their people yet';
  return ` · you see ${p.theirs} of their people`;
}

function accessWords(p, names) {
  if (!p.people.length) return 'No one yet';
  return listWords(p.people.map((u) => names[u] || u));
}

async function partners() {
  const [list, ppl] = await Promise.all([api('partners'), api('people')]);
  const names = Object.fromEntries(ppl.map((x) => [x.username, x.name]));
  requests(list);
  const ul = $('partner-list');
  ul.replaceChildren();
  $('partner-empty').hidden = list.length > 0;
  const order = { incoming: 0, 'key-changed': 1, connected: 2, outgoing: 3 };
  list.sort((a, b) => order[a.state] - order[b.state] || a.domain.localeCompare(b.domain));
  for (const p of list) {
    const [word, kind] = stateWords[p.state] || [p.state, 'none'];
    const side = el('div', { class: 'row-side' }, pill(word, kind));
    const li = el('li', { class: 'row' });
    if (p.state === 'incoming') {
      li.dataset.attention = '';
      side.append(el('button', { type: 'button', class: 'small', onclick: () => accept(p) }, 'Accept'));
      side.append(el('button', { type: 'button', class: 'secondary small', onclick: () => removePartner(p, 'Decline') }, 'Decline'));
    } else if (p.state === 'key-changed') {
      li.dataset.attention = '';
      side.append(el('button', { type: 'button', class: 'small', onclick: () => trust(p) }, 'Review'));
      side.append(el('button', { type: 'button', class: 'secondary small', onclick: () => removePartner(p, 'Remove') }, 'Remove'));
    } else {
      side.append(el('button', { type: 'button', class: 'secondary small', onclick: () => removePartner(p, p.state === 'outgoing' ? 'Cancel request' : 'Disconnect') }, p.state === 'outgoing' ? 'Cancel' : 'Disconnect'));
    }
    const sub = p.state === 'incoming' ? `${p.domain} · verified by its domain · asked ${when(p.updated)}` : `${p.domain}${theirsWords(p)} · since ${when(p.created)}`;
    const access = p.state === 'incoming' ? null : el('span', { class: 'access-line', 'data-kind': p.people.length ? 'some' : 'none' }, 'Who can write:', el('strong', {}, accessWords(p, names)),
      el('button', { type: 'button', class: 'link-button', onclick: () => openAccess(p, ppl) }, p.people.length ? 'Change' : 'Choose people'));
    const details = p.securityCode ? el('details', {}, el('summary', {}, 'Security code'),
      el('p', { class: 'help' }, 'Both admins see the same code. You do not need to compare it, but you can, on a call, for extra certainty.'),
      el('p', { class: 'code-groups' }, p.securityCode)) : null;
    li.append(el('span', { class: 'avatar', 'aria-hidden': 'true' }, p.name.slice(0, 1).toUpperCase()),
      el('div', { class: 'row-main' }, el('strong', {}, p.name), el('span', { class: 'sub' }, sub), access), side);
    if (details) li.append(details);
    ul.append(li);
  }
}

async function accept(p) {
  try {
    await api('partners/accept', { domain: p.domain });
    notice($('page-partners'), `Connected with ${p.name}.`);
    await partners();
    openAccess({ ...p, state: 'connected', people: [] }, await api('people'), true);
  } catch (e) { notice($('page-partners'), e.message, 'bad'); }
}

async function trust(p) {
  const ok = await confirmAction(`Accept the new key of ${p.newName || p.name}?`,
    `${p.domain} now shows a different organization key. Its domain record and certificate both confirm the new one. Accept it only if ${p.name} told you they moved or rebuilt their Mohur server. New security code: ${p.newCode}`, 'Accept new key');
  if (!ok) return;
  try {
    await api('partners/trust', { domain: p.domain, key: p.newKey });
    await partners();
  } catch (e) { notice($('page-partners'), e.message, 'bad'); }
}

async function removePartner(p, verb) {
  if (!await confirmAction(`${verb}: ${p.name}?`, 'People in the two organizations can no longer write to each other. You can connect again later.', verb)) return;
  try {
    await api('partners/remove', { domain: p.domain });
    await partners();
  } catch (e) { notice($('page-partners'), e.message, 'bad'); }
}

let accessFor = null;
// openAccess asks who here can write with a partner. Right after a connection
// is made, it says that no one can yet, and Later leaves it so.
function openAccess(p, ppl, fresh) {
  accessFor = p;
  const d = $('access-dialog');
  $('access-title').textContent = `Who at ${state.org.name} can write with ${p.name}?`;
  $('access-hint').textContent = (fresh ? `No one can yet. ` : '') +
    `Only the people you tick see ${p.name}'s people and can write to them; ${p.name} sees only them. People you invite later are added only when you tick them.`;
  pickList($('access-people'), 'people', ppl.map((x) => [x.username, x.name, x.address]), p.people || [], 'No one here yet. Invite people on the People page.');
  $('access-all').hidden = ppl.length < 2;
  $('access-cancel').textContent = fresh ? 'Later' : 'Cancel';
  notice(d, '');
  d.showModal();
}

let found = null;
function openConnect() {
  found = null;
  $('connect-form').reset();
  $('connect-found').hidden = true;
  $('connect-submit').textContent = 'Check';
  notice($('connect-dialog'), '');
  $('connect-dialog').showModal();
  $('connect-domain').focus();
}

function domain() {
  const o = state.org;
  $('dom-title').textContent = o.domain;
  $('dom-name').textContent = o.recordName;
  $('dom-value').textContent = o.record;
  const ok = Boolean(o.dnsChecked);
  $('dom-pill').textContent = ok ? 'Verified' : 'Not verified';
  $('dom-pill').dataset.kind = ok ? 'good' : 'warn';
  $('dom-status').textContent = ok ? `Last checked ${when(o.dnsChecked)}.` : 'Add the record, then press Check.';
}

function confirmAction(title, text, yes) {
  const d = $('confirm-dialog');
  $('confirm-title').textContent = title;
  $('confirm-text').textContent = text;
  $('confirm-yes').textContent = yes;
  return new Promise((resolve) => {
    d.onclose = () => resolve(d.returnValue === 'yes');
    d.returnValue = '';
    $('confirm-yes').value = 'yes';
    d.showModal();
  });
}

// ── Wiring ───────────────────────────────────────────────────────────────

function wire() {
  document.addEventListener('click', (ev) => {
    const a = ev.target.closest('a[data-link]');
    if (a && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey) {
      ev.preventDefault();
      if (location.pathname !== a.getAttribute('href')) history.pushState(null, '', a.getAttribute('href'));
      route();
      return;
    }
    const copy = ev.target.closest('[data-copy]');
    if (copy) {
      navigator.clipboard.writeText($(copy.dataset.copy).textContent).then(() => {
        const was = copy.textContent;
        copy.textContent = 'Copied';
        setTimeout(() => { copy.textContent = was; }, 1500);
      });
      return;
    }
    if (ev.target.closest('[data-close]')) ev.target.closest('dialog').close();
  });
  window.addEventListener('popstate', () => (state.admin ? route() : load()));

  document.querySelector('.menu-toggle').addEventListener('click', (ev) => {
    const rail = document.querySelector('.rail');
    const open = !rail.hasAttribute('data-open');
    if (open) rail.setAttribute('data-open', ''); else rail.removeAttribute('data-open');
    ev.currentTarget.setAttribute('aria-expanded', String(open));
  });

  $('setup-code-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      setupCode = $('setup-code-input').value.trim();
      const res = await api('setup/start', { code: setupCode });
      drawQR($('setup-qr'), res.qr);
      $('setup-seed').textContent = res.seed.match(/.{1,4}/g).join(' ');
      $('setup-code').hidden = true;
      $('setup-details').hidden = false;
      notice($('setup'), '');
      $('setup-org').focus();
    } catch (e) { notice($('setup'), e.message, 'bad'); }
  });
  $('setup-domain').addEventListener('input', () => {
    const d = $('setup-domain').value.trim().toLowerCase();
    if (!$('setup-server').dataset.touched) $('setup-server').value = d ? 'mohur.' + d : '';
  });
  $('setup-server').addEventListener('input', () => { $('setup-server').dataset.touched = '1'; });
  $('setup-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = Object.fromEntries(new FormData(ev.target));
    try {
      const res = await api('setup/finish', { ...f, code: setupCode });
      $('setup-details').hidden = true;
      $('setup-recovery').hidden = false;
      $('recovery-list').textContent = res.recovery.map((c) => c.match(/.{1,4}/g).join('-')).join('\n');
      notice($('setup'), '');
    } catch (e) { notice($('setup'), e.message, 'bad'); }
  });
  $('recovery-done').addEventListener('click', () => { history.replaceState(null, '', '/domain'); load(); });

  $('signin-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('signin', Object.fromEntries(new FormData(ev.target)));
      ev.target.reset();
      notice($('signin'), '');
      history.replaceState(null, '', '/');
      await load();
    } catch (e) {
      notice($('signin'), e.message, 'bad');
      $('signin-code').value = '';
    }
  });
  for (const [id, path] of [['reset-open', '/reset'], ['reset-back', '/signin']]) {
    $(id).addEventListener('click', (ev) => {
      ev.preventDefault();
      notice($('signin'), '');
      notice($('reset'), '');
      history.pushState(null, '', path);
      load();
    });
  }
  $('reset-code-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      resetCode = $('reset-code-input').value.trim();
      const res = await api('reset/start', { code: resetCode });
      $('reset-user').value = res.admin;
      drawQR($('reset-qr'), res.qr);
      $('reset-seed').textContent = res.seed.match(/.{1,4}/g).join(' ');
      $('reset-code').hidden = true;
      $('reset-details').hidden = false;
      notice($('reset'), '');
      $('reset-password').focus();
    } catch (e) { notice($('reset'), e.message, 'bad'); }
  });
  $('reset-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = Object.fromEntries(new FormData(ev.target));
    try {
      const res = await api('reset/finish', { ...f, code: resetCode });
      $('reset-details').hidden = true;
      $('reset-recovery').hidden = false;
      $('reset-recovery-list').textContent = res.recovery.map((c) => c.match(/.{1,4}/g).join('-')).join('\n');
      notice($('reset'), '');
    } catch (e) {
      notice($('reset'), e.message, 'bad');
      $('reset-totp').value = '';
    }
  });
  $('reset-done').addEventListener('click', () => {
    resetCode = '';
    for (const f of ['reset-code-form', 'reset-form']) $(f).reset();
    $('reset-recovery-list').textContent = '';
    $('reset-recovery').hidden = true;
    $('reset-code').hidden = false;
    history.replaceState(null, '', '/');
    load();
  });
  $('signout').addEventListener('click', async () => {
    await api('signout', {}).catch(() => {});
    await load();
  });

  $('invite-open').addEventListener('click', () => openInvite());
  $('invite-name').addEventListener('input', () => {
    const u = $('invite-user');
    if (u.dataset.touched) return;
    const first = $('invite-name').value.trim().split(/\s+/)[0] || '';
    u.value = first.normalize('NFKD').toLowerCase().replace(/ə/g, 'e').replace(/ı/g, 'i').replace(/[^a-z0-9]/g, '');
  });
  $('invite-user').addEventListener('input', () => { $('invite-user').dataset.touched = '1'; });
  $('invite-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = { name: $('invite-name').value, username: $('invite-user').value, partners: picked($('invite-partners')) };
    try {
      const res = await api('people/invite', f);
      showInvite(f.name, res);
      delete $('invite-user').dataset.touched;
      await people();
    } catch (e) { notice($('invite-dialog'), e.message, 'bad'); }
  });

  $('access-all').addEventListener('click', () => {
    for (const b of $('access-people').querySelectorAll('input')) b.checked = true;
  });
  $('access-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const people = picked($('access-people'));
    try {
      await api('partners/access', { domain: accessFor.domain, people });
      $('access-dialog').close();
      notice($('page-partners'), people.length ? `Saved. ${people.length === 1 ? 'One person' : people.length + ' people'} here can write with ${accessFor.name}.`
        : `Saved. No one at ${state.org.name} can write with ${accessFor.name}.`);
      await partners();
    } catch (e) { notice($('access-dialog'), e.message, 'bad'); }
  });
  $('person-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('people/partners', { username: personFor.username, partners: picked($('person-partners')) });
      $('person-dialog').close();
      notice($('page-people'), `Saved ${personFor.name}'s partners.`);
      await people();
    } catch (e) { notice($('person-dialog'), e.message, 'bad'); }
  });

  $('connect-open').addEventListener('click', openConnect);
  $('connect-domain').addEventListener('input', () => {
    found = null;
    $('connect-found').hidden = true;
    $('connect-submit').textContent = 'Check';
  });
  $('connect-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const d = $('connect-domain').value;
    try {
      if (!found) {
        notice($('connect-dialog'), 'Checking the domain record and certificate…');
        found = await api('partners/preview', { domain: d });
        $('connect-name').textContent = found.name;
        $('connect-where').textContent = `${found.domain} · ${found.server}`;
        $('connect-found').hidden = false;
        $('connect-submit').textContent = 'Connect';
        notice($('connect-dialog'), '');
        return;
      }
      const res = await api('partners/connect', { domain: found.domain });
      $('connect-dialog').close();
      notice($('page-partners'), res.state === 'connected' ? `Connected with ${found.name}.` : `Request sent. ${found.name}'s admin will see it on their Partners page.`);
      await partners();
      openAccess({ domain: found.domain, name: found.name, people: [] }, await api('people'), true);
    } catch (e) { notice($('connect-dialog'), e.message, 'bad'); }
  });

  $('dom-check').addEventListener('click', async () => {
    notice($('page-domain'), 'Checking, as a partner would…');
    try {
      const res = await api('domain/check', {});
      state = await api('state');
      domain();
      $('rail-domain-warn').hidden = res.ok;
      notice($('page-domain'), res.ok ? 'Verified. Partners can find you now.' : res.problem, res.ok ? '' : 'bad');
    } catch (e) { notice($('page-domain'), e.message, 'bad'); }
  });
}

wire();
load().catch((e) => {
  delete document.body.dataset.loading;
  document.body.textContent = e.message;
});
