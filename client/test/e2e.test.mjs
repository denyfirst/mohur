// End to end, with nothing simulated but the internet: two real Mohur servers
// (mohur-lab), real DNS answers and TLS, and two engines using libsignal.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Engine } from '../src/core/engine.mjs';
import { Net } from '../src/core/net.mjs';
import { Vault } from '../src/core/vault.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mohur-e2e-'));
let lab;
let labProc;
let labLog = '';

before(async () => {
  const exe = path.join(tmp, process.platform === 'win32' ? 'mohur-lab.exe' : 'mohur-lab');
  execFileSync('go', ['build', '-o', exe, './cmd/mohur-lab'], { cwd: root, stdio: 'inherit', env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'go1.27.4' } });
  labProc = spawn(exe, ['-dir', path.join(tmp, 'lab'), '-log-all', '-orgs', 'alpha.e2e.test,beta.e2e.test', '-invite', 'alpha.e2e.test:aylin:Aylin Məmmədova', '-invite', 'beta.e2e.test:kamran:Kamran Əliyev',
    '-invite', 'beta.e2e.test:leyla:Leyla Həsənova'], { stdio: ['pipe', 'pipe', 'pipe'] });
  // The servers log every event, as mohurd does. The log is kept to check it
  // later; warnings are still shown.
  labProc.stderr.on('data', (c) => {
    labLog += c;
    for (const line of String(c).split('\n')) if (line && !line.includes('level=INFO')) process.stderr.write(line + '\n');
  });
  await new Promise((resolve, reject) => {
    let out = '';
    labProc.stdout.on('data', (c) => { out += c; if (out.includes('READY')) resolve(); });
    labProc.on('exit', (code) => reject(new Error('lab exited ' + code)));
  });
  lab = JSON.parse(fs.readFileSync(path.join(tmp, 'lab', 'lab.json'), 'utf8'));
});

after(() => {
  if (labProc) labProc.stdin.end();
});

const keys = {};
async function engine(name) {
  keys[name] ||= crypto.randomBytes(32);
  const vault = await Vault.open(path.join(tmp, name, 'vault.bin'), async () => keys[name]);
  const net = new Net({ resolver: lab.resolver, extraCA: fs.readFileSync(lab.ca, 'utf8') });
  return new Engine(vault, net, { label: name + "'s laptop" });
}

let aylin, kamran, fileData;

test('an invite shows the verified organization, then joins once', async () => {
  aylin = await engine('aylin');
  kamran = await engine('kamran');
  const preview = await aylin.previewInvite(lab.invites['aylin@alpha.e2e.test']);
  assert.equal(preview.name, 'Alpha LLC');
  assert.equal(preview.domain, 'alpha.e2e.test');
  const me = await aylin.join(lab.invites['aylin@alpha.e2e.test']);
  assert.equal(me.address, 'aylin@alpha.e2e.test');
  assert.equal(me.name, 'Aylin Məmmədova');
  await kamran.join(lab.invites['kamran@beta.e2e.test']);
  const again = await engine('someone-else');
  await assert.rejects(again.join(lab.invites['aylin@alpha.e2e.test']), /expired or was already used/);
});

test('partners appear as contacts with certified devices', async () => {
  await aylin.syncContacts();
  await kamran.syncContacts();
  const snap = aylin.snapshot();
  const k = snap.people.find((p) => p.address === 'kamran@beta.e2e.test');
  assert.ok(k, 'Kamran is in Aylin\'s contacts');
  assert.equal(k.org, 'Beta LLC');
  assert.equal(snap.partners[0].blocked, false);
});

test('a message, its delivery receipt and a reply', async () => {
  await aylin.sendText('kamran@beta.e2e.test', 'Salam, Kamran! Müqaviləni göndərirəm.');
  assert.equal(await kamran.pollOnce(), 1);
  const conv = kamran.snapshot().convs['aylin@alpha.e2e.test'];
  assert.equal(conv.length, 1);
  assert.equal(conv[0].text, 'Salam, Kamran! Müqaviləni göndərirəm.');
  assert.equal(conv[0].dir, 'in');
  assert.equal(await aylin.pollOnce(), 1);
  assert.equal(aylin.snapshot().convs['kamran@beta.e2e.test'][0].status, 'delivered');
  await kamran.sendText('aylin@alpha.e2e.test', 'Aldım, təşəkkürlər.');
  await aylin.pollOnce();
  const back = aylin.snapshot().convs['kamran@beta.e2e.test'];
  assert.equal(back.at(-1).text, 'Aldım, təşəkkürlər.');
});

test('a file arrives whole and is checked before it opens', async () => {
  const data = fileData = crypto.randomBytes(3 * 1024 * 1024 + 17);
  await aylin.sendFile('kamran@beta.e2e.test', { name: 'contract.pdf', type: 'application/pdf', data });
  await kamran.pollOnce();
  const msg = kamran.snapshot().convs['aylin@alpha.e2e.test'].at(-1);
  assert.equal(msg.kind, 'file');
  assert.equal(msg.file.name, 'contract.pdf');
  const opened = await kamran.openFile('aylin@alpha.e2e.test', msg.id);
  assert.ok(opened.data.equals(data));
});

test('many messages both ways, and sessions survive a restart', async () => {
  for (let i = 0; i < 10; i++) {
    await aylin.sendText('kamran@beta.e2e.test', 'a' + i);
    await kamran.sendText('aylin@alpha.e2e.test', 'k' + i);
  }
  // Kamran's app restarts: a new engine over the same encrypted vault file.
  kamran = await engine('kamran');
  assert.equal(kamran.joined, true);
  while (await kamran.pollOnce() > 0) { /* drain */ }
  while (await aylin.pollOnce() > 0) { /* drain */ }
  const k = kamran.snapshot().convs['aylin@alpha.e2e.test'].filter((m) => m.dir === 'in').map((m) => m.text);
  const a = aylin.snapshot().convs['kamran@beta.e2e.test'].filter((m) => m.dir === 'in').map((m) => m.text);
  for (let i = 0; i < 10; i++) {
    assert.ok(k.includes('a' + i), 'kamran got a' + i);
    assert.ok(a.includes('k' + i), 'aylin got k' + i);
  }
});

test('unread messages are counted until read, and the mark survives a restart', async () => {
  const unread = () => kamran.snapshot().people.find((p) => p.address === 'aylin@alpha.e2e.test').unread;
  assert.ok(unread() > 0, 'a new app counts what arrived since it joined');
  // A vault from before unread counts takes everything it holds as read.
  delete kamran.vault.data.read;
  delete kamran.vault.data.readFrom;
  await kamran.vault.save();
  kamran = await engine('kamran');
  assert.equal(unread(), 0);

  await aylin.sendText('kamran@beta.e2e.test', 'one');
  await aylin.sendText('kamran@beta.e2e.test', 'two');
  while (await kamran.pollOnce() > 0) { /* drain */ }
  assert.equal(unread(), 2);
  // Writing back is not reading: the count stays until the conversation is read.
  await kamran.sendText('aylin@alpha.e2e.test', 'reply');
  assert.equal(unread(), 2);
  assert.equal(await kamran.markRead('aylin@alpha.e2e.test'), true);
  assert.equal(unread(), 0);
  assert.equal(await kamran.markRead('aylin@alpha.e2e.test'), false, 'nothing new to mark');
  kamran = await engine('kamran');
  assert.equal(unread(), 0, 'the mark survives a restart');
  // Unknown and odd addresses change nothing.
  for (const bad of ['nobody@beta.e2e.test', '__proto__', 'constructor', 'toString', '']) {
    assert.equal(await kamran.markRead(bad), false, bad);
  }
  assert.equal(Object.keys(kamran.vault.data.read).join(), 'aylin@alpha.e2e.test');
  while (await aylin.pollOnce() > 0) { /* drain receipts */ }
});

test("a blocked person's messages are neither kept nor answered", async () => {
  const aylinFor = () => kamran.snapshot().people.find((x) => x.address === 'aylin@alpha.e2e.test');
  // Blocking asks nothing of any server.
  const requests = [];
  const request = kamran.net.request;
  kamran.net.request = (...args) => { requests.push(args[1]); return request.apply(kamran.net, args); };
  await kamran.block('aylin@alpha.e2e.test');
  kamran.net.request = request;
  assert.deepEqual(requests, [], 'blocking reached a server');
  assert.equal(aylinFor().blocked, true);
  // The block is on disk at once, before anything else saves the vault.
  kamran = await engine('kamran');
  assert.equal(aylinFor().blocked, true, 'the block was saved');
  const kept = kamran.snapshot().convs['aylin@alpha.e2e.test'].length;
  await aylin.sendText('kamran@beta.e2e.test', 'while blocked');
  while (await kamran.pollOnce() > 0) { /* drain */ }
  assert.equal(kamran.snapshot().convs['aylin@alpha.e2e.test'].length, kept, 'nothing from a blocked person is kept');
  assert.equal(aylinFor().unread, 0);
  while (await aylin.pollOnce() > 0) { /* drain */ }
  const sent = aylin.snapshot().convs['kamran@beta.e2e.test'].at(-1);
  assert.equal(sent.text, 'while blocked');
  assert.notEqual(sent.status, 'delivered', 'a blocked person gets no receipt');
  await assert.rejects(kamran.sendText('aylin@alpha.e2e.test', 'hello?'), /blocked/);
  await assert.rejects(kamran.sendFile('aylin@alpha.e2e.test', { name: 'a.txt', type: 'text/plain', data: Buffer.from('a') }), /blocked/);

  // The block survives a restart; unblocking finds the keys still in step.
  kamran = await engine('kamran');
  assert.equal(aylinFor().blocked, true);
  kamran.net.request = (...args) => { requests.push(args[1]); return request.apply(kamran.net, args); };
  await kamran.unblock('aylin@alpha.e2e.test');
  kamran.net.request = request;
  assert.deepEqual(requests, [], 'unblocking reached a server');
  assert.equal(aylinFor().blocked, false);
  await aylin.sendText('kamran@beta.e2e.test', 'after the block');
  while (await kamran.pollOnce() > 0) { /* drain */ }
  assert.equal(kamran.snapshot().convs['aylin@alpha.e2e.test'].at(-1).text, 'after the block');
  while (await aylin.pollOnce() > 0) { /* drain */ }
  assert.equal(aylin.snapshot().convs['kamran@beta.e2e.test'].at(-1).status, 'delivered');

  for (const bad of ['', 'nobody', '__proto__', 'Aylin@alpha.e2e.test', 'kamran@beta.e2e.test', 'a'.repeat(301)]) {
    await assert.rejects(kamran.block(bad), undefined, JSON.stringify(bad));
  }
  assert.deepEqual(Object.keys(kamran.vault.data.blocked), []);
});

test('a report goes to the reporter\'s own admin, with a reason and a note only', async () => {
  await kamran.report('aylin@alpha.e2e.test', 'spam', 'Testing the report button.');
  await kamran.report('aylin@alpha.e2e.test', 'other');
  // Bad reports are refused by the app itself, before anything is sent.
  const calls = [];
  const api = kamran.api;
  kamran.api = (...args) => { calls.push(args[1]); return api.apply(kamran, args); };
  try {
    await assert.rejects(kamran.report('aylin@alpha.e2e.test', 'nonsense'), /reason/);
    await assert.rejects(kamran.report('aylin@alpha.e2e.test', 'other', 'x'.repeat(1001)), /1,000/);
    await assert.rejects(kamran.report('kamran@beta.e2e.test', 'spam'), /you/);
    await assert.rejects(kamran.report('not an address', 'spam'));
  } finally {
    kamran.api = api;
  }
  assert.deepEqual(calls, [], 'a refused report reached the server');
});

test('the vault on disk holds no readable message text or keys', async () => {
  const raw = fs.readFileSync(path.join(tmp, 'kamran', 'vault.bin'));
  assert.equal(raw.subarray(0, 4).toString(), 'MHV1');
  assert.equal(raw.includes(Buffer.from('Müqaviləni')), false);
  assert.equal(raw.includes(Buffer.from('kamran@beta.e2e.test')), false);
  const wrongKey = await Vault.open(path.join(tmp, 'kamran', 'vault.bin'), async () => crypto.randomBytes(32)).catch((e) => e);
  assert.ok(wrongKey instanceof Error);
});

test('the servers keep and log no message text, file name or file content', async () => {
  // Everything both servers wrote: databases, stored files and their log.
  const files = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else files.push(p);
    }
  };
  walk(path.join(tmp, 'lab'));
  assert.ok(files.some((p) => p.endsWith('.db')), 'found the servers\' databases');
  const secrets = [Buffer.from('Müqaviləni'), Buffer.from('while blocked'), Buffer.from('contract.pdf'), fileData.subarray(4096, 4160), Buffer.from('Testing the report button')];
  // Each also as base64 and base64url at every alignment, as JSON stores bytes.
  const forms = (s) => [s, ...[0, 1, 2].flatMap((o) => {
    const enc = Buffer.concat([Buffer.alloc(o), s]).toString('base64').slice(Math.ceil(o * 8 / 6), Math.floor((o + s.length) * 8 / 6));
    return [Buffer.from(enc), Buffer.from(enc.replace(/\+/g, '-').replace(/\//g, '_'))];
  })];
  const named = (s) => (s.length === 64 ? 'file bytes' : String(s));
  const log = Buffer.from(labLog);
  assert.ok(log.includes('level=INFO'), 'the servers logged their events');
  for (const s of secrets) {
    for (const f of forms(s)) {
      for (const p of files) assert.equal(fs.readFileSync(p).includes(f), false, `${path.relative(tmp, p)} holds ${named(s)}`);
      assert.equal(log.includes(f), false, 'the servers logged ' + named(s));
    }
  }
});

let leyla;
test('a person who joins a partner shows up without waiting for the minute', async () => {
  await aylin.syncContacts();
  assert.equal(aylin.directoryChanged, false);
  leyla = await engine('leyla');
  await leyla.join(lab.invites['leyla@beta.e2e.test']);
  // Beta tells Alpha; the next mail check of Aylin's app carries a new version.
  for (let i = 0; i < 50 && !aylin.directoryChanged; i++) {
    await aylin.pollOnce();
    if (!aylin.directoryChanged) await new Promise((r) => setTimeout(r, 100));
  }
  assert.equal(aylin.directoryChanged, true);
  await aylin.syncContacts();
  assert.equal(aylin.directoryChanged, false);
  assert.ok(aylin.snapshot().people.some((p) => p.address === 'leyla@beta.e2e.test'), 'Leyla is listed');
});

test("a certificate not signed by the contact's organization is refused", async () => {
  await aylin.sendText('leyla@beta.e2e.test', 'first');
  await leyla.pollOnce();
  assert.equal(leyla.snapshot().convs['aylin@alpha.e2e.test'][0].text, 'first');
  const before = aylin.vault.data.pins['leyla@beta.e2e.test'];
  // A certificate claiming Leyla but signed by alpha, not beta, is refused.
  const forged = { ...aylin.me.cert, address: 'leyla@beta.e2e.test', issued: before.issued + 100 };
  assert.equal(aylin.acceptCert(forged), 'rejected');
  assert.equal(aylin.vault.data.pins['leyla@beta.e2e.test'].identityKey, before.identityKey);
});
