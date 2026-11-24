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

before(async () => {
  const exe = path.join(tmp, process.platform === 'win32' ? 'mohur-lab.exe' : 'mohur-lab');
  execFileSync('go', ['build', '-o', exe, './cmd/mohur-lab'], { cwd: root, stdio: 'inherit', env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'go1.27.4' } });
  labProc = spawn(exe, ['-dir', path.join(tmp, 'lab'), '-orgs', 'alpha.e2e.test,beta.e2e.test', '-invite', 'alpha.e2e.test:aylin:Aylin Məmmədova', '-invite', 'beta.e2e.test:kamran:Kamran Əliyev',
    '-invite', 'beta.e2e.test:leyla:Leyla Həsənova'], { stdio: ['pipe', 'pipe', 'inherit'] });
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

let aylin, kamran;

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
  const data = crypto.randomBytes(3 * 1024 * 1024 + 17);
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

test('the vault on disk holds no readable message text or keys', async () => {
  const raw = fs.readFileSync(path.join(tmp, 'kamran', 'vault.bin'));
  assert.equal(raw.subarray(0, 4).toString(), 'MHV1');
  assert.equal(raw.includes(Buffer.from('Müqaviləni')), false);
  assert.equal(raw.includes(Buffer.from('kamran@beta.e2e.test')), false);
  const wrongKey = await Vault.open(path.join(tmp, 'kamran', 'vault.bin'), async () => crypto.randomBytes(32)).catch((e) => e);
  assert.ok(wrongKey instanceof Error);
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
