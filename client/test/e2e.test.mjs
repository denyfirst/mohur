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
  labProc = spawn(exe, ['-dir', path.join(tmp, 'lab'), '-invite', 'alpha.test:aylin:Aylin Məmmədova', '-invite', 'beta.test:kamran:Kamran Əliyev',
    '-invite', 'beta.test:leyla:Leyla Həsənova'], { stdio: ['pipe', 'pipe', 'inherit'] });
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
  const preview = await aylin.previewInvite(lab.invites['aylin@alpha.test']);
  assert.equal(preview.name, 'Alpha LLC');
  assert.equal(preview.domain, 'alpha.test');
  const me = await aylin.join(lab.invites['aylin@alpha.test']);
  assert.equal(me.address, 'aylin@alpha.test');
  assert.equal(me.name, 'Aylin Məmmədova');
  await kamran.join(lab.invites['kamran@beta.test']);
  const again = await engine('someone-else');
  await assert.rejects(again.join(lab.invites['aylin@alpha.test']), /expired or was already used/);
});

test('partners appear as contacts with certified devices', async () => {
  await aylin.syncContacts();
  await kamran.syncContacts();
  const snap = aylin.snapshot();
  const k = snap.people.find((p) => p.address === 'kamran@beta.test');
  assert.ok(k, 'Kamran is in Aylin\'s contacts');
  assert.equal(k.org, 'Beta LLC');
  assert.equal(snap.partners[0].blocked, false);
});

test('a message, its delivery receipt and a reply', async () => {
  await aylin.sendText('kamran@beta.test', 'Salam, Kamran! Müqaviləni göndərirəm.');
  assert.equal(await kamran.pollOnce(), 1);
  const conv = kamran.snapshot().convs['aylin@alpha.test'];
  assert.equal(conv.length, 1);
  assert.equal(conv[0].text, 'Salam, Kamran! Müqaviləni göndərirəm.');
  assert.equal(conv[0].dir, 'in');
  assert.equal(await aylin.pollOnce(), 1);
  assert.equal(aylin.snapshot().convs['kamran@beta.test'][0].status, 'delivered');
  await kamran.sendText('aylin@alpha.test', 'Aldım, təşəkkürlər.');
  await aylin.pollOnce();
  const back = aylin.snapshot().convs['kamran@beta.test'];
  assert.equal(back.at(-1).text, 'Aldım, təşəkkürlər.');
});

test('a file arrives whole and is checked before it opens', async () => {
  const data = crypto.randomBytes(3 * 1024 * 1024 + 17);
  await aylin.sendFile('kamran@beta.test', { name: 'contract.pdf', type: 'application/pdf', data });
  await kamran.pollOnce();
  const msg = kamran.snapshot().convs['aylin@alpha.test'].at(-1);
  assert.equal(msg.kind, 'file');
  assert.equal(msg.file.name, 'contract.pdf');
  const opened = await kamran.openFile('aylin@alpha.test', msg.id);
  assert.ok(opened.data.equals(data));
});

test('many messages both ways, and sessions survive a restart', async () => {
  for (let i = 0; i < 10; i++) {
    await aylin.sendText('kamran@beta.test', 'a' + i);
    await kamran.sendText('aylin@alpha.test', 'k' + i);
  }
  // Kamran's app restarts: a new engine over the same encrypted vault file.
  kamran = await engine('kamran');
  assert.equal(kamran.joined, true);
  while (await kamran.pollOnce() > 0) { /* drain */ }
  while (await aylin.pollOnce() > 0) { /* drain */ }
  const k = kamran.snapshot().convs['aylin@alpha.test'].filter((m) => m.dir === 'in').map((m) => m.text);
  const a = aylin.snapshot().convs['kamran@beta.test'].filter((m) => m.dir === 'in').map((m) => m.text);
  for (let i = 0; i < 10; i++) {
    assert.ok(k.includes('a' + i), 'kamran got a' + i);
    assert.ok(a.includes('k' + i), 'aylin got k' + i);
  }
});

test('the vault on disk holds no readable message text or keys', async () => {
  const raw = fs.readFileSync(path.join(tmp, 'kamran', 'vault.bin'));
  assert.equal(raw.subarray(0, 4).toString(), 'MHV1');
  assert.equal(raw.includes(Buffer.from('Müqaviləni')), false);
  assert.equal(raw.includes(Buffer.from('kamran@beta.test')), false);
  const wrongKey = await Vault.open(path.join(tmp, 'kamran', 'vault.bin'), async () => crypto.randomBytes(32)).catch((e) => e);
  assert.ok(wrongKey instanceof Error);
});

test("a certificate not signed by the contact's organization is refused", async () => {
  const leyla = await engine('leyla');
  await leyla.join(lab.invites['leyla@beta.test']);
  await aylin.syncContacts();
  await aylin.sendText('leyla@beta.test', 'first');
  await leyla.pollOnce();
  assert.equal(leyla.snapshot().convs['aylin@alpha.test'][0].text, 'first');
  const before = aylin.vault.data.pins['leyla@beta.test'];
  // A certificate claiming Leyla but signed by alpha, not beta, is refused.
  const forged = { ...aylin.me.cert, address: 'leyla@beta.test', issued: before.issued + 100 };
  assert.equal(aylin.acceptCert(forged), 'rejected');
  assert.equal(aylin.vault.data.pins['leyla@beta.test'].identityKey, before.identityKey);
});
