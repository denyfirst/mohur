// The app's organization check, with DNS and HTTPS answers chosen by the test.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { Engine } from '../src/core/engine.mjs';
import { b64, sign, ContextOrg } from '../src/core/proto.mjs';

function org(domain, server, name = 'Example LLC') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const key = b64(publicKey.export({ format: 'der', type: 'spki' }).subarray(12));
  const doc = { v: 1, domain, name, server, key };
  doc.sig = sign(privateKey, ContextOrg, domain, name, server, key);
  return { doc, record: `v=mohur1 server=${server} key=${key}`, privateKey };
}

function engineWith(records, doc) {
  const net = { txt: async () => records, request: async () => doc };
  return new Engine({ data: null }, net);
}

test('an organization is trusted only when DNS, server and signature agree', async () => {
  const good = org('example.com', 'mohur.example.com');
  const ok = await engineWith([good.record], good.doc).verifyOrg('example.com');
  assert.equal(ok.key, good.doc.key);

  const other = org('example.com', 'mohur.example.com');
  const cases = {
    'no record': [[], good.doc],
    'record names another key': [[other.record], good.doc],
    'record names a server outside the domain': [[good.record.replace('mohur.example.com', 'mohur.evil.com')], good.doc],
    'document for another domain': [[good.record], { ...good.doc, domain: 'evil.com' }],
    'document with another server': [[good.record], { ...good.doc, server: 'other.example.com' }],
    'document name changed after signing': [[good.record], { ...good.doc, name: 'Someone Else' }],
    'two records': [[good.record, good.record], good.doc],
  };
  for (const [name, [records, doc]] of Object.entries(cases)) {
    await assert.rejects(engineWith(records, doc).verifyOrg('example.com'), Error, name);
  }
});

test('invites are read strictly', () => {
  assert.deepEqual(Engine.parseInvite(' Example.com/abcd-efgh-ijkl-mnop-qrst-uvwx '), { domain: 'example.com', code: 'ABCDEFGHIJKLMNOPQRSTUVWX' });
  for (const bad of ['', 'example.com', 'ABCD-EFGH', 'https://example.com/ABCD-EFGH-IJKL-MNOP', 'example.com/ABCD-1890-IJKL-MNOP', 'localhost/ABCDEFGHIJKLMNOPQRST']) {
    assert.throws(() => Engine.parseInvite(bad), Error, bad);
  }
});
