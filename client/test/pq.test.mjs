// What ARCHITECTURE.md claims about libsignal, checked against the installed
// library: sessions start with a post-quantum (Kyber/ML-KEM) prekey, and later
// messages carry the post-quantum ratchet.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as S from '@signalapp/libsignal-client';

class Mem {
  constructor(name) {
    this.id = S.PrivateKey.generate();
    this.addr = S.ProtocolAddress.new(name, 1);
    const self = this;
    this.sessions = new (class extends S.SessionStore {
      m = new Map();
      async saveSession(a, r) { this.m.set(a.toString(), r.serialize()); }
      async getSession(a) { const v = this.m.get(a.toString()); return v ? S.SessionRecord.deserialize(v) : null; }
      async getExistingSessions(as) { return Promise.all(as.map((a) => this.getSession(a))); }
    })();
    this.identity = new (class extends S.IdentityKeyStore {
      async getIdentityKey() { return self.id; }
      async getLocalRegistrationId() { return 7; }
      async saveIdentity() { return S.IdentityChange.NewOrUnchanged; }
      async isTrustedIdentity() { return true; }
      async getIdentity() { return null; }
    })();
    this.pre = new (class extends S.PreKeyStore {
      m = new Map();
      async savePreKey(i, r) { this.m.set(i, r); }
      async getPreKey(i) { return this.m.get(i); }
      async removePreKey(i) { this.m.delete(i); }
    })();
    this.signed = new (class extends S.SignedPreKeyStore {
      m = new Map();
      async saveSignedPreKey(i, r) { this.m.set(i, r); }
      async getSignedPreKey(i) { return this.m.get(i); }
    })();
    this.kyber = new (class extends S.KyberPreKeyStore {
      m = new Map();
      async saveKyberPreKey(i, r) { this.m.set(i, r); }
      async getKyberPreKey(i) { return this.m.get(i); }
      async markKyberPreKeyUsed() {}
    })();
  }
  async bundle() {
    const pk = S.PrivateKey.generate();
    const spk = S.PrivateKey.generate();
    const kem = S.KEMKeyPair.generate();
    const spkSig = this.id.sign(spk.getPublicKey().serialize());
    const kemSig = this.id.sign(kem.getPublicKey().serialize());
    await this.pre.savePreKey(1, S.PreKeyRecord.new(1, pk.getPublicKey(), pk));
    await this.signed.saveSignedPreKey(1, S.SignedPreKeyRecord.new(1, Date.now(), spk.getPublicKey(), spk, spkSig));
    await this.kyber.saveKyberPreKey(1, S.KyberPreKeyRecord.new(1, Date.now(), kem, kemSig));
    return S.PreKeyBundle.new(7, 1, 1, pk.getPublicKey(), 1, spk.getPublicKey(), spkSig, this.id.getPublicKey(), 1, kem.getPublicKey(), kemSig);
  }
}

test('sessions use the PQ prekey and later messages carry the PQ ratchet', async () => {
  const a = new Mem('a@alpha.test');
  const b = new Mem('b@beta.test');
  await S.processPreKeyBundle(await b.bundle(), b.addr, a.addr, a.sessions, a.identity);
  const first = await S.signalEncrypt(Buffer.from('hi'), b.addr, a.addr, a.sessions, a.identity);
  assert.equal(first.type(), S.CiphertextMessageType.PreKey);
  await S.signalDecryptPreKey(S.PreKeySignalMessage.deserialize(first.serialize()), a.addr, b.addr, b.sessions, b.identity, b.pre, b.signed, b.kyber);
  let pq = 0;
  for (let i = 0; i < 6; i++) {
    const [from, to] = i % 2 ? [a, b] : [b, a];
    const ct = await S.signalEncrypt(Buffer.from('m' + i), to.addr, from.addr, from.sessions, from.identity);
    if (ct.type() === S.CiphertextMessageType.Whisper) {
      const msg = S.SignalMessage.deserialize(ct.serialize());
      if (msg.pqRatchet().length > 0) pq++;
      await S.signalDecrypt(msg, from.addr, to.addr, to.sessions, to.identity);
    } else {
      await S.signalDecryptPreKey(S.PreKeySignalMessage.deserialize(ct.serialize()), from.addr, to.addr, to.sessions, to.identity, to.pre, to.signed, to.kyber);
    }
  }
  assert.ok(pq > 0, 'no message carried post-quantum ratchet data');
});
