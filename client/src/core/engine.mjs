// The Mohur engine: everything the app does except drawing it. It holds the
// person's keys, talks only to their own organization's server, and uses
// libsignal unchanged for every message. It runs in Electron's main process
// and in plain Node for tests; the window only ever sees snapshot().
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import * as Signal from '@signalapp/libsignal-client';
import { b64, unb64, sign, ContextSession, parseTXT, checkOrgDoc, checkCert, parseAddress, domainOK } from './proto.mjs';
import { HttpError } from './net.mjs';

const PREKEY_BATCH = 100;
const PREKEY_LOW = 20;
const MAX_FILE = 100 * 1024 * 1024;
const FILE_AAD = Buffer.from('mohur/file/v1');

// Plaintexts are padded to 160-byte steps (ISO/IEC 7816-4), so a message's
// length shows only roughly how long it is.
function pad(buf) {
  const n = Math.ceil((buf.length + 1) / 160) * 160;
  const out = Buffer.alloc(n);
  buf.copy(out);
  out[buf.length] = 0x80;
  return out;
}
function unpad(buf) {
  let i = buf.length - 1;
  while (i >= 0 && buf[i] === 0) i--;
  if (i < 0 || buf[i] !== 0x80) throw new Error('bad padding');
  return buf.subarray(0, i);
}

const addrKey = (a) => `${a.name()}.${a.deviceId()}`;
const newId = () => b64(crypto.randomBytes(16));

// ── libsignal stores over the vault ───────────────────────────────────────

class Stores {
  constructor(engine) { this.e = engine; }
  get s() { return this.e.vault.data.signal; }
}

class SessionStore extends Signal.SessionStore {
  constructor(st) { super(); this.st = st; }
  async saveSession(a, record) { this.st.s.sessions[addrKey(a)] = b64(record.serialize()); }
  async getSession(a) {
    const v = this.st.s.sessions[addrKey(a)];
    return v ? Signal.SessionRecord.deserialize(unb64(v)) : null;
  }
  async getExistingSessions(addresses) {
    return Promise.all(addresses.map(async (a) => {
      const r = await this.getSession(a);
      if (!r) throw new Error('session missing');
      return r;
    }));
  }
}

// IdentityStore trusts exactly the identity key in the device certificate the
// organization signed and the app accepted (Engine.acceptCert). There is no
// trust on first use and no way for a message to introduce its own key.
class IdentityStore extends Signal.IdentityKeyStore {
  constructor(st) { super(); this.st = st; }
  async getIdentityKey() { return Signal.PrivateKey.deserialize(unb64(this.st.e.vault.data.me.identity)); }
  async getLocalRegistrationId() { return this.st.e.vault.data.me.registrationId; }
  #pinned(a) {
    const pin = this.st.e.vault.data.pins[a.name()];
    return pin && pin.device === a.deviceId() ? pin.identityKey : null;
  }
  async saveIdentity(a, key) {
    return this.#pinned(a) === b64(key.serialize()) ? Signal.IdentityChange.NewOrUnchanged : Signal.IdentityChange.ReplacedExisting;
  }
  async isTrustedIdentity(a, key) { return this.#pinned(a) === b64(key.serialize()); }
  async getIdentity(a) {
    const k = this.#pinned(a);
    return k ? Signal.PublicKey.deserialize(unb64(k)) : null;
  }
}

class PreKeyStore extends Signal.PreKeyStore {
  constructor(st) { super(); this.st = st; }
  async savePreKey(id, r) { this.st.s.prekeys[id] = b64(r.serialize()); }
  async getPreKey(id) {
    const v = this.st.s.prekeys[id];
    if (!v) throw new Error('prekey missing');
    return Signal.PreKeyRecord.deserialize(unb64(v));
  }
  async removePreKey(id) { delete this.st.s.prekeys[id]; }
}

class SignedPreKeyStore extends Signal.SignedPreKeyStore {
  constructor(st) { super(); this.st = st; }
  async saveSignedPreKey(id, r) { this.st.s.signed[id] = b64(r.serialize()); }
  async getSignedPreKey(id) {
    const v = this.st.s.signed[id];
    if (!v) throw new Error('signed prekey missing');
    return Signal.SignedPreKeyRecord.deserialize(unb64(v));
  }
}

// The PQ prekey is a last-resort key that may serve several sessions; each
// (key, signed key, base key) combination is accepted once.
class KyberStore extends Signal.KyberPreKeyStore {
  constructor(st) { super(); this.st = st; }
  async saveKyberPreKey(id, r) { this.st.s.kyber[id] = b64(r.serialize()); }
  async getKyberPreKey(id) {
    const v = this.st.s.kyber[id];
    if (!v) throw new Error('PQ prekey missing');
    return Signal.KyberPreKeyRecord.deserialize(unb64(v));
  }
  async markKyberPreKeyUsed(id, signedId, baseKey) {
    const use = `${id}:${signedId}:${b64(baseKey.serialize())}`;
    const used = this.st.s.kyberUsed;
    if (used.includes(use)) throw new Error('PQ prekey reuse');
    used.push(use);
    if (used.length > 5000) used.splice(0, used.length - 5000);
  }
}

// ── The engine ────────────────────────────────────────────────────────────

export class Engine extends EventEmitter {
  constructor(vault, net, { label = 'Computer', log = () => {} } = {}) {
    super();
    this.vault = vault;
    this.net = net;
    this.label = label;
    this.log = log;
    this.token = null;
    this.running = false;
    this.queue = Promise.resolve();
    const st = new Stores(this);
    this.sessions = new SessionStore(st);
    this.identity = new IdentityStore(st);
    this.prekeys = new PreKeyStore(st);
    this.signed = new SignedPreKeyStore(st);
    this.kyber = new KyberStore(st);
  }

  get joined() { return Boolean(this.vault.data && this.vault.data.me); }
  get me() { return this.vault.data.me; }

  // serial runs f after every earlier engine operation, so libsignal state is
  // never touched by two operations at once.
  serial(f) {
    const run = this.queue.then(f, f);
    this.queue = run.catch(() => {});
    return run;
  }

  changed() { this.emit('update'); }

  // ── Organization verification ──

  // verifyOrg finds an organization from its domain exactly as servers do:
  // the TXT record, a certificate for its server and its signed document must
  // all name the same key.
  async verifyOrg(domain) {
    let txt;
    try {
      txt = parseTXT(await this.net.txt('_mohur.' + domain), domain);
    } catch {
      throw new Error(`${domain} has no valid Mohur DNS record.`);
    }
    let doc;
    try {
      doc = await this.net.request('GET', `https://${txt.server}/.well-known/mohur`, { limit: 16 << 10 });
    } catch {
      throw new Error(`The Mohur server of ${domain} could not be reached securely.`);
    }
    if (!checkOrgDoc(doc) || doc.domain !== domain || doc.server !== txt.server || doc.key !== txt.key) {
      throw new Error(`${domain}'s DNS record and server do not agree.`);
    }
    return doc;
  }

  // ── Joining ──

  static parseInvite(text) {
    const m = /^\s*([a-z0-9.-]+)\/([A-Za-z2-7 -]{16,64})\s*$/.exec(String(text || '').toLowerCase());
    if (!m || !domainOK(m[1])) throw new Error('That does not look like a Mohur invite. It looks like company.com/ABCD-EFGH-…');
    return { domain: m[1], code: m[2].replace(/[\s-]/g, '').toUpperCase() };
  }

  // previewInvite verifies the organization an invite is for, before joining.
  async previewInvite(text) {
    const { domain } = Engine.parseInvite(text);
    const doc = await this.verifyOrg(domain);
    return { domain: doc.domain, name: doc.name, server: doc.server };
  }

  async join(text) {
    if (this.joined) throw new Error('This app has already joined.');
    const { domain, code } = Engine.parseInvite(text);
    const doc = await this.verifyOrg(domain);

    const identity = Signal.PrivateKey.generate();
    const registrationId = crypto.randomInt(1, 16380);
    const auth = crypto.generateKeyPairSync('ed25519');
    const authRaw = auth.publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
    this.vault.data = {
      v: 1,
      me: null,
      pending: { domain, server: doc.server, orgKey: doc.key, orgName: doc.name },
      signal: { sessions: {}, prekeys: {}, signed: {}, kyber: {}, kyberUsed: [], nextPreKey: 1 },
      identityPriv: b64(identity.serialize()),
      registrationId,
      authPriv: b64(auth.privateKey.export({ format: 'der', type: 'pkcs8' })),
      pins: {},
      orgs: { [domain]: { name: doc.name, key: doc.key } },
      people: [],
      convs: {},
      outbox: [],
      notices: [],
    };
    const signedPriv = Signal.PrivateKey.generate();
    const signedSig = identity.sign(signedPriv.getPublicKey().serialize());
    await this.signed.saveSignedPreKey(1, Signal.SignedPreKeyRecord.new(1, Date.now(), signedPriv.getPublicKey(), signedPriv, signedSig));
    const kem = Signal.KEMKeyPair.generate();
    const kemSig = identity.sign(kem.getPublicKey().serialize());
    await this.kyber.saveKyberPreKey(1, Signal.KyberPreKeyRecord.new(1, Date.now(), kem, kemSig));
    const preKeys = await this.#newPreKeys();
    await this.vault.save();

    const res = await this.net.request('POST', `https://${doc.server}/api/v1/join`, {
      body: {
        invite: `${domain}/${code}`, label: this.label, identityKey: b64(identity.getPublicKey().serialize()), authKey: b64(authRaw),
        registrationId, signedPreKey: { id: 1, pub: b64(signedPriv.getPublicKey().serialize()), sig: b64(signedSig) },
        kyberPreKey: { id: 1, pub: b64(kem.getPublicKey().serialize()), sig: b64(kemSig) }, preKeys,
      },
    });
    const cert = res.cert;
    if (!checkCert(cert, doc.key, domain) || cert.identityKey !== b64(identity.getPublicKey().serialize()) || cert.authKey !== b64(authRaw)) {
      throw new Error('The server returned a certificate that does not match this device.');
    }
    const d = this.vault.data;
    d.me = { address: cert.address, name: cert.name, device: cert.device, domain, server: doc.server, orgKey: doc.key, orgName: doc.name, cert,
      identity: d.identityPriv, registrationId, auth: d.authPriv, joined: Date.now() };
    delete d.pending; delete d.identityPriv; delete d.authPriv;
    d.pins[cert.address] = { device: cert.device, identityKey: cert.identityKey, issued: cert.issued, name: cert.name };
    await this.vault.save();
    this.changed();
    return { address: cert.address, name: cert.name, org: doc.name };
  }

  async #newPreKeys() {
    const s = this.vault.data.signal;
    const out = [];
    for (let i = 0; i < PREKEY_BATCH; i++) {
      const id = s.nextPreKey++;
      const k = Signal.PrivateKey.generate();
      await this.prekeys.savePreKey(id, Signal.PreKeyRecord.new(id, k.getPublicKey(), k));
      out.push({ id, pub: b64(k.getPublicKey().serialize()) });
    }
    return out;
  }

  // ── Talking to our own server ──

  url(path) { return `https://${this.me.server}${path}`; }

  async signIn() {
    const me = this.me;
    const ch = await this.net.request('POST', this.url('/api/v1/session/challenge'), { body: { address: me.address, device: me.device } });
    const key = crypto.createPrivateKey({ key: unb64(me.auth), format: 'der', type: 'pkcs8' });
    const sig = sign(key, ContextSession, me.domain, me.address, String(me.device), ch.nonce);
    const res = await this.net.request('POST', this.url('/api/v1/session'), { body: { address: me.address, device: me.device, nonce: ch.nonce, sig } });
    this.token = res.token;
  }

  async api(method, path, opts = {}) {
    if (!this.token) await this.signIn();
    try {
      return await this.net.request(method, this.url(path), { ...opts, token: this.token });
    } catch (e) {
      if (!(e instanceof HttpError) || e.status !== 401) throw e;
      this.token = null;
      await this.signIn();
      return this.net.request(method, this.url(path), { ...opts, token: this.token });
    }
  }

  // ── Trust ──

  // orgKey returns the verified key of a domain we may talk to, or null.
  orgKey(domain) {
    if (domain === this.me.domain) return this.me.orgKey;
    const o = this.vault.data.orgs[domain];
    return o && !o.blocked ? o.key : null;
  }

  // acceptCert pins a device the organization certified. A newer certificate
  // with another key means the person has a new device; it replaces the old
  // one and leaves a notice in the conversation. An older one is refused.
  acceptCert(cert) {
    let domain;
    try { ({ domain } = parseAddress(cert.address)); } catch { return 'rejected'; }
    const key = this.orgKey(domain);
    if (!key || !checkCert(cert, key, domain)) return 'rejected';
    const pins = this.vault.data.pins;
    const pin = pins[cert.address];
    if (pin && pin.device === cert.device && pin.identityKey === cert.identityKey) {
      pin.name = cert.name;
      return 'same';
    }
    if (pin && cert.issued < pin.issued) return 'rejected';
    pins[cert.address] = { device: cert.device, identityKey: cert.identityKey, issued: cert.issued, name: cert.name };
    if (pin) {
      for (const k of Object.keys(this.vault.data.signal.sessions)) {
        if (k.startsWith(cert.address + '.')) delete this.vault.data.signal.sessions[k];
      }
      this.#system(cert.address, `${cert.name} has a new device. It was confirmed by ${domain}.`);
      return 'changed';
    }
    return 'new';
  }

  #system(address, text) {
    const conv = (this.vault.data.convs[address] ||= []);
    conv.push({ id: newId(), dir: 'system', kind: 'notice', text, at: Date.now() });
  }

  // syncContacts reads the directory from our server. Partner keys it reports
  // are checked against each partner's own DNS record, so our own server
  // cannot quietly swap a partner's key.
  async syncContacts(fresh = false) {
    const res = await this.api('GET', '/api/v1/contacts' + (fresh ? '?fresh=1' : ''));
    const d = this.vault.data;
    for (const o of res.orgs) {
      if (o.domain === this.me.domain) {
        if (o.key !== this.me.orgKey) throw new Error('Your organization\'s key changed. Ask your admin.');
        continue;
      }
      const known = d.orgs[o.domain];
      let dnsKey = null;
      try { dnsKey = parseTXT(await this.net.txt('_mohur.' + o.domain), o.domain).key; } catch { /* DNS unreachable from here */ }
      const blocked = dnsKey ? dnsKey !== o.key : Boolean(known && known.key !== o.key);
      d.orgs[o.domain] = { name: o.name, key: blocked && known ? known.key : o.key, blocked };
      if (blocked) this.log(`partner ${o.domain} blocked: its key does not match its DNS record`);
    }
    const people = [];
    for (const p of res.people) {
      if (p.address === this.me.address) continue;
      const cert = p.devices[0];
      if (!cert || cert.address !== p.address || this.acceptCert(cert) === 'rejected') continue;
      people.push({ address: p.address, name: p.name, domain: parseAddress(p.address).domain });
    }
    d.people = people;
    await this.vault.save();
    this.changed();
  }

  // ── Sending ──

  async #ensureSession(address) {
    const pin = this.vault.data.pins[address];
    if (pin && this.vault.data.signal.sessions[`${address}.${pin.device}`]) return pin;
    const { domain } = parseAddress(address);
    if (!this.orgKey(domain)) throw new Error('Your organization is not connected with ' + domain + '.');
    const res = await this.api('GET', '/api/v1/keys?address=' + encodeURIComponent(address));
    const b = res.bundles[0];
    if (!b || b.cert.address !== address || this.acceptCert(b.cert) === 'rejected') throw new Error('That person\'s device could not be verified.');
    const bundle = Signal.PreKeyBundle.new(b.registrationId, b.cert.device,
      b.preKey ? b.preKey.id : null, b.preKey ? Signal.PublicKey.deserialize(unb64(b.preKey.pub)) : null,
      b.signedPreKey.id, Signal.PublicKey.deserialize(unb64(b.signedPreKey.pub)), unb64(b.signedPreKey.sig),
      Signal.PublicKey.deserialize(unb64(b.cert.identityKey)),
      b.kyberPreKey.id, Signal.KEMPublicKey.deserialize(unb64(b.kyberPreKey.pub)), unb64(b.kyberPreKey.sig));
    await Signal.processPreKeyBundle(bundle, Signal.ProtocolAddress.new(address, b.cert.device), this.#self(), this.sessions, this.identity);
    return this.vault.data.pins[address];
  }

  #self() { return Signal.ProtocolAddress.new(this.me.address, this.me.device); }

  async #encrypt(address, payload) {
    const pin = await this.#ensureSession(address);
    const remote = Signal.ProtocolAddress.new(address, pin.device);
    const ct = await Signal.signalEncrypt(pad(Buffer.from(JSON.stringify(payload))), remote, this.#self(), this.sessions, this.identity);
    return { to: address, toDevice: pin.device, type: ct.type(), body: b64(ct.serialize()) };
  }

  // #deliver encrypts and sends one payload; it keeps it in the outbox when
  // the server or the partner cannot be reached, and tries again later.
  async #deliver(item) {
    const env = await this.#encrypt(item.to, item.payload);
    if (item.blobs) env.blobs = item.blobs;
    await this.vault.save();
    await this.api('POST', '/api/v1/send', { body: { envelopes: [env] } });
  }

  async #sendPayload(to, payload, blobs) {
    const item = { to, payload, blobs };
    try {
      await this.#deliver(item);
      return 'sent';
    } catch (e) {
      if (e instanceof HttpError && e.status !== 502 && e.status !== 503) throw e;
      this.vault.data.outbox.push(item);
      await this.vault.save();
      return 'waiting';
    }
  }

  sendText(to, text) {
    return this.serial(async () => {
      text = String(text || '').trim();
      if (!text || text.length > 20000) throw new Error('Messages can be up to 20,000 characters.');
      const msg = { id: newId(), dir: 'out', kind: 'text', text, at: Date.now(), status: 'sending' };
      this.#store(to, msg);
      msg.status = await this.#sendPayload(to, { v: 1, kind: 'text', id: msg.id, text, at: msg.at });
      await this.vault.save();
      this.changed();
      return msg.id;
    });
  }

  sendFile(to, { name, type, data }) {
    return this.serial(async () => {
      if (!Buffer.isBuffer(data) || data.length === 0 || data.length > MAX_FILE) throw new Error('Files can be up to 100 MB.');
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(FILE_AAD);
      const sealed = Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
      const sha256 = b64(crypto.createHash('sha256').update(sealed).digest());
      const { id: blob } = await this.api('POST', '/api/v1/blobs?to=' + encodeURIComponent(to), { body: sealed, timeout: 10 * 60000 });
      const file = { blob, name: String(name).slice(0, 255), type: String(type || 'application/octet-stream').slice(0, 127), size: data.length, key: b64(key), iv: b64(iv), sha256 };
      const msg = { id: newId(), dir: 'out', kind: 'file', file, at: Date.now(), status: 'sending' };
      this.#store(to, msg);
      msg.status = await this.#sendPayload(to, { v: 1, kind: 'file', id: msg.id, file, at: msg.at }, [blob]);
      await this.vault.save();
      this.changed();
      return msg.id;
    });
  }

  // openFile downloads a received file, checks it and returns its bytes.
  openFile(address, msgId) {
    return this.serial(async () => {
      const msg = (this.vault.data.convs[address] || []).find((m) => m.id === msgId && m.kind === 'file');
      if (!msg) throw new Error('That file is not in this conversation.');
      const f = msg.file;
      if (msg.dir === 'out') throw new Error('Files you sent are not kept on the server.');
      const sealed = await this.api('GET', '/api/v1/blobs/' + encodeURIComponent(f.blob), { raw: true, timeout: 10 * 60000, limit: MAX_FILE + 64 });
      if (b64(crypto.createHash('sha256').update(sealed).digest()) !== f.sha256) throw new Error('The file was changed on the way and was not opened.');
      const d = crypto.createDecipheriv('aes-256-gcm', unb64(f.key), unb64(f.iv));
      d.setAAD(FILE_AAD);
      d.setAuthTag(sealed.subarray(sealed.length - 16));
      const data = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
      return { name: f.name, type: f.type, data };
    });
  }

  async flushOutbox() {
    return this.serial(async () => {
      const box = this.vault.data.outbox;
      while (box.length) {
        try {
          await this.#deliver(box[0]);
        } catch (e) {
          if (e instanceof HttpError && e.status !== 502 && e.status !== 503) {
            this.#markFailed(box[0]);
          } else {
            return;
          }
        }
        this.#markSent(box.shift());
        await this.vault.save();
        this.changed();
      }
    });
  }

  #markSent(item) {
    const m = (this.vault.data.convs[item.to] || []).find((x) => x.id === item.payload.id);
    if (m && m.status !== 'delivered') m.status = 'sent';
  }
  #markFailed(item) {
    const m = (this.vault.data.convs[item.to] || []).find((x) => x.id === item.payload.id);
    if (m) m.status = 'failed';
  }

  #store(address, msg) {
    const conv = (this.vault.data.convs[address] ||= []);
    if (msg.dir === 'in' && conv.some((m) => m.dir === 'in' && m.id === msg.id)) return false;
    conv.push(msg);
    return true;
  }

  // ── Receiving ──

  async #open(env) {
    const { domain } = parseAddress(env.from);
    if (!this.orgKey(domain) || !this.vault.data.pins[env.from]) await this.syncContacts(true).catch(() => {});
    if (env.fromCert.address !== env.from || env.fromCert.device !== env.fromDevice || this.acceptCert(env.fromCert) === 'rejected') {
      throw new Error('sender not verified');
    }
    const from = Signal.ProtocolAddress.new(env.from, env.fromDevice);
    const body = unb64(env.body);
    let plain;
    if (env.type === Signal.CiphertextMessageType.PreKey) {
      plain = await Signal.signalDecryptPreKey(Signal.PreKeySignalMessage.deserialize(body), from, this.#self(),
        this.sessions, this.identity, this.prekeys, this.signed, this.kyber);
    } else if (env.type === Signal.CiphertextMessageType.Whisper) {
      plain = await Signal.signalDecrypt(Signal.SignalMessage.deserialize(body), from, this.#self(), this.sessions, this.identity);
    } else {
      throw new Error('unknown message type');
    }
    return JSON.parse(unpad(Buffer.from(plain)).toString('utf8'));
  }

  async #receive(envs) {
    const receipts = {};
    for (const env of envs) {
      try {
        const p = await this.#open(env);
        if (p.v !== 1 || typeof p.id !== 'string') throw new Error('unknown payload');
        if (p.kind === 'text' && typeof p.text === 'string') {
          if (this.#store(env.from, { id: p.id, dir: 'in', kind: 'text', text: p.text.slice(0, 20000), at: p.at || Date.now(), received: Date.now() })) {
            (receipts[env.from] ||= []).push(p.id);
          }
        } else if (p.kind === 'file' && p.file && env.blobs && env.blobs.includes(p.file.blob)) {
          const f = p.file;
          const file = { blob: f.blob, name: String(f.name).slice(0, 255), type: String(f.type).slice(0, 127), size: Number(f.size), key: f.key, iv: f.iv, sha256: f.sha256 };
          if (this.#store(env.from, { id: p.id, dir: 'in', kind: 'file', file, at: p.at || Date.now(), received: Date.now() })) {
            (receipts[env.from] ||= []).push(p.id);
          }
        } else if (p.kind === 'receipt' && Array.isArray(p.ids)) {
          for (const m of this.vault.data.convs[env.from] || []) {
            if (m.dir === 'out' && p.ids.includes(m.id)) m.status = 'delivered';
          }
        }
      } catch (e) {
        if (e && e.code === Signal.ErrorCode.DuplicatedMessage) continue;
        this.log(`a message from ${env.from} could not be opened: ${e.message}`);
        if (/^[a-z0-9._-]+@[a-z0-9.-]+$/.test(env.from || '')) this.#system(env.from, 'A message could not be opened and was dropped.');
      }
    }
    // State first, then acknowledge: a crash in between means the server sends
    // the message again and libsignal reports it as a duplicate.
    await this.vault.save();
    await this.api('POST', '/api/v1/inbox/ack', { body: { ids: envs.map((e) => e.id) } });
    this.changed();
    for (const [to, ids] of Object.entries(receipts)) {
      await this.#sendPayload(to, { v: 1, kind: 'receipt', id: newId(), ids }).catch((e) => this.log('receipt not sent: ' + e.message));
    }
    await this.vault.save();
  }

  // pollOnce fetches and opens waiting messages; wait makes it a long poll.
  pollOnce(wait = false) {
    return this.api('GET', '/api/v1/inbox' + (wait ? '?wait=1' : ''), { timeout: 45000 }).then((res) => {
      if (!res.envelopes.length) return 0;
      return this.serial(() => this.#receive(res.envelopes)).then(() => res.envelopes.length);
    });
  }

  async #replenish() {
    const { count } = await this.api('GET', '/api/v1/prekeys');
    if (count >= PREKEY_LOW) return;
    await this.serial(async () => {
      const preKeys = await this.#newPreKeys();
      await this.vault.save();
      await this.api('POST', '/api/v1/prekeys', { body: { preKeys } });
    });
  }

  // start keeps the app in touch with its server until stop().
  async start() {
    if (this.running) return;
    this.running = true;
    this.online = false;
    const loop = async () => {
      let lastSync = 0;
      while (this.running) {
        try {
          if (Date.now() - lastSync > 60000) {
            await this.serial(() => this.syncContacts());
            await this.#replenish();
            lastSync = Date.now();
          }
          await this.flushOutbox();
          if (!this.online) { this.online = true; this.changed(); }
          await this.pollOnce(true);
        } catch (e) {
          if (this.online) { this.online = false; this.changed(); }
          this.log('connection problem: ' + e.message);
          await new Promise((r) => setTimeout(r, 5000));
        }
      }
    };
    this.loop = loop();
  }

  async stop() {
    this.running = false;
  }

  // ── What the window sees ──

  snapshot() {
    if (!this.joined) return { joined: false };
    const d = this.vault.data;
    const orgName = (domain) => (domain === this.me.domain ? this.me.orgName : d.orgs[domain] ? d.orgs[domain].name : domain);
    const people = d.people.map((p) => {
      const conv = d.convs[p.address] || [];
      const last = conv[conv.length - 1];
      return { address: p.address, name: p.name, org: orgName(p.domain), domain: p.domain, own: p.domain === this.me.domain,
        last: last ? (last.kind === 'file' ? '📎 ' + last.file.name : last.text) : '', lastAt: last ? last.at : 0 };
    });
    const convs = {};
    for (const [a, list] of Object.entries(d.convs)) {
      convs[a] = list.map((m) => ({ id: m.id, dir: m.dir, kind: m.kind, text: m.text, at: m.at, status: m.status,
        file: m.file ? { name: m.file.name, size: m.file.size, type: m.file.type } : undefined }));
    }
    return {
      joined: true, online: Boolean(this.online),
      me: { address: this.me.address, name: this.me.name, org: this.me.orgName, domain: this.me.domain },
      people, convs,
      partners: Object.entries(d.orgs).filter(([k]) => k !== this.me.domain).map(([domain, o]) => ({ domain, name: o.name, blocked: Boolean(o.blocked) })),
    };
  }
}
