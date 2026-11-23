// The vault is the app's whole local state in one file, encrypted with
// AES-256-GCM. Its key comes from a key provider: the operating system's user
// store in the app (Electron safeStorage), a fixed key in tests. Writes go to
// a temporary file that is renamed into place, so a crash leaves either the
// old or the new state, never half of one.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const MAGIC = Buffer.from('MHV1');
const AAD = Buffer.from('mohur/vault/v1');

export class Vault {
  constructor(file, key, data) {
    this.file = file;
    this.key = key;
    this.data = data;
    this.chain = Promise.resolve();
  }

  static async open(file, keyProvider) {
    const key = await keyProvider();
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('vault key unavailable');
    let raw;
    try {
      raw = await fs.readFile(file);
    } catch (e) {
      if (e.code === 'ENOENT') return new Vault(file, key, null);
      throw e;
    }
    if (raw.length < 4 + 12 + 16 || !raw.subarray(0, 4).equals(MAGIC)) throw new Error('vault file is not a Mohur vault');
    const iv = raw.subarray(4, 16);
    const body = raw.subarray(16, raw.length - 16);
    const tag = raw.subarray(raw.length - 16);
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(AAD);
    d.setAuthTag(tag);
    const plain = Buffer.concat([d.update(body), d.final()]);
    return new Vault(file, key, JSON.parse(plain.toString('utf8')));
  }

  // save writes the current state. Calls are serialized, and each write sees
  // the state as it is when the write starts.
  save() {
    this.chain = this.chain.then(() => this.#write(), () => this.#write());
    return this.chain;
  }

  async #write() {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    c.setAAD(AAD);
    const body = Buffer.concat([c.update(Buffer.from(JSON.stringify(this.data), 'utf8')), c.final()]);
    const out = Buffer.concat([MAGIC, iv, body, c.getAuthTag()]);
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const tmp = this.file + '.' + crypto.randomBytes(6).toString('hex') + '.tmp';
    const h = await fs.open(tmp, 'w', 0o600);
    try {
      await h.writeFile(out);
      await h.sync();
    } finally {
      await h.close();
    }
    await fs.rename(tmp, this.file);
  }
}
