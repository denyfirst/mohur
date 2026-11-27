// HTTPS and DNS for the app. Certificates are always verified. A lab or a
// company with a private certificate authority can add CAs and choose a DNS
// server; nothing here can turn verification off.
import dns from 'node:dns';
import https from 'node:https';
import tls from 'node:tls';

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export class Net {
  constructor({ resolver, extraCA } = {}) {
    let ca;
    try {
      ca = [...tls.getCACertificates('default'), ...tls.getCACertificates('system')];
    } catch {
      ca = [...tls.rootCertificates];
    }
    if (extraCA) ca.push(extraCA);
    this.agent = new https.Agent({ ca, keepAlive: true, maxSockets: 8, minVersion: 'TLSv1.2' });
    this.resolver = new dns.promises.Resolver({ timeout: 5000, tries: 2 });
    if (resolver) {
      this.resolver.setServers([resolver]);
      this.lookup = (host, opts, cb) => {
        this.resolver.resolve4(host).then(
          (addrs) => (opts && opts.all ? cb(null, addrs.map((a) => ({ address: a, family: 4 }))) : cb(null, addrs[0], 4)),
          (err) => cb(err),
        );
      };
    }
  }

  async txt(name) {
    const records = await this.resolver.resolveTxt(name);
    return records.map((chunks) => chunks.join(''));
  }

  // request sends one HTTPS request. body may be an object (sent as JSON) or
  // a Buffer. The answer is parsed as JSON unless raw is set. app is the app's
  // version, given only to the person's own server when joining and signing in.
  request(method, url, { body, token, app, raw = false, timeout = 30000, limit = 64 << 20 } = {}) {
    return new Promise((resolve, reject) => {
      const u = new URL(url);
      if (u.protocol !== 'https:') return reject(new Error('HTTPS only'));
      const headers = {};
      let data;
      if (Buffer.isBuffer(body)) {
        data = body;
        headers['Content-Type'] = 'application/octet-stream';
      } else if (body !== undefined) {
        data = Buffer.from(JSON.stringify(body));
        headers['Content-Type'] = 'application/json';
      }
      if (data) headers['Content-Length'] = data.length;
      if (token) headers.Authorization = 'Bearer ' + token;
      if (app) headers['Mohur-App'] = app;
      const req = https.request(u, { method, headers, agent: this.agent, lookup: this.lookup, timeout }, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > limit) req.destroy(new Error('response too large'));
          else chunks.push(c);
        });
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          if (res.statusCode !== 200) {
            let msg = `server answered ${res.statusCode}`;
            try { msg = JSON.parse(buf.toString('utf8')).error || msg; } catch { /* keep */ }
            return reject(new HttpError(res.statusCode, msg));
          }
          if (raw) return resolve(buf);
          try { resolve(JSON.parse(buf.toString('utf8'))); } catch (e) { reject(e); }
        });
        res.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new Error('request timed out')));
      req.on('error', reject);
      if (data) req.write(data);
      req.end();
    });
  }
}
