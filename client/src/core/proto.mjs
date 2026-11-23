// The values the app exchanges with Mohur servers, and the one signing format
// they share with the Go server (internal/proto): a context label and fields,
// each a 4-byte big-endian length and its bytes.
import crypto from 'node:crypto';

export const ContextOrg = 'mohur/org/v1';
export const ContextDevice = 'mohur/device/v1';
export const ContextSession = 'mohur/session/v1';

export const b64 = (buf) => Buffer.from(buf).toString('base64url');

export function unb64(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('invalid base64url');
  const b = Buffer.from(s, 'base64url');
  if (b64(b) !== s) throw new Error('invalid base64url');
  return b;
}

export function signedBytes(context, ...fields) {
  const parts = [];
  for (const f of [context, ...fields]) {
    const b = Buffer.from(String(f), 'utf8');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    parts.push(len, b);
  }
  return Buffer.concat(parts);
}

const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

export function ed25519Public(raw) {
  const b = typeof raw === 'string' ? unb64(raw) : raw;
  if (b.length !== 32) throw new Error('invalid Ed25519 key');
  return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI, b]), format: 'der', type: 'spki' });
}

export function verify(publicRaw, sig, context, ...fields) {
  try {
    const s = unb64(sig);
    return s.length === 64 && crypto.verify(null, signedBytes(context, ...fields), ed25519Public(publicRaw), s);
  } catch {
    return false;
  }
}

export function sign(privateKey, context, ...fields) {
  return b64(crypto.sign(null, signedBytes(context, ...fields), privateKey));
}

const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export function domainOK(d) {
  return typeof d === 'string' && d.length <= 253 && d.includes('.') && d.split('.').every((l) => label.test(l));
}

export function parseAddress(a) {
  const m = /^([a-z0-9][a-z0-9._-]{0,31})@(.+)$/.exec(a || '');
  if (!m || !domainOK(m[2])) throw new Error('invalid address');
  return { user: m[1], domain: m[2] };
}

// serverOK mirrors proto.ServerName: the host is the domain or under it.
export function serverOK(server, domain) {
  const m = /^([a-z0-9.-]+)(?::([0-9]{1,5}))?$/.exec(server || '');
  if (!m || !domainOK(m[1])) return false;
  if (m[2] !== undefined && (Number(m[2]) < 1 || Number(m[2]) > 65535 || String(Number(m[2])) !== m[2])) return false;
  return m[1] === domain || m[1].endsWith('.' + domain);
}

export function parseTXT(records, domain) {
  const found = records.filter((r) => r === 'v=mohur1' || r.startsWith('v=mohur1 '));
  if (found.length !== 1) throw new Error('no single Mohur record');
  const out = {};
  for (const f of found[0].split(/\s+/).slice(1)) {
    const i = f.indexOf('=');
    if (i < 1) throw new Error('bad record');
    const k = f.slice(0, i);
    const v = f.slice(i + 1);
    if (k in out) throw new Error('bad record');
    out[k] = v;
  }
  if (!serverOK(out.server, domain)) throw new Error('server not under the domain');
  if (unb64(out.key || '').length !== 32) throw new Error('bad key');
  return { server: out.server, key: out.key };
}

export function checkOrgDoc(d) {
  if (!d || d.v !== 1 || !domainOK(d.domain) || !serverOK(d.server, d.domain) || typeof d.name !== 'string' || !d.name) return false;
  return verify(d.key, d.sig, ContextOrg, d.domain, d.name, d.server, d.key);
}

export function checkCert(c, orgKey, domain) {
  try {
    const { domain: d } = parseAddress(c.address);
    if (d !== domain || !Number.isInteger(c.device) || c.device < 1) return false;
    const ik = unb64(c.identityKey);
    if (ik.length !== 33 || ik[0] !== 5 || unb64(c.authKey).length !== 32) return false;
    return verify(orgKey, c.sig, ContextDevice, c.address, c.name, String(c.device), c.identityKey, c.authKey, String(c.issued));
  } catch {
    return false;
  }
}
