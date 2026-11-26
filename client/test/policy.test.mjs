// The privacy page and terms of use: the app can show them, every promise
// can be checked, and the app holds no address of denyfirst's.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parsePolicy, POLICIES } from '../src/core/policy.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (name) => fs.readFileSync(path.join(root, 'docs', 'policies', name + '.md'), 'utf8');
const text = (parts) => parts.map((p) => p.v).join('');

test('both policies are in the part of Markdown the app shows', () => {
  for (const name of POLICIES) {
    const blocks = parsePolicy(read(name));
    assert.equal(blocks[0].t, 'h1', name);
    assert.match(text(blocks[1].inline), /^Last changed \d{1,2} [A-Z][a-z]+ \d{4}\.$/, name + ' says when it last changed');
    for (const b of blocks) {
      for (const parts of b.items || [b.inline]) {
        for (const p of parts) {
          if (p.t === 'link') assert.match(p.href, /^https:\/\/[a-z0-9.-]+\//, `${name}: ${p.href}`);
        }
      }
    }
  }
});

test('every promise says how to check it, and the tests it names exist', () => {
  const blocks = parsePolicy(read('privacy'));
  const start = blocks.findIndex((b) => b.t === 'h2' && text(b.inline) === 'What Mohur promises');
  const end = blocks.findIndex((b, i) => i > start && b.t === 'h2');
  const promises = [];
  for (let i = start + 1; i < end; i++) {
    if (blocks[i].t === 'h3') promises.push({ title: text(blocks[i].inline), body: [] });
    else if (promises.length) promises.at(-1).body.push(blocks[i]);
  }
  assert.equal(promises.length, 7);
  const sources = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (['node_modules', '.work', '.git'].includes(e.name)) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(go|mjs)$/.test(e.name)) sources.push(fs.readFileSync(p, 'utf8'));
    }
  };
  walk(path.join(root, 'internal'));
  walk(path.join(root, 'client', 'test'));
  walk(path.join(root, 'client', 'src'));
  const ids = new Set();
  for (const p of promises) {
    const check = p.body.find((b) => b.t === 'p' && b.inline[0].t === 'b' && b.inline[0].v === 'How you check it.');
    assert.ok(check, `"${p.title}" says how to check it`);
    const id = /ID: (mohur-[a-z0-9-]+)\.$/.exec(text(check.inline));
    assert.ok(id && check.inline.at(-2).t === 'code', `"${p.title}" ends with its ID`);
    assert.ok(!ids.has(id[1]), 'IDs are unique');
    ids.add(id[1]);
    for (const named of text(check.inline).matchAll(/\bTest[A-Z]\w+/g)) {
      assert.ok(sources.some((s) => s.includes(`func ${named[0]}(`)), `${named[0]} exists`);
    }
    for (const c of check.inline.filter((x) => x.t === 'code' && /^(client|internal)\//.test(x.v))) {
      assert.ok(fs.existsSync(path.join(root, c.v)), `${c.v} exists`);
    }
  }
});

test('the app holds no address of denyfirst\'s', () => {
  const files = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else files.push(p);
    }
  };
  walk(path.join(root, 'client', 'src'));
  walk(path.join(root, 'client', 'assets'));
  for (const f of files) assert.equal(/denyfirst\.(dev|com|net|org)/.test(fs.readFileSync(f, 'latin1')), false, path.relative(root, f));
});

test('crash reports stay on this computer and go at the next start', () => {
  const main = fs.readFileSync(path.join(root, 'client', 'src', 'main.mjs'), 'utf8');
  assert.match(main, /crashReporter\.start\(\{ uploadToServer: false, ignoreSystemCrashHandler: true \}\)/);
  assert.doesNotMatch(main, /submitURL/);
  const wipe = main.indexOf('rmSync(crashDir, { recursive: true, force: true })');
  assert.ok(wipe > 0 && wipe < main.indexOf("app.setPath('crashDumps', crashDir)") && wipe < main.indexOf('crashReporter.start('), 'the old reports go before the reporter starts');
});

test('anything outside that part of Markdown is refused', () => {
  const ok = '# Title\n\nLast changed 1 January 2027.\n\n';
  for (const bad of [
    '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '| a | b |', '```\ncode\n```', '1. first', '* star', '> quote',
    '    indented', '[link](http://plain.example/)', '[mail](mailto:a@b.c)', '![image](https://x.example/a.png)', '**open bold', 'a `tick', 'an *emphasis*', 'an _emphasis_', 'an &amp; entity', 'an \\* escape', 'some <b>html</b> inside', '- a list <i>item</i>',
  ]) {
    assert.throws(() => parsePolicy(ok + bad), undefined, JSON.stringify(bad));
  }
  assert.throws(() => parsePolicy('No title\n'));
  assert.throws(() => parsePolicy(''));
  assert.throws(() => parsePolicy('# T\n' + 'x'.repeat(70000)));
  assert.throws(() => parsePolicy(null));
  const blocks = parsePolicy(ok + 'Some **bold**, `code` and a [link](https://example.com/a).\n\n- one\n  more\n- two\n\n## Next');
  assert.deepEqual(blocks.slice(2), [
    { t: 'p', inline: [{ t: 'text', v: 'Some ' }, { t: 'b', v: 'bold' }, { t: 'text', v: ', ' }, { t: 'code', v: 'code' }, { t: 'text', v: ' and a ' }, { t: 'link', v: 'link', href: 'https://example.com/a' }, { t: 'text', v: '.' }] },
    { t: 'ul', items: [[{ t: 'text', v: 'one more' }], [{ t: 'text', v: 'two' }]] },
    { t: 'h2', inline: [{ t: 'text', v: 'Next' }] },
  ]);
});
