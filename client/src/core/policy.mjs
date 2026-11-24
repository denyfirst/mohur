// Reads Mohur's privacy page and terms of use (docs/policies) into plain
// blocks the window can show. The files use a small part of Markdown on
// purpose: headings, paragraphs, lists, **bold**, `code` and [links](https://…).
// Anything else is refused, so a page never shows differently in the app
// from on the website. The window builds text nodes only, never HTML.

const MAX = 64 << 10;

export const POLICIES = ['privacy', 'terms'];

// inline splits a line into text, bold, code and link pieces.
function inline(text, where) {
  if (/!\[/.test(text)) throw new Error(`${where}: images are not shown`);
  const out = [];
  const re = /\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\((https:\/\/[^\s)]+)\)/g;
  let at = 0;
  for (let m; (m = re.exec(text));) {
    if (m.index > at) out.push({ t: 'text', v: text.slice(at, m.index) });
    if (m[1] !== undefined) out.push({ t: 'b', v: m[1] });
    else if (m[2] !== undefined) out.push({ t: 'code', v: m[2] });
    else out.push({ t: 'link', v: m[3], href: m[4] });
    at = re.lastIndex;
  }
  if (at < text.length) out.push({ t: 'text', v: text.slice(at) });
  for (const p of out) {
    if (p.t === 'text' && /[*`\\]|\]\(|<[a-z!/]|&#?\w+;|(^|[^\w])_\S/i.test(p.v)) throw new Error(`${where}: unsupported markup in "${p.v.trim().slice(0, 40)}"`);
  }
  return out;
}

// parsePolicy turns a policy file into blocks:
// { t: 'h1' | 'h2' | 'h3' | 'p', inline } and { t: 'ul', items: [inline] }.
export function parsePolicy(source) {
  if (typeof source !== 'string' || source.length > MAX) throw new Error('A policy file is missing or too long.');
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const blocks = [];
  let para = null;
  let list = null;
  const flush = () => {
    if (para) blocks.push({ t: 'p', inline: inline(para.join(' '), 'paragraph') });
    if (list) blocks.push({ t: 'ul', items: list.map((item) => inline(item.join(' '), 'list')) });
    para = list = null;
  };
  lines.forEach((raw, i) => {
    const line = raw.trimEnd();
    const where = `line ${i + 1}`;
    if (line === '') return flush();
    const h = /^(#{1,3}) (.+)$/.exec(line);
    if (h) {
      flush();
      blocks.push({ t: 'h' + h[1].length, inline: inline(h[2], where) });
      return;
    }
    if (line.startsWith('- ')) {
      if (para) flush();
      (list ||= []).push([line.slice(2)]);
      return;
    }
    if (line.startsWith('  ') && list) {
      list.at(-1).push(line.trim());
      return;
    }
    if (/^(\s|#|>|\||```|\d+\.|\* |<)/.test(line)) throw new Error(`${where}: only headings, paragraphs and "- " lists are shown`);
    if (list) flush();
    (para ||= []).push(line);
  });
  flush();
  if (!blocks.length || blocks[0].t !== 'h1') throw new Error('A policy starts with a "# " title.');
  return blocks;
}
