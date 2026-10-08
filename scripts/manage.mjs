#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────
//  Content manager for the blog.
//
//  Add content:
//    npm run new                       (interactive)
//
//  Remove the password from a writeup (make it public):
//    npm run unlock -- https://z3r0s6.github.io/machines/connected/
//    npm run unlock -- machines/connected
//    npm run unlock -- connected
//
//  Re-protect a writeup with the password:
//    npm run lock -- challenges/crypto-aliens
//
//  After editing, publish with:  npm run deploy
// ─────────────────────────────────────────────────────────────
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { stdin as input, stdout as output } from 'node:process';
import { fileURLToPath } from 'node:url';

// Line-buffered prompt that works both interactively and with piped input
// (plain readline/promises can drop buffered lines when stdin is a pipe).
function makeAsker() {
  const rl = readline.createInterface({ input, output });
  const queue = [];
  const waiters = [];
  let closed = false;
  rl.on('line', (line) => (waiters.length ? waiters.shift()(line) : queue.push(line)));
  rl.on('close', () => {
    closed = true;
    while (waiters.length) waiters.shift()(null);
  });
  const ask = async (q, def = '') => {
    output.write(def ? `${q} [${def}]: ` : `${q}: `);
    const line = await new Promise((res) => {
      if (queue.length) res(queue.shift());
      else if (closed) res(null);
      else waiters.push(res);
    });
    const a = (line ?? '').trim();
    return a || def;
  };
  return { ask, close: () => rl.close() };
}

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTENT = path.join(ROOT, 'src', 'content');
const SECTIONS = ['machines', 'challenges', 'posts'];
const ENCRYPTABLE = ['machines', 'challenges'];
const MARKER = '<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>';

const slugify = (s) =>
  s
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

const today = () => new Date().toISOString().slice(0, 10);

// Turn a URL / path / bare slug into { section, slug, file }.
function resolveTarget(raw) {
  let s = (raw || '').trim();
  if (!s) throw new Error('No writeup link/slug given.');
  s = s.replace(/^https?:\/\/[^/]+/i, ''); // drop scheme + host
  const parts = s.split('/').filter(Boolean); // e.g. ["machines","connected"]

  let section, slug;
  if (parts.length >= 2 && SECTIONS.includes(parts[0])) {
    section = parts[0];
    slug = parts[1];
  } else {
    slug = parts[parts.length - 1]; // bare slug — search every section
  }

  const candidates = section ? [section] : SECTIONS;
  for (const sec of candidates) {
    const file = path.join(CONTENT, sec, `${slug}.md`);
    if (fs.existsSync(file)) return { section: sec, slug, file };
  }
  throw new Error(`Writeup not found for "${raw}". Looked for ${slug}.md in ${candidates.join(', ')}.`);
}

// Insert the marker right after the closing frontmatter fence.
function addMarker(text) {
  const m = text.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n/);
  if (!m) return `${MARKER}\n\n${text}`;
  const idx = m[0].length;
  return `${text.slice(0, idx)}\n${MARKER}\n${text.slice(idx)}`;
}

function unlock(raw) {
  const { section, slug, file } = resolveTarget(raw);
  const text = fs.readFileSync(file, 'utf8');
  if (text.includes('Z3R0S_NO_PASSWORD_PLEASE')) {
    console.log(`✓ ${section}/${slug} is already public (no password).`);
    return;
  }
  fs.writeFileSync(file, addMarker(text));
  console.log(`🔓 Unlocked ${section}/${slug} — it will be public on the next build.`);
  console.log('   Publish with:  npm run deploy');
}

function lock(raw) {
  const { section, slug, file } = resolveTarget(raw);
  let text = fs.readFileSync(file, 'utf8');
  if (!text.includes('Z3R0S_NO_PASSWORD_PLEASE')) {
    console.log(`✓ ${section}/${slug} is already password-protected.`);
    return;
  }
  // Remove the marker line (and a trailing blank line if left behind).
  text = text
    .split(/\r?\n/)
    .filter((line) => !line.includes('Z3R0S_NO_PASSWORD_PLEASE'))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n');
  fs.writeFileSync(file, text);
  console.log(`🔒 Locked ${section}/${slug} — password-protected on the next build.`);
  console.log('   Publish with:  npm run deploy');
}

async function create() {
  const { ask, close } = makeAsker();

  try {
    let type = (await ask('Type (machine / challenge / post)', 'machine')).toLowerCase();
    const map = { machine: 'machines', challenge: 'challenges', post: 'posts', machines: 'machines', challenges: 'challenges', posts: 'posts' };
    const section = map[type];
    if (!section) throw new Error(`Unknown type "${type}".`);

    const title = await ask('Title');
    if (!title) throw new Error('Title is required.');
    const slug = slugify(await ask('Slug', slugify(title)));
    const file = path.join(CONTENT, section, `${slug}.md`);
    if (fs.existsSync(file)) throw new Error(`Already exists: ${section}/${slug}.md`);

    const date = await ask('Date (YYYY-MM-DD)', today());
    const author = await ask('Author', 'z3r0s');
    const tagsRaw = await ask('Tags (comma separated)', section === 'machines' ? 'HackTheBox,Linux' : '');
    const tags = tagsRaw ? tagsRaw.split(',').map((t) => t.trim()).filter(Boolean) : [];

    const fm = ['---', `title: "${title.replace(/"/g, '\\"')}"`, `date: ${date}`];
    fm.push(`tags: [${tags.map((t) => `"${t}"`).join(', ')}]`);

    if (section === 'machines') {
      const difficulty = await ask('Difficulty', 'Easy');
      const os = await ask('OS', 'Linux');
      const featured = await ask('Featured logo path (optional, e.g. /logos/Foo.png)', '');
      fm.push('categories: ["Machines&Challenges"]');
      fm.push(`difficulty: "${difficulty}"`);
      fm.push(`os: "${os}"`);
      if (featured) fm.push(`featuredImage: "${featured}"`);
    } else if (section === 'challenges') {
      fm.push('categories: ["Machines&Challenges"]');
    } else {
      fm.push('categories: ["Blog"]');
    }
    fm.push(`author: "${author}"`);
    fm.push('---');

    // Password protection (machines & challenges only).
    let markerBlock = '';
    if (ENCRYPTABLE.includes(section)) {
      const prot = (await ask('Password-protect this writeup? (Y/n)', 'Y')).toLowerCase();
      if (prot.startsWith('n')) markerBlock = `\n${MARKER}\n`;
    }

    // Body: import an existing markdown file, or start with a placeholder.
    const bodyPath = await ask('Path to a markdown file for the body (optional)', '');
    let body = 'Write your content here.\n';
    if (bodyPath) {
      const p = bodyPath.replace(/^['"]|['"]$/g, '');
      if (!fs.existsSync(p)) throw new Error(`Body file not found: ${p}`);
      body = fs.readFileSync(p, 'utf8');
    }

    fs.writeFileSync(file, `${fm.join('\n')}\n${markerBlock}\n${body}`);
    console.log(`\n✅ Created ${path.relative(ROOT, file)}`);
    if (ENCRYPTABLE.includes(section)) {
      console.log(markerBlock ? '   → Public (no password).' : '   → Password-protected until you run "npm run unlock".');
    }
    console.log('   Preview with:  npm run dev');
    console.log('   Publish with:  npm run deploy');
  } finally {
    close();
  }
}

const [cmd, ...rest] = process.argv.slice(2);
const arg = rest.join(' ');

try {
  switch (cmd) {
    case 'new':
    case 'add':
      await create();
      break;
    case 'unlock':
      unlock(arg);
      break;
    case 'lock':
      lock(arg);
      break;
    default:
      console.log('Usage:');
      console.log('  npm run new                         # add a machine / challenge / post');
      console.log('  npm run unlock -- <link|slug>       # remove the password (make public)');
      console.log('  npm run lock -- <link|slug>         # re-protect with the password');
      process.exit(cmd ? 1 : 0);
  }
} catch (err) {
  console.error(`✗ ${err.message}`);
  process.exit(1);
}
