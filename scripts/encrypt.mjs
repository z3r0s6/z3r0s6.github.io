// Post-build step: AES-encrypt machine/challenge writeups in the built site
// so active boxes stay spoiler-free until retired. Mirrors the original
// Hugo `encrypt_writeups.js`. Runs automatically via the `postbuild` script.
//
// To publish a writeup immediately (no password), add this marker anywhere in
// its Markdown body:
//   <span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as cheerio from 'cheerio';
import CryptoJS from 'crypto-js';

// Keep this in sync with WRITEUP_PASSWORD in src/config.ts.
const PASSWORD = 'Z3R0S{IH4TESPOILERS}';
const NO_PASSWORD_MARKER = 'Z3R0S_NO_PASSWORD_PLEASE';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(__dirname, '..', 'dist');
const DIRS = [path.join(DIST, 'machines'), path.join(DIST, 'challenges')];

function walk(dir, cb) {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    fs.statSync(p).isDirectory() ? walk(p, cb) : cb(p);
  }
}

let encrypted = 0;
let skipped = 0;

function processFile(filePath) {
  if (!filePath.endsWith('.html')) return;
  const html = fs.readFileSync(filePath, 'utf8');
  if (html.includes(NO_PASSWORD_MARKER)) {
    skipped++;
    return;
  }

  const $ = cheerio.load(html);
  const body = $('.writeup-body');
  if (body.length === 0) return;

  const innerHtml = body.html();
  const ciphertext = CryptoJS.AES.encrypt(innerHtml, PASSWORD).toString();

  const ui = `
    <div id="encryption-ui" class="lock-ui">
      <h3>This content is password-protected while the machine/challenge is active. It will be published once retired.</h3>
      <div class="lock-row">
        <input type="password" id="decrypt-password" placeholder="Enter password" />
        <button id="decrypt-btn">Unlock</button>
      </div>
      <p id="decrypt-error" class="lock-error">Incorrect password.</p>
    </div>
    <div id="encrypted-content" style="display:none;">${ciphertext}</div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"><\/script>
    <script>
      (function () {
        var btn = document.getElementById('decrypt-btn');
        var input = document.getElementById('decrypt-password');
        function unlock() {
          var pass = input.value;
          var ct = document.getElementById('encrypted-content').innerText;
          try {
            var bytes = CryptoJS.AES.decrypt(ct, pass);
            var text = bytes.toString(CryptoJS.enc.Utf8);
            if (!text) throw new Error('bad password');
            document.querySelector('.writeup-body').innerHTML = text;
          } catch (e) {
            document.getElementById('decrypt-error').style.display = 'block';
          }
        }
        btn.addEventListener('click', unlock);
        input.addEventListener('keyup', function (e) { if (e.key === 'Enter') unlock(); });
      })();
    <\/script>
  `;

  body.html(ui);
  fs.writeFileSync(filePath, $.html());
  encrypted++;
}

for (const dir of DIRS) {
  if (fs.existsSync(dir)) walk(dir, processFile);
  else console.warn('[encrypt] directory not found (no entries?):', dir);
}
console.log(`[encrypt] done — ${encrypted} protected, ${skipped} public.`);
