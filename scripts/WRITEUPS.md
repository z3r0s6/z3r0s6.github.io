# Writeup Manager (`writeups.py`)

Manages **machines** and **challenges** — the HTB/CTF writeups. This is a
different tool from `drafts.py` (which handles blog *posts*), because machines
and challenges use a **password/lock** system instead of a draft flag.

- **File:** `scripts/writeups.py`
- **Manages:** `src/content/machines/*.md` and `src/content/challenges/*.md`
- **Logos:** `public/logos/`
- **Deploys to:** `origin/main` → GitHub Actions → GitHub Pages

---

## How the lock works (read once)

An active box's writeup is **AES-encrypted at build time** (`scripts/encrypt.mjs`)
so it stays spoiler-free. You make a writeup public by inserting a marker span in
its markdown:

```html
<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
```

| Marker in the `.md`? | State | Meaning |
|----------------------|-------|---------|
| **absent**  | 🔒 **LOCKED** | Encrypted on the site (box is active). |
| **present** | 🔓 **PUBLIC** | Published in the clear (box retired). |

So **"remove the password when a box retires" = `unlock`** (it adds the marker).
`unlock`/`lock` only toggle that one marker line — **your writeup text is never
edited or redacted.**

The password itself (`Z3R0S{IH4TESPOILERS}`) lives in `src/config.ts` and
`scripts/encrypt.mjs`; this tool never touches it.

---

## Requirements

- **Python 3** (standard library only)
- **Node / npm** (for the build validation `deploy` runs)
- **GitHub CLI (`gh`)** installed + logged in — for `deploy` only
  (`gh auth status`, or `gh auth login`)

---

## Quick start

```bash
cd /home/zeros/blog
python3 scripts/writeups.py            # interactive menu
python3 scripts/writeups.py list       # print the table and exit
```

The table shows kind, lock state, whether the logo file exists, date, and title:

```
  #   Kind        Lock        Logo   Date         Title
  --------------------------------------------------------------------------
  7   machine     🔒 LOCKED  ok     2026-06-06   HTB - Connected
  5   machine     🔓 PUBLIC  ok     2026-06-07   HTB - Abducted
  10  machine     🔒 LOCKED  MISS   2026-05-18   HTB - SmartHire   <- logo missing
  29  challenge   🔓 PUBLIC    -    2026-05-10   Pwn - cyKer
```

`Logo` column: `ok` = file exists, `MISS` = `featuredImage` points at a file that
isn't in `public/logos/`, `none` = no logo set.

---

## Commands

| Command | What it does |
|---------|--------------|
| `list` | Reprint the table |
| `add` | Create a machine/challenge (asks for the `.md` body path and logo path) |
| `unlock <sel>` / `retire <sel>` | Remove the password → 🔓 PUBLIC (use when a box retires) |
| `lock <sel>` | Re-protect with the password → 🔒 LOCKED |
| `deploy [msg]` | Build, commit & push (machines/challenges/logos only) |
| `help` / `quit` | — |

**`<sel>` = list number(s) or a name.** All of these work:

```
unlock 7
unlock connected          # match by slug/title
retire connected          # alias for unlock
lock 2,4-5
```

Same commands work straight from the shell:

```bash
python3 scripts/writeups.py unlock connected
python3 scripts/writeups.py deploy "retire Connected"
```

---

## Adding a machine or challenge

Run `add` (menu) or `python3 scripts/writeups.py add`. It asks for:

1. **Type** — `machine` or `challenge`
2. **Path to the writeup `.md` file** — your writeup body. If that file has its own
   `--- frontmatter ---`, it's stripped and its values are used as defaults; only
   the body is imported (no double frontmatter).
3. **Title / Slug / Date / Author / Tags** — defaults offered
4. **Difficulty / OS** — machines only
5. **Path to the logo image** — machines only. The file is **copied into
   `public/logos/`** and `featuredImage` is set for you.
6. **Password-protect? (Y/n)** — default **Y** (locked/encrypted). Choose `n` to
   publish immediately (adds the marker).

Example:

```
python3 scripts/writeups.py add
  Type (machine / challenge) [machine]: machine
  Path to the writeup .md file: ~/Desktop/connected.md
  Title [HTB - Connected]:
  Slug [htb-connected]: connected
  Date (YYYY-MM-DD) [2026-06-06]:
  Author [z3r0s]:
  Tags (comma separated) [HackTheBox,Linux]: HackTheBox,Linux,SUID
  Difficulty [Easy]: Medium
  OS [Linux]:
  Path to the logo image: ~/Desktop/Connected.png
  Save logo as [connected.png]: Connected.png
  Password-protect (lock) this writeup? (Y/n) [Y]: Y

  copied logo -> public/logos/Connected.png
  ✅ created src/content/machines/connected.md
     🔒 LOCKED (encrypted on the site) — run `unlock` when retired.
```

Then `deploy` when you want it on the site.

---

## Retiring a box (remove the password)

When HTB retires a machine:

```bash
python3 scripts/writeups.py
writeups> unlock connected      # marker added -> 🔓 PUBLIC
writeups> deploy "retire Connected"
```

The writeup renders in the clear on the next build. To re-hide it: `lock connected`.

---

## `deploy` — what it stages

`deploy` is **scoped**. It only ever stages:

```
src/content/machines/    src/content/challenges/    public/logos/
```

- It **never** runs `git add -A`, and it **hard-aborts** (with `git reset`) if
  anything outside that scope ends up staged.
- So it cannot touch or publish your blog posts / embargoed drafts. Use
  `drafts.py` for posts, this tool for boxes.
- It runs a local `astro build` first and aborts if the build fails.

Flow: shows the changed files → you type `deploy` → build check → stage scope →
scope assertion → commit → `git push origin main` → prints `gh run watch`.

> Note: a **LOCKED** writeup is encrypted on the *site*, but its markdown **source
> is committed to the public repo** (same as the old `npm run deploy`). The lock
> protects the rendered page, not the repo source.

---

## Troubleshooting

- **`Logo` shows `MISS`** → `featuredImage` in that `.md` points to a file not in
  `public/logos/`. Fix the path or add the image. (SmartHire currently shows this.)
- **`build FAILED` on deploy** → frontmatter/markdown error; the tool prints the
  tail. Fix and re-run. Nothing was pushed.
- **`gh is not logged in`** → `gh auth login`.
- **Title shows as the filename** → the `.md` is missing a `title:` line.

---

## Golden rules

1. New boxes start **LOCKED** (encrypted) by default.
2. `unlock` = remove password = make public — use it **only after HTB retires** the box.
3. `unlock`/`lock` toggle only the marker line; they never edit writeup content.
4. `deploy` here is scoped to machines/challenges/logos — it can't publish posts.
