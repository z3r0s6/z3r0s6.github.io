# Blog Post Manager (`drafts.py`)

A small tool to manage which blog posts are drafts vs live, and to publish them
to GitHub safely — without ever leaking an embargoed draft into the public repo.

- **File:** `scripts/drafts.py`
- **Manages:** `src/content/posts/*.md`
- **Deploys to:** `origin/main` → GitHub Actions → GitHub Pages
  (`https://z3r0s6.github.io`)

---

## How the blog actually works (read this once)

The GitHub Actions workflow (`.github/workflows/deploy.yml`) **builds from source**:
on every push to `main` it runs `npm run build` and deploys the result.

That means the public repo contains your `.md` source files. A post with
`draft: true` is hidden from the *rendered site*, but if its `.md` ever gets
committed, the markdown is **publicly readable in the repo**.

So the rule for anything under embargo is: **keep it untracked until it's ready.**
The deploy command enforces this for you (see [Safety](#safety-what-deploy-will-never-do)).

Two states a post can be in:

| `draft:` value | On the live site? | Notes |
|---------------|-------------------|-------|
| `draft: true`  | Hidden            | Held back by `deploy`. Safe for embargoes. |
| `draft: false` | Visible           | Published on next `deploy`. |

If a post has **no** `draft:` line at all, it counts as live (`false` is the default).

---

## Requirements

- **Python 3** (no external packages, standard library only)
- **Node / npm** (for the local build validation the tool runs before pushing)
- **GitHub CLI (`gh`)**, installed and logged in — only needed for `deploy`:
  ```bash
  gh auth status        # should say "Logged in to github.com"
  # if not:
  gh auth login
  ```

---

## Quick start

```bash
cd /home/zeros/blog
python3 scripts/drafts.py          # interactive menu
python3 scripts/drafts.py list     # just print the table and exit
```

Example table:

```
  #   Status    Date         Title
  --------------------------------------------------------------------
  1   → LINK   2026-05-10   Machines
  2   → LINK   2026-05-10   Challenges
  3   ○ DRAFT  2026-07-21   Reading /etc/shadow Through rsync: Server-S...
  4   ● LIVE   2026-07-04   Gitea Draft-Release Attachments Leak to Any...
  --------------------------------------------------------------------
  1 live, 1 draft (list order = how the site shows them)
```

- `● LIVE`  — `draft: false`, on the site
- `○ DRAFT` — `draft: true`, hidden
- `→ LINK`  — nav stub (Machines/Challenges); the tool never publishes or drafts these

The list is sorted exactly how the site shows posts (nav links first, then newest first).

---

## Commands

Run these inside the interactive menu (`posts> `). Select posts by the `#` column.

| Command | What it does |
|---------|--------------|
| `list` | Reprint the table |
| `publish <sel>` | Set `draft: false` (make live) |
| `draft <sel>` | Set `draft: true` (hide) |
| `remove <sel>` | Delete the file(s) — asks you to type `yes` |
| `deploy [msg]` | Build, commit & push the live posts to GitHub — asks you to type `deploy` |
| `help` | Show command help |
| `quit` | Exit |

**Selection syntax** (`<sel>`) works with single numbers, commas, and ranges:

```
publish 4          # just #4
draft 3,5          # #3 and #5
remove 4-6         # #4, #5, #6
publish 3,5-7      # #3, #5, #6, #7
```

`publish`/`draft`/`remove` only change local files. **Only `deploy` touches GitHub.**

You can also run `deploy` (and `list`) straight from the shell:

```bash
python3 scripts/drafts.py deploy
python3 scripts/drafts.py deploy "publish gitea writeup"
```

---

## Adding a new post

### 1. Create the file

New file in `src/content/posts/`. **The filename is the URL slug.**

```
src/content/posts/my-new-finding.md   ->   https://z3r0s6.github.io/posts/my-new-finding/
```

Paste this template at the very top, then write your post under it:

```markdown
---
title: "My New Finding: Something Broke"
date: 2026-07-22
categories: ["Blog"]
tags: ["WordPress", "Access Control", "Research"]
author: "z3r0s"
draft: true
---

Your post content starts here. Plain markdown.
```

**Always start with `draft: true`.** It stays hidden and, because it's a new
untracked file, `deploy` will refuse to push it until you flip it to live.

### 2. Images (optional)

Put images in a folder named after the slug:

```
public/images/my-new-finding/screenshot.png
```

Reference them in the post with an absolute path:

```markdown
![what happened](/images/my-new-finding/screenshot.png)
```

When you publish the post, `deploy` automatically includes its image folder.

### 3. Preview locally (optional)

```bash
npm run dev      # http://127.0.0.1:4321
```

The dev server hides drafts just like production. To *see* a draft, publish it
locally first, look, then draft it again:

```bash
python3 scripts/drafts.py
posts> publish 5     # temporarily
# open http://127.0.0.1:4321/posts/my-new-finding/ , review
posts> draft 5       # hide again — nothing was pushed
```

### 4. Publish it

```bash
python3 scripts/drafts.py
posts> list          # find the number
posts> publish 5     # draft:false
posts> deploy        # confirm -> live in ~1 minute
```

---

## The `deploy` command in detail

`deploy`:

1. **Preflight** — checks you're in a git repo and `gh` is installed + logged in.
2. **Shows a plan** and groups every change:
   - `NEW PUBLIC POSTS` (red) — untracked posts now `draft:false`, about to go public
   - `update` — live posts whose content changed
   - `hide` — posts that were live and are now `draft:true`
   - `other tracked changes` — non-post files that changed (e.g. layout edits)
   - `held back` — embargoed drafts (untracked + `draft:true`); **never pushed**
3. Makes you type **`deploy`** to confirm.
4. Runs a local **`astro build`** — aborts if the build fails, nothing is pushed.
5. Stages **only** safe things (see below), commits, and `git push origin main`.
6. Prints how to watch CI: `gh run watch`.

### Safety: what `deploy` will *never* do

- It **never runs `git add -A`**.
- It stages `git add -u` (changes to already-tracked files) **plus** explicit adds
  of newly-published (`draft:false`) posts and their image folders.
- An **untracked `draft:true`** post is embargoed: it's listed under *held back*
  and is never staged.
- Before committing it runs a **final assertion** — if any previously-untracked
  draft somehow ended up staged, it runs `git reset` and aborts with nothing pushed.

This is why you can keep unpatched-0day writeups sitting in the posts folder as
`draft:true` without worrying they'll ship.

---

## Common workflows (copy/paste)

**Publish a finished draft**
```bash
python3 scripts/drafts.py
posts> publish 3
posts> deploy
```

**Publish several at once**
```bash
posts> publish 3,5-6
posts> deploy
```

**Hide a post that's currently live**
```bash
posts> draft 4
posts> deploy
```

**Delete a post from the site**
```bash
posts> remove 4        # type 'yes' to confirm
posts> deploy
```

**Check what's live right now, without opening the menu**
```bash
python3 scripts/drafts.py list
```

**Just see the deploy plan, then back out**
```bash
python3 scripts/drafts.py deploy
# read the plan, then type anything other than 'deploy' to cancel
```

---

## Watching a deploy

After `deploy` pushes, GitHub Actions builds and deploys automatically:

```bash
gh run watch                 # live progress of the latest run
gh run list --limit 3        # recent runs and their status
```

The site updates about a minute after the run goes green.

---

## Troubleshooting

- **`gh is not logged in`** → `gh auth login`
- **`build FAILED`** → your markdown/frontmatter has an error; the tool prints the
  build tail. Fix it and re-run `deploy`. Nothing was pushed.
- **A post won't show on the live site** → it's still `draft: true`, or the deploy
  hasn't finished. Check `python3 scripts/drafts.py list` and `gh run list`.
- **A post won't show on `npm run dev` either** → same reason; the dev server also
  hides drafts. Publish it locally to preview.
- **Title shows as the filename in the list** → the file's frontmatter is missing a
  `title:` line (or the file has no `--- ... ---` block).

---

## Golden rules

1. New posts start as `draft: true`.
2. Only `deploy` pushes to GitHub. `publish`/`draft`/`remove` are local edits.
3. Embargoed writeups stay `draft: true` and untracked until their CVE/clearance —
   the tool keeps them out of every push automatically.
