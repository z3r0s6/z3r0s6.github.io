# 📓 Blog Usage Guide

Everything you need to run the blog, add content, and control password protection.
Live site: **https://z3r0s6.github.io** (auto-deploys on every push to `main`).

---

## Table of contents

1. [Everyday commands](#1-everyday-commands)
2. [Add content](#2-add-content-npm-run-new)
3. [Password: unlock / lock](#3-password-unlock--lock)
4. [Publish (deploy)](#4-publish-deploy)
5. [Markdown & front-matter format](#5-markdown--front-matter-format)
6. [Where things live](#6-where-things-live)
7. [FAQ / troubleshooting](#7-faq--troubleshooting)

---

## 1. Everyday commands

```bash
npm install        # first time only — install dependencies
npm run dev        # live preview at http://localhost:4321
npm run build      # build the site into ./dist (applies password encryption)
npm run preview    # preview the built (encrypted) site locally
```

> In `npm run dev` writeups are shown **unencrypted** so you can edit them.
> Encryption is only applied by `npm run build` (and in the GitHub Actions deploy).

---

## 2. Add content (`npm run new`)

Interactive wizard to create a **machine**, **challenge**, or **post**.
It asks for the title, tags, date, and — for machines/challenges — whether to
**password-protect** it.

```bash
npm run new
```

Example session (typing a new machine):

```text
Type (machine / challenge / post) [machine]: machine
Title: HTB - Example
Slug [htb-example]:                       ← press Enter to accept
Date (YYYY-MM-DD) [2026-07-01]:           ← press Enter for today
Author [z3r0s]:
Tags (comma separated) [HackTheBox,Linux]: HackTheBox,Linux,Web
Difficulty [Easy]: Medium
OS [Linux]: Linux
Featured logo path (optional, e.g. /logos/Foo.png): /logos/Example.png
Password-protect this writeup? (Y/n) [Y]: Y
Path to a markdown file for the body (optional): ~/notes/example.md
```

Result:

```text
✅ Created src/content/machines/htb-example.md
   → Password-protected until you run "npm run unlock".
```

**Tips**

- Leave **body path** blank to get a placeholder you can fill in later.
- To import an existing writeup, pass its `.md` path at the **body** prompt.
- Put the machine logo in `public/logos/` and reference it as `/logos/Name.png`.
- **Posts are never encrypted** (the password question is skipped for posts).

---

## 3. Password: unlock / lock

All protected writeups share one password: **`Z3R0S{IH4TESPOILERS}`**.

### Make a writeup public (remove the password)

Paste the **live link**, a `section/slug`, or just the **slug**:

```bash
npm run unlock -- https://z3r0s6.github.io/machines/connected/
npm run unlock -- machines/connected
npm run unlock -- connected
```

```text
🔓 Unlocked machines/connected — it will be public on the next build.
   Publish with:  npm run deploy
```

### Re-protect a writeup (add the password back)

```bash
npm run lock -- challenges/crypto-aliens
```

```text
🔒 Locked challenges/crypto-aliens — password-protected on the next build.
```

> Under the hood, "public" just means the file contains a hidden marker:
> `<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>`
> — `unlock` adds it, `lock` removes it.

---

## 4. Publish (deploy)

Commit your changes and push — GitHub Actions rebuilds and deploys automatically:

```bash
npm run deploy
```

This runs `git add -A && git commit -m "content update" && git push`.
Watch the build at **https://github.com/z3r0s6/z3r0s6.github.io/actions**.

> First-time git auth: run `gh auth login` then `gh auth setup-git` once, so
> `git push` works without prompting.

---

## 5. Markdown & front-matter format

Each writeup is a Markdown file. The block between the `---` lines at the top is
**front-matter** (metadata). Everything below it is the content.

### Machine — `src/content/machines/<slug>.md`

```markdown
---
title: "HTB - Example"
date: 2026-07-01
tags: ["HackTheBox", "Linux", "Web"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Example.png"
---

## Recon

Your writeup content in **Markdown** goes here.
```

### Challenge — `src/content/challenges/<slug>.md`

```markdown
---
title: "Crypto - Example"
date: 2026-07-01
tags: ["HackTheBox", "Crypto"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---

## Challenge Summary

Content here.
```

### Post — `src/content/posts/<slug>.md`

```markdown
---
title: "My Research Post"
date: 2026-07-01
tags: ["Android", "Research"]
categories: ["Blog"]
author: "z3r0s"
---

Post body here.
```

### Front-matter fields

| Field | Used by | Required | Notes |
|-------|---------|----------|-------|
| `title` | all | ✅ | Shown as the page heading |
| `date` | all | ✅ | `YYYY-MM-DD`; sorts newest-first |
| `tags` | all | – | Array of strings, e.g. `["HackTheBox", "Linux"]` |
| `categories` | all | – | Machines/challenges use `["Machines&Challenges"]` |
| `author` | all | – | Defaults shown as-is |
| `difficulty` | machines | – | `Easy` / `Medium` / `Hard` — colored badge |
| `os` | machines | – | e.g. `Linux`, `Windows` |
| `featuredImage` | machines | – | Path under `public/`, e.g. `/logos/Foo.png` |
| `draft` | all | – | `true` hides it from the site |

### Making a writeup public in the file itself

To publish without a password, add this line right under the front-matter
(this is exactly what `npm run unlock` does for you):

```markdown
---
title: "..."
date: 2026-07-01
---

<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>

## Your content...
```

### Common Markdown you can use

```markdown
## Heading

**bold**, *italic*, `inline code`, [a link](https://example.com)

- bullet list
- second item

> a blockquote / callout

![image alt text](/images/my-folder/screenshot.png)

​```python
print("fenced code block with syntax highlighting")
​```

| col A | col B |
|-------|-------|
| 1     | 2     |
```

> Images go in `public/images/...` and are referenced with an **absolute** path
> starting with `/` (e.g. `/images/example/pic.png`).

---

## 6. Where things live

| What | Path |
|------|------|
| Name, bio, socials, avatar | `src/config.ts` |
| Colors / fonts / theme | `src/styles/global.css` (CSS variables at top) |
| Machine writeups | `src/content/machines/` |
| Challenge writeups | `src/content/challenges/` |
| Posts | `src/content/posts/` |
| Images & logos | `public/images/`, `public/logos/` |
| Encryption step | `scripts/encrypt.mjs` |
| Content tool | `scripts/manage.mjs` |
| Deploy workflow | `.github/workflows/deploy.yml` |

---

## 7. FAQ / troubleshooting

**The writeup shows as plain text locally but locked on the site — why?**
That's expected. `npm run dev` shows unencrypted content for editing; encryption
is applied by `npm run build` and the live deploy.

**I changed the password. What else do I update?**
The password is in **two places that must match**: `WRITEUP_PASSWORD` in
`src/config.ts` and `PASSWORD` in `scripts/encrypt.mjs`.

**A new machine still asks for a password after I published it.**
Run `npm run unlock -- <slug>` then `npm run deploy`. Rebuilding is required.

**`npm run deploy` says "nothing to commit".**
You have no changes staged — edit or add content first.

**Build fails on an image "Could not find requested image".**
Use an **absolute** image path (`/images/...`) and make sure the file exists in
`public/`. Relative paths like `![x](pic.png)` are treated as bundled assets.

**`git push` asks for a password / fails.**
Run `gh auth login` and `gh auth setup-git` once to configure git credentials.
```
