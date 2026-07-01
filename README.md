# z3r0s blog

A minimalist, dark, monospace security blog built with [Astro](https://astro.build).
Homepage + HackTheBox machine writeups, CTF challenge writeups, and research posts.
Active machine/challenge writeups are AES-encrypted (password-protected) until retired.

Live: **https://z3r0s6.github.io** — auto-deploys from `main` via GitHub Actions.

## Develop

```bash
npm install
npm run dev        # http://localhost:4321  (writeups shown unencrypted for editing)
npm run build      # → ./dist, with password-encryption applied
```

## Content tools

```bash
# Add a machine / challenge / post (interactive; asks password-protect or not)
npm run new

# Remove the password from a writeup (make it public). Accepts a link or slug:
npm run unlock -- https://z3r0s6.github.io/machines/connected/
npm run unlock -- machines/connected
npm run unlock -- connected

# Re-protect a writeup with the password:
npm run lock -- challenges/crypto-aliens

# Commit + push (triggers the GitHub Actions build & deploy)
npm run deploy
```

## Password protection

- Password lives in **two places that must match**: `WRITEUP_PASSWORD` in `src/config.ts`
  and `PASSWORD` in `scripts/encrypt.mjs`.
- Writeups under `src/content/machines/` and `src/content/challenges/` are encrypted at
  build time (`scripts/encrypt.mjs` runs after `astro build`).
- A writeup is **public** if its Markdown contains the marker
  `Z3R0S_NO_PASSWORD_PLEASE` (added/removed by `npm run unlock` / `npm run lock`).
- Posts (`src/content/posts/`) are never encrypted.

## Make it yours

| What | Where |
|------|-------|
| Name, bio, socials, avatar | `src/config.ts` |
| Colors / fonts / theme | `src/styles/global.css` (CSS variables at the top) |
| Writeups & posts | Markdown in `src/content/{machines,challenges,posts}/` |
| Images / logos | `public/images/`, `public/logos/` |

## Deploy

Pushing to `main` runs `.github/workflows/deploy.yml`: it installs deps, runs
`npm run build` (Astro build + encryption), and publishes `dist/` to GitHub Pages.
