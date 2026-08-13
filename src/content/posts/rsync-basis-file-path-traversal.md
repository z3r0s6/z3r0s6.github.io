---
title: "Reading /etc/shadow Through rsync: Server-Side Path Traversal in Incremental Backups"
date: 2026-07-21
categories: ["Blog"]
tags: ["rsync", "Path Traversal", "CWE-22", "Backups", "C", "Research", "CVE-2026-53793"]
author: "z3r0s"
draft: false
---

rsync's whole trust model bends the moment you flip who is malicious. Everyone pictures the server as the thing you are copying from, a passive pile of files. But when you run `rsync server:path dest/`, the server is a program on the other end of a socket, and it gets to send your client instructions. This bug, tracked as **CVE-2026-53793** ([GHSA-wj7w-vh23-mm44](https://github.com/RsyncProject/rsync/security/advisories/GHSA-wj7w-vh23-mm44)), is about one instruction the client trusts more than it should: which file to use as the delta basis.

## The trust model, quickly

Delta transfer is the reason rsync is fast. Instead of shipping a whole file, the two sides find the blocks that already match and ship only the differences. To do that the receiver needs a "basis file", a local file it already has, and it reconstructs the new version by splicing basis blocks together with the literal data the sender sends.

The important part: the sender decides which basis file the receiver should use. Normally that is the file with the same name that is already sitting in the destination. But the protocol also lets the sender name an *alternate* basis file, and that name comes straight off the wire. So the question writes itself. When a server hands the client a basis filename, does the client trust that path blindly?

It does.

## The sanitization gap

I was reading `rsync.c` around the `ITEM_XNAME_FOLLOWS` handling. When the sender transfers a file, it can set a `fnamecmp_type` byte and send an `xname` string, the name of the alternate basis file. Here is where that string is supposed to get cleaned up (rsync.c:411-414):

```c
if (sanitize_paths) {
    sanitize_path(buf, buf, "", 0, SP_DEFAULT);
    len = strlen(buf);
}
```

`sanitize_path()` is the function that strips leading slashes and collapses `../` so a remote-supplied path cant escape where its supposed to live. But notice the guard. It only runs when `sanitize_paths` is set. And `sanitize_paths` is only set to `1` in daemon mode (clientserver.c:999). In SSH / remote-shell mode, the plain `rsync -e ssh server:path dest/` case, `sanitize_paths` stays `0`.

So in the mode almost everybody actually uses, the server-supplied basis path is never sanitized. The `../` sequences pass through untouched.

## The unconfined open

Follow the untouched `xname` into the receiver. There are two ways it becomes the file the client opens.

Path one is the destination-hint family, `--link-dest`, `--copy-dest`, and `--compare-dest` (receiver.c:844-852):

```c
default:
    if (fnamecmp_type > FNAMECMP_FUZZY && fnamecmp_type-FNAMECMP_FUZZY <= basis_dir_cnt) {
        fnamecmp_type -= FNAMECMP_FUZZY + 1;
        if (file->dirname) {
            pathjoin(fnamecmpbuf, sizeof fnamecmpbuf, basis_dir[fnamecmp_type], file->dirname);
            basedir = fnamecmpbuf;
        } else {
            basedir = basis_dir[fnamecmp_type];
        }
        fnamecmp = xname;  // attacker-controlled path
    }
```

Path two is fuzzy matching, `--fuzzy` / `-y` (receiver.c:833-841):

```c
case FNAMECMP_FUZZY:
    if (fuzzy_basis == 0) {
        rprintf(FERROR_XFER, "rsync: refusing malicious fuzzy operation for %s\n", xname);
        exit_cleanup(RERR_PROTOCOL);
    }
    if (file->dirname) {
        basedir = file->dirname;
    }
    fnamecmp = xname;  // attacker-controlled path
```

Both of them set `fnamecmp = xname`, the raw server string, and both land in the same place, `secure_basis_open()` (receiver.c:100-121):

```c
if (!am_daemon || am_chrooted) {       // true in SSH mode (am_daemon=0)
    if (basedir) {
        char fullpath[MAXPATHLEN];
        pathjoin(fullpath, sizeof fullpath, basedir, relpath);
        return do_open(fullpath, flags, mode);  // bare open, no path confinement
    }
    return do_open(relpath, flags, mode);
}
```

`pathjoin()` is just string concatenation. It does not resolve or validate anything. It hands the joined string to `do_open()`, which is a thin wrapper over `open()`, and the kernel resolves the `../` for you during the syscall. There is no confinement anywhere in this branch. In SSH mode `am_daemon` is `0`, so this is the branch that runs.

## The catch, and why it doesnt save you

There is a precondition. The alternate-basis path is only reached when the client uses one of `--link-dest`, `--copy-dest`, `--compare-dest`, or `--fuzzy`. Without one of those flags, none of that receiver code runs and there is nothing to exploit.

That sounds like it narrows things a lot, right up until you remember what `--link-dest` is for. `--link-dest` is the backbone of incremental backups. rsnapshot is built on it. Every Time Machine-style rsync script uses it. Half the "roll your own incremental backup" guides on the internet tell you to use it, because it hardlinks unchanged files against yesterdays snapshot so each daily backup only costs the changed files in disk. `--fuzzy` shows up everywhere people resume interrupted transfers. So the precondition isnt exotic. Its the single most common way people point rsync at a remote for backups.

## The attack

A malicious server, or a legit server someone compromised, sends:

- `fnamecmp_type = 0x84` (that is `FNAMECMP_FUZZY + 1`, selecting the first `--link-dest` basis dir)
- `xname = "../../../../etc/shadow"`

The client is running a completely ordinary incremental backup:

```
rsync -a --link-dest=/backup/daily.0 server:/data/ /backup/daily.1/
```

The resolution becomes:

```
pathjoin("/backup/daily.0", "../../../../etc/shadow")
 = /backup/daily.0/../../../../etc/shadow
 -> /etc/shadow
```

The kernel walks the `../` sequence and opens `/etc/shadow` as the basis file. From there the server sends delta instructions that copy basis blocks straight into the output file. Reconstruct a file entirely out of "unchanged" blocks and the output *is* the basis file. The server just exfiltrated `/etc/shadow` off the client by asking it to reconstruct a file out of it.

The read primitive is the headline, but its not the only outcome:

1. **Arbitrary file read.** Basis content gets pulled into the transferred file through delta instructions, as above.
2. **File existence oracle.** Even without pulling the content out, the transfer behaves differently depending on whether the traversal target exists and is readable, so a server can probe the client's filesystem layout.
3. **Data corruption with `--inplace`.** With `--inplace` the direction flips. The server can splice arbitrary local file content into existing destination files, so its not just a read, its corruption.
4. **Denial of service.** Point the traversal at a FIFO or a device node and the client's `open()` or subsequent read can block indefinitely, hanging the process.

## The mirror image of CVE-2022-29154

If this feels familiar its because its the converse of CVE-2022-29154. That one was a malicious server *writing* files outside the intended destination by manipulating the file list. This one is a malicious server *reading* files outside the basis directory by manipulating `xname`. Same trust boundary, same SSH-mode assumption that the server is honest, opposite direction. Write versus read. The two together are a decent argument that "the server is trusted" was never a safe default for a tool people run against arbitrary remotes.

## The fix

Two options, either one closes it:

- Always sanitize `xname`, regardless of `sanitize_paths`. There is no good reason the SSH-mode path should trust a server-supplied filename that still has `../` in it. The sanitization already exists, it just needs to not be gated behind daemon mode.
- Or open the basis with `openat2(RESOLVE_BENEATH)` in `secure_basis_open()`, so the kernel itself refuses any resolution that escapes the basis directory.

I lean toward the second where its available, because it makes the confinement a property the kernel enforces instead of a string check you have to get exactly right every time. The sanitization existed here. It just lived behind a flag that only gets set in daemon mode, so the mode most people run every single night for backups, SSH mode, quietly skipped it. "We sanitize the path" is only true if you also check *when*, and the when here was `--link-dest` over SSH, which is to say, the way incremental backups actually work.

Scored it 6.8 Medium: `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`. The official advisory title is "rsync: chroot '/./' inner-module escape via a parent-component symlink (xname basis file path traversal)". If you run backups against remotes you dont fully control, this is the one that reads your client's files back through the very channel you set up to protect them.

*Found by z3r0s (https://github.com/z3r0s6). Related: my writeups on the [zero-length block sender crash](/posts/rsync-zero-length-block-sender-crash/) and the [MSG_IO_TIMEOUT integer overflow](/posts/rsync-msg-io-timeout-overflow/), two other rsync bugs from the same review.*
