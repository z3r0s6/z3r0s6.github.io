---
title: "68 Years of Patience: Defeating rsync's Timeout With One Integer"
date: 2026-07-22
categories: ["Blog"]
tags: ["rsync", "DoS", "CWE-190", "Integer Overflow", "Protocol", "C", "Research", "CVE-2026-70462"]
author: "z3r0s"
draft: false
---

rsync has an I/O timeout. You set it with `--timeout`, or the server sets it for you through a protocol message called `MSG_IO_TIMEOUT`. The idea is simple: if the other side goes quiet for too long, give up and close the connection. But the implementation trusted the peer to send a reasonable value, and the arithmetic that consumed it was not overflow-safe. Send `INT_MAX` and the math wraps negative, turning the timeout mechanism into the opposite of what it was built for. This is **CVE-2026-70462** ([GHSA-j9wh-5jmp-2m64](https://github.com/RsyncProject/rsync/security/advisories/GHSA-j9wh-5jmp-2m64)).

## How I found it

I was already in the rsync protocol code from the two other bugs in this same review (the [zero-length block sender crash](/posts/rsync-zero-length-block-sender-crash/) and the [xname basis-file path traversal](/posts/rsync-basis-file-path-traversal/)). Both of those were about the sender and receiver trusting wire values in transfer operations. I wanted to see if the pattern extended to the control-plane messages, the metadata that rsync sends alongside file data.

`MSG_IO_TIMEOUT` is one of those messages. The server sends a timeout value during multiplexed I/O, and the client applies it to its own timeout logic. The question was the same one I keep asking: what happens when the value is degenerate?

## The handler

When the client receives a `MSG_IO_TIMEOUT` message, it processes it in io.c around line 1596:

```c
case MSG_IO_TIMEOUT:
    if (msg_bytes != 4 || am_server || am_generator)
        goto invalid_msg;
    val = raw_read_int();
    iobuf.in_multiplexed = 1;
    if (val <= 0)
        break;
    if (!io_timeout || io_timeout > val) {
        set_io_timeout(val);
    }
    break;
```

Notice the `val <= 0` guard. That was actually part of the pending security fixes for an older bug, reported separately by Leonid Bugaev, where a non-positive value would disable the client's timeout entirely. The fix rejects zero and negatives. But there is no upper bound. `INT_MAX` passes this check just fine.

The second condition, `!io_timeout || io_timeout > val`, decides whether to apply the peer's value. When the client runs without `--timeout` (the default), `io_timeout` is `0`, so `!io_timeout` is true. The server's value gets applied unconditionally.

## The overflow

`set_io_timeout()` takes the peer-supplied value and computes a "lull" interval from it (io.c:1176):

```c
void set_io_timeout(int secs)
{
    io_timeout = secs;
    allowed_lull = (io_timeout + 1) / 2;

    if (!io_timeout || allowed_lull > SELECT_TIMEOUT)
        select_timeout = SELECT_TIMEOUT;
    else
        select_timeout = allowed_lull;
    // ...
}
```

With `secs = 0x7FFFFFFF` (2,147,483,647):

1. `io_timeout + 1` overflows. `0x7FFFFFFF + 1 = 0x80000000`, which is `-2147483648` in signed two's complement.
2. `-2147483648 / 2 = -1073741824`.
3. `allowed_lull = -1073741824`.

Now the branch. `!io_timeout` is false (it is `0x7FFFFFFF`). `allowed_lull > SELECT_TIMEOUT` is `-1073741824 > 60`, which is false. So it takes the else branch, and `select_timeout = -1073741824`.

A negative `select_timeout`. That single value breaks everything downstream.

## The tight loop

Every I/O read path in rsync uses `select_timeout` as the timeout for `select()` (io.c:264):

```c
tv.tv_sec = select_timeout;    // -1073741824
tv.tv_usec = 0;
cnt = select(fd+1, &r_fds, NULL, &e_fds, &tv);
if (cnt <= 0) {
    if (cnt < 0 && errno == EBADF)
        exit_cleanup(RERR_FILEIO);
    check_timeout(1, MSK_ALLOW_FLUSH);
    continue;
}
```

POSIX leaves the behavior of `select()` with a negative `tv_sec` undefined. On Linux and BSD it returns `-1` with `errno = EINVAL`. Since `EINVAL` is not `EBADF`, the error falls through to `check_timeout()` then `continue`. The loop starts over. `select()` fails again, immediately. The client is now spinning at 100% CPU doing nothing useful.

Could `check_timeout()` rescue us? No. Inside it, the exit condition is:

```c
if (t - chk >= io_timeout)
    exit_cleanup(RERR_TIMEOUT);
```

With `io_timeout = 2147483647`, that is roughly 68 years. The timeout will never fire. The client spins until someone kills the process.

## The keepalive flood

There is a secondary effect. `maybe_send_keepalive()` checks (io.c:1510):

```c
if (now - last_io_out >= allowed_lull)
    send_msg(MSG_DATA, "", 0, 0);
```

Since `allowed_lull = -1073741824`, any non-negative time difference exceeds it. The condition is always true. On every iteration of the tight loop, the client sends a zero-length keepalive message back to the server. So the spin is not just burning CPU, it is also flooding the network connection with tiny packets.

## The two shapes

This CVE actually covers two related defects on the same boundary:

1. **The overflow** (my finding): `INT_MAX` passes the `val <= 0` guard, overflows `(io_timeout + 1) / 2`, and traps the client in a CPU-bound spin. The old guard was incomplete.

2. **The disable** (Leonid Bugaev's finding, pre-existing since 2009): a non-positive value was accepted and set `io_timeout = 0`, which disabled the client's timeout entirely. A server could suppress the timeout rather than overflow it.

The fix addresses both: peer-supplied values are rejected when non-positive and capped when large, and `set_io_timeout()` uses overflow-safe arithmetic.

## Why compiler flags matter

I demonstrated the spin by building rsync with `-fwrapv` (defined signed overflow wraps in two's complement). At `-O2` without that flag, the compiler's undefined-behavior assumptions happened to mask the effect on my test machine, because the optimizer assumed the overflow could not happen and folded the branch differently. That is precisely why the overflow must be prevented at the source rather than relied on to "not happen in practice." The regression test builds the affected translation unit with `-fwrapv` so the guard is exercised, not optimized away.

## The attack

A malicious server, or an attacker with a man-in-the-middle position on the rsync protocol stream, injects a single `MSG_IO_TIMEOUT` message with payload `0x7FFFFFFF` during multiplexed I/O. The message format is:

```
Tag byte: (MSG_IO_TIMEOUT << 24) | 4    // message type + 4 bytes payload
Payload:  0xFF 0xFF 0xFF 0x7F           // INT_MAX, little-endian
```

The victim runs a completely default rsync command:

```
rsync -avz server:/data/ /local/backup/
```

No `--timeout` flag, because most people do not set one. The client immediately enters a tight loop. CPU pegs at 100% on one core. No data transfers. The process has to be killed manually. Automated backup scripts hang silently, with no timeout to bail them out, because the timeout mechanism itself is the thing that broke.

## The fix

Two changes, both applied in 3.5.0:

1. Cap the peer-supplied value on receipt. There is no reason a server needs to set a client timeout above a reasonable maximum (the fix caps it).
2. Make `set_io_timeout()` overflow-safe. Even if a large value somehow got through, the arithmetic should not wrap.

The broader point is that `MSG_IO_TIMEOUT` was a peer-controlled input feeding directly into arithmetic that governed the client's own safety mechanism. The timeout exists to protect the client from a misbehaving server, and the server could defeat it with a single four-byte message. When a safety mechanism accepts its parameters from the thing it is meant to protect against, the mechanism needs to validate those parameters like any other untrusted input.

Scored it 6.5 Medium: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`, CWE-190 with secondaries CWE-835 and CWE-693. The official advisory title is "Peer-supplied MSG_IO_TIMEOUT defeats the client's own I/O timeout (signed overflow, and a non-positive value)".

*Found by z3r0s (https://github.com/z3r0s6). Related: my writeups on the [zero-length block sender crash](/posts/rsync-zero-length-block-sender-crash/) and the [xname basis-file path traversal](/posts/rsync-basis-file-path-traversal/), two other rsync bugs from the same review.*
