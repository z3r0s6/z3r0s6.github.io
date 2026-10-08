---
title: "Zero-Length Blocks, Negative Offsets: Crashing rsync Daemons With Protocol Math"
date: 2026-07-20
categories: ["Blog"]
tags: ["rsync", "DoS", "CWE-1284", "Protocol", "C", "Research", "CVE-2026-53792"]
author: "z3r0s"
draft: false
---

rsync's delta-transfer algorithm is genuinely elegant. It lets two machines sync a file by shipping only the differences, using rolling checksums to find the blocks that already match. But elegant algorithms tend to assume well-formed input, and rsync's checksum protocol is one of those places where each field gets checked on its own and nobody checks the combination. Feed it a degenerate combination and the math walks straight off a cliff. This one is **CVE-2026-53792** ([GHSA-cg57-rp9g-56hw](https://github.com/RsyncProject/rsync/security/advisories/GHSA-cg57-rp9g-56hw)), a remote crash of the daemon's sender.

## Where I was reading

I was in the sender path this time, `read_sum_head()` in io.c. This function reads checksum headers off the wire during a transfer. In delta transfer the receiver (the client, during a download) computes block checksums for the file it already has and sends them to the sender (the daemon), and the sender uses them to find matching blocks. So the sender is trusting a pile of numbers that came from the other end of the socket.

My question was the usual one. What happens with degenerate input? Not a malformed packet that fails parsing, but a technically valid header that describes something nonsensical.

## Each field is fine, the combination is not

Here is how `read_sum_head()` checks the block length (io.c:2049-2054):

```c
sum->blength = read_int(f);
if (sum->blength < 0 || sum->blength > max_blength) {
    rprintf(FERROR, "Invalid block length %ld [%s]\n",
        (long)sum->blength, who_am_i());
    exit_cleanup(RERR_PROTOCOL);
}
```

`blength` cant be negative, cant exceed the max. Reasonable. But it allows `blength = 0`. Pair that with `count = 1` and `remainder = 0` and you have a checksum header that passes every individual check and describes exactly one block of zero length.

I think of this as a cross-field validation gap. `blength` is valid. `count` is valid. `remainder` is valid. The tuple `(count=1, blength=0, remainder=0)` is nonsense, and nothing in the code looks at the tuple. Each field is validated against a range. The relationship between them is not validated against anything.

## Making the match land

Next question. Can an attacker actually get that zero-length block to *match* something so the buggy downstream code runs? Yes, and its deterministic, not luck.

In `hash_search()` (match.c:163-197), with `blength = 0` the code takes `k = MIN(len, s->blength) = 0` and computes the checksum over zero bytes. `get_checksum1(NULL, 0)` returns `0`, cleanly, because both of its loops run zero iterations. The strong checksum for zero bytes is `get_checksum2(NULL, 0, sum2)`, which ends up hashing just the checksum seed and nothing else. And the seed is not a secret. The server sends it to the client during protocol negotiation (compat.c:814), so the attacker knows it and precomputes the exact `sum2` that will match.

So the attacker sends `sum1 = 0`, which matches the computed weak checksum, and a `sum2` they derived from the known seed, which matches the strong checksum. The block match is confirmed. Every step of that was arithmetic the attacker fully controls.

## The underflow

When a match gets confirmed, the code advances the offset (match.c:335-338):

```c
offset += s->sums[i].len - 1;   // offset += 0 - 1 = -1
```

With `sums[0].len = 0`, that is `offset += 0 - 1`, so `offset` becomes `-1`. Signed underflow, a negative file offset, and nothing between here and the syscall notices.

That negative offset flows into `map_ptr()` (fileio.c:240-295):

```c
align_fudge = (int32)ALIGNED_OVERSHOOT(offset);  // (-1) & 0x3FF = 1023
window_start = offset - align_fudge;             // -1 - 1023 = -1024
// ...
OFF_T ret = do_lseek(map->fd, read_start, SEEK_SET);  // lseek(fd, -1024, SEEK_SET)
```

The alignment math takes the low bits of `-1`, which is `1023`, and subtracts, landing the window start at `-1024`. Then it seeks there. Seeking to a negative absolute position fails with `EINVAL`, `ret` comes back `-1` instead of the expected `-1024`, the sanity check trips, and the sender tears itself down with `exit_cleanup(RERR_FILEIO)`. The sender child process is dead.

Worth being precise about what this is and isnt. There is no memory corruption here. The offset never indexes an array, it goes to `lseek`, which rejects it. The process exits cleanly. This is a clean, deterministic remote crash, not a memory-safety bug.

## Why this is a real DoS

Any client that can connect to an rsync daemon can send crafted checksums, because the client is the side that generates them. Each malicious connection crashes one sender child. The parent daemon survives one crash fine, thats by design, one bad transfer shouldnt take down the whole server. But the exploit is a loop: connect, send the crafted header, watch the sender die, reconnect, repeat. Rapid reconnections chew through the daemon's connection slots and legitimate clients stop getting served. Public mirrors and anonymous rsync modules are exactly the kind of thing that expose a daemon to arbitrary clients, so this isnt a lab-only concern.

The whole chain in four stages:

1. `read_sum_head()` accepts `blength=0, count=1, remainder=0`.
2. `hash_search()` matches deterministically because the attacker precomputed `sum2` from the leaked seed.
3. `offset += sums[i].len - 1` underflows to `-1`.
4. `map_ptr()` calls `lseek(fd, -1024, SEEK_SET)`, which fails, and the sender crashes.

To reproduce it you patch a client generator to emit `count=1, blength=0, remainder=0, sum1=0, sum2=<hash of the seed>`, point it at an anonymous module, `./rsync rsync://target:873/pub/anyfile /dev/null`, and the sender child dies. Loop it for sustained denial of service.

## The fix

One line, and it lives right where the gap is. Reject the degenerate combination at header-read time, before any of the downstream math runs:

```c
if (sum->count > 0 && sum->blength == 0) {
    rprintf(FERROR, "Invalid zero block length with count %ld [%s]\n",
        (long)sum->count, who_am_i());
    exit_cleanup(RERR_PROTOCOL);
}
```

A block count greater than zero with a block length of zero is not a real checksum header. Validating fields one at a time feels like validation, and it does catch the obvious garbage. But the interesting bugs live in the combinations. `blength=0` is a fine block length in isolation and `count=1` is a fine count. Its only `count=1, blength=0` together that means "one block of nothing", and that meaninglessness is what becomes `offset = -1` and a dead process three functions later. When fields interact downstream, validate the tuple, not just the pieces.

Scored it 7.5 High: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-1284 with a secondary CWE-191. The official advisory title is "rsync: receiver-supplied zero checksum block length drives sender matching negative".

*Found by z3r0s (https://github.com/z3r0s6). Related: my writeups on the [xname basis-file path traversal](/posts/rsync-basis-file-path-traversal/) and the [MSG_IO_TIMEOUT integer overflow](/posts/rsync-msg-io-timeout-overflow/), two other rsync bugs from the same review.*
