---
title: "Reverse Engineering - Cyberpsychosis"
date: 2026-05-10
tags: ["HackTheBox", "Reverse Engineering"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
---
# HackTheBox - Cyberpsychosis (Reverse Engineering)

## Challenge Description

> Malicious actors have infiltrated our systems and we believe they've implanted a custom rootkit. Can you disarm the rootkit and find the hidden data?

**Difficulty:** Medium  
**Category:** Reverse Engineering  
**Files:** `diamorphine.ko`, `LICENSE.txt`  
**Target:** TCP service hosting a QEMU VM

## Analysis

### Identifying the Rootkit

The challenge provides `diamorphine.ko`, a Linux kernel module (LKM). Diamorphine is a well-known open-source Linux rootkit. Basic identification:

```
$ file diamorphine.ko
ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped

$ modinfo diamorphine.ko
description:    LKM rootkit
author:         m0nad
license:        Dual BSD/GPL
```

### Reverse Engineering the Module

Key exported and local symbols found via `readelf -s`:

| Function             | Purpose                                  |
|----------------------|------------------------------------------|
| `hacked_getdents`    | Hooks `getdents` syscall to hide files   |
| `hacked_getdents64`  | Hooks `getdents64` syscall to hide files |
| `hacked_kill`        | Hooks `kill` syscall for secret signals  |
| `give_root`          | Escalates current process to root        |
| `module_hide/show`   | Toggles module visibility in `/proc/modules` |

### Hidden File Prefix

The `hacked_getdents` and `hacked_getdents64` functions compare directory entry names against a hardcoded 8-byte value loaded into `r9`:

```asm
movabs r9, 0x69736f6863797370    ; "psychosi" in little-endian
```

Followed by a check for the 9th character:

```asm
cmp BYTE PTR [rdi+0x8], 0x73    ; 0x73 = 's'
```

This means **any file/directory starting with "psychosis" is hidden** from directory listings.

### Secret Signal Handlers

The `hacked_kill` function intercepts the `kill` syscall and checks for three magic signal numbers:

| Signal | Value (hex) | Value (dec) | Action |
|--------|------------|-------------|--------|
| `SIGSUPER`    | 0x40 | 64 | Calls `give_root` - escalates calling process to uid=0 (root) |
| `SIGINVIS`    | 0x2E | 46 | Toggles module visibility in `/proc/modules` and `lsmod` |
| `SIGMODINVIS` | 0x1F | 31 | Toggles process invisibility for a given PID |

The `give_root` function works by calling `prepare_creds()`, zeroing out uid/gid/euid/egid/suid/sgid fields, then `commit_creds()`.

## Exploitation

### Step 1: Connect to the Target VM

The target hosts a QEMU virtual machine accessible via TCP. Connecting with `nc` drops into a BusyBox shell as uid 1000.

```
$ nc 154.57.164.64 31131
~ $ id
uid=1000 gid=1000 groups=1000
```

### Step 2: Confirm the Rootkit is Active

```
~ $ cat /proc/modules
(empty - module is hidden)

~ $ lsmod
(empty - module is hidden)

~ $ ls -la /opt/
drwxr-xr-x    3 root     root            60 Sep  7  2023 .
drwxr-xr-x   13 root     root           260 ...            ..
```

Note: `/opt/` shows link count of 3 (indicating a subdirectory exists) but only `.` and `..` are visible. The rootkit is hiding a directory starting with "psychosis".

### Step 3: Escalate to Root (Signal 64)

Send signal 64 (`SIGSUPER`) to any process to trigger `give_root`:

```
~ $ kill -64 1
~ # id
uid=0(root) gid=0(root) groups=1000
```

### Step 4: Reveal the Hidden Module (Signal 46)

Send signal 46 (`SIGINVIS`) to make the module visible:

```
~ # kill -46 1
~ # cat /proc/modules
diamorphine 16384 0 - Live 0xffffffffc00ef000 (OE)
```

### Step 5: Unload the Rootkit

With the module visible and root privileges, remove it:

```
~ # rmmod diamorphine
```

### Step 6: Access the Hidden Directory

With the rootkit removed, the "psychosis" directory is now visible:

```
~ # ls -la /opt/psychosis/
-rw-r--r--    1 root     root        306912 Sep  7  2023 diamorphine.ko
-rw-r--r--    1 root     root            73 Sep  7  2023 flag.txt

~ # cat /opt/psychosis/flag.txt
HTB{N0w_Y0u_C4n_S33_m3_4nd_th3_r00tk1t_h4s_b33n_sUcc3ssfully_d3f34t3d!!}
```

## Flag

```
HTB{N0w_Y0u_C4n_S33_m3_4nd_th3_r00tk1t_h4s_b33n_sUcc3ssfully_d3f34t3d!!}
```

## Summary

1. Reverse engineered the Diamorphine rootkit kernel module to find:
   - File-hiding prefix: **"psychosis"**
   - Signal 64 â†’ privilege escalation to root
   - Signal 46 â†’ toggle module visibility
2. Connected to the target QEMU VM
3. Used `kill -64 1` to get root
4. Used `kill -46 1` to make the module visible in `/proc/modules`
5. Used `rmmod diamorphine` to unload the rootkit
6. Read the now-visible flag from `/opt/psychosis/flag.txt`
