---
title: "Jet - HTB Fortress"
date: 2026-02-26 00:07:00 +0000
categories: [HTB-Fortress]
tags: [web, sqli, buffer-overflow, heap, rsa, format-string, elasticsearch, fortress]
layout: locked
password: "HTB{Join_Me_In_Death}"
---

## Overview

A comprehensive penetration testing challenge involving multiple exploitation techniques across web, binary, and cryptographic vulnerabilities.

## Key Vulnerabilities Exploited

### 1. DNS Enumeration & Web Discovery

Initial reconnaissance revealed port 53 (DNS) was open. Reverse DNS lookup identified the domain `www.securewebinc.jet`, which when accessed revealed additional content including JavaScript files.

### 2. Obfuscated JavaScript Analysis

The `secure.js` file used `String.fromCharCode()` with `eval()` execution. By converting this to `console.log()`, the script revealed a hidden admin directory path:

```
/dirb_safe_dir_rf9EmcEIx/admin/stats.php
```

### 3. SQL Injection in Login

The admin login form contained SQL injection vulnerability in the username parameter. Using sqlmap identified:
- Boolean-based blind injection
- Error-based injection
- Time-based blind injection
- UNION-based injection

Dumped the `jetadmin` database revealing the admin user hash (SHA256).

### 4. Hash Cracking

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Password: Hackthesystem200
```

### 5. PHP preg_replace() RCE

The email form processed user input with `preg_replace()` using `/i` flag. By changing the flag to `/e`, PHP code execution was achieved:

```
swearwords[/fuck/e]=system('command')
```

This allowed reverse shell execution as `www-data`.

### 6. Buffer Overflow (Stack-based)

The `/home/leak` SUID binary had:
- No stack canary protection
- NX disabled
- No PIE

Used a 72-byte offset to overwrite RIP with leaked stack address, executing inline shellcode for shell as `alex` user.

### 7. Elasticsearch Data Exposure

Port 9300 ran Elasticsearch internally. Using port forwarding with socat and a custom Java client program, accessed the `test` index containing sensitive communications with embedded flag data.

### 8. Heap Exploitation

The `membermanager` binary (port 5555) contained a heap vulnerability. The exploit involved:
- Heap grooming and chunk manipulation
- LIBC base address leakage
- One-gadget RCE execution

### 9. RSA Weak Key Generation (Wiener Attack)

Tony's RSA public key was vulnerable to Wiener attack due to poorly chosen exponent. RsaCtfTool recovered the private key, enabling decryption:

```bash
# Decrypt key.bin.enc
openssl rsautl -decrypt -inkey private.pem -in key.bin.enc -out key.bin

# Decrypt secret.enc using AES-256-CBC
openssl enc -d -aes-256-cbc -in secret.enc -out secret.txt -pass file:key.bin
```

### 10. Format String & Heap Leak (Memo Binary)

The `memo` service (port 7777) contained:
- Stack canary bypass through controlled reads
- Heap address leakage
- LIBC base address recovery
- Arbitrary write primitive via heap manipulation leading to RCE

## Tools Used

- nmap, ffuf (reconnaissance)
- sqlmap (SQL injection)
- John the Ripper, hashcat (hash cracking)
- xortool (XOR cryptanalysis)
- zip2john, RsaCtfTool (cryptanalysis)
- GDB with pwndbg (binary debugging)
- socat (port forwarding)
- OpenSSL (RSA/AES operations)
