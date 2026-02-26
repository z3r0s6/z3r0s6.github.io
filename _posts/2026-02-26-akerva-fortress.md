---
title: "Akerva - HTB Fortress"
date: 2026-02-26 00:08:00 +0000
categories: [HTB-Fortress]
tags: [web, snmp, lfi, backup, flask, ffuf, fortress]
---

<div id="protected-content" style="display:none">

## Reconnaissance

Initial nmap scan revealed three open ports:
- Port 22 (SSH)
- Port 80 (HTTP)
- Port 5000 (UPNP)

## Flag 1 — SNMP Misconfiguration

Using UDP scanning and SNMP enumeration with public credentials revealed:

```
/var/www/html/scripts/backup_every_17minutes.sh
AKERVA{IkN0w_SnMP@@@MIsconfigur@T!onS}
```

## Backup Script Analysis

Accessing the backup script via POST request (GET was unauthorized) disclosed:

> "This script performs backups of production and development websites. Backups are done every 17 minutes."

The script creates timestamped zip archives every 17 minutes (1020 seconds) containing all `/var/www/html` contents.

**Flag 2 found in comments:** `AKERVA{IKNoW###VeRbTamper!nG_==}`

## Backup File Enumeration

Server time revealed approximate timestamp. Using ffuf to fuzz minutes and seconds across a 17-minute window:

```bash
ffuf -c -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
  -u http://10.13.37.11/backups/backup_2023041018FUZZ.zip
```

Located and downloaded the backup zip containing source code.

## Development Server Credentials

Extracted Flask application revealed hardcoded credentials in `space_dev.py`:

- Username: `aas`
- Password: `AKERVA{1kn0w_H0w_TO_$Cr1p_T_$$$$$$$$}`

## Local File Inclusion Vulnerability

The `/file` endpoint accepts a filename parameter with no validation:

```python
@app.route("/file")
@auth.login_required
def file():
    filename = request.args.get('filename')
    try:
        with open(filename, 'r') as f:
            return f.read()
```

This vulnerability enables arbitrary file reading with authenticated access.

## Final Flag

Using LFI with valid credentials to read the target user's home directory:

**Final flag:** `AKERVA{IKNOW#LFi_@_}`

</div>

<div id="password-gate">
  <div style="text-align:center; padding: 60px 20px; font-family: monospace;">
    <h2>🔒 Protected Content</h2>
    <p>This writeup is password protected.</p>
    <input type="password" id="pw-input" placeholder="Enter password"
      style="padding:10px; font-size:16px; border-radius:6px; border:1px solid #ccc; margin-right:8px;" />
    <button onclick="checkPassword()"
      style="padding:10px 20px; font-size:16px; border-radius:6px; background:#e74c3c; color:#fff; border:none; cursor:pointer;">
      Unlock
    </button>
    <p id="pw-error" style="color:red; display:none;">Wrong password. Try again.</p>
  </div>
</div>

<script>
function checkPassword() {
  var input = document.getElementById('pw-input').value;
  if (input === 'HTB{Join_Me_In_Death}') {
    document.getElementById('password-gate').style.display = 'none';
    document.getElementById('protected-content').style.display = 'block';
  } else {
    document.getElementById('pw-error').style.display = 'block';
  }
}
document.getElementById('pw-input').addEventListener('keypress', function(e) {
  if (e.key === 'Enter') checkPassword();
});
</script>
