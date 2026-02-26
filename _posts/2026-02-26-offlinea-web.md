---
title: "Offlinea - Web Challenge"
date: 2026-02-26 00:04:00 +0000
categories: [HTB-Challenges]
tags: [web, ssti, ssrf, hpp, flask, jwt, parameter-pollution]
---

## Overview

This web security challenge demonstrates a sophisticated attack chain combining HTTP Parameter Pollution (HPP), Server-Side Template Injection (SSTI), and Server-Side Request Forgery (SSRF) to compromise a Flask application and extract sensitive credentials.

## Vulnerability Chain

The exploitation path involves:

1. **HPP exploitation** — Leveraging differential parameter parsing between PHP and Flask
2. **SSTI via format strings** — Extracting Flask's secret key through template injection
3. **SSRF to internal service** — Forcing Selenium to access internal endpoints
4. **JWT forgery** — Creating authenticated admin tokens using the leaked secret

## Critical Flaw: Parameter Parsing Mismatch

The fundamental weakness stems from how different components handle duplicate URL parameters. PHP reads only the last `url` parameter, but Flask reads the first one. This allows attackers to submit multiple URL values where PHP validates one while Flask processes another.

**Example payload structure:**
```
url=MALICIOUS_PAYLOAD&url=SAFE_URL
```

## SSTI Injection Mechanism

The Flask `/logs` endpoint processes database records through Python's `.format()` method without sanitization. Injecting template syntax in URL fragments allows access to application internals:

```
{logify.__globals__[app].config[SECRET_KEY]}
```

This retrieves the secret key used for JWT signing.

## Exploitation Sequence

**Step 1:** Submit URL with injected payload in fragment
**Step 2:** Trigger SSRF to internal Flask service at `http://127.0.0.1:5000/logs`
**Step 3:** Extract leaked `SECRET_KEY` from rendered PDF
**Step 4:** Forge HS256 JWT token with admin privileges
**Step 5:** Access restricted endpoint using forged token

## Key Takeaways

- Sanitize and reject duplicate parameters
- Never apply string formatting to untrusted input
- Restrict Selenium/browser automation from accessing internal networks
- Implement secure secret management practices
