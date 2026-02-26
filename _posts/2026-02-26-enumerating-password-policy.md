---
title: "Enumerating the Password Policy - AD Attacks"
date: 2026-02-26 00:09:00 +0000
categories: [Active-Directory]
tags: [active-directory, password-policy, smb, ldap, rpcclient, crackmapexec, enum4linux]
---

## Overview

Password policies in Active Directory domains control account lockout thresholds, password length requirements, complexity rules, and expiration settings. Enumeration methods vary based on domain configuration and credential availability.

## Linux-Based Enumeration

### With Valid Credentials

```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

This reveals settings including minimum length, history, complexity flags, lockout thresholds, and durations.

### SMB NULL Sessions

Unauthenticated attackers may exploit SMB NULL session misconfigurations to retrieve password policies and user information.

```bash
rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

### enum4linux and enum4linux-ng

```bash
enum4linux -P IP
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

### LDAP Anonymous Bind

```bash
ldapsearch -H 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep pwdHistoryLength
```

## Windows-Based Enumeration

### Built-in Commands

```bash
net accounts
```

### PowerView

PowerView's `Get-DomainPolicy` cmdlet retrieves comprehensive policy information including complexity requirements and lockout settings.

## Policy Analysis

Key findings from the INLANEFREIGHT.LOCAL domain:

- **Minimum password length:** 8 characters
- **Account lockout threshold:** 5 attempts
- **Lockout duration:** 30 minutes (automatic unlock)
- **Password complexity:** Enabled
- **Password history:** 24 days
- **Maximum age:** Unlimited

These settings are favorable for password spraying — the 5-attempt threshold allows 2-3 spray attempts every 31 minutes without account lockouts.

### Default Domain Policy Values

| Setting | Default |
|---------|---------|
| Minimum password length | 7 |
| Maximum password age | 42 days |
| Minimum password age | 1 day |
| Complexity requirements | Enabled |
| Account lockout threshold | 0 (disabled) |
