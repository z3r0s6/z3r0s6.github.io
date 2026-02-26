---
title: "Enumerating Security Controls - AD Attacks"
date: 2026-02-26 00:11:00 +0000
categories: [Active-Directory]
tags: [active-directory, windows-defender, applocker, laps, powershell, constrained-language]
---

## Windows Defender

Microsoft Defender provides built-in antivirus and antispyware protection on modern Windows systems.

```powershell
Get-MpComputerStatus
```

Key indicators:
- `RealTimeProtectionEnabled`: Active protection status
- `AntivirusEnabled` / `AntispywareEnabled`: Protection modules
- `BehaviorMonitorEnabled` / `OnAccessProtectionEnabled`: Advanced features

## AppLocker

Application whitelisting restricts which programs can execute. AppLocker provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

Common weaknesses:
- Blocking only specific PowerShell locations while missing alternatives like `powershell_ise.exe` or the SysWOW64 directory
- Default rules allowing execution from `%ProgramFiles%` and `%WINDIR%`
- Administrative groups retaining unrestricted execution rights

## PowerShell Constrained Language Mode

This security feature locks down many PowerShell capabilities by blocking COM objects, restricting .NET types, and disabling advanced scripting.

```powershell
$ExecutionContext.SessionState.LanguageMode
```

## LAPS (Local Administrator Password Solution)

LAPS randomizes and rotates local admin passwords to prevent lateral movement. Use LAPSToolkit for enumeration:

```powershell
# Groups that can read LAPS passwords per OU
Find-LAPSDelegatedGroups

# Users with "All Extended Rights" (can read LAPS passwords)
Find-AdmPwdExtendedRights

# List LAPS-enabled computers with expiration dates
Get-LAPSComputers
```

> **Note:** Users with "All Extended Rights" may be less protected than those in delegated groups and warrant specific attention during assessments.
