---
title: "Android Fundamentals - App Pentest"
date: 2026-02-26 00:12:00 +0000
categories: [Android-App-Pentest]
tags: [android, mobile, apk, pentest, jadx, adb, frida, fundamentals]
---

## Overview

Android devices primarily use ARM architecture, though emulators typically run on x86_64. The platform consists of six layered components built on a Linux foundation.

## 1. Android Layers (Bottom to Top)

### Linux Kernel
Foundational layer providing direct hardware communication and core security mechanisms:
- Isolates each app in its own sandbox
- Prevents resource monopolization
- Enforces permission-based access to GPS, camera, and telephony

### Hardware Abstraction Layer (HAL)
Enables Android compatibility across diverse hardware manufacturers by standardizing device communication protocols.

### Android Runtime (ART)
Used from Android 5 (Lollipop) onwards, ART performs Ahead-of-Time (AOT) compilation during app installation for optimized performance.

### Native C/C++ Libraries
High-performance libraries used by resource-intensive applications.

### Java API Framework
Provides ready-made development tools including UI components, notifications, location services, and camera functionality.

### System Apps
Pre-installed applications such as Camera, Messages, Phone, Settings, and Play Store.

## 2. File System Structure

| Directory | Purpose |
|-----------|---------|
| `/data/data` | User-installed applications |
| `/data/user/0` | App-specific private data |
| `/data/app` | APK files for user applications |
| `/system/app` | Pre-installed system applications |
| `/system/bin` | Binary executables |
| `/data/local/tmp` | World-writable temporary directory |
| `/data/system` | System configuration files |
| `/data/misc/wifi` | WiFi settings |
| `/etc/security/cacerts/` | System certificate store |

## 3. APK Structure

The APK is a ZIP archive containing:
- Compiled code (`.dex` files)
- Android manifest
- Resources (images, layouts)
- Pre-built libraries

**Key file:** `classes.dex` — contains the executable bytecode.

### Application Sandbox
- Unique UID assigned per application
- File access restricted to app-specific UID
- Separate process with independent ART instance
- Least privilege principle

## 4. Application Signing

```bash
# Create keypair
keytool -genkey -keystore key.keystore -validity 1000 -keyalg RSA -alias mykey

# Optimize APK
zipalign -p -f -v 4 myapp.apk myapp_aligned.apk

# Sign application
apksigner sign --ks key.keystore myapp_aligned.apk
```

> **CVE-2017-13156 (Janus):** Signature scheme v1 could be bypassed by prepending malicious DEX files.

## 5. Application Components

### Activities
UI-based components representing individual screens.

**Lifecycle:** `onCreate()` → `onStart()` → `onResume()` → `onPause()` → `onStop()` → `onDestroy()`

> **Security Risk:** `android:exported="true"` allows external apps to launch the Activity.

### Services
Background components with no user interface that persist even when the app closes.

| Type | Persistence | Start Method |
|------|-------------|--------------|
| **Foreground** | Always running with notification | `startForegroundService()` |
| **Background** | Limited runtime when app inactive | `startService()` |
| **Bound** | IPC-enabled | `bindService()` |

### Broadcast Receivers

```java
public class MyBroadcastReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if ("android.intent.action.ACTION_POWER_CONNECTED".equals(intent.getAction())) {
            Toast.makeText(context, "Power Connected", Toast.LENGTH_LONG).show();
        }
    }
}
```

> **Security Risk:** If `android:exported` is true or omitted, external apps or ADB can send arbitrary Intents.

### Content Providers

```xml
<provider
    android:name=".MyContentProvider"
    android:authorities="com.example.myapp.provider"
    android:exported="false" />
```

> **Security Risk:** Setting `android:exported="true"` allows unauthorized data access.

## 6. Inter-Process Communication (IPC)

### Intents

- **Explicit Intent** — targets specific component: `new Intent(this, SecretActivity.class)`
- **Implicit Intent** — targets action capability: `Intent.ACTION_VIEW` with URL

> **Pentest Risk:** Exported components can receive arbitrary Intents containing malicious data (tokens, passwords, commands).

### Deep Links

Standard deep links (custom schemes) have no ownership verification — malicious apps can hijack custom schemes. Use Android App Links (HTTPS-based) with domain ownership verification via `assetlinks.json` instead.

## 7. Attack Surface Summary

| Component | Export Risk | Attack Vector | Mitigation |
|-----------|-------------|----------------|------------|
| Activity | `exported="true"` | External Intent launch | Restrict exports |
| Service | `exported="true"` | Command injection via Intent extras | Validate input |
| Broadcast Receiver | Manifest-declared | Arbitrary Intent sending | Require permissions |
| Content Provider | `exported="true"` | Unauthorized data queries | Disable export |
| Deep Link | Custom schemes | Scheme hijacking | Use HTTPS App Links |
| Binder | IPC exposed | Remote function invocation | Validate callers |

## 8. Framework Decompilation

| Framework | Language | Result | Analysis Type |
|-----------|----------|--------|---------------|
| Flutter | Dart | `.so` libraries | Native code analysis |
| Xamarin | C# | `.dll` libraries | .NET decompilation |
| React Native/Cordova | JavaScript | WebView+JS | XSS, web vulns |
