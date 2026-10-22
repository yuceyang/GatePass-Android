[English] | [简体中文](README.md)

# GatePass Android

> A native Android client that removes repeated logins for cloud NAS apps behind an
> authenticated gateway.

[![License: MIT](https://img.shields.io/badge/License-MIT-166534.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-10%2B-3DDC84.svg)](https://developer.android.com/)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.2-7F52FF.svg)](https://kotlinlang.org/)

## The problem

Some private-cloud NAS systems (UGOS, for example) put Docker apps behind an official global
proxy, addressed as `app-<port>-<user>.<domain>`. Visiting one redirects you to the NAS login
page. After logging in once, browser extensions, WebDAV clients and CLI tools still have no
session, so each of them has to log in again.

GatePass completes the authentication **on your phone** ahead of time (NAS login → gateway
one-time token → credential injection), so backend apps receive an already-authenticated request.

```
       app (browser / SiYuan / WebDAV client)
                    │
                    ▼
        ┌───────────────────────────┐
        │  GatePass Android (local) │
        │  ① log in to NAS (RSA)    │
        │  ② exchange gateway token │
        │  ③ inject Cookie / Basic  │
        └───────────────────────────┘
                    │  already authenticated
                    ▼
        NAS gateway ──► backend app (no login redirect)
```

## Two ways to connect

| | A. Certificate-free HTTP ingress (**recommended**) | B. VPN + local CA |
|---|---|---|
| Works with | **Go/CLI apps (SiYuan, etc.)**, any client with a custom URL | Browsers and clients that accept a user CA |
| Address | `http://127.0.0.1:18080/<host>/<path>` | Original hostname (VPN takes over system DNS) |
| Certificate needed | **No** | Yes, installed once |
| VPN required | No | Yes |

> **Why do Go apps need option A?** Go only reads the Android **system** CA store; a
> user-installed CA is invisible to it, and Android 7+ forbids apps from trusting user CAs by
> default. TLS interception therefore cannot work for these apps — the certificate-free local
> HTTP ingress is the only viable path.

## Features

- **Local HTTP/WebDAV forwarding** with per-domain routing and automatic credential injection
- **System DNS interception** — configured domains resolve to a local mapped address via VPN
- **Per-route controls** — toggle each domain's ingress, copy its URL, run a connectivity test
- **Concurrent domains** — per-host pools with a global connection cap; one busy host cannot
  starve another
- **Connection reuse** — HTTP/1.1 keep-alive plus a pooled upstream TLS connection cache
- **Certificate caching** — leaf certificates are encrypted at rest and reused across restarts
- **On-demand wake lock** — held while traffic flows, released after 3 idle minutes
- **Credential protection** — account, session, tokens and CA key all encrypted with
  Android Keystore AES-GCM
- **Coexists with Clash** — the mapped range is `198.19.0.0/16`, deliberately outside Clash's
  default `198.18.0.1/16`

## Install

Download the latest APK from [Releases](../../releases).

```bash
adb install -r GatePass-Android-x.y.z.apk
```

Requires Android 10 (API 29) or newer.

> Release builds use this project's own signing key. Debug and release APKs have different
> signatures and cannot overwrite each other — uninstall before switching.

## Usage

1. **NAS login** — enter the NAS URL, username and password, then tap "Save and test login".
2. **Add a route** — enter an app hostname such as `app-5006-xxxx.ugdocker.link`. Its ingress is
   enabled by default.
3. **Connect an app**
   - SiYuan and friends: set the WebDAV URL to `http://127.0.0.1:18080/<host>/<path>`
   - Browsers: tap "Install root certificate" → choose "Install from storage" in system
     Settings → pick `Download/gatepass-ca.crt`, then start the VPN.
4. **Troubleshoot** — every route has a "Test" button; the in-app log shows live activity.

## Build from source

| Requirement | Version |
|---|---|
| JDK | 17 |
| Android SDK | Platform 36 + Build Tools 36.0.0 |
| Gradle | via the bundled wrapper (8.13) |

```bash
git clone https://github.com/yuceyang/GatePass-Android.git
cd GatePass-Android
./gradlew testDebugUnitTest assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

If Gradle cannot find the SDK, create `local.properties` (git-ignored):

```properties
sdk.dir=/absolute/path/to/Android/Sdk
```

### Release build

Release signing requires your own keystore — **never commit it**:

```bash
keytool -genkeypair -v -keystore gatepass-release.jks -alias gatepass \
        -keyalg RSA -keysize 2048 -validity 10000
```

Put the credentials in `~/.gradle/gradle.properties`, not in the project:

```properties
GATEPASS_STORE_FILE=/absolute/path/gatepass-release.jks
GATEPASS_STORE_PASSWORD=***
GATEPASS_KEY_ALIAS=gatepass
GATEPASS_KEY_PASSWORD=***
```

> `app/build.gradle.kts` currently configures debug signing only. Add your own
> `signingConfigs` block using the property names above so the repository itself never has to
> contain key material.

## Architecture

```
app/src/main/java/com/yuceyang/gatepassandroid/
├── auth/UgosAuthClient.kt          UGOS login and gateway token (RSA + dockerToken)
├── data/
│   ├── SecureSettingsStore.kt      Keystore-encrypted storage
│   └── ProxyRoute.kt               Hostname validation and port inference
├── diag/DiagLog.kt                 In-app log plus logcat
├── proxy/
│   ├── CertificateAuthority.kt     Local CA and leaf certificates (disk-cached)
│   ├── Http1Framing.kt             HTTP/1.1 framing (prerequisite for reuse)
│   ├── UpstreamConnectionPool.kt   Pooled TLS connections + global concurrency cap
│   ├── LocalHttpIngress.kt         Certificate-free ingress (127.0.0.1:18080)
│   └── Socks5ProxyServer.kt        SOCKS5 backend for HEV (TLS interception)
├── ui/MainActivity.kt              UI
└── vpn/GatePassVpnService.kt       VpnService lifecycle, DNS mapping, keep-alive
```

## Known limitations

- **IPv4 + TCP only**; UDP is used for DNS forwarding only, IPv6 is not proxied
- Only **configured hostnames** are proxied; everything else connects directly
- Apps that **pin certificates** cannot use option B
- Traffic using **DoH/DoT**, hard-coded IPs or another VPN bypasses system DNS and is not covered
- Android forbids silent CA installation, so option B always needs one confirmation in Settings
- Validated on a limited set of devices; known to work on ColorOS (Android 16)

## Security

- All credentials are encrypted with a key held in the Android Keystore; `allowBackup=false`
- Passwords, cookies and tokens are never written to logs or exported
- Cleartext HTTP is permitted **only** for `127.0.0.1`; everything else is forced to HTTPS
- The local CA exists only on-device and dies with the app; never share it or the app data
- Upstream connections keep standard HTTPS certificate validation

## License

[MIT](LICENSE).

Bundled third-party components keep their own licenses — see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Disclaimer

This project is intended for accessing NAS services you own or are authorized to use. Obey local
law and the service provider's terms. The authors take no responsibility for misuse.
