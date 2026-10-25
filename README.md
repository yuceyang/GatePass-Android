[给中文用户] / [For English readers]

# GatePass Android

> 私有云 NAS 应用免登录代理 · 独立原生 Android 客户端

[![License: MIT](https://img.shields.io/badge/License-MIT-166534.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-10%2B-3DDC84.svg)](https://developer.android.com/)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.2-7F52FF.svg)](https://kotlinlang.org/)

**简体中文** | [English](README.en.md)

---

## 这个项目解决什么问题

部分私有云 NAS（如绿联 UGOS）把 Docker 应用放在官方全局代理之后，地址形如
`app-<端口>-<用户>.<域名>`。直接访问时会被拦截并跳转到官方登录页；登录一次之后，
浏览器扩展、WebDAV 客户端、命令行工具仍然拿不到会话，各自还要再登录一次。

GatePass 的做法是：**在手机上提前完成身份鉴别**（登录 NAS、换取网关令牌、注入 Cookie），
对后端应用而言请求已经是「已认证」的，你只需要关心真实服务本身。

```
        应用（浏览器 / 思源 / WebDAV 客户端）
                    │
                    ▼
        ┌───────────────────────────┐
        │   GatePass Android (本机)  │
        │  ① 自动登录 NAS（RSA 加密） │
        │  ② 换取网关一次性令牌       │
        │  ③ 注入 Cookie / Basic     │
        └───────────────────────────┘
                    │  已是「已认证」的请求
                    ▼
        官方全局代理网关 ──► 后端应用（不再跳登录页）
```

## 两种接入方式

| | A. 免证书 HTTP 入口（推荐） | B. VPN + 本地 CA |
|---|---|---|
| 适用 | **思源等 Go/CLI 应用**、任何支持自定义地址的客户端 | 浏览器等接受用户 CA 的应用 |
| 地址 | `http://127.0.0.1:18080/<域名>/<原路径>` | 原域名（系统 DNS 被 VPN 接管） |
| 需要装证书 | **不需要** | 需要手动安装一次 |
| 需要开 VPN | 不需要 | 需要 |

> **为什么 Go 应用必须用 A？** Go 只读取 Android **系统** CA 库，用户手动安装的 CA 对它无效；
> Android 7 起也禁止应用默认信任用户 CA。因此对这类应用，TLS 解密方案无法生效，
> 免证书的本地 HTTP 入口是唯一可行路径。

## 功能

- **本地 WebDAV/HTTP 转发**：按域名路由，自动注入 NAS 会话与网关令牌
- **系统 DNS 拦截**：通过 VPN 把已配置域名解析到本机映射地址
- **逐条路由开关**：每个域名独立开关入口、复制地址、测试连通
- **多域名并发**：连接池按域名隔离，全局连接数受限，单个繁忙域名不会饿死其他域名
- **连接复用**：HTTP/1.1 keep-alive + 上游 TLS 连接池，同步不再每次握手
- **证书缓存**：叶证书加密落盘，重启复用，客户端无需重新信任
- **按需唤醒**：有流量时持有 CPU 唤醒锁，空闲 3 分钟自动释放
- **凭据保护**：账号、会话、令牌、CA 私钥全部用 Android Keystore AES-GCM 加密
- **与 Clash 等 VPN 共存**：映射段用 `198.19.0.0/16`，刻意避开 Clash 默认的 `198.18.0.1/16`

## 安装

从 [Releases](../../releases) 下载最新 APK 安装即可。

```bash
adb install -r GatePass-Android-x.y.z.apk
```

要求：Android 10（API 29）及以上。

> 发布包使用项目自己的签名密钥；如果你要自己构建，debug 包与 release 包的签名不同，
> 二者不能互相覆盖安装，切换前请先卸载。

## 使用

1. **NAS 登录**：填写 NAS 地址、用户名、密码，点「保存并测试登录」
2. **添加路由**：输入应用域名（如 `app-5006-xxxx.ugdocker.link`），添加后默认开启入口
3. **接入应用**：
   - 思源等：把 WebDAV 地址改成 `http://127.0.0.1:18080/<域名>/<原路径>`
   - 浏览器等：点「一键安装根证书」→ 系统设置里选「从存储设备安装证书」→ 选 `Download/gatepass-ca.crt`，
     然后启动 VPN
4. **排查**：每条路由有「测试连通」按钮；页面底部有实时运行日志

## 从源码构建

环境要求：

| 项 | 要求 |
|---|---|
| JDK | 17 |
| Android SDK | Platform 36 + Build Tools 36.0.0 |
| Gradle | 使用仓库自带的 Wrapper（8.13） |

```bash
git clone https://github.com/yuceyang/GatePass-Android.git
cd GatePass-Android
./gradlew testDebugUnitTest assembleDebug
```

Windows：

```powershell
.\gradlew.bat testDebugUnitTest assembleDebug
```

产物：`app/build/outputs/apk/debug/app-debug.apk`

若 Gradle 找不到 SDK，创建 `local.properties`（该文件已被 git 忽略）：

```properties
sdk.dir=C\:\\Users\\<你>\\AppData\\Local\\Android\\Sdk
```

### 构建 release 包

发布包需要你自己的签名密钥，**不要**把密钥提交到仓库：

```bash
keytool -genkeypair -v -keystore gatepass-release.jks -alias gatepass \
        -keyalg RSA -keysize 2048 -validity 10000
```

在 `~/.gradle/gradle.properties` 中配置（而不是项目里）：

```properties
GATEPASS_STORE_FILE=/absolute/path/gatepass-release.jks
GATEPASS_STORE_PASSWORD=***
GATEPASS_KEY_ALIAS=gatepass
GATEPASS_KEY_PASSWORD=***
```

然后：

```bash
./gradlew assembleRelease
```

> 本仓库的 `app/build.gradle.kts` 当前只配置了 debug 签名；如需要 release 签名，
> 请按上面的属性名自行加入 `signingConfigs`。这样设计是为了让仓库本身不含任何密钥材料。

## 多终端配置同步

安卓端与 PC 端 GatePass 使用**同一份配置文件**，换设备不用重新填写。

```jsonc
{
  "$schema": "gatepass-portable/v1",
  "version": 1,
  "provider": {
    "id": "ugos",
    "authBase": "https://nas.example",
    "username": "you",
    "password": "••••",
    "domainSuffix": "example.ugdocker.link"
  },
  "routes": [
    { "host": "app-5006-example.ugdocker.link", "enabled": true, "httpIngress": true }
  ]
}
```

**只包含跨平台通用的内容**：NAS 地址、账号密码、路由列表。监听端口、开机自启、
hosts、CA 信任这些因平台而异的状态**不在文件里**，所以同一个文件在每台设备上都能直接用。

| 端 | 导出 | 导入 |
|---|---|---|
| Android | 应用内「多终端配置 → 导出配置」 | 「导入配置…」选择 JSON 文件 |
| PC (Node) | `gatepass export [文件]` | `gatepass import <文件>` |

> ⚠️ 含密码的导出文件是**明文**，请勿提交到仓库或公开分享。选「不含密码」可导出可分享的版本。

iOS 客户端尚未实现，但沿用同一 `gatepass-portable/v1` 格式即可互通。

## 架构

```
app/src/main/java/com/yuceyang/gatepassandroid/
├── auth/UgosAuthClient.kt          UGOS 登录与网关令牌（RSA + dockerToken）
├── data/
│   ├── SecureSettingsStore.kt      Keystore 加密存储（账号/会话/令牌/证书）
│   └── ProxyRoute.kt               域名校验与端口推断
├── diag/DiagLog.kt                 应用内日志 + logcat
├── proxy/
│   ├── CertificateAuthority.kt     本地 CA 与叶证书（含磁盘缓存）
│   ├── Http1Framing.kt             HTTP/1.1 分帧（复用连接的前提）
│   ├── UpstreamConnectionPool.kt   上游 TLS 连接池 + 全局并发上限
│   ├── LocalHttpIngress.kt         免证书 HTTP 入口（127.0.0.1:18080）
│   └── Socks5ProxyServer.kt        HEV 的 SOCKS5 后端（TLS 拦截）
├── ui/MainActivity.kt              界面
└── vpn/GatePassVpnService.kt       VpnService 生命周期、DNS 映射、保活
```

请求流向：

```
应用 → (A) 127.0.0.1:18080 ┐
      (B) VPN tun → HEV → SOCKS5 ┘ → 本地 CA 签发证书 → 连上游 443
                                     → 注入 Cookie/令牌/Basic → 返回
```

## 已知限制

- 只处理 **IPv4 + TCP**；UDP 仅用于 DNS 转发，IPv6 未纳入代理
- 只有**已添加的域名**经代理，其余走直连
- **证书固定（pinning）**的应用无法使用 B 方案
- 使用 **DoH/DoT**、硬编码 IP 或自有 VPN 的流量绕过系统 DNS，不受控制
- Android 不允许应用静默安装 CA，B 方案必须由用户在系统设置中确认一次
- 未在大量机型上验证；已知在 ColorOS（Android 16）上工作正常

### ⚠️ 本地 CA 会随重装变化（最常见的坑）

GatePass 的根证书在**首次运行时生成**，数据被清除或卸载重装后会**重新生成一张新的**。
如果你之前装过旧 CA，浏览器/应用仍会用它验证，握手会失败并报：

```
CERTIFICATE_UNKNOWN / BLOCK_TYPE_IS_NOT_01 / 「无法验证服务器证书」
```

**判断方法**：在 GatePass 日志里找到「当前 CA 指纹」，与已安装证书的指纹对比，
不一致就是这个问题。

**处理**：点「一键安装根证书」重新导出并安装，然后重启 VPN。

> 因此建议：**先装好最终要用的版本（release），再装 CA**。在 debug 和 release 之间切换
> 必须先卸载（签名不同），每次切换都会换一张 CA，需要重新安装。

## 安全说明

- 所有凭据使用 Android Keystore 派生的密钥加密，`allowBackup=false`
- 应用**不会**把密码、Cookie、令牌写入日志或导出文件
- 明文 HTTP 仅对 `127.0.0.1` 放行（见 `network_security_config.xml`），其余强制 HTTPS
- 本地 CA 只在本机生成，随应用卸载失效；请勿把 `gatepass-ca.crt` 或应用数据外传
- 上游连接保持标准 HTTPS 证书校验，不弱化

## 许可证

本项目以 [MIT 许可证](LICENSE) 开源。

打包的第三方组件（hev-socks5-tunnel、Bouncy Castle、AndroidX）各自遵循其原始许可证，
详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

## 免责声明

本项目仅用于访问**你自己拥有或已获授权**的 NAS 服务。请遵守所在地区法律法规及
服务提供方的使用条款。作者不对任何滥用行为负责。

---

## English

GatePass Android is a native Android client that removes repeated logins for cloud NAS apps
behind an authenticated gateway. It logs into the NAS, exchanges a one-time gateway token, and
injects the resulting credentials into requests, so applications see an already-authenticated
session.

Two ways to connect:

- **A. Certificate-free HTTP ingress** — `http://127.0.0.1:18080/<host>/<path>`. Required for
  Go-based apps (e.g. SiYuan), which only trust the system CA store. No certificate needed.
- **B. VPN + local CA** — for browsers and other clients that accept a user-installed CA.

Build: JDK 17, Android SDK Platform 36, Build Tools 36.0.0.

```bash
./gradlew testDebugUnitTest assembleDebug
```

Licensed under the [MIT License](LICENSE). See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
for bundled components.
