# 第三方组件声明

本项目在构建与发布产物中包含以下第三方组件，它们的授权条款独立于本项目的 MIT 许可证。

## hev-socks5-tunnel

- 版本：2.19.1
- 来源：<https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.19.1>
- 文件：`app/libs/hev-socks5-tunnel-2.19.1.aar`
- 许可证：MIT
- 用途：TUN 接口与 SOCKS5 之间的转发（tun2socks），并提供 `mapdns` 虚拟地址映射。
- 完整性：下载后经 SHA-256 校验，校验值记录在 `app/libs/hev-socks5-tunnel-2.19.1.sha256`。
- 许可证全文：`app/libs/HEV-LICENSE.txt`

## Bouncy Castle

- 版本：`bcprov-jdk18on` / `bcpkix-jdk18on` 1.80
- 来源：<https://www.bouncycastle.org/>
- 许可证：Bouncy Castle License（MIT 风格）
- 用途：仅使用其 X.509 证书构造 API（`JcaX509v3CertificateBuilder` 等）生成本地 CA 与叶证书。
- 说明：运行时**不会**注册 BouncyCastle 作为 JCA Provider，签名仍由平台 Provider 完成。

## AndroidX Core KTX

- 来源：<https://developer.android.com/jetpack/androidx>
- 许可证：Apache License 2.0
