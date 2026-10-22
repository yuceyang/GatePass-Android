package com.yuceyang.gatepassandroid.auth

import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

/**
 * UGOS (绿联 NAS) auth adapter. Mirrors the protocol used by the desktop GatePass agent.
 *
 * [network] must be the VPN's underlying network. Outbound calls are bound to it so that
 * requests for routed hostnames (e.g. the gateway `redirect_url`) never re-enter our own TUN.
 */
class UgosAuthClient(
    private val network: android.net.Network? = null,
    private val log: (String) -> Unit = {},
) {

    fun login(baseUrl: String, username: String, password: String): LoginResult {
        val normalizedBase = baseUrl.trim().trimEnd('/')
        require(normalizedBase.startsWith("https://", ignoreCase = true)) { "NAS 地址必须以 https:// 开头" }
        require(username.isNotBlank() && password.isNotBlank()) { "请填写 NAS 用户名和密码" }

        log("检查 NAS: $normalizedBase/ugreen/v1/verify/check")
        val check = request(
            "POST",
            "$normalizedBase/ugreen/v1/verify/check",
            JSONObject().put("username", username).toString(),
        )
        log("verify/check → HTTP ${check.code}")
        val rsaHeader = check.headers.entries
            .firstOrNull { it.key.equals("x-rsa-token", ignoreCase = true) }
            ?.value?.firstOrNull()
            ?: throw IllegalStateException("响应缺少 x-rsa-token 头，无法获取 RSA 公钥（HTTP ${check.code}）")
        val publicKeyPem = decodePublicKeyPem(rsaHeader)
        val encryptedPassword = encryptPassword(publicKeyPem, password)

        val loginBody = JSONObject()
            .put("username", username)
            .put("password", encryptedPassword)
            .put("keepalive", true)
            .put("otp", true)
            .put("is_simple", false)
            .put("login_event", JSONObject.NULL)
        log("提交登录: /ugreen/v1/verify/login")
        val response = request("POST", "$normalizedBase/ugreen/v1/verify/login", loginBody.toString())
        log("verify/login → HTTP ${response.code}")

        val json = runCatching { JSONObject(response.body) }.getOrElse {
            throw IllegalStateException("登录响应不是 JSON（HTTP ${response.code}）: ${response.body.take(160)}")
        }
        val code = json.optInt("code", -1)
        if (response.code >= 400 || code != 200) {
            val msg = json.optString("msg").ifBlank { "code=$code" }
            throw IllegalStateException("登录失败 HTTP=${response.code} $msg")
        }
        if (json.optBoolean("needOtp", false)) throw IllegalStateException("账号开启了 OTP 二次验证，暂不支持自动登录")

        val token = json.optJSONObject("data")?.optString("token").orEmpty()
            .ifBlank { json.optString("token") }
        val cookies = response.headers.entries
            .filter { it.key.equals("Set-Cookie", ignoreCase = true) }
            .flatMap { it.value }
            .mapNotNull { raw ->
                val pair = raw.substringBefore(';')
                val eq = pair.indexOf('=')
                if (eq <= 0) null else pair.substring(0, eq).trim() + "=" + pair.substring(eq + 1).trim()
            }
            .joinToString("; ")
        if (token.isBlank() && cookies.isBlank()) throw IllegalStateException("NAS 未返回会话凭据")
        log("登录成功: token=${if (token.isBlank()) "(空)" else token.take(12) + "…"}, cookies=${cookies.length} 字节")
        return LoginResult(token, cookies)
    }

    /**
     * Gateway token: GET /ugreen/v1/gateway/proxy/dockerToken?port=&token= → redirect_url → HTML
     * → `ugreen-proxy-token=<uuid>`.
     */
    fun gatewayToken(baseUrl: String, host: String, session: LoginResult): GatewayToken {
        if (session.sessionToken.isBlank()) throw IllegalStateException("NAS 会话缺少 token，请先重新登录")
        val port = extractPortFromHost(host)
        require(port.isNotBlank()) { "无法从域名 $host 推断应用端口（应形如 app-8080-…）" }
        val url = "${baseUrl.trim().trimEnd('/')}/ugreen/v1/gateway/proxy/dockerToken" +
            "?port=${encodeUrl(port)}&token=${encodeUrl(session.sessionToken)}"
        log("获取网关令牌 port=$port")
        val res = request("GET", url, null, mapOf("Cookie" to session.cookieHeader))
        log("dockerToken → HTTP ${res.code}")
        val json = runCatching { JSONObject(res.body) }.getOrElse {
            throw IllegalStateException("dockerToken 响应不是 JSON（HTTP ${res.code}）: ${res.body.take(160)}")
        }
        if (json.optInt("code", -1) != 200) {
            throw IllegalStateException("获取网关 token 失败 port=$port code=${json.optInt("code", -1)} msg=${json.optString("msg")}")
        }
        val redirectUrl = json.optJSONObject("data")?.optString("redirect_url").orEmpty()
        if (redirectUrl.isBlank()) throw IllegalStateException("dockerToken 未返回 redirect_url")

        log("抓取 auth 页")
        val html = request("GET", redirectUrl, null, mapOf("Cookie" to session.cookieHeader)).body
        val match = PROXY_TOKEN.find(html)
            ?: throw IllegalStateException("auth 页未找到 ugreen-proxy-token（host=$host）")
        val token = match.groupValues[1]
        log("网关令牌获取成功: ${token.take(8)}…")
        return GatewayToken(token, System.currentTimeMillis() + GATEWAY_TOKEN_TTL_MS)
    }

    private fun request(
        method: String,
        url: String,
        jsonBody: String? = null,
        extraHeaders: Map<String, String> = emptyMap(),
    ): HttpResult {
        val connection = runCatching {
            val opened = network?.openConnection(URL(url)) ?: URL(url).openConnection()
            opened as HttpURLConnection
        }.getOrElse { error ->
            throw IllegalStateException("无法建立连接（$url）: ${error.message}")
        }.apply {
            requestMethod = method
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json, text/html")
            setRequestProperty("UG-Agent", "PC/WEB")
            setRequestProperty("Cache-Control", "no-cache")
            if (jsonBody != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
            extraHeaders.forEach { (name, value) -> if (value.isNotBlank()) setRequestProperty(name, value) }
            if (this is HttpsURLConnection) {
                sslSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            }
        }
        try {
            if (jsonBody != null) connection.outputStream.use { it.write(jsonBody.toByteArray(Charsets.UTF_8)) }
            val code = connection.responseCode
            val stream = if (code in 200..399) connection.inputStream else connection.errorStream
            val body = stream?.let { input ->
                BufferedInputStream(input).use { buffered ->
                    val output = ByteArrayOutputStream()
                    val chunk = ByteArray(8192)
                    while (true) {
                        val count = buffered.read(chunk)
                        if (count < 0) break
                        output.write(chunk, 0, count)
                    }
                    output.toString(Charsets.UTF_8.name())
                }
            }.orEmpty()
            val headers = connection.headerFields.entries
                .filter { it.key != null }
                .associate { (key, value) -> key!! to value.orEmpty() }
            return HttpResult(code, body, headers)
        } catch (error: Exception) {
            throw IllegalStateException("网络请求失败（$url）: ${error.message ?: error.javaClass.simpleName}")
        } finally {
            connection.disconnect()
        }
    }

    private fun encryptPassword(publicKeyPem: String, password: String): String {
        val encoded = publicKeyPem
            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace("-----END RSA PUBLIC KEY-----", "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s".toRegex(), "")
        val der = java.util.Base64.getDecoder().decode(encoded)
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der))
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return java.util.Base64.getEncoder().encodeToString(cipher.doFinal(password.toByteArray(Charsets.UTF_8)))
    }

    private fun encodeUrl(value: String): String =
        java.net.URLEncoder.encode(value, "UTF-8")

    data class LoginResult(val sessionToken: String, val cookieHeader: String)
    data class GatewayToken(val value: String, val expiresAtEpochMs: Long)
    private data class HttpResult(val code: Int, val body: String, val headers: Map<String, List<String>>)

    companion object {
        private const val TIMEOUT_MS = 15_000
        private const val GATEWAY_TOKEN_TTL_MS = 2L * 60 * 60 * 1000
        private val PROXY_TOKEN = Regex("""ugreen-proxy-token=([0-9a-fA-F-]{36})""")
        private val PORT_FROM_HOST = Regex("""^app-?(\d+)""", RegexOption.IGNORE_CASE)

        /** `x-rsa-token` is base64 of a PEM public key. */
        fun decodePublicKeyPem(headerValue: String): String {
            val pem = String(java.util.Base64.getDecoder().decode(headerValue.trim()), Charsets.UTF_8)
            require(pem.contains("BEGIN")) { "x-rsa-token 解码后不是 PEM 公钥" }
            return pem
        }

        fun extractPortFromHost(host: String): String =
            PORT_FROM_HOST.find(host.trim().lowercase())?.groupValues?.get(1).orEmpty()
    }
}
