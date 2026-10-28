package com.yuceyang.gatepassandroid.proxy

import android.net.Network
import com.yuceyang.gatepassandroid.auth.RouteResolver
import com.yuceyang.gatepassandroid.auth.UgosAuthClient
import com.yuceyang.gatepassandroid.data.SecureSettingsStore
import com.yuceyang.gatepassandroid.diag.DiagLog
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Plain-HTTP loopback ingress for clients that cannot trust a user-installed CA.
 *
 * Go-based apps (SiYuan, many CLI tools) read only the Android **system** CA store, so TLS
 * interception is impossible for them without root. Instead they talk plain HTTP to this
 * local server, which re-encrypts to the NAS and injects NAS credentials:
 *
 *     http://127.0.0.1:18080/<host>/<path>
 *
 * Loopback is not covered by our VPN routes, so this never re-enters the TUN device.
 * Client connections are kept alive (HTTP/1.1) and upstream TLS connections are pooled, so a
 * WebDAV sync no longer pays a handshake per request.
 */
class LocalHttpIngress(
    private val store: SecureSettingsStore,
    private val underlyingNetwork: Network?,
    private val port: Int = DEFAULT_PORT,
    /** Maps a route's host to the gateway host to dial right now (suffix may have moved). */
    private val resolver: RouteResolver = RouteResolver(store, underlyingNetwork),
) : AutoCloseable {
    private val running = AtomicBoolean(false)
    private val workers = Executors.newFixedThreadPool(MAX_WORKERS)
    private val upstreams = UpstreamConnectionPool(underlyingNetwork)
    @Volatile private var lastActivityAt = 0L
    private val startedAt = System.currentTimeMillis()
    @Volatile private var listener: ServerSocket? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val socket = ServerSocket()
        socket.reuseAddress = true
        socket.bind(InetSocketAddress("127.0.0.1", port))
        listener = socket
        DiagLog.log("HTTP 入口监听 http://127.0.0.1:$port/<host>/<path>")
        Thread({ acceptLoop(socket) }, "gatepass-http-ingress").start()
    }

    private fun acceptLoop(server: ServerSocket) {
        while (running.get()) {
            try {
                val client = server.accept()
                workers.execute { serveClient(client) }
            } catch (_: Exception) {
                if (running.get()) continue
            }
        }
    }

    /** Serves requests on one client connection, honouring HTTP/1.1 keep-alive. */
    private fun serveClient(client: Socket) {
        client.use { downstream ->
            downstream.soTimeout = CLIENT_IDLE_TIMEOUT_MS
            val input = BufferedInputStream(downstream.getInputStream())
            val output = BufferedOutputStream(downstream.getOutputStream())
            while (running.get() && !downstream.isClosed) {
                val headerBytes = try {
                    Http1Framing.readRequestHead(input)
                } catch (_: Exception) {
                    return
                } ?: return
                val keepAlive = try {
                    if (!handleOne(headerBytes, input, output)) return
                    true
                } catch (error: Exception) {
                    DiagLog.error("HTTP 入口处理失败", error)
                    runCatching { writeError(output, 502, "代理失败: ${error.message}") }
                    false
                }
                if (!keepAlive) return
            }
        }
    }

    /** @return false when the client connection must be closed after this request. */
    private fun handleOne(
        headerBytes: ByteArray,
        input: BufferedInputStream,
        output: BufferedOutputStream,
    ): Boolean {
        val requestLine = parseRequestLine(headerBytes) ?: run {
            writeError(output, 400, "Bad Request")
            return false
        }
        val headers = Http1Framing.parseHeaders(headerBytes)
        val clientWantsClose = headers.any {
            it.first.equals("Connection", true) && it.second.contains("close", true)
        } || requestLine.version == "HTTP/1.0"

        val (host, upstreamPath) = splitTarget(requestLine.target) ?: run {
            writeError(output, 421, "路径需以主机名开头，例如 http://127.0.0.1:$port/app-5006-xxx.ugdocker.link/docker/WebDAV/")
            return false
        }
        if (host !in store.loadRoutes()) {
            writeError(output, 421, "未配置该域名的路由: $host")
            return false
        }
        if (!store.isHttpIngressEnabled(host)) {
            writeError(output, 403, "该域名的 HTTP 入口已关闭，请在 GatePass 中开启")
            return false
        }

        val nas = store.loadNas()
        val session = store.loadSession()
        if (session.token.isBlank() && session.cookies.isBlank()) {
            writeError(output, 401, "请先在 GatePass 中登录 NAS")
            return false
        }
        // The gateway may have moved (cn68 → cn11); dial whatever it is now, not the route name.
        val resolverUpstream = resolver.upstreamFor(host)
        val dialHost = resolverUpstream.host
        // A system route (the UGOS desktop) is served by the relay host, which authenticates
        // from the NAS session cookie. There is no dockerToken for it — :9443 is not a mapped
        // port, so asking would only yield the "not a mapped port" error page.
        val gatewayToken = if (resolverUpstream.system) "" else store.loadGatewayToken(host).ifBlank {
            DiagLog.log("HTTP 入口：缓存无网关令牌，刷新 $host")
            val issued = UgosAuthClient(underlyingNetwork, DiagLog::log).gatewayToken(
                nas.baseUrl,
                host,
                UgosAuthClient.LoginResult(session.token, session.cookies),
            )
            store.saveGatewayToken(host, issued.value, issued.expiresAtEpochMs)
            issued.value
        }

        DiagLog.log("HTTP 入口转发 ${requestLine.method} $host$upstreamPath → $dialHost")
        lastActivityAt = System.currentTimeMillis()
        val upstreamReusable = relay(
            input, output, requestLine, headers, host, dialHost, upstreamPath, nas, session, gatewayToken,
        )
        if (!upstreamReusable || clientWantsClose) {
            if (!clientWantsClose) {
                // The upstream side is gone, but the client connection is still healthy.
                writeKeepAliveHint(output)
            }
            return !clientWantsClose
        }
        return true
    }

    /**
     * Sends one request upstream and relays the response.
     * @return true when the upstream connection went back to the pool.
     */
    private fun relay(
        clientInput: BufferedInputStream,
        clientOutput: BufferedOutputStream,
        request: RequestLine,
        headers: List<Pair<String, String>>,
        host: String,
        dialHost: String,
        upstreamPath: String,
        nas: SecureSettingsStore.NasSettings,
        session: SecureSettingsStore.AuthSession,
        gatewayToken: String,
    ): Boolean {
        // A pooled connection can die between the liveness probe and the write (idle timeouts,
        // NAT expiry). Retrying once on a fresh connection is safe here because nothing has been
        // written to the client yet; a retry after that would duplicate a response.
        var attempt = 0
        while (true) {
            val pooled = upstreams.acquire(dialHost)
            var reusable = false
            try {
                return sendAndRelay(
                    pooled, clientInput, clientOutput, request, headers, dialHost, upstreamPath,
                    nas, session, gatewayToken,
                ).also { reusable = it }
            } catch (error: Exception) {
                pooled.broken = true
                val retryable = error is java.io.IOException && attempt == 0
                if (!retryable) throw error
                DiagLog.log("上游连接失效，改用新连接重试 $host")
                attempt++
            } finally {
                upstreams.release(dialHost, pooled, reusable)
            }
        }
    }

    private fun sendAndRelay(
        pooled: UpstreamConnectionPool.Pooled,
        clientInput: BufferedInputStream,
        clientOutput: BufferedOutputStream,
        request: RequestLine,
        headers: List<Pair<String, String>>,
        dialHost: String,
        upstreamPath: String,
        nas: SecureSettingsStore.NasSettings,
        session: SecureSettingsStore.AuthSession,
        gatewayToken: String,
    ): Boolean {
        var reusable = false
        run {
            val upstreamOut = pooled.output
            val upstreamIn = pooled.input

            upstreamOut.write("${request.method} $upstreamPath ${request.version}\r\n".toByteArray(Charsets.ISO_8859_1))
            headers.forEach { (name, value) ->
                if (name.lowercase() !in DROP_REQUEST_HEADERS) {
                    upstreamOut.write("$name: $value\r\n".toByteArray(Charsets.ISO_8859_1))
                }
            }
            upstreamOut.write("Host: $dialHost\r\n".toByteArray(Charsets.ISO_8859_1))
            // Only synthesize NAS Basic auth when the client did not authenticate itself.
            // Overwriting this header breaks apps that use it for their own tokens — Bitwarden
            // sends "Authorization: Bearer <token>" on /api/sync, and replacing it makes the
            // vault sync fail with 401 even though login succeeded.
            val clientAuthorization = headers.firstOrNull { it.first.equals("Authorization", true) }?.second
            DiagLog.log(
                "鉴权头: " + when {
                    clientAuthorization.isNullOrBlank() -> "客户端未提供，注入 NAS Basic"
                    else -> "透传客户端 ${clientAuthorization.substringBefore(' ')} 令牌"
                },
            )
            if (clientAuthorization.isNullOrBlank() && nas.username.isNotBlank()) {
                val basic = java.util.Base64.getEncoder()
                    .encodeToString("${nas.username}:${nas.password}".toByteArray(Charsets.UTF_8))
                upstreamOut.write("Authorization: Basic $basic\r\n".toByteArray(Charsets.ISO_8859_1))
            }
            val clientCookies = headers.firstOrNull { it.first.equals("Cookie", true) }?.second.orEmpty()
            val cookies = mergeCookies(
                clientCookies,
                session.cookies,
                if (gatewayToken.isBlank()) "" else "ugreen-proxy-token=$gatewayToken",
            )
            if (cookies.isNotBlank()) upstreamOut.write("Cookie: $cookies\r\n".toByteArray(Charsets.ISO_8859_1))
            upstreamOut.write("Connection: keep-alive\r\n\r\n".toByteArray(Charsets.ISO_8859_1))

            Http1Framing.copyRequestBody(clientInput, upstreamOut, headers, MAX_BODY_BYTES)
            upstreamOut.flush()

            val head = Http1Framing.readResponseHead(upstreamIn)
                ?: throw java.io.IOException("上游未返回响应")

            // Relay the status line and headers verbatim, but advertise our own connection policy.
            clientOutput.write((head.statusLine + "\r\n").toByteArray(Charsets.ISO_8859_1))
            head.headers.forEach { (name, value) ->
                if (!name.equals("Connection", true)) {
                    clientOutput.write("$name: $value\r\n".toByteArray(Charsets.ISO_8859_1))
                }
            }
            clientOutput.write("Connection: keep-alive\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
            clientOutput.flush()

            val selfDelimited = Http1Framing.copyResponseBody(upstreamIn, clientOutput, head, request.method)
            clientOutput.flush()

            reusable = selfDelimited && !head.connectionClose && !pooled.broken
        }
        return reusable
    }

    private fun writeKeepAliveHint(output: BufferedOutputStream) {
        runCatching { output.flush() }
    }

    /**
     * Splits `<authority>/<host>/<path>` into the target host and the upstream path.
     * The leading authority (127.0.0.1:18080) is dropped first — the first path segment is the
     * routed hostname, not the listener address.
     */
    private fun splitTarget(target: String): Pair<String, String>? {
        val afterScheme = target.substringAfter("://", target)
        val firstSlash = afterScheme.indexOf('/')
        if (firstSlash < 0 || firstSlash == afterScheme.length - 1) return null
        val rest = afterScheme.substring(firstSlash + 1)
        val host = rest.substringBefore('/').substringBefore('?').substringBefore(':').lowercase()
        if (host.isBlank() || !host.contains('.')) return null
        val pathStart = rest.indexOf('/')
        val path = if (pathStart < 0) "/" else rest.substring(pathStart)
        return host to path
    }

    private fun parseRequestLine(bytes: ByteArray): RequestLine? {
        val line = String(bytes, Charsets.ISO_8859_1).substringBefore("\r\n")
        val parts = line.split(' ', limit = 3)
        if (parts.size != 3 || !parts[2].startsWith("HTTP/1.")) return null
        return RequestLine(parts[0], parts[1], parts[2])
    }

    private fun mergeCookies(vararg values: String): String {
        val cookies = linkedMapOf<String, String>()
        values.asSequence()
            .flatMap { it.split(';').asSequence() }
            .map { it.trim() }
            .filter { it.contains('=') }
            .forEach { cookie -> cookies[cookie.substringBefore('=').trim()] = cookie }
        return cookies.values.joinToString("; ")
    }

    private fun writeError(output: BufferedOutputStream, status: Int, reason: String) {
        val body = reason.toByteArray(Charsets.UTF_8)
        val head = "HTTP/1.1 $status ${statusText(status)}\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\nContent-Length: ${body.size}\r\n" +
            "Connection: close\r\n\r\n"
        runCatching {
            output.write(head.toByteArray(Charsets.ISO_8859_1))
            output.write(body)
            output.flush()
        }
    }

    private fun statusText(status: Int): String = when (status) {
        400 -> "Bad Request"
        401 -> "Unauthorized"
        403 -> "Forbidden"
        421 -> "Misdirected Request"
        502 -> "Bad Gateway"
        503 -> "Service Unavailable"
        else -> "Error"
    }

    /** Drops idle upstream connections; called periodically by the VPN service. */
    fun evictIdleUpstreams() = upstreams.evictIdle()

    /**
     * Milliseconds since the last proxied request; drives the adaptive wake lock.
     * A never-used ingress counts as idle since it started, not as an astronomically large
     * number (which previously produced nonsense in the log).
     */
    fun idleForMs(now: Long = System.currentTimeMillis()): Long =
        now - (if (lastActivityAt == 0L) startedAt else lastActivityAt)

    fun activeConnections(): Int = upstreams.pooledCount()

    fun upstreamStats(): String =
        "上游连接池=${upstreams.pooledCount()}，复用次数=${upstreams.reuseStats()}"

    override fun close() {
        running.set(false)
        runCatching { listener?.close() }
        listener = null
        upstreams.close()
        workers.shutdownNow()
    }

    private data class RequestLine(val method: String, val target: String, val version: String)

    companion object {
        const val DEFAULT_PORT = 18080
        private const val MAX_BODY_BYTES = 512L * 1024 * 1024
        private const val CLIENT_IDLE_TIMEOUT_MS = 65_000
        // Bounded so a burst of client connections cannot spawn unlimited threads.
        private const val MAX_WORKERS = 16
        private val DROP_REQUEST_HEADERS = setOf(
            "connection", "proxy-connection", "keep-alive", "te", "trailer",
            "transfer-encoding", "upgrade", "host", "cookie",
            // We send the body immediately; waiting for 100-continue would deadlock the relay.
            "expect",
        )
    }
}
