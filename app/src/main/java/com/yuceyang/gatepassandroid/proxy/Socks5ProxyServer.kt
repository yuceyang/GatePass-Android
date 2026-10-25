package com.yuceyang.gatepassandroid.proxy

import com.yuceyang.gatepassandroid.auth.UgosAuthClient
import com.yuceyang.gatepassandroid.data.SecureSettingsStore
import com.yuceyang.gatepassandroid.diag.DiagLog
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import android.net.Network
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Local SOCKS5 endpoint consumed by the pinned HEV TUN-to-SOCKS5 AAR. */
class Socks5ProxyServer(
    private val store: SecureSettingsStore,
    private val ca: CertificateAuthority,
    private val protectSocket: (Socket) -> Boolean,
    private val protectDatagram: (DatagramSocket) -> Boolean,
    private val underlyingNetwork: Network?,
    private val port: Int = DEFAULT_PORT,
) : AutoCloseable {
    private val running = AtomicBoolean(false)
    private val workers = Executors.newCachedThreadPool()
    private val upstreams = UpstreamConnectionPool(underlyingNetwork)
    @Volatile private var listener: ServerSocket? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val socket = ServerSocket()
        socket.reuseAddress = true
        socket.bind(InetSocketAddress("127.0.0.1", port))
        listener = socket
        DiagLog.log("SOCKS5 监听 127.0.0.1:$port")
        Thread({ acceptLoop(socket) }, "gatepass-socks5-accept").start()
    }

    private fun acceptLoop(server: ServerSocket) {
        while (running.get()) {
            try {
                val socket = server.accept()
                workers.execute { handleClient(socket) }
            } catch (_: Exception) {
                if (running.get()) continue
            }
        }
    }

    private fun handleClient(socket: Socket) {
        socket.use { client ->
            client.soTimeout = SOCKET_TIMEOUT_MS
            // Do NOT wrap in BufferedInputStream: it could swallow the TLS ClientHello that
            // follows the SOCKS reply in the same segment, and the SSLSocket would never see it.
            val input = DataInputStream(client.getInputStream())
            val output = DataOutputStream(BufferedOutputStream(client.getOutputStream()))
            try {
                val version = input.readUnsignedByte()
                val methodCount = input.readUnsignedByte()
                if (version != SOCKS_VERSION || methodCount !in 1..32) return
                val methods = ByteArray(methodCount)
                input.readFully(methods)
                if (methods.none { (it.toInt() and 0xff) == NO_AUTH }) {
                    output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0xff.toByte()))
                    output.flush()
                    return
                }
                output.write(byteArrayOf(SOCKS_VERSION.toByte(), NO_AUTH.toByte()))
                output.flush()

                if (input.readUnsignedByte() != SOCKS_VERSION) return
                val command = input.readUnsignedByte()
                input.readUnsignedByte() // reserved
                val target = readTarget(input) ?: return reply(output, REP_ADDRESS_TYPE_NOT_SUPPORTED)
                when (command) {
                    CMD_CONNECT -> handleConnect(client, input, output, target)
                    CMD_UDP_ASSOCIATE -> handleUdpAssociate(client, input, output)
                    else -> reply(output, REP_COMMAND_NOT_SUPPORTED)
                }
            } catch (error: Exception) {
                DiagLog.error("SOCKS 会话处理异常", error)
                runCatching { reply(output, REP_GENERAL_FAILURE) }
            }
        }
    }

    private fun handleConnect(client: Socket, input: DataInputStream, output: DataOutputStream, target: Target) {
        if (target.host !in store.loadRoutes()) {
            tunnelDirect(client, output, target)
            return
        }
        if (target.port != HTTP_PORT && target.port != HTTPS_PORT) {
            reply(output, REP_CONNECTION_NOT_ALLOWED)
            return
        }
        reply(output, REP_SUCCEEDED)
        if (target.port == HTTPS_PORT) {
        DiagLog.log("命中路由 ${target.host}，本地 TLS 终结")
        interceptTls(client, target.host)
        } else {
            val clientInput = BufferedInputStream(client.getInputStream())
            val clientOutput = BufferedOutputStream(client.getOutputStream())
            val headers = readHeaders(clientInput) ?: return
            val request = parseRequestLine(headers) ?: return writeError(clientOutput, 400, "Bad Request")
            forwardAuthenticated(clientInput, clientOutput, request, target.host, parseHeaders(headers))
        }
    }

    private fun interceptTls(client: Socket, host: String) {
        val context = try {
            ca.serverContext(host)
        } catch (error: Exception) {
            DiagLog.error("生成 $host 证书失败", error)
            return
        }
        DiagLog.log("已生成 $host 的本地证书，等待客户端 TLS 握手")
        val tls = context.socketFactory.createSocket(client, host, HTTPS_PORT, true) as SSLSocket
        tls.use { secureClient ->
            secureClient.useClientMode = false
            secureClient.soTimeout = SOCKET_TIMEOUT_MS
            try {
                secureClient.startHandshake()
            } catch (error: Exception) {
                DiagLog.error("与客户端的 TLS 握手失败 $host", error)
                return
            }
            DiagLog.log("客户端 TLS 握手完成 $host")
            val input = BufferedInputStream(secureClient.inputStream)
            val output = BufferedOutputStream(secureClient.outputStream)
            val headers = readHeaders(input) ?: return
            val request = parseRequestLine(headers) ?: return writeError(output, 400, "Bad Request")
            if (request.method.equals("CONNECT", true)) return writeError(output, 400, "Nested CONNECT is unsupported")
            DiagLog.log("TLS 解密成功 $host → ${request.method} ${request.target}")
            forwardAuthenticated(input, output, request, host, parseHeaders(headers))
        }
    }

    private fun forwardAuthenticated(
        clientInput: BufferedInputStream,
        clientOutput: BufferedOutputStream,
        request: RequestLine,
        host: String,
        headers: List<Pair<String, String>>,
    ) {
        if (host !in store.loadRoutes()) return writeError(clientOutput, 421, "No enabled route for $host")
        val bodyLength = headers.firstOrNull { it.first.equals("Content-Length", true) }
            ?.second?.toLongOrNull() ?: 0L
        if (bodyLength > MAX_BODY_BYTES) return writeError(clientOutput, 413, "Request body too large")

        val nas = store.loadNas()
        val session = store.loadSession()
        if (session.token.isBlank() && session.cookies.isBlank()) {
            DiagLog.log("拦截 $host：尚未登录 NAS")
            return writeError(clientOutput, 401, "NAS login required")
        }
        if (store.sessionState() == SecureSettingsStore.SessionState.Expired) {
            DiagLog.log("拦截 $host：NAS 会话已过期，请在 GatePass 中重新登录")
            return writeError(clientOutput, 401, "NAS session expired — reopen GatePass and log in again")
        }
        val gatewayToken = store.loadGatewayToken(host).ifBlank {
            DiagLog.log("缓存无网关令牌，刷新 $host")
            val issued = UgosAuthClient(underlyingNetwork, DiagLog::log).gatewayToken(
                nas.baseUrl,
                host,
                UgosAuthClient.LoginResult(session.token, session.cookies),
            )
            store.saveGatewayToken(host, issued.value, issued.expiresAtEpochMs)
            issued.value
        }

        DiagLog.log("转发 ${request.method} https://$host${request.target}（已注入 NAS 凭据）")
        val pooled = upstreams.acquire(host)
        var reusable = false
        try {
            val upstreamOutput = pooled.output
            val upstreamInput = pooled.input
            upstreamOutput.write("${request.method} ${request.target} ${request.version}\r\n".toByteArray(Charsets.ISO_8859_1))
            headers.forEach { (name, value) ->
                if (name.lowercase() !in HOP_BY_HOP_HEADERS &&
                    !name.equals("cookie", true) &&
                    !name.equals("host", true)
                ) {
                    upstreamOutput.write("$name: $value\r\n".toByteArray(Charsets.ISO_8859_1))
                }
            }
            upstreamOutput.write("Host: $host\r\n".toByteArray(Charsets.ISO_8859_1))
            // Some Docker apps sit behind HTTP Basic on the gateway, but the client's own
            // Authorization (Bearer, etc.) must win when present — otherwise per-app tokens
            // such as Bitwarden's /api/sync credential get clobbered and sync fails with 401.
            val clientAuthorization = headers.firstOrNull { it.first.equals("Authorization", true) }?.second
            if (clientAuthorization.isNullOrBlank() && nas.username.isNotBlank()) {
                val basic = java.util.Base64.getEncoder()
                    .encodeToString("${nas.username}:${nas.password}".toByteArray(Charsets.UTF_8))
                upstreamOutput.write("Authorization: Basic $basic\r\n".toByteArray(Charsets.ISO_8859_1))
            }
            val clientCookies = headers.firstOrNull { it.first.equals("cookie", true) }?.second.orEmpty()
            val cookies = mergeCookies(clientCookies, session.cookies, "ugreen-proxy-token=$gatewayToken")
            if (cookies.isNotBlank()) upstreamOutput.write("Cookie: $cookies\r\n".toByteArray(Charsets.ISO_8859_1))
            upstreamOutput.write("Connection: keep-alive\r\n\r\n".toByteArray(Charsets.ISO_8859_1))

            Http1Framing.copyRequestBody(clientInput, upstreamOutput, headers, MAX_BODY_BYTES)
            upstreamOutput.flush()

            val head = Http1Framing.readResponseHead(upstreamInput)
                ?: throw java.io.IOException("上游未返回响应")
            clientOutput.write((head.statusLine + "\r\n").toByteArray(Charsets.ISO_8859_1))
            head.headers.forEach { (name, value) ->
                if (!name.equals("Connection", true)) {
                    clientOutput.write("$name: $value\r\n".toByteArray(Charsets.ISO_8859_1))
                }
            }
            clientOutput.write("Connection: close\r\n\r\n".toByteArray(Charsets.ISO_8859_1))

            clientOutput.flush()
            val selfDelimited = Http1Framing.copyResponseBody(upstreamInput, clientOutput, head, request.method)
            clientOutput.flush()
            reusable = selfDelimited && !head.connectionClose && !pooled.broken
        } finally {
            upstreams.release(host, pooled, reusable)
        }
    }

    private fun tunnelDirect(client: Socket, output: DataOutputStream, target: Target) {
        val upstream = try {
            openUnderlyingSocket(target.host, target.port)
        } catch (_: Exception) {
            reply(output, REP_HOST_UNREACHABLE)
            return
        }
        upstream.use { remote ->
            reply(output, REP_SUCCEEDED)
            val clientToUpstream = Thread({
                runCatching { client.getInputStream().copyTo(remote.getOutputStream()) }
                runCatching { remote.shutdownOutput() }
            }, "gatepass-socks5-uplink")
            clientToUpstream.start()
            runCatching { remote.getInputStream().copyTo(client.getOutputStream()) }
            clientToUpstream.join(SOCKET_TIMEOUT_MS.toLong())
        }
    }

    private fun openUnderlyingSocket(host: String, port: Int): Socket {
        val socket = Socket()
        try {
            val network = underlyingNetwork
            if (network != null) network.bindSocket(socket)
            else check(protectSocket(socket)) { "Could not protect upstream socket" }
            val address = network?.getAllByName(host)?.firstOrNull() ?: InetAddress.getAllByName(host).first()
            socket.connect(InetSocketAddress(address, port), SOCKET_TIMEOUT_MS)
            return socket
        } catch (error: Exception) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun handleUdpAssociate(control: Socket, input: DataInputStream, output: DataOutputStream) {
        val relay = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
        if (!protectDatagram(relay)) {
            relay.close()
            reply(output, REP_GENERAL_FAILURE)
            return
        }
        reply(output, REP_SUCCEEDED, InetAddress.getByName("127.0.0.1"), relay.localPort)
        control.soTimeout = 0
        val pending = ConcurrentHashMap<DnsKey, PendingDns>()
        val relayThread = Thread({ udpRelayLoop(relay, pending) }, "gatepass-socks5-udp")
        relayThread.start()
        try {
            while (running.get() && !control.isClosed && input.read() >= 0) Unit
        } finally {
            relay.close()
            relayThread.interrupt()
        }
    }

    private fun udpRelayLoop(relay: DatagramSocket, pending: ConcurrentHashMap<DnsKey, PendingDns>) {
        val bytes = ByteArray(MAX_UDP_PACKET)
        while (running.get() && !relay.isClosed) {
            try {
                val packet = DatagramPacket(bytes, bytes.size)
                relay.receive(packet)
                if (packet.address.isLoopbackAddress) {
                    val parsed = parseSocksUdp(packet.data, packet.offset, packet.length) ?: continue
                    val payload = parsed.payload
                    if (parsed.port != DNS_PORT || payload.size < 2) continue
                    val target = if (parsed.host == MAPDNS_IP) DNS_RESOLVER else parsed.address
                    if (pending.size >= MAX_PENDING_DNS) pending.clear()
                    val key = DnsKey(readU16(payload, 0), target.hostAddress.orEmpty(), parsed.port)
                    pending[key] = PendingDns(packet.socketAddress, parsed.address, parsed.port)
                    relay.send(DatagramPacket(payload, payload.size, target, parsed.port))
                } else {
                    val payload = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    if (payload.size < 2) continue
                    val key = DnsKey(readU16(payload, 0), packet.address.hostAddress.orEmpty(), packet.port)
                    val request = pending.remove(key) ?: continue
                    val encoded = encodeSocksUdp(request.targetAddress, request.targetPort, payload)
                    relay.send(DatagramPacket(encoded, encoded.size, request.clientAddress))
                }
            } catch (_: Exception) {
                if (!relay.isClosed) continue
            }
        }
    }

    private fun parseSocksUdp(buffer: ByteArray, offset: Int, length: Int): UdpRequest? {
        if (length < 10 || buffer[offset] != 0.toByte() || buffer[offset + 1] != 0.toByte() || buffer[offset + 2] != 0.toByte()) return null
        var index = offset + 3
        val address: InetAddress
        val host: String
        when (buffer[index++].toInt() and 0xff) {
            ATYP_IPV4 -> {
                val raw = buffer.copyOfRange(index, index + 4)
                address = InetAddress.getByAddress(raw)
                host = address.hostAddress.orEmpty()
                index += 4
            }
            ATYP_DOMAIN -> {
                val size = buffer[index++].toInt() and 0xff
                host = String(buffer, index, size, Charsets.UTF_8)
                address = InetAddress.getByName(host)
                index += size
            }
            ATYP_IPV6 -> {
                val raw = buffer.copyOfRange(index, index + 16)
                address = InetAddress.getByAddress(raw)
                host = address.hostAddress.orEmpty()
                index += 16
            }
            else -> return null
        }
        if (index + 2 > offset + length) return null
        val port = readU16(buffer, index)
        index += 2
        return UdpRequest(host, address, port, buffer.copyOfRange(index, offset + length))
    }

    private fun encodeSocksUdp(source: InetAddress, port: Int, data: ByteArray): ByteArray {
        val address = source.address
        val atyp = if (address.size == 4) ATYP_IPV4 else ATYP_IPV6
        return byteArrayOf(0, 0, 0, atyp.toByte()) + address + byteArrayOf((port ushr 8).toByte(), port.toByte()) + data
    }

    private fun readTarget(input: DataInputStream): Target? {
        val host = when (input.readUnsignedByte()) {
            ATYP_IPV4 -> ByteArray(4).also(input::readFully).let { InetAddress.getByAddress(it).hostAddress }
            ATYP_DOMAIN -> {
                val size = input.readUnsignedByte()
                ByteArray(size).also(input::readFully).toString(Charsets.UTF_8)
            }
            ATYP_IPV6 -> ByteArray(16).also(input::readFully).let { InetAddress.getByAddress(it).hostAddress }
            else -> return null
        }
        val port = input.readUnsignedShort()
        return Target(host.lowercase(), port)
    }

    private fun reply(output: DataOutputStream, status: Int, address: InetAddress = InetAddress.getByName("127.0.0.1"), port: Int = 0) {
        val raw = address.address
        output.writeByte(SOCKS_VERSION)
        output.writeByte(status)
        output.writeByte(0)
        output.writeByte(if (raw.size == 4) ATYP_IPV4 else ATYP_IPV6)
        output.write(raw)
        output.writeShort(port)
        output.flush()
    }

    private fun parseRequestLine(bytes: ByteArray): RequestLine? {
        val line = String(bytes, Charsets.ISO_8859_1).substringBefore("\r\n")
        val parts = line.split(' ', limit = 3)
        if (parts.size != 3 || !parts[2].startsWith("HTTP/1.")) return null
        return RequestLine(parts[0], parts[1], parts[2])
    }

    private fun parseHeaders(bytes: ByteArray): List<Pair<String, String>> =
        String(bytes, Charsets.ISO_8859_1).split("\r\n")
            .drop(1)
            .takeWhile { it.isNotEmpty() }
            .mapNotNull { line ->
                val colon = line.indexOf(':')
                if (colon <= 0) null else line.substring(0, colon).trim() to line.substring(colon + 1).trim()
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

    private fun readHeaders(input: BufferedInputStream): ByteArray? {
        val output = java.io.ByteArrayOutputStream()
        var matched = 0
        while (output.size() < MAX_HEADER_BYTES) {
            val value = input.read()
            if (value < 0) return if (output.size() == 0) null else output.toByteArray()
            output.write(value)
            matched = when {
                matched == 0 && value == '\r'.code -> 1
                matched == 1 && value == '\n'.code -> 2
                matched == 2 && value == '\r'.code -> 3
                matched == 3 && value == '\n'.code -> 4
                value == '\r'.code -> 1
                else -> 0
            }
            if (matched == 4) return output.toByteArray()
        }
        throw IllegalArgumentException("Request headers exceed limit")
    }

    private fun writeError(output: java.io.OutputStream, status: Int, reason: String) {
        val body = reason.toByteArray(Charsets.UTF_8)
        val response = "HTTP/1.1 $status $reason\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        output.write(response)
        output.write(body)
        output.flush()
    }

    override fun close() {
        running.set(false)
        runCatching { listener?.close() }
        listener = null
        upstreams.close()
        workers.shutdownNow()
    }

    private data class Target(val host: String, val port: Int)
    private data class RequestLine(val method: String, val target: String, val version: String)
    private data class UdpRequest(val host: String, val address: InetAddress, val port: Int, val payload: ByteArray)
    private data class PendingDns(val clientAddress: java.net.SocketAddress, val targetAddress: InetAddress, val targetPort: Int)
    private data class DnsKey(val id: Int, val host: String, val port: Int)

    companion object {
        const val DEFAULT_PORT = 17890
        private const val MAX_HEADER_BYTES = 32 * 1024
        private const val MAX_BODY_BYTES = 512L * 1024 * 1024
        private const val SOCKET_TIMEOUT_MS = 15_000
        private const val SOCKS_VERSION = 5
        private const val NO_AUTH = 0
        private const val CMD_CONNECT = 1
        private const val CMD_UDP_ASSOCIATE = 3
        private const val REP_SUCCEEDED = 0
        private const val REP_GENERAL_FAILURE = 1
        private const val REP_CONNECTION_NOT_ALLOWED = 2
        private const val REP_NETWORK_UNREACHABLE = 3
        private const val REP_HOST_UNREACHABLE = 4
        private const val REP_COMMAND_NOT_SUPPORTED = 7
        private const val REP_ADDRESS_TYPE_NOT_SUPPORTED = 8
        private const val ATYP_IPV4 = 1
        private const val ATYP_DOMAIN = 3
        private const val ATYP_IPV6 = 4
        private const val HTTP_PORT = 80
        private const val HTTPS_PORT = 443
        private const val DNS_PORT = 53
        private const val MAPDNS_IP = "10.79.0.2"
        private val HOP_BY_HOP_HEADERS = setOf(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade",
        )
        private val DNS_RESOLVER: InetAddress = InetAddress.getByName("1.1.1.1")
        private const val MAX_UDP_PACKET = 4096
        private const val MAX_PENDING_DNS = 2048

        private fun readU16(bytes: ByteArray, offset: Int) =
            ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    }
}
