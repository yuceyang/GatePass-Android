package com.yuceyang.gatepassandroid.proxy

import android.net.Network
import com.yuceyang.gatepassandroid.diag.DiagLog
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Keep-alive pool of TLS connections to upstream hosts.
 *
 * Every WebDAV sync used to pay a TCP + TLS handshake per request; the desktop agent reuses
 * connections, which is why it stays fast. A connection is returned to the pool only when the
 * response body was self-delimited and neither side asked to close.
 */
class UpstreamConnectionPool(
    private val underlyingNetwork: Network?,
    private val idleTtlMs: Long = 45_000,
    private val maxPerHost: Int = 4,
    private val maxTotal: Int = 16,
) : AutoCloseable {
    /** One idle-capable TLS connection to an upstream host. */
    class Pooled internal constructor(
        val socket: SSLSocket,
        val input: BufferedInputStream,
        val output: BufferedOutputStream,
        @Volatile var lastUsedAt: Long,
    ) {
        @Volatile internal var broken = false
        internal val released = java.util.concurrent.atomic.AtomicBoolean(false)
    }

    private val pools = ConcurrentHashMap<String, ArrayBlockingQueue<Pooled>>()
    private val total = AtomicInteger(0)
    private val stats = ConcurrentHashMap<String, AtomicInteger>()
    private val connectFailures = AtomicInteger(0)
    // Global ceiling on simultaneous connections. Hosts are pooled independently, so one busy
    // host can no longer starve another; this semaphore is what bounds the process overall.
    private val permits = Semaphore(maxTotal, true)

    /**
     * @throws IllegalStateException when the global connection budget cannot be obtained, so the
     * caller can answer 503 instead of queueing forever behind a saturated pool.
     */
    fun acquire(host: String): Pooled {
        val queue = pools.computeIfAbsent(host) { ArrayBlockingQueue(maxPerHost) }
        while (true) {
            val candidate = queue.poll() ?: break
            if (isUsable(candidate)) {
                stats.computeIfAbsent(host) { AtomicInteger() }.incrementAndGet()
                DiagLog.log("复用上游连接 $host（空闲 ${(System.currentTimeMillis() - candidate.lastUsedAt) / 1000}s）")
                return candidate
            }
            discard(candidate)
        }
        if (!permits.tryAcquire(ACQUIRE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
            throw IllegalStateException("连接数已达上限（$maxTotal），请稍后重试")
        }
        try {
            return connect(host)
        } catch (error: Exception) {
            permits.release()
            connectFailures.incrementAndGet()
            throw error
        }
    }

    /** Visible for tests: is an idle pooled connection still safe to reuse? */
    internal fun isUsableForTest(pooled: Any): Boolean = isUsable(pooled as Pooled)

    /** Visible for tests: inspect pool bookkeeping without opening a real connection. */
    internal fun poolSizeForTest(host: String): Int = pools[host]?.size ?: 0

    private fun isUsable(pooled: Pooled): Boolean {
        if (pooled.broken) return false
        if (System.currentTimeMillis() - pooled.lastUsedAt > idleTtlMs) return false
        if (pooled.socket.isClosed || pooled.socket.isInputShutdown || pooled.socket.isOutputShutdown) return false
        // Peek for either EOF (peer closed) or unsolicited bytes; both make the framing untrustworthy.
        // available() alone is not enough: a closed TLS connection often reports 0 buffered bytes
        // until something actually reads from the socket.
        val previousTimeout = runCatching { pooled.socket.soTimeout }.getOrDefault(IO_TIMEOUT_MS)
        return runCatching {
            pooled.socket.soTimeout = PROBE_TIMEOUT_MS
            pooled.input.mark(1)
            val probe = pooled.input.read()
            if (probe < 0) {
                false
            } else {
                pooled.input.reset()
                false
            }
        }.getOrElse { error ->
            // Read timeout means "idle and still open"; anything else means the connection is dead.
            error is java.net.SocketTimeoutException
        }.also {
            runCatching { pooled.socket.soTimeout = previousTimeout }
        }
    }

    private fun connect(host: String): Pooled {
        val raw = openRaw(host)
        val socket = (SSLSocketFactory.getDefault() as SSLSocketFactory)
            .createSocket(raw, host, HTTPS_PORT, true) as SSLSocket
        socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
        socket.soTimeout = IO_TIMEOUT_MS
        try {
            socket.startHandshake()
        } catch (error: Exception) {
            runCatching { socket.close() }
            throw error
        }
        total.incrementAndGet()
        return Pooled(socket, BufferedInputStream(socket.inputStream), BufferedOutputStream(socket.outputStream), System.currentTimeMillis())
    }

    private fun openRaw(host: String): Socket {
        val socket = Socket()
        try {
            val network = underlyingNetwork
            val address = network?.getAllByName(host)?.firstOrNull() ?: InetAddress.getAllByName(host).first()
            if (network != null) network.bindSocket(socket) else socket.bind(null)
            socket.connect(InetSocketAddress(address, HTTPS_PORT), CONNECT_TIMEOUT_MS)
            return socket
        } catch (error: Exception) {
            runCatching { socket.close() }
            throw error
        }
    }

    /** Returns a healthy connection to the pool; otherwise closes it. */
    fun release(host: String, pooled: Pooled, reusable: Boolean) {
        if (!reusable || pooled.broken || pooled.socket.isClosed) {
            discard(pooled)
            return
        }
        pooled.lastUsedAt = System.currentTimeMillis()
        runCatching { pooled.socket.soTimeout = IO_TIMEOUT_MS }
        val queue = pools[host]
        if (queue == null || !queue.offer(pooled)) discard(pooled)
    }

    fun discard(pooled: Pooled) {
        if (!pooled.released.compareAndSet(false, true)) return
        pooled.broken = true
        runCatching { pooled.socket.close() }
        total.updateAndGet { if (it > 0) it - 1 else 0 }
        permits.release()
    }

    /** Drops idle connections past their TTL; called periodically by the VPN service. */
    fun evictIdle(now: Long = System.currentTimeMillis()) {
        pools.forEach { (host, queue) ->
            val expired = mutableListOf<Pooled>()
            queue.forEach { if (now - it.lastUsedAt > idleTtlMs || it.broken) expired += it }
            expired.forEach { if (queue.remove(it)) discard(it) }
            if (queue.isEmpty()) pools.remove(host, queue)
        }
        if (total.get() > maxTotal) DiagLog.log("上游连接数偏高: ${total.get()}")
    }

    fun pooledCount(): Int = total.get()

    fun reuseStats(): Map<String, Int> = stats.mapValues { it.value.get() }

    fun failures(): Int = connectFailures.get()

    fun hostsInPool(): Int = pools.size

    /** Per-host connection counts, for diagnostics. */
    fun hostCounts(): Map<String, Int> = pools.mapValues { it.value.size }

    override fun close() {
        pools.values.forEach { queue -> queue.forEach { discard(it) }; queue.clear() }
        pools.clear()
    }

    private companion object {
        const val HTTPS_PORT = 443
        const val CONNECT_TIMEOUT_MS = 15_000
        const val IO_TIMEOUT_MS = 60_000
        /** Short enough to be invisible, long enough to distinguish "idle" from "closed". */
        const val PROBE_TIMEOUT_MS = 60
        const val ACQUIRE_TIMEOUT_MS = 10_000L
    }
}
