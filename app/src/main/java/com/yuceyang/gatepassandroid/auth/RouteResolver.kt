package com.yuceyang.gatepassandroid.auth

import com.yuceyang.gatepassandroid.data.ProxyRoute
import com.yuceyang.gatepassandroid.data.SecureSettingsStore
import com.yuceyang.gatepassandroid.diag.DiagLog

/**
 * Decides *where* a routed host is actually reached, and keeps that answer fresh.
 *
 * A route's host is the name the user's apps and bookmarks ask for, and it is built from the
 * fixed suffix the user chose. The gateway behind it moves whenever the NAS re-registers
 * (cn68 → cn11), so dialling the route host directly breaks everything with no visible cause.
 * This resolves the alias once, caches the result, and hands the proxy the current host.
 *
 * System routes (the UGOS desktop on :9443) are not behind the docker port mapping at all —
 * that mapping forwards plain HTTP and IIS there speaks TLS only, so they go to the relay host.
 */
class RouteResolver(
    private val store: SecureSettingsStore,
    private val network: android.net.Network? = null,
    private val now: () -> Long = System::currentTimeMillis,
) {
    /**
     * The hostname to open for [host], and whether it is the relay (system) path.
     * Never throws: a failed lookup leaves the caller on the route's own host, which is the
     * best guess available and is what worked before the NAS re-registered.
     */
    fun upstreamFor(host: String): Upstream {
        val kind = store.routeKind(host)
        if (kind == ProxyRoute.KIND_SYSTEM) {
            val relay = store.relayHost() ?: refresh()?.relayHost
            if (relay != null) return Upstream(host = relay, system = true)
            // No relay yet: fall back to the mapped host so the request still has a chance.
            return Upstream(host = store.liveUpstreamHost(host), system = false)
        }
        ensureFresh()
        return Upstream(host = store.liveUpstreamHost(host), system = false)
    }

    /** Re-resolves the alias when the cached answer is missing or older than the TTL. */
    fun ensureFresh() {
        val d = store.loadDiscovered()
        if (d.domainSuffix.isNotBlank() && now() - d.atEpochMs < TTL_MS) return
        refresh()
    }

    /** Forces a lookup; returns the fresh answer, or null when it could not be obtained. */
    fun refresh(): Discovered? {
        val alias = store.loadNas().alias
        if (alias.isBlank()) return null
        val node = UgosAuthClient(network, DiagLog::log).lookupByAlias(alias) ?: run {
            DiagLog.log("别名 $alias 查询失败，沿用当前后缀")
            return null
        }
        val previous = store.loadDiscovered()
        store.saveDiscovered(node.domainSuffix, node.relayHost, now())
        if (node.domainSuffix.isNotBlank() && previous.domainSuffix != node.domainSuffix) {
            DiagLog.log("网关后缀变化: ${previous.domainSuffix.ifBlank { "(未知)" }} → ${node.domainSuffix}")
        }
        return Discovered(node.domainSuffix, node.relayHost)
    }

    data class Upstream(val host: String, val system: Boolean)
    data class Discovered(val domainSuffix: String, val relayHost: String)

    companion object {
        /** Short enough to notice a re-register, long enough not to chat to UGREENlink per request. */
        private const val TTL_MS = 10L * 60 * 1000
    }
}
