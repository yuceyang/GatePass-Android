package com.yuceyang.gatepassandroid.proxy

import java.net.URI

/**
 * WebDAV's `Destination` is an absolute URL carrying the host the client knows — the fixed
 * route name a bookmark uses. The upstream validates that authority against the host it was
 * reached as, so a MOVE whose Destination still says `cn68` while the request dialled `cn11`
 * is answered 404 and every sync fails at the final rename.
 *
 * Rewriting only the authority keeps the path, query and port exactly as the client sent them.
 */
object WebDavDestination {

    /**
     * @param value the client's Destination header, possibly relative or absent.
     * @param knownHost the route's own host (what the client addressed us as).
     * @param dialHost the host the request is actually being sent to.
     * @return the header to forward, unchanged when it does not name [knownHost].
     */
    fun rewrite(value: String?, knownHost: String, dialHost: String): String? {
        if (value.isNullOrBlank() || knownHost.isBlank() || dialHost.isBlank()) return value
        val uri = runCatching { URI(value.trim()) }.getOrNull() ?: return value
        // A relative Destination has no authority; the upstream resolves it against `Host`.
        val host = uri.host ?: return value
        if (!host.equals(knownHost, ignoreCase = true)) return value
        if (host.equals(dialHost, ignoreCase = true)) return value

        val port = if (uri.port == -1) "" else ":${uri.port}"
        val userInfo = uri.rawUserInfo?.let { "$it@" } ?: ""
        return "${uri.scheme}://$userInfo$dialHost$port${uri.rawPath.orEmpty()}${uri.rawQuery?.let { "?$it" } ?: ""}"
    }
}
