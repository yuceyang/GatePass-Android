package com.yuceyang.gatepassandroid.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Stores NAS credentials encrypted with a device-local Android Keystore key. */
class SecureSettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("gatepass_private", Context.MODE_PRIVATE)

    fun saveNas(baseUrl: String, username: String, password: String) {
        prefs.edit()
            .putString("nas_url", baseUrl.trim().trimEnd('/'))
            .putString("nas_user", encrypt(username))
            .putString("nas_password", encrypt(password))
            .apply()
    }

    fun loadNas(): NasSettings = NasSettings(
        baseUrl = prefs.getString("nas_url", "") ?: "",
        username = decrypt(prefs.getString("nas_user", null)),
        password = decrypt(prefs.getString("nas_password", null)),
        alias = prefs.getString(KEY_LINK_ALIAS, "") ?: "",
    )

    /** UGREENlink alias; the login host is resolved from it at runtime. */
    fun saveAlias(alias: String) {
        prefs.edit().putString(KEY_LINK_ALIAS, alias.trim()).apply()
    }

    /**
     * The suffix UGREENlink reports right now, and the relay host that serves NAS system pages.
     *
     * The gateway suffix moves whenever the NAS re-registers (cn68 → cn11). Routes keep the
     * user's fixed suffix (bookmarks), and this is what the proxy dials instead.
     */
    fun saveDiscovered(domainSuffix: String, relayHost: String, nowEpochMs: Long = System.currentTimeMillis()) {
        prefs.edit()
            .putString(KEY_LIVE_SUFFIX, domainSuffix.trim())
            .putString(KEY_RELAY_HOST, relayHost.trim())
            .putLong(KEY_DISCOVERED_AT, nowEpochMs)
            .apply()
    }

    data class Discovered(val domainSuffix: String, val relayHost: String, val atEpochMs: Long)

    fun loadDiscovered(): Discovered = Discovered(
        domainSuffix = prefs.getString(KEY_LIVE_SUFFIX, "") ?: "",
        relayHost = prefs.getString(KEY_RELAY_HOST, "") ?: "",
        atEpochMs = prefs.getLong(KEY_DISCOVERED_AT, 0L),
    )

    /** True when a lookup has ever completed, i.e. dialling may use the live suffix. */
    fun hasDiscovered(): Boolean = loadDiscovered().domainSuffix.isNotBlank()

    /** The user's fixed suffix — what routes and bookmarks are built from. */
    fun fixedSuffix(): String = persistedDomainSuffix()

    fun saveFixedSuffix(suffix: String) {
        prefs.edit().putString(KEY_DOMAIN_SUFFIX, suffix.trim().removePrefix(".")).apply()
    }

    /**
     * Rewrites [host]'s suffix from the fixed one to the live one, so a route keeps working
     * after the NAS re-registers without the user editing a bookmark.
     */
    fun liveUpstreamHost(host: String): String {
        val d = loadDiscovered()
        val fixed = fixedSuffix()
        if (d.domainSuffix.isBlank() || fixed.isBlank() || d.domainSuffix == fixed) return host
        val lower = host.lowercase()
        if (!lower.endsWith(fixed.lowercase())) return host
        return host.dropLast(fixed.length) + d.domainSuffix
    }

    /** The relay host for a system route, or null before any lookup has happened. */
    fun relayHost(): String? = loadDiscovered().relayHost.takeIf { it.isNotBlank() }

    /**
     * Stores the NAS session together with when it was obtained.
     *
     * The UGOS login token lives for roughly 12 hours; recording the timestamp lets the UI show
     * "logged in / expiring / expired" instead of failing later with an opaque 401.
     */
    fun saveSession(sessionToken: String, cookieHeader: String, nowEpochMs: Long = System.currentTimeMillis()) {
        prefs.edit()
            .putString("session_token", encrypt(sessionToken))
            .putString("session_cookie", encrypt(cookieHeader))
            .putLong("session_obtained_at", nowEpochMs)
            .apply()
    }

    fun loadSession(): AuthSession = AuthSession(
        token = decrypt(prefs.getString("session_token", null)),
        cookies = decrypt(prefs.getString("session_cookie", null)),
        obtainedAtEpochMs = prefs.getLong("session_obtained_at", 0L),
    )

    /** Login state derived from storage alone, without touching the network. */
    fun sessionState(nowEpochMs: Long = System.currentTimeMillis()): SessionState {
        val s = loadSession()
        if (s.token.isBlank() && s.cookies.isBlank()) return SessionState.Missing
        if (s.obtainedAtEpochMs <= 0L) return SessionState.Unknown
        val ageMs = nowEpochMs - s.obtainedAtEpochMs
        return when {
            ageMs >= SESSION_TTL_MS -> SessionState.Expired
            ageMs >= SESSION_TTL_MS - SESSION_WARN_MS -> SessionState.Expiring
            else -> SessionState.Valid
        }
    }

    /** How long the current session has been alive, or null when unknown/no session. */
    fun sessionAgeMs(nowEpochMs: Long = System.currentTimeMillis()): Long? {
        val s = loadSession()
        return if (s.obtainedAtEpochMs <= 0L) null else (nowEpochMs - s.obtainedAtEpochMs).coerceAtLeast(0L)
    }

    enum class SessionState { Valid, Expiring, Expired, Missing, Unknown }

    fun saveCaMaterial(privateKeyPkcs8: ByteArray, certificateDer: ByteArray) {
        prefs.edit()
            .putString("ca_private_key", encrypt(Base64.encodeToString(privateKeyPkcs8, Base64.NO_WRAP)))
            .putString("ca_certificate", encrypt(Base64.encodeToString(certificateDer, Base64.NO_WRAP)))
            .apply()
    }

    fun loadCaMaterial(): CaMaterial? {
        val privateKey = decrypt(prefs.getString("ca_private_key", null)).takeIf { it.isNotEmpty() } ?: return null
        val certificate = decrypt(prefs.getString("ca_certificate", null)).takeIf { it.isNotEmpty() } ?: return null
        return runCatching {
            CaMaterial(Base64.decode(privateKey, Base64.NO_WRAP), Base64.decode(certificate, Base64.NO_WRAP))
        }.getOrNull()
    }

    fun saveLeaf(host: String, privateKeyPkcs8: ByteArray, certificateDer: ByteArray, expiresAtEpochMs: Long) {
        val key = leafKey(host)
        prefs.edit()
            .putString(key, encrypt(Base64.encodeToString(privateKeyPkcs8, Base64.NO_WRAP)))
            .putString("$key.cert", encrypt(Base64.encodeToString(certificateDer, Base64.NO_WRAP)))
            .putLong("$key.expires", expiresAtEpochMs)
            .apply()
    }

    /** Returns a cached leaf certificate/private key, or null when absent or close to expiry. */
    fun loadLeaf(host: String, nowEpochMs: Long = System.currentTimeMillis()): LeafMaterial? {
        val key = leafKey(host)
        val expiresAt = prefs.getLong("$key.expires", 0L)
        // Renew a bit early so a cached leaf never expires mid-session.
        if (expiresAt - LEAF_RENEW_MARGIN_MS <= nowEpochMs) return null
        val privateKey = decrypt(prefs.getString(key, null)).takeIf { it.isNotEmpty() } ?: return null
        val certificate = decrypt(prefs.getString("$key.cert", null)).takeIf { it.isNotEmpty() } ?: return null
        return runCatching {
            LeafMaterial(
                Base64.decode(privateKey, Base64.NO_WRAP),
                Base64.decode(certificate, Base64.NO_WRAP),
                expiresAt,
            )
        }.getOrNull()
    }

    private fun leafKey(host: String): String =
        "leaf_" + Base64.encodeToString(
            host.lowercase().toByteArray(Charsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )

    /** Builds the portable snapshot from what is currently stored. */
    fun toPortable(includePassword: Boolean = true): PortableConfig.Data {
        val nas = loadNas()
        return PortableConfig.Data(
            providerId = "ugos",
            alias = nas.alias,
            authBase = nas.baseUrl,
            username = nas.username,
            password = if (includePassword) nas.password else "",
            domainSuffix = fixedSuffix().ifBlank { deriveDomainSuffix(loadRoutes()) },
            routes = loadRoutes().sorted().map { host ->
                PortableConfig.Rule(
                    host = host,
                    enabled = true,
                    httpIngress = isHttpIngressEnabled(host),
                    kind = routeKind(host),
                )
            },
        )
    }

    /** Applies an imported snapshot; returns how many routes were written. */
    fun applyPortable(data: PortableConfig.Data): Int {
        saveNas(data.authBase, data.username, data.password)
        saveAlias(data.alias)
        saveFixedSuffix(data.domainSuffix)
        // The imported file may point at a different NAS, so drop the previous lookup and any
        // gateway tokens keyed by the old hostnames.
        clearDiscovery()
        clearGatewayTokens()
        val hosts = data.routes.filter { it.enabled }.map { it.host }
        saveRoutes(hosts)
        saveRouteKinds(data.routes.associate { it.host to it.kind })
        // Reset the ingress switches so the import is authoritative rather than additive.
        prefs.edit().remove("ingress_enabled_hosts").apply()
        data.routes.filter { it.enabled && it.httpIngress }.forEach {
            setHttpIngressEnabled(it.host, true)
        }
        return hosts.size
    }

    private fun clearDiscovery() {
        prefs.edit()
            .remove(KEY_LIVE_SUFFIX)
            .remove(KEY_RELAY_HOST)
            .remove(KEY_DISCOVERED_AT)
            .apply()
    }

    private fun clearGatewayTokens() {
        val edit = prefs.edit()
        prefs.all.keys.filter { it.startsWith("gateway_token_") }.forEach(edit::remove)
        edit.apply()
    }

    // ---- route kind ('app' | 'system')

    fun routeKind(host: String): String =
        ProxyRoute.normaliseKind(prefs.getString("route_kind_" + keyOf(host), null))

    fun setRouteKind(host: String, kind: String) {
        prefs.edit().putString("route_kind_" + keyOf(host), ProxyRoute.normaliseKind(kind)).apply()
    }

    private fun saveRouteKinds(kinds: Map<String, String>) {
        val edit = prefs.edit()
        prefs.all.keys.filter { it.startsWith("route_kind_") }.forEach(edit::remove)
        kinds.forEach { (host, kind) -> edit.putString("route_kind_" + keyOf(host), ProxyRoute.normaliseKind(kind)) }
        edit.apply()
    }

    private fun keyOf(host: String): String =
        Base64.encodeToString(
            host.lowercase().toByteArray(Charsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )

    /** The user's fixed suffix, remembered across import/export round trips. */
    private fun persistedDomainSuffix(): String = prefs.getString(KEY_DOMAIN_SUFFIX, "") ?: ""

    /**
     * Fallback when no suffix was ever imported: the longest common suffix of the routes.
     * Note this is coarser than the real gateway suffix (it cannot know the extra labels).
     */
    private fun deriveDomainSuffix(hosts: Set<String>): String {
        if (hosts.isEmpty()) return ""
        val split = hosts.map { it.split('.') }
        val shortest = split.minOf { it.size }
        var common = 0
        while (common < shortest) {
            val reference = split.first()
            val candidate = reference[reference.size - 1 - common]
            if (split.all { h -> h[h.size - 1 - common] == candidate }) common++ else break
        }
        return if (common == 0) "" else split.first().takeLast(common).joinToString(".")
    }

    fun saveRoutes(hosts: Collection<String>) {
        prefs.edit().putStringSet("route_hosts", hosts.map { it.trim().lowercase() }.toSet()).apply()
    }

    fun loadRoutes(): Set<String> = prefs.getStringSet("route_hosts", emptySet())?.toSet().orEmpty()

    /** Per-route switch for the certificate-free HTTP ingress. */
    fun setHttpIngressEnabled(host: String, enabled: Boolean) {
        val keys = prefs.getStringSet(INGRESS_ENABLED_KEY, emptySet()).orEmpty().toMutableSet()
        if (enabled) keys.add(host.lowercase()) else keys.remove(host.lowercase())
        prefs.edit().putStringSet(INGRESS_ENABLED_KEY, keys).apply()
    }

    fun isHttpIngressEnabled(host: String): Boolean =
        prefs.getStringSet(INGRESS_ENABLED_KEY, emptySet()).orEmpty().contains(host.lowercase())

    fun enabledIngressRoutes(): Set<String> =
        loadRoutes().filter { isHttpIngressEnabled(it) }.toSet()

    fun httpIngressUrl(host: String): String = "http://127.0.0.1:18080/$host/"

    fun addRoute(host: String): Set<String> {
        val routes = loadRoutes() + host.trim().lowercase()
        saveRoutes(routes)
        return routes
    }

    fun removeRoute(host: String): Set<String> {
        val routes = loadRoutes() - host.trim().lowercase()
        saveRoutes(routes)
        setHttpIngressEnabled(host, false)
        return routes
    }

    fun saveGatewayToken(host: String, token: String, expiresAtEpochMs: Long) {
        val key = gatewayTokenKey(host)
        prefs.edit()
            .putString(key, encrypt(token))
            .putLong("$key.expires", expiresAtEpochMs)
            .apply()
    }

    fun loadGatewayToken(host: String, nowEpochMs: Long = System.currentTimeMillis()): String {
        val key = gatewayTokenKey(host)
        if (prefs.getLong("$key.expires", 0L) <= nowEpochMs) return ""
        return decrypt(prefs.getString(key, null))
    }

    fun clearSecrets() {
        val edit = prefs.edit()
            .remove("nas_user")
            .remove("nas_password")
            .remove("session_token")
            .remove("session_cookie")
            .remove("ca_private_key")
            .remove("ca_certificate")
        prefs.all.keys.filter { it.startsWith("leaf_") }.forEach(edit::remove)
        prefs.all.keys.filter { it.startsWith("gateway_token_") }.forEach(edit::remove)
        edit.apply()
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    private fun gatewayTokenKey(host: String): String =
        "gateway_token_" + Base64.encodeToString(
            host.lowercase().toByteArray(Charsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )

    private fun encrypt(value: String): String {
        if (value.isEmpty()) return ""
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val payload = cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(payload, Base64.NO_WRAP)
    }

    private fun decrypt(value: String?): String {
        if (value.isNullOrEmpty()) return ""
        return runCatching {
            val payload = Base64.decode(value, Base64.NO_WRAP)
            val iv = payload.copyOfRange(0, IV_LENGTH)
            val ciphertext = payload.copyOfRange(IV_LENGTH, payload.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), javax.crypto.spec.GCMParameterSpec(128, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        }.getOrDefault("")
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    data class NasSettings(
        val baseUrl: String,
        val username: String,
        val password: String,
        val alias: String = "",
    )
    data class AuthSession(val token: String, val cookies: String, val obtainedAtEpochMs: Long = 0L)
    data class CaMaterial(val privateKeyPkcs8: ByteArray, val certificateDer: ByteArray)
    data class LeafMaterial(val privateKeyPkcs8: ByteArray, val certificateDer: ByteArray, val expiresAtEpochMs: Long)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "gatepass.nas.credentials.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
        private const val LEAF_RENEW_MARGIN_MS = 12L * 60 * 60 * 1000
        private const val INGRESS_ENABLED_KEY = "ingress_enabled_hosts"
        private const val KEY_DOMAIN_SUFFIX = "domain_suffix"
        private const val KEY_LINK_ALIAS = "nas_alias"
        private const val KEY_LIVE_SUFFIX = "live_domain_suffix"
        private const val KEY_RELAY_HOST = "relay_host"
        private const val KEY_DISCOVERED_AT = "discovered_at"

        /** UGOS keeps a login alive for about this long; used to warn before it lapses. */
        const val SESSION_TTL_MS = 12L * 60 * 60 * 1000
        /** Start showing a heads-up once the session is within this window of expiring. */
        const val SESSION_WARN_MS = 2L * 60 * 60 * 1000
    }
}
