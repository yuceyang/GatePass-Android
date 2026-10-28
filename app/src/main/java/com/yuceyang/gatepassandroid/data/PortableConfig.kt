package com.yuceyang.gatepassandroid.data

import org.json.JSONArray
import org.json.JSONObject

/**
 * Portable configuration shared with desktop GatePass and (later) iOS.
 *
 * Only platform-neutral data is stored here — NAS endpoint, credentials and the route list.
 * Listen ports, autostart and CA trust stay device-local so the same file works everywhere.
 * The field names match `src/core/portable.js` in the desktop project.
 *
 * `provider.alias` is the portable identity: the login host moves when the NAS re-registers
 * (cn68 → cn11), so the desktop stopped exporting a fixed `authBase`. Either the alias or an
 * explicit `authBase` must be present; a file with both is valid and the alias wins.
 */
object PortableConfig {
    const val SCHEMA = "gatepass-portable/v1"
    const val VERSION = 1

    data class Rule(
        val host: String,
        val enabled: Boolean,
        val httpIngress: Boolean,
        val kind: String = ProxyRoute.KIND_APP,
    )

    data class Data(
        val providerId: String,
        val alias: String,
        val authBase: String,
        val username: String,
        val password: String,
        val domainSuffix: String,
        val routes: List<Rule>,
    )

    /** Serialises current settings; [includePassword] lets callers export a shareable copy. */
    fun encode(data: Data, includePassword: Boolean = true): String {
        val provider = JSONObject()
            .put("id", data.providerId)
            .put("alias", data.alias)
            .put("authBase", data.authBase)
            .put("username", data.username)
            .put("password", if (includePassword) data.password else "")
            .put("domainSuffix", data.domainSuffix)
        val routes = JSONArray()
        data.routes.forEach { rule ->
            routes.put(
                JSONObject()
                    .put("host", rule.host)
                    .put("enabled", rule.enabled)
                    .put("httpIngress", rule.httpIngress)
                    .put("kind", ProxyRoute.normaliseKind(rule.kind)),
            )
        }
        return JSONObject()
            .put("\$schema", SCHEMA)
            .put("version", VERSION)
            .put("provider", provider)
            .put("routes", routes)
            .toString(2)
    }

    /**
     * Parses and validates a portable config.
     * @throws IllegalArgumentException with a user-facing message when the file is unusable.
     */
    fun decode(text: String): Data {
        val raw = try {
            JSONObject(text.trim().removePrefix("﻿"))
        } catch (e: Exception) {
            throw IllegalArgumentException("配置文件不是合法 JSON")
        }
        val version = raw.optInt("version", -1)
        if (version != VERSION) {
            throw IllegalArgumentException("不支持的配置版本 $version（本应用支持 $VERSION）")
        }
        val provider = raw.optJSONObject("provider")
            ?: throw IllegalArgumentException("缺少 provider 字段")
        val alias = provider.optString("alias").trim()
        val authBase = provider.optString("authBase").trim().trimEnd('/')
        // Either identity is enough: with an alias the real host is looked up at runtime.
        if (alias.isBlank() && authBase.isBlank()) {
            throw IllegalArgumentException("provider 需要别名（alias）或 NAS 地址（authBase）")
        }
        if (authBase.isNotBlank() &&
            !authBase.startsWith("https://", ignoreCase = true) &&
            !authBase.startsWith("http://", ignoreCase = true)
        ) {
            throw IllegalArgumentException("provider.authBase 必须是 http(s) 地址")
        }
        if (alias.isNotBlank() && !ALIAS_PATTERN.matches(alias)) {
            throw IllegalArgumentException("非法的 UGREENlink 别名: $alias")
        }

        val seen = linkedSetOf<String>()
        val rules = mutableListOf<Rule>()
        val array = raw.optJSONArray("routes") ?: JSONArray()
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val host = item.optString("host").trim().lowercase()
            if (host.isBlank()) throw IllegalArgumentException("第 ${index + 1} 条路由缺少 host")
            val parsed = ProxyRoute.parse(host, item.optString("kind"))
                ?: throw IllegalArgumentException("非法主机名: $host")
            if (!seen.add(parsed.host)) continue
            rules += Rule(
                host = parsed.host,
                enabled = item.optBoolean("enabled", true),
                httpIngress = item.optBoolean("httpIngress", true),
                kind = parsed.kind,
            )
        }

        return Data(
            providerId = provider.optString("id").ifBlank { "ugos" },
            alias = alias,
            authBase = authBase,
            username = provider.optString("username").trim(),
            password = provider.optString("password"),
            domainSuffix = provider.optString("domainSuffix").trim(),
            routes = rules,
        )
    }

    private val ALIAS_PATTERN = Regex("""^[a-zA-Z0-9][a-zA-Z0-9-]*$""")
}
