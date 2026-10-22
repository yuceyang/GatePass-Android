package com.yuceyang.gatepassandroid.data

data class ProxyRoute(val host: String, val enabled: Boolean = true) {
    fun inferredPort(): Int? = APP_HOST_PREFIX.find(host)?.groupValues?.get(1)?.toIntOrNull()

    companion object {
        private val APP_HOST_PREFIX = Regex("""^app-?(\d+)-""", RegexOption.IGNORE_CASE)
        private val HOST_PATTERN = Regex("""(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+""")

        fun parse(value: String): ProxyRoute? {
            val normalized = value.trim().trimEnd('.').lowercase()
            if (!HOST_PATTERN.matches(normalized)) return null
            if (normalized.any { it.isWhitespace() }) return null
            return ProxyRoute(normalized)
        }
    }
}
