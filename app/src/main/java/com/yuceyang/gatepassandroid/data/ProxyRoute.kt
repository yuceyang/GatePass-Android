package com.yuceyang.gatepassandroid.data

data class ProxyRoute(val host: String, val enabled: Boolean = true, val kind: String = KIND_APP) {
    fun inferredPort(): Int? = APP_HOST_PREFIX.find(host)?.groupValues?.get(1)?.toIntOrNull()

    /** The UGOS desktop and similar system services live behind the relay host, not the port map. */
    val isSystem: Boolean get() = kind == KIND_SYSTEM

    companion object {
        const val KIND_APP = "app"
        const val KIND_SYSTEM = "system"

        private val APP_HOST_PREFIX = Regex("""^app-?(\d+)-""", RegexOption.IGNORE_CASE)
        private val HOST_PATTERN = Regex("""(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+""")

        /** Normalises a kind string from storage or a portable file. */
        fun normaliseKind(value: String?): String =
            if (value?.trim()?.equals(KIND_SYSTEM, ignoreCase = true) == true) KIND_SYSTEM else KIND_APP

        fun parse(value: String, kind: String = KIND_APP): ProxyRoute? {
            val normalized = value.trim().trimEnd('.').lowercase()
            if (!HOST_PATTERN.matches(normalized)) return null
            if (normalized.any { it.isWhitespace() }) return null
            return ProxyRoute(normalized, kind = normaliseKind(kind))
        }
    }
}
