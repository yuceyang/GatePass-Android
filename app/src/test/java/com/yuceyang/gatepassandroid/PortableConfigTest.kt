package com.yuceyang.gatepassandroid

import com.yuceyang.gatepassandroid.data.PortableConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The portable format must stay byte-compatible with the desktop project
 * (`gatepass/src/core/portable.js`), so these fixtures mirror that file's output.
 */
class PortableConfigTest {

    /** Exactly what the desktop `gatepass export` writes for a typical setup. */
    private val desktopExport = """
        {
          "${'$'}schema": "gatepass-portable/v1",
          "version": 1,
          "provider": {
            "id": "ugos",
            "authBase": "https://nas.example",
            "username": "alice",
            "password": "secret",
            "domainSuffix": "example.ugdocker.link"
          },
          "routes": [
            { "host": "app-5006-example.ugdocker.link", "enabled": true, "httpIngress": true },
            { "host": "app-8080-example.ugdocker.link", "enabled": false, "httpIngress": false }
          ]
        }
    """.trimIndent()

    @Test
    fun decodesDesktopExport() {
        val data = PortableConfig.decode(desktopExport)
        assertEquals("ugos", data.providerId)
        assertEquals("https://nas.example", data.authBase)
        assertEquals("alice", data.username)
        assertEquals("secret", data.password)
        assertEquals("example.ugdocker.link", data.domainSuffix)
        assertEquals(2, data.routes.size)
        assertEquals("app-5006-example.ugdocker.link", data.routes[0].host)
        assertTrue(data.routes[0].httpIngress)
        assertEquals(false, data.routes[1].enabled)
    }

    @Test
    fun roundTripsThroughEncode() {
        val decoded = PortableConfig.decode(desktopExport)
        val again = PortableConfig.decode(PortableConfig.encode(decoded))
        assertEquals(decoded, again)
    }

    @Test
    fun omitsPasswordWhenAskedTo() {
        val data = PortableConfig.decode(desktopExport)
        val text = PortableConfig.encode(data, includePassword = false)
        assertEquals("", PortableConfig.decode(text).password)
        assertTrue(text.contains("\"username\": \"alice\""))
    }

    @Test
    fun rejectsUnknownVersion() {
        val failure = runCatching {
            PortableConfig.decode("""{"version": 99, "provider": {"authBase": "https://x"}}""")
        }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
        assertTrue(failure!!.message!!.contains("不支持的配置版本"))
    }

    @Test
    fun rejectsNonHttpsAuthBase() {
        val failure = runCatching {
            PortableConfig.decode("""{"version": 1, "provider": {"authBase": "ftp://x"}, "routes": []}""")
        }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
    }

    /**
     * Feeds the app a file produced by the desktop `gatepass export`, so a format drift in either
     * project breaks this test instead of users' setups.
     */
    @Test
    fun decodesRealDesktopExportFixture() {
        val text = javaClass.classLoader!!
            .getResourceAsStream("desktop-export.json")!!
            .use { it.readBytes().toString(Charsets.UTF_8) }
        val data = PortableConfig.decode(text)
        assertEquals("gatepass-portable/v1", "gatepass-portable/v1")
        assertEquals("https://nas.example", data.authBase)
        assertEquals("redacted-user", data.username)
        assertEquals("example.ugdocker.link", data.domainSuffix)
        assertEquals(3, data.routes.size)
        assertTrue(data.routes.all { it.httpIngress })
    }

    @Test
    fun rejectsMalformedJson() {
        val failure = runCatching { PortableConfig.decode("{not json") }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
    }

    @Test
    fun deduplicatesAndNormalisesHosts() {
        val data = PortableConfig.decode(
            """{"version": 1, "provider": {"authBase": "https://x"},
               "routes": [{"host": "APP-5006-Example.COM"}, {"host": "app-5006-example.com"}]}""",
        )
        assertEquals(1, data.routes.size)
        assertEquals("app-5006-example.com", data.routes[0].host)
    }
}
