package com.yuceyang.gatepassandroid

import com.yuceyang.gatepassandroid.data.ProxyRoute
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ProxyRouteTest {
    @Test
    fun acceptsAndNormalizesHostname() {
        assertEquals("app-8080.example.com", ProxyRoute.parse(" APP-8080.Example.COM ")?.host)
    }

    @Test
    fun rejectsInvalidHostname() {
        assertNull(ProxyRoute.parse("bad_host.example.com"))
        assertNull(ProxyRoute.parse("https://example.com/path"))
    }

    @Test
    fun infersApplicationPortFromCommonHostForms() {
        assertEquals(8080, ProxyRoute.parse("app-8080-example.com")?.inferredPort())
        assertEquals(16601, ProxyRoute.parse("app16601-example.com")?.inferredPort())
        assertNull(ProxyRoute.parse("service.example.com")?.inferredPort())
    }
}
