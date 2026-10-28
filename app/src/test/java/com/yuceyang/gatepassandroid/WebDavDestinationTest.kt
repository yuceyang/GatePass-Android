package com.yuceyang.gatepassandroid

import com.yuceyang.gatepassandroid.proxy.WebDavDestination
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * A WebDAV MOVE names the host the client knows; the upstream compares that authority with the
 * host it was reached as and answers 404 when they differ, which aborted every sync at the
 * final rename once the gateway moved from cn68 to cn11.
 */
class WebDavDestinationTest {

    private val fixed = "app-5006-alice.cn68.ugdocker.link"
    private val live = "app-5006-alice.cn11.ugdocker.link"

    @Test
    fun rewritesTheAuthorityOnly() {
        assertEquals(
            "https://$live/WebDAV/a.xbel",
            WebDavDestination.rewrite("https://$fixed/WebDAV/a.xbel", fixed, live),
        )
    }

    @Test
    fun keepsPortPathAndQuery() {
        assertEquals(
            "https://$live:8443/a/b?c=d",
            WebDavDestination.rewrite("https://$fixed:8443/a/b?c=d", fixed, live),
        )
    }

    @Test
    fun leavesRelativeDestinationAlone() {
        assertEquals("/a/b", WebDavDestination.rewrite("/a/b", fixed, live))
    }

    @Test
    fun leavesForeignHostAlone() {
        assertEquals(
            "https://other.example/a",
            WebDavDestination.rewrite("https://other.example/a", fixed, live),
        )
    }

    @Test
    fun noOpWhenHostsMatch() {
        assertEquals("https://$live/x", WebDavDestination.rewrite("https://$live/x", live, live))
    }

    @Test
    fun toleratesMissingValue() {
        assertNull(WebDavDestination.rewrite(null, fixed, live))
    }
}
