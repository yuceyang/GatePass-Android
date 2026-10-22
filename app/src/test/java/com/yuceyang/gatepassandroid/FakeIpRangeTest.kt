package com.yuceyang.gatepassandroid

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the fake-ip range against colliding with Clash's default `198.18.0.1/16`.
 *
 * When two VPNs hand out overlapping virtual addresses, the same IP can mean different hosts
 * depending on which tunnel resolves it, which shows up as "configured route goes to the wrong
 * site". Keeping our range in a separate /16 avoids that entirely.
 */
class FakeIpRangeTest {

    private val gatePassNetwork = parseIpv4("198.19.0.0")
    private val gatePassMask = parseIpv4("255.255.0.0")

    private val clashRangeStart = parseIpv4("198.18.0.0")
    private val clashRangeEnd = parseIpv4("198.18.255.255")

    @Test
    fun gatePassRangeDoesNotOverlapClashDefaultRange() {
        for (address in listOf(gatePassNetwork, 0xFFFFFFFF.toInt())) {
            assertFalse(
                "GatePass range must not include $address from Clash's 198.18.0.1/16",
                address in clashRangeStart..clashRangeEnd,
            )
        }
    }

    @Test
    fun maskCoversAWholeClassBSizedBlock() {
        val first = gatePassNetwork and gatePassMask
        val last = gatePassNetwork or gatePassMask.inv()
        assertEquals(gatePassNetwork, first)
        assertEquals("198.19.255.255", formatIpv4(last))
    }

    @Test
    fun clashDefaultRangeIsStillOutsideOurBlock() {
        val inOurBlock = (clashRangeStart and gatePassMask) == gatePassNetwork
        assertFalse("Clash's 198.18.0.0 must not fall inside 198.19.0.0/16", inOurBlock)
    }

    @Test
    fun mappedAddressesStayInsideOurBlock() {
        // The mapdns allocator hands out sequential addresses starting at the network address.
        for (index in listOf(1, 42, 65534)) {
            val mapped = gatePassNetwork or index
            assertTrue(
                "mapped address ${formatIpv4(mapped)} must stay within 198.19.0.0/16",
                (mapped and gatePassMask) == gatePassNetwork,
            )
        }
    }

    private fun parseIpv4(text: String): Int {
        val parts = text.split('.').map { it.toInt() }
        require(parts.size == 4)
        return (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
    }

    private fun formatIpv4(value: Int): String =
        listOf(24, 16, 8, 0).joinToString(".") { shift -> ((value ushr shift) and 0xFF).toString() }
}
