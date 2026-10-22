package com.yuceyang.gatepassandroid

import com.yuceyang.gatepassandroid.proxy.Http1Framing
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class Http1FramingTest {

    private fun input(text: String) = BufferedInputStream(ByteArrayInputStream(text.toByteArray(Charsets.ISO_8859_1)))

    private fun parse(head: String) = Http1Framing.readResponseHead(input(head))!!

    @Test
    fun contentLengthBodyIsSelfDelimitedAndReusable() {
        val head = parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
        val source = input("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        Http1Framing.readResponseHead(source)
        val sink = ByteArrayOutputStream()
        val out = BufferedOutputStream(sink)
        val reusable = Http1Framing.copyResponseBody(source, out, head, "GET")
        out.flush()
        assertTrue(reusable)
        assertEquals("hello", sink.toString(Charsets.ISO_8859_1.name()))
    }

    @Test
    fun chunkedBodyStopsAfterTerminatorSoConnectionCanBeReused() {
        val head = parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        val source = input("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n\r\nNEXT")
        Http1Framing.readResponseHead(source)
        val sink = ByteArrayOutputStream()
        val out = BufferedOutputStream(sink)
        val reusable = Http1Framing.copyResponseBody(source, out, head, "GET")
        out.flush()
        assertTrue(reusable)
        assertEquals("4\r\nwiki\r\n0\r\n\r\n", sink.toString(Charsets.ISO_8859_1.name()))
        // The following bytes belong to the next response and must still be readable.
        assertEquals("NEXT", String(source.readBytes(), Charsets.ISO_8859_1))
    }

    @Test
    fun bodylessResponsesAreReusableWithoutReading() {
        for (status in listOf(204, 304)) {
            val head = parse("HTTP/1.1 $status No Content\r\n\r\n")
            val source = input("HTTP/1.1 $status No Content\r\n\r\nNEXT")
            Http1Framing.readResponseHead(source)
            val sink = ByteArrayOutputStream()
            val out = BufferedOutputStream(sink)
            assertTrue(Http1Framing.copyResponseBody(source, out, head, "GET"))
            out.flush()
            assertEquals(0, sink.size())
            assertEquals("NEXT", String(source.readBytes(), Charsets.ISO_8859_1))
        }
    }

    @Test
    fun headRequestsHaveNoBodyEvenWithContentLength() {
        val head = parse("HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n")
        val source = input("HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\nNEXT")
        Http1Framing.readResponseHead(source)
        assertTrue(Http1Framing.copyResponseBody(source, BufferedOutputStream(ByteArrayOutputStream()), head, "HEAD"))
        assertEquals("NEXT", String(source.readBytes(), Charsets.ISO_8859_1))
    }

    @Test
    fun unframedBodyIsStreamedButNotReusable() {
        val head = parse("HTTP/1.1 200 OK\r\n\r\n")
        val source = input("HTTP/1.1 200 OK\r\n\r\nuntil-close")
        Http1Framing.readResponseHead(source)
        val sink = ByteArrayOutputStream()
        val out = BufferedOutputStream(sink)
        assertFalse(Http1Framing.copyResponseBody(source, out, head, "GET"))
        out.flush()
        assertEquals("until-close", sink.toString(Charsets.ISO_8859_1.name()))
    }

    @Test
    fun connectionCloseHeaderIsReported() {
        assertTrue(parse("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").connectionClose)
        assertFalse(parse("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n").connectionClose)
    }

    @Test
    fun chunkedRequestBodyIsCopiedVerbatim() {
        val headers = listOf("Transfer-Encoding" to "chunked")
        val source = input("3\r\nabc\r\n0\r\n\r\n")
        val sink = ByteArrayOutputStream()
        val out = BufferedOutputStream(sink)
        Http1Framing.copyRequestBody(source, out, headers, 1024)
        out.flush()
        assertEquals("3\r\nabc\r\n0\r\n\r\n", sink.toString(Charsets.ISO_8859_1.name()))
    }

    @Test
    fun contentLengthRequestBodyIsCopiedExactly() {
        val headers = listOf("Content-Length" to "5")
        val source = input("helloEXTRA")
        val sink = ByteArrayOutputStream()
        val out = BufferedOutputStream(sink)
        Http1Framing.copyRequestBody(source, out, headers, 1024)
        out.flush()
        assertEquals("hello", sink.toString(Charsets.ISO_8859_1.name()))
    }
}
