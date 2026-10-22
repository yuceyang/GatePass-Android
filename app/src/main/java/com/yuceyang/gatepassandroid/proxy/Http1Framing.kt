package com.yuceyang.gatepassandroid.proxy

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream

/**
 * Minimal HTTP/1.1 framing helpers.
 *
 * Reusing a connection requires knowing exactly where a response body ends, so that the next
 * request does not read leftover bytes. Three framings are handled: no body (204/304/HEAD),
 * Content-Length, and chunked. Anything else is "until the peer closes", which is streamed but
 * never reused.
 */
internal object Http1Framing {

    data class ResponseHead(
        val statusLine: String,
        val status: Int,
        val headers: List<Pair<String, String>>,
    ) {
        fun header(name: String): String? =
            headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

        val isChunked: Boolean
            get() = header("Transfer-Encoding")?.contains("chunked", ignoreCase = true) == true

        val contentLength: Long?
            get() = header("Content-Length")?.trim()?.toLongOrNull()

        val connectionClose: Boolean
            get() = header("Connection")?.contains("close", ignoreCase = true) == true
    }

    /** Reads the status line and headers. Returns null on a clean EOF before any byte. */
    fun readResponseHead(input: BufferedInputStream): ResponseHead? {
        val raw = readHeadBytes(input) ?: return null
        val lines = String(raw, Charsets.ISO_8859_1).split("\r\n").filter { it.isNotEmpty() }
        if (lines.isEmpty()) return null
        val statusLine = lines.first()
        val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
        val headers = lines.drop(1).mapNotNull { line ->
            val colon = line.indexOf(':')
            if (colon <= 0) null else line.substring(0, colon).trim() to line.substring(colon + 1).trim()
        }
        return ResponseHead(statusLine, status, headers)
    }

    private fun readHeadBytes(input: BufferedInputStream): ByteArray? {
        val buffer = ByteArrayOutputStream(512)
        var matched = 0
        while (buffer.size() < MAX_HEAD_BYTES) {
            val value = input.read()
            if (value < 0) return if (buffer.size() == 0) null else buffer.toByteArray()
            buffer.write(value)
            matched = when {
                matched == 0 && value == '\r'.code -> 1
                matched == 1 && value == '\n'.code -> 2
                matched == 2 && value == '\r'.code -> 3
                matched == 3 && value == '\n'.code -> 4
                value == '\r'.code -> 1
                else -> 0
            }
            if (matched == 4) return buffer.toByteArray()
        }
        throw IllegalStateException("响应头过大")
    }

    /**
     * Streams the body to [output] according to the head's framing.
     *
     * @return true when the body was self-delimited, meaning the connection may be reused.
     */
    fun copyResponseBody(
        input: BufferedInputStream,
        output: BufferedOutputStream,
        head: ResponseHead,
        requestMethod: String,
    ): Boolean {
        if (requestMethod.equals("HEAD", true) || head.status == 204 || head.status == 304 || head.status in 100..199) {
            return true
        }
        if (head.isChunked) {
            copyChunked(input, output)
            return true
        }
        val length = head.contentLength
        if (length != null) {
            copyFixed(input, output, length)
            return true
        }
        // No framing: the body runs until the peer closes, so this connection is not reusable.
        input.copyTo(output)
        return false
    }

    private fun copyFixed(input: BufferedInputStream, output: BufferedOutputStream, length: Long) {
        var remaining = length
        val buffer = ByteArray(BUFFER_SIZE)
        while (remaining > 0) {
            val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (count < 0) throw IllegalStateException("响应体提前结束")
            output.write(buffer, 0, count)
            remaining -= count
        }
    }

    /** Streams chunked framing verbatim, stopping after the terminating chunk and trailers. */
    fun copyChunked(input: BufferedInputStream, output: BufferedOutputStream) {
        val buffer = ByteArray(BUFFER_SIZE)
        while (true) {
            val header = readLine(input) ?: throw IllegalStateException("chunk 头不完整")
            output.write((header + "\r\n").toByteArray(Charsets.ISO_8859_1))
            val size = header.substringBefore(';').trim().toLongOrNull(16)
                ?: throw IllegalStateException("chunk 大小非法")
            if (size == 0L) {
                while (true) {
                    val trailer = readLine(input) ?: break
                    output.write((trailer + "\r\n").toByteArray(Charsets.ISO_8859_1))
                    if (trailer.isEmpty()) break
                }
                return
            }
            var remaining = size
            while (remaining > 0) {
                val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (count < 0) throw IllegalStateException("chunk 数据不完整")
                output.write(buffer, 0, count)
                remaining -= count
            }
            val crlf = ByteArray(2)
            var read = 0
            while (read < 2) {
                val n = input.read(crlf, read, 2 - read)
                if (n < 0) throw IllegalStateException("chunk 结尾不完整")
                read += n
            }
            output.write(crlf, 0, 2)
        }
    }

    /** Copies a request body, preserving its framing. */
    fun copyRequestBody(
        input: BufferedInputStream,
        output: BufferedOutputStream,
        headers: List<Pair<String, String>>,
        maxBytes: Long,
    ) {
        val chunked = headers.any {
            it.first.equals("Transfer-Encoding", true) && it.second.contains("chunked", true)
        }
        if (chunked) {
            copyChunked(input, output)
            return
        }
        val length = headers.firstOrNull { it.first.equals("Content-Length", true) }
            ?.second?.toLongOrNull() ?: 0L
        if (length <= 0) return
        if (length > maxBytes) throw IllegalStateException("请求体超过上限（$length 字节）")
        copyFixed(input, output, length)
    }

    fun readLine(input: BufferedInputStream): String? {
        val line = StringBuilder()
        while (true) {
            val value = input.read()
            if (value < 0) return if (line.isEmpty()) null else line.toString()
            if (value == '\n'.code) return line.toString()
            if (value != '\r'.code) line.append(value.toChar())
        }
    }

    fun readRequestHead(input: BufferedInputStream): ByteArray? {
        val buffer = ByteArrayOutputStream(512)
        var matched = 0
        while (buffer.size() < MAX_HEAD_BYTES) {
            val value = input.read()
            if (value < 0) return if (buffer.size() == 0) null else buffer.toByteArray()
            buffer.write(value)
            matched = when {
                matched == 0 && value == '\r'.code -> 1
                matched == 1 && value == '\n'.code -> 2
                matched == 2 && value == '\r'.code -> 3
                matched == 3 && value == '\n'.code -> 4
                value == '\r'.code -> 1
                else -> 0
            }
            if (matched == 4) return buffer.toByteArray()
        }
        throw IllegalStateException("请求头过大")
    }

    fun parseHeaders(bytes: ByteArray): List<Pair<String, String>> =
        String(bytes, Charsets.ISO_8859_1).split("\r\n")
            .drop(1)
            .takeWhile { it.isNotEmpty() }
            .mapNotNull { line ->
                val colon = line.indexOf(':')
                if (colon <= 0) null else line.substring(0, colon).trim() to line.substring(colon + 1).trim()
            }

    private const val BUFFER_SIZE = 16 * 1024
    private const val MAX_HEAD_BYTES = 64 * 1024
}
