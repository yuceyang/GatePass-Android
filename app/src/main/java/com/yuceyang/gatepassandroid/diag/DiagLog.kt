package com.yuceyang.gatepassandroid.diag

import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** In-app diagnostic log: shown on screen and mirrored to logcat under tag "GatePass". */
object DiagLog {
    private const val TAG = "GatePass"
    private const val MAX_LINES = 400
    private val lines = ArrayDeque<String>()
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)
    private val listeners = mutableListOf<() -> Unit>()

    @Synchronized
    fun log(message: String) {
        val line = "${timeFormat.format(Date())}  $message"
        lines.addLast(line)
        while (lines.size > MAX_LINES) lines.removeFirst()
        Log.i(TAG, message)
        listeners.forEach { runCatching { it() } }
    }

    @Synchronized
    fun error(message: String, error: Throwable? = null) {
        val detail = error?.let { "${it.javaClass.simpleName}: ${it.message}" }.orEmpty()
        log("错误  $message${if (detail.isBlank()) "" else " — $detail"}")
        if (error != null) Log.e(TAG, message, error)
    }

    @Synchronized
    fun snapshot(): String = lines.joinToString("\n")

    @Synchronized
    fun clear() {
        lines.clear()
        listeners.forEach { runCatching { it() } }
    }

    @Synchronized
    fun addListener(listener: () -> Unit) {
        listeners.add(listener)
    }

    @Synchronized
    fun removeListener(listener: () -> Unit) {
        listeners.remove(listener)
    }
}
