package org.sharkdroid

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

object UpdateCheck {
    enum class State { IDLE, CHECKING, LATEST, NEWER, FAILED }

    private const val REPO = "d224407/SharkDroid"
    private const val MAX_BYTES = 256 * 1024

    var state by mutableStateOf(State.IDLE); private set
    var latest by mutableStateOf(""); private set
    var url by mutableStateOf(""); private set

    fun check(current: String, build: Int) {
        if (state == State.CHECKING) return
        state = State.CHECKING
        thread(name = "update-check") {
            state = try {
                val c = URL("https://api.github.com/repos/$REPO/releases/latest").openConnection() as HttpURLConnection
                c.connectTimeout = 8000; c.readTimeout = 8000
                c.setRequestProperty("Accept", "application/vnd.github+json")
                c.setRequestProperty("User-Agent", "SharkDroid")
                try {
                    if (c.responseCode != 200) State.FAILED
                    else {
                        val body = c.inputStream.use { inp ->
                            val out = java.io.ByteArrayOutputStream()
                            val buf = ByteArray(8192)
                            while (out.size() < MAX_BYTES) { val n = inp.read(buf); if (n < 0) break; out.write(buf, 0, n) }
                            out.toByteArray()
                        }
                        val j = JSONObject(String(body, Charsets.UTF_8))
                        val tag = j.optString("tag_name").removePrefix("v")
                        val page = j.optString("html_url")
                        if (tag.isEmpty() || !page.startsWith("https://github.com/")) State.FAILED
                        else {
                            url = page
                            // Releases are tagged "build-<run number>-<sha>"; fall back to dotted versions for other tags.
                            val n = Regex("^build-(\\d+)-").find(tag)?.groupValues?.get(1)?.toIntOrNull()
                            latest = if (n != null) "build $n" else tag
                            if (if (n != null) n > build else newer(tag, current)) State.NEWER else State.LATEST
                        }
                    }
                } finally { c.disconnect() }
            } catch (_: Exception) { State.FAILED }
        }
    }

    private fun newer(a: String, b: String): Boolean {
        val x = a.split('.', '-').map { it.toIntOrNull() ?: 0 }
        val y = b.split('.', '-').map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(x.size, y.size)) {
            val d = x.getOrElse(i) { 0 } - y.getOrElse(i) { 0 }
            if (d != 0) return d > 0
        }
        return false
    }
}
