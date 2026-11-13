package org.sharkdroid

import android.content.Context
import android.os.ParcelFileDescriptor
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.URLDecoder

/**
 * Files that crossed the wire in decrypted HTTP/1 and HTTP/2 (images, video, scripts, JSON, downloads...).
 *
 * tshark runs in an isolated process that can only use its stdin/stdout/stderr, so `--export-objects` (which needs a
 * directory) cannot work: the bodies are read from stdout as hex and written to the cache here, one file per
 * response, never held in memory. HTTP/1 bodies come already decompressed (`http.file_data`); HTTP/2 bodies
 * (`http2.body.reassembled.data`) are gzip and are decompressed here.
 */
object Resources {
    enum class Kind { IMAGE, VIDEO, AUDIO, TEXT, OTHER }

    /** [url] is "host/path" of the request that produced the file (may be empty). */
    class Item(val file: File, val name: String, val size: Long, val mime: String, val kind: Kind, val url: String)

    private const val MAX_FILE = 256L * 1024 * 1024

    /** Called by [streamLines] for every tshark line; the last column is the (hex) body, ',' separates several bodies. */
    private interface Lines {
        /** The first [nMeta] columns are in [meta]; false skips the body column of this line. */
        fun wantBody(meta: Array<String>): Boolean
        fun newBody(meta: Array<String>, index: Int): File
        /** [bodies] are the files that received data, in order. */
        fun end(meta: Array<String>, bodies: List<File>)
    }

    fun extract(ctx: Context, capture: File): List<Item> {
        val dir = File(ctx.cacheDir, "resources")
        dir.deleteRecursively()
        dir.mkdirs()
        val items = ArrayList<Item>()
        // HTTP/1: one line per request / response.
        run(ctx, capture, "(http.request || http.response)",
            listOf("-E", "occurrence=f", "-e", "frame.number", "-e", "http.response.code", "-e", "http.request_in",
                "-e", "http.request.uri", "-e", "http.host", "-e", "http.file_data"), 5, http1(dir, items))
        // HTTP/2: request headers (to name the files) and completed response bodies.
        run(ctx, capture, "(http2.headers.path || http2.body.reassembled.data)",
            listOf("-e", "frame.number", "-e", "tcp.stream", "-e", "http2.type", "-e", "http2.streamid",
                "-e", "http2.headers.path", "-e", "http2.headers.authority", "-e", "http2.body.reassembled.data"), 6, http2(dir, items))
        return items.sortedWith(compareBy({ it.kind.ordinal }, { it.name.lowercase() }))
    }

    private fun run(ctx: Context, capture: File, filter: String, fields: List<String>, nMeta: Int, h: Lines) {
        try {
            val pfd = ParcelFileDescriptor.open(capture, ParcelFileDescriptor.MODE_READ_ONLY)
            val job = Dissector.start(ctx, listOf("-n", "-r", "-", "-Y", filter, "-T", "fields") + fields, pfd)
            Thread { try { job.stderr.readBytes() } catch (_: Exception) { } }.start() // keep the pipe drained
            try { job.stdout.bufferedReader().use { streamLines(it, nMeta, h) } } catch (_: Exception) { }
            job.waitFor()
        } catch (_: Exception) { }
    }

    private fun http1(dir: File, items: MutableList<Item>): Lines = object : Lines {
        private val urls = HashMap<String, String>() // request frame -> host + uri
        override fun wantBody(meta: Array<String>) = meta[1].isNotEmpty() // responses only
        override fun newBody(meta: Array<String>, index: Int) =
            File(dir, "h1_" + meta[0] + "_" + safeName(urls[meta[2]].orEmpty()))
        override fun end(meta: Array<String>, bodies: List<File>) {
            if (meta[1].isEmpty()) { urls[meta[0]] = meta[4] + meta[3]; return }
            for (f in bodies) items += describe(f, urls[meta[2]].orEmpty())
        }
    }

    private fun http2(dir: File, items: MutableList<Item>): Lines = object : Lines {
        private val urls = HashMap<String, String>() // "stream/sid" -> authority + path
        override fun wantBody(meta: Array<String>) = true
        override fun newBody(meta: Array<String>, index: Int) = File(dir, "h2_" + meta[0] + "_" + index)
        override fun end(meta: Array<String>, bodies: List<File>) {
            val types = meta[2].split(',')
            val sids = meta[3].split(',')
            if (meta[4].isNotEmpty()) { // a packet with request headers: remember which stream asked for what
                val headerSids = sids.filterIndexed { i, _ -> i < types.size && types[i] == "1" }
                val paths = meta[4].split(',')
                val hosts = meta[5].split(',')
                for (i in paths.indices) if (i < headerSids.size) urls[meta[1] + "/" + headerSids[i]] = hosts.getOrElse(i) { "" } + paths[i]
            }
            if (bodies.isEmpty()) return
            // The completed responses are the last streams that had DATA in this packet.
            val data = ArrayList<String>()
            for (i in sids.indices) if (i < types.size && types[i] == "0" && sids[i] !in data) data += sids[i]
            val sidOf = if (bodies.size <= data.size) data.takeLast(bodies.size) else data
            for ((i, f) in bodies.withIndex()) {
                val url = urls[meta[1] + "/" + sidOf.getOrElse(i) { "?" }].orEmpty()
                val named = File(dir, "h2_" + meta[0] + "_" + safeName(url))
                val use = if (f.renameTo(named)) named else f
                items += describe(gunzipIfNeeded(use), url)
            }
        }
    }

    /** Streams tshark's tab-separated lines; the last column (hex, ',' between bodies) goes straight to files. */
    private fun streamLines(r: java.io.BufferedReader, nMeta: Int, h: Lines) {
        val meta = Array(nMeta) { "" }
        val sb = StringBuilder()
        val done = ArrayList<File>()
        var col = 0
        var want = false
        var index = 0
        var out: BufferedOutputStream? = null
        var file: File? = null
        var written = 0L
        var hi = -1
        val buf = CharArray(16384)

        fun closeBody() {
            out?.close()
            val f = file
            if (f != null) { if (written > 0) done += f else f.delete() }
            out = null; file = null; written = 0; hi = -1
        }
        fun reset() { col = 0; sb.setLength(0); want = false; index = 0; done.clear(); closeBody(); for (i in meta.indices) meta[i] = "" }
        fun finish() { closeBody(); h.end(meta, ArrayList(done)) }

        while (true) {
            val n = r.read(buf)
            if (n < 0) break
            for (i in 0 until n) {
                val c = buf[i]
                if (col < nMeta) {
                    when (c) {
                        '\t' -> { meta[col++] = sb.toString(); sb.setLength(0); if (col == nMeta) want = h.wantBody(meta) }
                        '\n' -> reset() // malformed line
                        '\r' -> {}
                        else -> sb.append(c)
                    }
                } else if (c == '\n') {
                    finish(); reset()
                } else if (c == ',') {
                    closeBody(); index++
                } else {
                    val d = Character.digit(c, 16)
                    if (d < 0 || !want) continue
                    if (hi < 0) { hi = d; continue }
                    if (out == null) {
                        val f = h.newBody(meta, index)
                        file = f
                        out = BufferedOutputStream(FileOutputStream(f), 65536)
                    }
                    val o = out
                    if (o != null && written < MAX_FILE) { o.write((hi shl 4) or d); written++ }
                    hi = -1
                }
            }
        }
        if (col >= nMeta) finish()
    }

    /** HTTP/2 bodies are the raw (usually gzip) bytes: replace the file by its decompressed content. */
    private fun gunzipIfNeeded(f: File): File {
        try {
            val magic = ByteArray(2)
            val n = f.inputStream().use { it.read(magic) }
            if (n < 2 || magic[0] != 0x1f.toByte() || magic[1] != 0x8b.toByte()) return f
            val tmp = File(f.parentFile, f.name + ".tmp")
            var total = 0L
            java.util.zip.GZIPInputStream(f.inputStream().buffered()).use { gz ->
                tmp.outputStream().buffered().use { o ->
                    val b = ByteArray(65536)
                    while (total < MAX_FILE) { val k = gz.read(b); if (k < 0) break; o.write(b, 0, k); total += k }
                }
            }
            if (total > 0 && f.delete() && tmp.renameTo(f)) return f
            tmp.delete()
        } catch (_: Exception) { }
        return f
    }

    private fun segment(url: String): String {
        val seg = url.substringBefore('?').substringAfterLast('/')
        return try { URLDecoder.decode(seg, "UTF-8") } catch (_: Exception) { seg }
    }

    private fun safeName(url: String): String =
        segment(url).replace(Regex("[^A-Za-z0-9._-]"), "_").take(80).ifBlank { "response" }

    private fun describe(f: File, url: String): Item {
        val head = ByteArray(4096)
        val n = try { f.inputStream().use { it.read(head) } } catch (_: Exception) { -1 }.coerceAtLeast(0)
        val (mime, kind) = sniff(head, n, f.name)
        var name = segment(url).ifBlank { url.substringBefore('/').ifBlank { "response" } }
        if (!name.substringAfterLast('.', "").let { it.isNotEmpty() && it.length <= 5 }) name += extension(mime)
        return Item(f, name, f.length(), mime, kind, url)
    }

    private fun extension(mime: String) = when (mime) {
        "image/jpeg" -> ".jpg"; "image/png" -> ".png"; "image/gif" -> ".gif"; "image/webp" -> ".webp"; "image/avif" -> ".avif"
        "image/svg+xml" -> ".svg"; "video/mp4" -> ".mp4"; "video/webm" -> ".webm"; "audio/mpeg" -> ".mp3"; "audio/ogg" -> ".ogg"
        "audio/mp4" -> ".m4a"; "application/json" -> ".json"; "text/javascript" -> ".js"; "text/html" -> ".html"
        "application/zip" -> ".zip"; "application/x-dex" -> ".dex"; "application/x-elf" -> ".so"
        else -> ""
    }

    /** Valid UTF-8 (a cut multi-byte tail is tolerated) that is almost all printable characters. */
    private fun looksLikeText(h: ByteArray, n: Int): Boolean {
        if (n == 0) return false
        for (cut in 0..3) {
            if (n - cut <= 0) break
            val s = try {
                Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(h, 0, n - cut)).toString()
            } catch (_: java.nio.charset.CharacterCodingException) { continue }
            val printable = s.count { it == '\n' || it == '\r' || it == '\t' || (it.code >= 0x20 && it.code != 0x7f) }
            return printable >= s.length * 0.9
        }
        return false
    }

    private fun sniff(h: ByteArray, n: Int, name: String): Pair<String, Kind> {
        fun at(i: Int, vararg b: Int) = n >= i + b.size && b.indices.all { (h[i + it].toInt() and 0xff) == b[it] }
        fun ascii(i: Int, len: Int) = if (n >= i + len) String(h, i, len, Charsets.US_ASCII) else ""
        return when {
            at(0, 0xFF, 0xD8, 0xFF) -> "image/jpeg" to Kind.IMAGE
            at(0, 0x89, 0x50, 0x4E, 0x47) -> "image/png" to Kind.IMAGE
            at(0, 0x47, 0x49, 0x46, 0x38) -> "image/gif" to Kind.IMAGE
            ascii(0, 4) == "RIFF" && ascii(8, 4) == "WEBP" -> "image/webp" to Kind.IMAGE
            ascii(0, 4) == "RIFF" && ascii(8, 4) == "AVI " -> "video/avi" to Kind.VIDEO
            ascii(4, 4) == "ftyp" -> when (ascii(8, 4)) {
                "avif", "avis", "heic", "heix", "mif1" -> "image/avif" to Kind.IMAGE
                "M4A ", "M4B " -> "audio/mp4" to Kind.AUDIO
                else -> "video/mp4" to Kind.VIDEO
            }
            at(0, 0x1A, 0x45, 0xDF, 0xA3) -> "video/webm" to Kind.VIDEO
            at(0, 0x4F, 0x67, 0x67, 0x53) -> "audio/ogg" to Kind.AUDIO
            at(0, 0x49, 0x44, 0x33) || (n > 1 && (h[0].toInt() and 0xff) == 0xFF && (h[1].toInt() and 0xE0) == 0xE0) -> "audio/mpeg" to Kind.AUDIO
            at(0, 0x50, 0x4B, 0x03, 0x04) -> "application/zip" to Kind.OTHER
            ascii(0, 4) == "dex\n" -> "application/x-dex" to Kind.OTHER
            at(0, 0x7F, 0x45, 0x4C, 0x46) -> "application/x-elf" to Kind.OTHER
            looksLikeText(h, n) -> {
                val t = String(h, 0, n, Charsets.UTF_8).trimStart()
                val mime = when {
                    t.startsWith("<svg") || (t.startsWith("<?xml") && t.contains("<svg")) -> "image/svg+xml"
                    t.startsWith("{") || t.startsWith("[") -> "application/json"
                    t.startsWith("<!") || t.startsWith("<html", true) -> "text/html"
                    name.substringBefore('?').endsWith(".js") -> "text/javascript"
                    else -> "text/plain"
                }
                mime to Kind.TEXT
            }
            else -> "application/octet-stream" to Kind.OTHER
        }
    }
}
