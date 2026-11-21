package org.sharkdroid

import android.content.Context
import android.os.ParcelFileDescriptor
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.URLDecoder

/** HTTP/1 and HTTP/2 bodies of a capture, saved as cache files. tshark's isolated process cannot use --export-objects, so bodies are read from stdout as hex; HTTP/2 bodies arrive gzipped and are inflated here. */
object Resources {
    enum class Kind { IMAGE, VIDEO, AUDIO, TEXT, DOCUMENT, FONT, ARCHIVE, OTHER }

    class Item(val file: File, val name: String, val size: Long, val mime: String, val kind: Kind, val url: String)

    private const val MAX_FILE = 256L * 1024 * 1024

    private interface Lines {
        fun wantBody(meta: Array<String>): Boolean
        fun newBody(meta: Array<String>, index: Int): File
        fun end(meta: Array<String>, bodies: List<File>)
    }

    fun extract(ctx: Context, capture: File): List<Item> {
        val dir = File(ctx.cacheDir, "resources")
        dir.deleteRecursively()
        dir.mkdirs()
        val items = ArrayList<Item>()
        run(ctx, capture, "(http.request || http.response)",
            listOf("-E", "occurrence=f", "-e", "frame.number", "-e", "http.response.code", "-e", "http.request_in",
                "-e", "http.request.uri", "-e", "http.host", "-e", "http.file_data"), 5, http1(dir, items))
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
        private val urls = HashMap<String, String>()
        override fun wantBody(meta: Array<String>) = meta[1].isNotEmpty()
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
                        '\n' -> reset()
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
        val (mime, kind) = sniff(head, n, url.ifBlank { f.name }).let { if (it.first == "application/octet-stream") byExtension(url) ?: it else it }
        var name = segment(url).ifBlank { url.substringBefore('/').ifBlank { "response" } }
        if (!name.substringAfterLast('.', "").let { it.isNotEmpty() && it.length <= 5 }) name += extension(mime)
        return Item(f, name, f.length(), mime, kind, url)
    }

    private val EXT = mapOf(
        "image/jpeg" to ".jpg", "image/png" to ".png", "image/gif" to ".gif", "image/webp" to ".webp", "image/avif" to ".avif",
        "image/heic" to ".heic", "image/bmp" to ".bmp", "image/x-icon" to ".ico", "image/tiff" to ".tiff", "image/svg+xml" to ".svg",
        "image/jxl" to ".jxl", "image/jp2" to ".jp2", "video/mp4" to ".mp4", "video/webm" to ".webm", "video/x-matroska" to ".mkv",
        "video/avi" to ".avi", "video/x-flv" to ".flv", "video/mp2t" to ".ts", "video/quicktime" to ".mov", "video/3gpp" to ".3gp",
        "video/x-ms-wmv" to ".wmv", "video/mpeg" to ".mpg", "audio/mpeg" to ".mp3", "audio/ogg" to ".ogg", "audio/mp4" to ".m4a",
        "audio/wav" to ".wav", "audio/flac" to ".flac", "audio/aac" to ".aac", "audio/amr" to ".amr", "audio/midi" to ".mid",
        "application/json" to ".json", "text/javascript" to ".js", "text/html" to ".html", "text/css" to ".css", "text/xml" to ".xml",
        "text/csv" to ".csv", "application/vnd.apple.mpegurl" to ".m3u8", "application/dash+xml" to ".mpd",
        "application/pdf" to ".pdf", "application/rtf" to ".rtf", "application/postscript" to ".ps",
        "application/zip" to ".zip", "application/gzip" to ".gz", "application/x-bzip2" to ".bz2", "application/x-xz" to ".xz",
        "application/zstd" to ".zst", "application/x-7z-compressed" to ".7z", "application/vnd.rar" to ".rar", "application/x-tar" to ".tar",
        "font/woff" to ".woff", "font/woff2" to ".woff2", "font/ttf" to ".ttf", "font/otf" to ".otf",
        "application/x-dex" to ".dex", "application/x-elf" to ".so", "application/wasm" to ".wasm", "application/x-sqlite3" to ".db",
        "application/java-vm" to ".class", "application/x-msdownload" to ".exe", "application/x-mach-binary" to ".macho",
        "application/x-protobuf" to ".pb"
    )

    private fun extension(mime: String) = EXT[mime].orEmpty()

    private val BY_EXT: Map<String, Pair<String, Kind>> by lazy {
        val m = HashMap<String, Pair<String, Kind>>()
        for ((mime, ext) in EXT) m[ext.drop(1)] = mime to kindOf(mime)
        m.putAll(mapOf(
            "jpeg" to ("image/jpeg" to Kind.IMAGE), "jpe" to ("image/jpeg" to Kind.IMAGE), "svgz" to ("image/svg+xml" to Kind.IMAGE),
            "heif" to ("image/heic" to Kind.IMAGE), "tif" to ("image/tiff" to Kind.IMAGE), "apng" to ("image/png" to Kind.IMAGE),
            "m4v" to ("video/mp4" to Kind.VIDEO), "m4s" to ("video/mp4" to Kind.VIDEO), "mpeg" to ("video/mpeg" to Kind.VIDEO),
            "weba" to ("audio/webm" to Kind.AUDIO), "opus" to ("audio/ogg" to Kind.AUDIO), "oga" to ("audio/ogg" to Kind.AUDIO),
            "mjs" to ("text/javascript" to Kind.TEXT), "txt" to ("text/plain" to Kind.TEXT), "log" to ("text/plain" to Kind.TEXT),
            "md" to ("text/markdown" to Kind.TEXT), "yaml" to ("text/yaml" to Kind.TEXT), "yml" to ("text/yaml" to Kind.TEXT),
            "ini" to ("text/plain" to Kind.TEXT), "vtt" to ("text/vtt" to Kind.TEXT), "srt" to ("text/plain" to Kind.TEXT),
            "m3u" to ("application/vnd.apple.mpegurl" to Kind.TEXT), "map" to ("application/json" to Kind.TEXT),
            "apk" to ("application/zip" to Kind.ARCHIVE), "jar" to ("application/zip" to Kind.ARCHIVE), "tgz" to ("application/gzip" to Kind.ARCHIVE),
            "doc" to ("application/msword" to Kind.DOCUMENT), "docx" to ("application/vnd.openxmlformats-officedocument.wordprocessingml.document" to Kind.DOCUMENT),
            "xls" to ("application/vnd.ms-excel" to Kind.DOCUMENT), "xlsx" to ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" to Kind.DOCUMENT),
            "ppt" to ("application/vnd.ms-powerpoint" to Kind.DOCUMENT), "pptx" to ("application/vnd.openxmlformats-officedocument.presentationml.presentation" to Kind.DOCUMENT),
            "epub" to ("application/epub+zip" to Kind.DOCUMENT), "eot" to ("application/vnd.ms-fontobject" to Kind.FONT)
        ))
        m
    }

    private val SHOWN_IMAGES = setOf("image/jpeg", "image/png", "image/gif", "image/webp", "image/avif", "image/heic", "image/bmp", "image/x-icon")

    private fun kindOf(mime: String) = when {
        mime == "image/svg+xml" -> Kind.TEXT
        mime in SHOWN_IMAGES -> Kind.IMAGE
        mime.startsWith("image/") -> Kind.OTHER
        mime.startsWith("video/") -> Kind.VIDEO
        mime.startsWith("audio/") -> Kind.AUDIO
        mime.startsWith("font/") -> Kind.FONT
        mime.startsWith("text/") || mime == "application/json" || mime == "application/vnd.apple.mpegurl" || mime == "application/dash+xml" -> Kind.TEXT
        mime == "application/pdf" || mime == "application/rtf" || mime == "application/postscript" -> Kind.DOCUMENT
        mime in setOf("application/zip", "application/gzip", "application/x-bzip2", "application/x-xz", "application/zstd",
            "application/x-7z-compressed", "application/vnd.rar", "application/x-tar") -> Kind.ARCHIVE
        else -> Kind.OTHER
    }

    private fun byExtension(url: String): Pair<String, Kind>? {
        val ext = segment(url).substringAfterLast('.', "").lowercase()
        return if (ext.isEmpty() || ext.length > 6) null else BY_EXT[ext]
    }

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
        fun r(mime: String) = mime to kindOf(mime)
        fun b(i: Int) = if (n > i) h[i].toInt() and 0xff else -1
        return when {
            at(0, 0xFF, 0xD8, 0xFF) -> r("image/jpeg")
            at(0, 0x89, 0x50, 0x4E, 0x47) -> r("image/png")
            ascii(0, 4) == "GIF8" -> r("image/gif")
            ascii(0, 2) == "BM" && n > 14 && at(6, 0, 0, 0, 0) -> r("image/bmp")
            at(0, 0, 0, 1, 0) -> r("image/x-icon")
            at(0, 0x49, 0x49, 0x2A, 0) || at(0, 0x4D, 0x4D, 0, 0x2A) -> r("image/tiff")
            at(0, 0xFF, 0x0A) || at(0, 0, 0, 0, 0x0C, 0x4A, 0x58, 0x4C, 0x20) -> r("image/jxl")
            at(0, 0, 0, 0, 0x0C, 0x6A, 0x50, 0x20, 0x20) -> r("image/jp2")
            ascii(0, 4) == "RIFF" && ascii(8, 4) == "WEBP" -> r("image/webp")
            ascii(0, 4) == "RIFF" && ascii(8, 4) == "AVI " -> r("video/avi")
            ascii(0, 4) == "RIFF" && ascii(8, 4) == "WAVE" -> r("audio/wav")
            ascii(4, 4) == "ftyp" -> when (ascii(8, 4)) {
                "avif", "avis" -> r("image/avif")
                "heic", "heix", "heim", "heis", "hevc", "hevx", "mif1", "msf1" -> r("image/heic")
                "M4A ", "M4B ", "M4P " -> r("audio/mp4")
                "qt  " -> r("video/quicktime")
                "3gp4", "3gp5", "3gp6", "3ge6", "3gg6", "3g2a" -> r("video/3gpp")
                else -> r("video/mp4")
            }
            ascii(4, 4) == "moov" || ascii(4, 4) == "mdat" || ascii(4, 4) == "styp" || ascii(4, 4) == "moof" -> r("video/mp4")
            at(0, 0x1A, 0x45, 0xDF, 0xA3) -> if (String(h, 0, n, Charsets.ISO_8859_1).contains("webm")) r("video/webm") else r("video/x-matroska")
            ascii(0, 3) == "FLV" && b(3) == 1 -> r("video/x-flv")
            at(0, 0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11) -> r("video/x-ms-wmv")
            at(0, 0, 0, 1, 0xBA) || at(0, 0, 0, 1, 0xB3) -> r("video/mpeg")
            n >= 376 && b(0) == 0x47 && b(188) == 0x47 && b(376) == 0x47 -> r("video/mp2t")
            at(0, 0x4F, 0x67, 0x67, 0x53) -> r("audio/ogg")
            ascii(0, 4) == "fLaC" -> r("audio/flac")
            ascii(0, 6) == "#!AMR\n" -> r("audio/amr")
            ascii(0, 4) == "MThd" -> r("audio/midi")
            at(0, 0x49, 0x44, 0x33) || (b(0) == 0xFF && b(1) != -1 && (b(1) and 0xFE) == 0xFA) || (b(0) == 0xFF && (b(1) and 0xE6) == 0xE2) -> r("audio/mpeg")
            b(0) == 0xFF && (b(1) == 0xF1 || b(1) == 0xF9) -> r("audio/aac")
            ascii(0, 4) == "%PDF" -> r("application/pdf")
            ascii(0, 5) == "{\\rtf" -> r("application/rtf")
            ascii(0, 2) == "%!" -> r("application/postscript")
            at(0, 0x50, 0x4B, 0x03, 0x04) || at(0, 0x50, 0x4B, 0x05, 0x06) -> r("application/zip")
            at(0, 0x1F, 0x8B) -> r("application/gzip")
            ascii(0, 3) == "BZh" -> r("application/x-bzip2")
            at(0, 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0) -> r("application/x-xz")
            at(0, 0x28, 0xB5, 0x2F, 0xFD) -> r("application/zstd")
            at(0, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C) -> r("application/x-7z-compressed")
            ascii(0, 6) == "Rar!\u001a\u0007" -> r("application/vnd.rar")
            ascii(257, 5) == "ustar" -> r("application/x-tar")
            ascii(0, 4) == "wOFF" -> r("font/woff")
            ascii(0, 4) == "wOF2" -> r("font/woff2")
            ascii(0, 4) == "OTTO" -> r("font/otf")
            at(0, 0, 1, 0, 0) || ascii(0, 4) == "true" || ascii(0, 4) == "ttcf" -> r("font/ttf")
            ascii(0, 4) == "dex\n" -> r("application/x-dex")
            at(0, 0x7F, 0x45, 0x4C, 0x46) -> r("application/x-elf")
            at(0, 0, 0x61, 0x73, 0x6D) -> r("application/wasm")
            ascii(0, 15) == "SQLite format 3" -> r("application/x-sqlite3")
            at(0, 0xCA, 0xFE, 0xBA, 0xBE) -> r("application/java-vm")
            ascii(0, 2) == "MZ" && n > 64 -> r("application/x-msdownload")
            at(0, 0xCF, 0xFA, 0xED, 0xFE) || at(0, 0xCE, 0xFA, 0xED, 0xFE) -> r("application/x-mach-binary")
            looksLikeText(h, n) -> {
                val t = String(h, 0, n, Charsets.UTF_8).trimStart('\uFEFF', ' ', '\t', '\r', '\n')
                val ext = name.substringBefore('?').substringAfterLast('.', "").lowercase()
                val mime = when {
                    t.startsWith("#EXTM3U") -> "application/vnd.apple.mpegurl"
                    t.startsWith("WEBVTT") -> "text/vtt"
                    t.startsWith("<svg") || (t.startsWith("<?xml") && t.contains("<svg")) -> "image/svg+xml"
                    t.contains("<MPD") && t.startsWith("<") -> "application/dash+xml"
                    t.startsWith("<?xml") -> "text/xml"
                    t.startsWith("<!") || t.startsWith("<html", true) || t.startsWith("<head", true) || t.startsWith("<body", true) -> "text/html"
                    t.startsWith("{") || t.startsWith("[") -> if (ext == "js") "text/javascript" else "application/json"
                    ext == "css" -> "text/css"
                    ext == "js" || ext == "mjs" -> "text/javascript"
                    ext == "csv" -> "text/csv"
                    ext == "xml" -> "text/xml"
                    else -> "text/plain"
                }
                mime to Kind.TEXT
            }
            else -> "application/octet-stream" to Kind.OTHER
        }
    }
}
