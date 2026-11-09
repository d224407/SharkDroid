package org.sharkdroid

import android.content.Context
import java.io.File
import java.util.zip.ZipFile

/** Tells whether an app's TLS can be decrypted: static look at its native libraries, plus counts from a capture. */
object TlsDiag {
    /** String resource with the warning for an app whose bundled libraries the key hook cannot reach, or null. */
    fun hint(ctx: Context, process: String): Int? {
        val libs = nativeLibs(ctx, process).map { it.lowercase() }
        fun has(vararg p: String) = libs.any { l -> p.any { l.startsWith(it) } }
        return when {
            has("libflutter") -> R.string.tls_hint_flutter
            has("libcronet", "libmonochrome", "libchrome", "libwebviewchromium") -> R.string.tls_hint_cronet
            has("libgojni") -> R.string.tls_hint_go
            has("libmbedtls", "libwolfssl", "librustls", "libnss3", "libssl3") -> R.string.tls_hint_other
            else -> null
        }
    }

    /** Names of the native libraries (.so files under lib/) inside the app's APK(s) (readable without root). */
    fun nativeLibs(ctx: Context, process: String): List<String> = try {
        val info = ctx.packageManager.getApplicationInfo(process.substringBefore(':'), 0)
        val paths = listOfNotNull(info.sourceDir) + (info.splitSourceDirs?.toList() ?: emptyList())
        paths.flatMap { path ->
            ZipFile(path).use { z ->
                z.entries().asSequence().map { it.name }
                    .filter { it.startsWith("lib/") && it.endsWith(".so") }.map { it.substringAfterLast('/') }.toList()
            }
        }.distinct()
    } catch (_: Exception) { emptyList() }

    /** (TLS connections with a ClientHello, connections with decrypted data) among the packets on [ports]; null on failure. */
    fun stats(ctx: Context, capture: File, ports: Set<Int>): Pair<Int, Int>? {
        val scope = "tcp.port in {" + ports.take(4000).joinToString(" ") + "}"
        fun streams(y: String): Int? {
            val (rc, out, _) = Dissector.runOnFile(ctx, capture, listOf("-Y", "($y) && $scope", "-T", "fields", "-e", "tcp.stream"))
            if (rc != 0) return null
            return out.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toSet().size
        }
        val hello = streams("tls.handshake.type == 1") ?: return null
        // Matches only records tshark actually decrypted (same test as DecryptExport).
        val decrypted = streams("tls.record.content_type == 23") ?: 0
        return hello to decrypted
    }
}
