package org.sharkdroid

import android.content.Context
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
}
