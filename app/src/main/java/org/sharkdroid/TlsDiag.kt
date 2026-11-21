package org.sharkdroid

import android.content.Context
import java.util.zip.ZipFile

object TlsDiag {
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
