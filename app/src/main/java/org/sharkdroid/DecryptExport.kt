package org.sharkdroid

import android.content.Context
import java.io.File
import java.io.OutputStream

object DecryptExport {
    /** Matches only decrypted records: the sequence number exists only after decryption (content_type is on every TLS 1.2 record). */
    private const val DECRYPTED = "tls.record.sequence_number"

    private fun streamIds(ctx: Context, capture: File, field: String): List<Int>? {
        val (rc, out, _) = Dissector.runOnFile(ctx, capture, listOf("-Y", DECRYPTED, "-T", "fields", "-e", field))
        if (rc != 0) return null // field unknown to this tshark version
        return out.lineSequence().flatMap { it.split(',', ' ', '\t').asSequence() }
            .mapNotNull { it.trim().toIntOrNull() }.distinct().sorted().toList()
    }

    fun write(ctx: Context, capture: File, out: OutputStream): Int {
        // Newer tshark indexes TLS follow by tls.stream, older ones by tcp.stream.
        val ids = streamIds(ctx, capture, "tls.stream")?.takeIf { it.isNotEmpty() }
            ?: streamIds(ctx, capture, "tcp.stream") ?: emptyList()
        val w = out.bufferedWriter()
        w.write("# SharkDroid - decrypted TLS streams\n# capture: ${capture.name}\n# streams: ${ids.size}\n\n")
        for (chunk in ids.chunked(50)) {
            val args = ArrayList<String>().apply { add("-q"); chunk.forEach { addAll(listOf("-z", "follow,tls,ascii,$it")) } }
            w.write(Dissector.runOnFile(ctx, capture, args, maxBytes = 64 * 1024 * 1024).second)
            w.write("\n")
        }
        w.flush()
        return ids.size
    }
}
