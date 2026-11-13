package org.sharkdroid

import android.content.Context
import java.io.File
import java.io.OutputStream

/** "Output" of the TLS add-on: every TLS stream tshark could decrypt, as one text file. */
object DecryptExport {
    /** Matches only records tshark actually decrypted: the sequence number is added only after decryption
     *  (tls.record.content_type is on every TLS 1.2 record, decrypted or not). */
    private const val DECRYPTED = "tls.record.sequence_number"

    private fun streamIds(ctx: Context, capture: File, field: String): List<Int>? {
        val (rc, out, _) = Dissector.runOnFile(ctx, capture, listOf("-Y", DECRYPTED, "-T", "fields", "-e", field))
        if (rc != 0) return null // field unknown to this tshark version
        return out.lineSequence().flatMap { it.split(',', ' ', '\t').asSequence() }
            .mapNotNull { it.trim().toIntOrNull() }.distinct().sorted().toList()
    }

    /** Writes the decrypted streams of [capture] to [out]; returns how many streams, 0 if there are none. */
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
