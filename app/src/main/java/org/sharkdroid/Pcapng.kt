package org.sharkdroid

import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Relays dumpcap's little-endian pcapng stream and inserts TLS key Decryption Secrets Blocks at block boundaries; anything else passes through unchanged. */
class DsbInjector {
    private val lock = Any()
    private val pending = ArrayList<String>()

    private val hdr = ByteArray(8)
    private var hdrLen = 0
    private var remaining = 0L      // bytes of the current block still to come after its 8-byte header
    private var seenShb = false
    private var seenIdb = false     // DSBs are only inserted after the first interface description block
    @Volatile var broken = false; private set

    fun addKeys(lines: Collection<String>) {
        if (lines.isEmpty()) return
        synchronized(lock) { pending.addAll(lines) }
    }

    fun write(buf: ByteArray, n: Int, out: OutputStream): Long {
        if (broken) { out.write(buf, 0, n); return n.toLong() }
        var written = 0L
        var start = 0
        var i = 0
        while (i < n) {
            if (hdrLen == 0 && remaining == 0L && seenIdb) {
                if (i > start) { out.write(buf, start, i - start); written += i - start; start = i }
                written += emitPending(out)
            }
            if (remaining > 0L) {
                val take = minOf(remaining, (n - i).toLong()).toInt()
                i += take
                remaining -= take
            } else {
                hdr[hdrLen++] = buf[i++]
                if (hdrLen == 8) {
                    hdrLen = 0
                    val type = u32(hdr, 0)
                    val total = u32(hdr, 4)
                    if (!seenShb) {
                        if (type != SHB) { broken = true; break }
                        seenShb = true
                    }
                    if (total < 12 || total > MAX_BLOCK || total % 4L != 0L) { broken = true; break }
                    if (type == IDB) seenIdb = true
                    remaining = total - 8
                }
            }
        }
        if (broken) {
            out.write(buf, start, n - start)
            return written + (n - start)
        }
        if (n > start) { out.write(buf, start, n - start); written += n - start }
        return written
    }

    private fun emitPending(out: OutputStream): Long {
        val lines = synchronized(lock) {
            if (pending.isEmpty()) return 0L
            val copy = ArrayList(pending); pending.clear(); copy
        }
        val data = lines.joinToString("\n", postfix = "\n").toByteArray(Charsets.US_ASCII)
        val block = buildDsb(data)
        out.write(block)
        return block.size.toLong()
    }

    companion object {
        private const val SHB = 0x0A0D0D0AL
        private const val IDB = 0x00000001L
        private const val MAX_BLOCK = 256L * 1024 * 1024
        const val DSB_TYPE = 0x0000000A
        const val SECRETS_TLS = 0x544c534b  // "TLSK": TLS key log

        private fun u32(b: ByteArray, off: Int): Long =
            (b[off].toLong() and 0xff) or ((b[off + 1].toLong() and 0xff) shl 8) or
                ((b[off + 2].toLong() and 0xff) shl 16) or ((b[off + 3].toLong() and 0xff) shl 24)

        /** TLS 1.3 needs the handshake secrets before the ServerHello: after capture, move all keys into one DSB right after the first interface block. */
        fun hoist(f: File): Boolean {
            val tmp = File(f.parentFile, f.name + ".hoist")
            try {
                val lines = LinkedHashSet<String>()
                var first = true
                DataInputStream(f.inputStream().buffered(1 shl 16)).use { inp ->
                    while (true) {
                        val b = readBlock(inp) ?: break
                        if (first) { first = false; if (u32(b, 0) != SHB || u32(b, 8) != 0x1A2B3C4DL) return false }
                        if (u32(b, 0) == DSB_TYPE.toLong() && b.size >= 20 && u32(b, 8) == SECRETS_TLS.toLong()) {
                            val len = u32(b, 12).toInt()
                            if (len >= 0 && 16 + len <= b.size) String(b, 16, len, Charsets.US_ASCII).lineSequence().filter { it.isNotBlank() }.forEach { lines.add(it) }
                        }
                    }
                }
                if (lines.isEmpty()) return false
                var done = false
                DataInputStream(f.inputStream().buffered(1 shl 16)).use { inp ->
                    tmp.outputStream().buffered(1 shl 16).use { out ->
                        while (true) {
                            val b = readBlock(inp) ?: break
                            if (u32(b, 0) == DSB_TYPE.toLong()) continue
                            out.write(b)
                            if (!done && u32(b, 0) == IDB) {
                                out.write(buildDsb(lines.joinToString("\n", postfix = "\n").toByteArray(Charsets.US_ASCII)))
                                done = true
                            }
                        }
                    }
                }
                if (!done) { tmp.delete(); return false }
                return tmp.renameTo(f)
            } catch (e: Exception) { tmp.delete(); return false }
        }

        private fun readBlock(inp: DataInputStream): ByteArray? {
            val h = ByteArray(8)
            try { inp.readFully(h) } catch (_: EOFException) { return null }
            val total = u32(h, 4)
            if (total < 12 || total > MAX_BLOCK || total % 4L != 0L) return null
            val b = ByteArray(total.toInt())
            System.arraycopy(h, 0, b, 0, 8)
            try { inp.readFully(b, 8, b.size - 8) } catch (_: EOFException) { return null }
            return b
        }

        fun buildDsb(secrets: ByteArray): ByteArray {
            val pad = (4 - secrets.size % 4) % 4
            val total = 20 + secrets.size + pad
            return ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(DSB_TYPE).putInt(total)
                .putInt(SECRETS_TLS).putInt(secrets.size)
                .put(secrets).put(ByteArray(pad))
                .putInt(total)
                .array()
        }
    }
}
