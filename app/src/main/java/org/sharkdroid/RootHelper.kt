package org.sharkdroid

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Talks to the root helper via `su -c '<path>'`; requests go over stdin as NUL-separated tokens, never through a shell. */
object RootHelper {
    class Result(val exit: Int, val stdout: String, val stderr: String)

    private fun encodeRequest(cmd: String, args: List<String>): ByteArray {
        require(args.size <= 8)
        val out = ByteArrayOutputStream()
        fun tok(s: String) {
            val b = s.toByteArray(Charsets.UTF_8)
            require(b.none { it.toInt() == 0 }) { "NUL in argument" }
            out.write(b); out.write(0)
        }
        tok("WSX1"); tok(cmd); tok(args.size.toString())
        args.forEach { tok(it) }
        return out.toByteArray()
    }

    fun startProcess(ctx: Context): Process {
        val pb = ProcessBuilder("su", "-c", Tools.shellQuotedPath(Tools.helper(ctx)))
        pb.redirectErrorStream(false)
        return pb.start()
    }

    fun run(ctx: Context, cmd: String, args: List<String> = emptyList(), timeoutSec: Long = 20): Result {
        val p = try {
            startProcess(ctx)
        } catch (e: Exception) {
            return Result(-1, "", "su: ${e.message}")
        }
        val errBuf = StringBuilder()
        val errT = thread(name = "su-stderr") { errBuf.append(readAllText(p.errorStream)) }
        val outBuf = StringBuilder()
        val outT = thread(name = "su-stdout") { outBuf.append(readAllText(p.inputStream)) }
        try {
            p.outputStream.use { it.write(encodeRequest(cmd, args)); it.flush() }
        } catch (_: Exception) { }
        val done = p.waitFor(timeoutSec, TimeUnit.SECONDS)
        if (!done) p.destroyForcibly()
        outT.join(2000); errT.join(2000)
        return Result(if (done) p.exitValue() else -2, outBuf.toString(), errBuf.toString())
    }

    fun startCapture(ctx: Context, iface: String, filter: String, snaplen: Int): Process {
        val p = startProcess(ctx)
        val os: OutputStream = p.outputStream
        os.write(encodeRequest("capture", listOf(iface, filter, snaplen.toString())))
        os.flush()
        return p
    }

    fun startTlsKeys(ctx: Context, pkg: String): Process {
        require(Tools.validPackage(pkg)) { "bad package name" }
        val p = startProcess(ctx)
        p.outputStream.write(encodeRequest("tlskeys", listOf(pkg)))
        p.outputStream.flush()
        return p
    }

    fun stopCapture(p: Process) {
        try { p.outputStream.write('q'.code); p.outputStream.flush() } catch (_: Exception) { }
        try { p.outputStream.close() } catch (_: Exception) { }
    }

    private fun readAllText(s: InputStream): String = try {
        s.bufferedReader().readText()
    } catch (_: Exception) { "" }
}
