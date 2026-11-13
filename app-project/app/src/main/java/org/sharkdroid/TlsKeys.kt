package org.sharkdroid

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

/**
 * Optional TLS decryption add-on, built on the ZygiskFrida module (https://github.com/lico-n/ZygiskFrida).
 *
 * The module injects a frida gadget into the target app when it starts. SharkDroid adds the app to the
 * module's config (through the root helper), pointing at its own gadget copy whose config loads a fixed
 * key-logging script (addon/tlskeys.js). The script appends every TLS key log line to a file in the app's
 * own data directory; the helper follows that file and every line is forwarded to the running capture as a
 * pcapng Decryption Secrets Block (see [DsbInjector]). Nothing is added to the module's own files except
 * the one config entry, which is put back when the capture ends.
 */
object TlsKeys {
    enum class State { IDLE, WAITING, STARTING, RUNNING }

    private const val ZF_DIR = "/data/local/tmp/re.zyg.fri"
    private const val OWN_LIB = "$ZF_DIR/libsharkdroid.so"
    private const val PREFIX = "[TLSKEY] "
    private const val MAX_KEYS = 20_000
    // NSS key log: LABEL <client_random hex> <secret hex>
    private val KEY_LINE = Regex("^[A-Z0-9_]{5,48} [0-9a-fA-F]{64} [0-9a-fA-F]{32,256}$")

    var state by mutableStateOf(State.IDLE); private set
    var target by mutableStateOf<String?>(null); private set
    var keyCount by mutableIntStateOf(0); private set
    /** True when the ZygiskFrida module (its gadget) is installed; see [probe]. */
    var ready by mutableStateOf(false); private set
    /** Last non-key output of the extractor (errors from the helper / the script). */
    var log by mutableStateOf(""); private set

    private val lock = Any()
    private val history = LinkedHashSet<String>()
    private val injectors = CopyOnWriteArrayList<DsbInjector>()
    @Volatile private var proc: Process? = null

    /** Looks (as root, in the background) for the ZygiskFrida module and the script bundled in the APK. */
    fun probe(ctx: Context) {
        val app = ctx.applicationContext
        thread(name = "tlsprobe") {
            ready = Tools.tlsScript(app).isFile && RootHelper.run(app, "zfcheck", timeoutSec = 10).exit == 0
            if (ready && state == State.IDLE) runCatching { removeStaleEntries(app) }
        }
    }

    /** An entry of ours left in the module's config (SharkDroid was killed mid-capture) would keep injecting the app. */
    private fun removeStaleEntries(ctx: Context) {
        val r = RootHelper.run(ctx, "zfconfig")
        if (r.exit != 0) return
        val root = try { JSONObject(r.stdout.ifBlank { "{}" }) } catch (_: Exception) { return }
        val old = root.optJSONArray("targets") ?: return
        val kept = JSONArray()
        for (i in 0 until old.length()) { val t = old.optJSONObject(i) ?: continue; if (!isOurs(t)) kept.put(t) }
        if (kept.length() == old.length()) return
        root.put("targets", kept)
        RootHelper.run(ctx, "zfsetconfig", listOf(root.toString()))
    }

    private fun helperError(r: RootHelper.Result) = r.stderr.trim().lineSequence().firstOrNull().orEmpty().ifEmpty { "exit ${r.exit}" }

    private fun isOurs(t: JSONObject): Boolean {
        val libs = t.optJSONArray("injected_libraries") ?: return false
        return (0 until libs.length()).any { libs.optJSONObject(it)?.optString("path") == OWN_LIB }
    }

    /**
     * Replaces the module's config entry for [pkg] with [entry] (null: just remove ours) and returns the entry
     * that was there before. Entries of other apps are kept untouched; an unreadable config is never overwritten.
     */
    private fun editConfig(ctx: Context, pkg: String, entry: JSONObject?): JSONObject? {
        val r = RootHelper.run(ctx, "zfconfig")
        if (r.exit != 0) error(helperError(r))
        val root = try { JSONObject(r.stdout.ifBlank { "{}" }) } catch (_: Exception) { error("ZygiskFrida config.json is not valid JSON") }
        val old = root.optJSONArray("targets") ?: JSONArray()
        val kept = JSONArray()
        var previous: JSONObject? = null
        for (i in 0 until old.length()) {
            val t = old.optJSONObject(i) ?: continue
            if (t.optString("app_name") == pkg) previous = t else kept.put(t)
        }
        if (entry != null) kept.put(entry)
        root.put("targets", kept)
        val w = RootHelper.run(ctx, "zfsetconfig", listOf(root.toString()))
        if (w.exit != 0) error(helperError(w))
        return previous
    }

    private fun ourEntry(pkg: String) = JSONObject()
        .put("app_name", pkg).put("enabled", true).put("start_up_delay_ms", 0)
        .put("injected_libraries", JSONArray().put(JSONObject().put("path", OWN_LIB)))

    /** Capture start: replay keys collected so far, then receive new ones live. */
    fun attach(inj: DsbInjector) {
        val snapshot = synchronized(lock) { ArrayList(history) }
        inj.addKeys(snapshot)
        injectors += inj
    }

    fun detach(inj: DsbInjector) { injectors -= inj }

    /** Hooks [pkg] through ZygiskFrida and starts following its keys. The app is restarted so the module injects it. */
    fun start(ctx: Context, pkg: String) {
        if (state != State.IDLE || !Tools.validPackage(pkg)) return
        val app = ctx.applicationContext
        state = State.WAITING; target = pkg; log = ""
        thread(name = "tlskeys") {
            var previous: JSONObject? = null
            var edited = false
            fun restore() { if (edited) runCatching { editConfig(app, pkg, previous) }; edited = false }
            try {
                val prep = RootHelper.run(app, "zfprep", listOf(pkg))
                if (prep.exit != 0) error(helperError(prep))
                previous = editConfig(app, pkg, ourEntry(pkg))?.takeIf { !isOurs(it) }
                edited = true
            } catch (e: Exception) {
                log = e.message ?: "setup failed"; state = State.IDLE; return@thread
            }
            val p = try { RootHelper.startTlsKeys(app, pkg) } catch (e: Exception) {
                log = e.message ?: "su failed"; restore(); state = State.IDLE; return@thread
            }
            proc = p
            thread(name = "tlskeys-restart") { RootHelper.run(app, "zfrestart", listOf(pkg), timeoutSec = 30) }
            val tail = ArrayDeque<String>()
            try {
                p.inputStream.bufferedReader().forEachLine { raw ->
                    val line = raw.trim()
                    if (line.startsWith(PREFIX)) {
                        accept(line.substring(PREFIX.length).trim())
                        if (state == State.STARTING) state = State.RUNNING
                    } else if (line.startsWith("[WAIT]")) {
                        state = State.WAITING          // app not running (yet, or again after a restart)
                    } else if (line.startsWith("[ATTACH]")) {
                        state = State.STARTING
                    } else if (line.isNotEmpty()) {
                        tail.addLast(line.take(300)); while (tail.size > 20) tail.removeFirst()
                        if (state == State.STARTING && line.contains("hooked")) state = State.RUNNING
                        log = tail.joinToString("\n")
                    }
                }
            } catch (_: Exception) { }
            val err = try { p.errorStream.bufferedReader().readText().trim() } catch (_: Exception) { "" }
            val rc = try { p.waitFor() } catch (_: Exception) { -1 }
            proc = null
            if (err.isNotEmpty()) log = (log + "\n" + err).trim()
            if (rc != 0 && rc != 143 && log.isEmpty()) log = "exit $rc"
            restore()
            state = State.IDLE
        }
    }

    fun stop() {
        val p = proc ?: return
        RootHelper.stopCapture(p) // same protocol: a 'q' byte (or EOF) asks the helper to stop its child
        thread(name = "tlskeys-stop") {
            Thread.sleep(6000)
            if (proc === p) try { p.destroy() } catch (_: Exception) { }
        }
    }

    fun clearKeys() { synchronized(lock) { history.clear() }; keyCount = 0 }

    private fun accept(line: String) {
        if (line.length > 512 || !KEY_LINE.matches(line)) return
        val fresh = synchronized(lock) {
            if (history.size >= MAX_KEYS) return
            history.add(line).also { if (it) keyCount = history.size }
        }
        if (fresh) injectors.forEach { it.addKeys(listOf(line)) }
    }
}
