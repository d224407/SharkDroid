package org.sharkdroid

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlin.concurrent.thread

/**
 * Optional key source for Chromium-based code (WebView, Chrome, Cronet in debuggable mode): sets ro.debuggable
 * with resetprop and lets the root helper write the Chromium command-line files with --ssl-key-log-file pointing
 * into the target app's cache, the file the TLS add-on already follows. Everything is put back when the capture ends.
 */
object ChromiumKeys {
    enum class Check { UNKNOWN, CHECKING, READY, NO_ROOT, NO_RESETPROP }

    var enabled by mutableStateOf(false); private set
    var check by mutableStateOf(Check.UNKNOWN); private set

    private var prefs: SharedPreferences? = null
    @Volatile private var applied = false

    fun init(ctx: Context) {
        if (prefs != null) return
        prefs = ctx.applicationContext.getSharedPreferences("chromium_keys", Context.MODE_PRIVATE)
        enabled = prefs!!.getBoolean("on", false)
    }

    fun setEnabled(ctx: Context, on: Boolean) {
        init(ctx)
        enabled = on
        prefs?.edit()?.putBoolean("on", on)?.apply()
        if (on) verify(ctx) else check = Check.UNKNOWN
    }

    /** Conditions: root works and a resetprop binary (Magisk, KernelSU or APatch) exists. */
    fun verify(ctx: Context) {
        val app = ctx.applicationContext
        check = Check.CHECKING
        thread(name = "dbgstate") {
            val r = RootHelper.run(app, "dbgstate", timeoutSec = 10)
            check = when {
                r.exit != 0 -> Check.NO_ROOT
                r.stdout.lineSequence().any { it == "resetprop=none" } -> Check.NO_RESETPROP
                else -> Check.READY
            }
        }
    }

    /** Before the target app is restarted; returns an error text, or null when nothing failed (or the option is off). */
    fun apply(ctx: Context, pkg: String): String? {
        init(ctx)
        if (!enabled) return null
        val r = RootHelper.run(ctx, "dbgset", listOf(pkg, "1"))
        if (r.exit != 0) return r.stderr.trim().lineSequence().firstOrNull().orEmpty().ifEmpty { "exit ${r.exit}" }
        applied = true
        return null
    }

    fun restore(ctx: Context) {
        if (!applied) return
        applied = false
        runCatching { RootHelper.run(ctx, "dbgset", listOf("-", "0")) }
    }
}
