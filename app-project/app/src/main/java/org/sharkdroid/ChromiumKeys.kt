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
    enum class Check { UNKNOWN, CHECKING, READY, NO_ROOT, NO_RESETPROP, NEEDS_PERMISSIVE }

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

    /** Conditions: root works and either resetprop exists, or the user-supplied mprop2 is present with SELinux permissive. */
    fun verify(ctx: Context) {
        val app = ctx.applicationContext
        check = Check.CHECKING
        thread(name = "dbgstate") {
            val r = RootHelper.run(app, "dbgstate", timeoutSec = 10)
            val v = r.stdout.lineSequence().mapNotNull { l -> l.split('=', limit = 2).takeIf { it.size == 2 } }.associate { it[0] to it[1] }
            check = when {
                r.exit != 0 -> Check.NO_ROOT
                v["resetprop"] != "none" -> Check.READY
                v["mprop2"] == "none" -> Check.NO_RESETPROP
                v["selinux"] != "permissive" -> Check.NEEDS_PERMISSIVE
                else -> Check.READY
            }
        }
    }

    /** Before the target app is restarted; returns an error text, or null when nothing failed (or the option is off). */
    fun apply(ctx: Context, pkg: String): String? {
        init(ctx)
        if (!enabled) return null
        val r = RootHelper.run(ctx, "dbgset", listOf(pkg, "1"), timeoutSec = 700)
        if (r.exit != 0) return r.stderr.trim().lineSequence().firstOrNull().orEmpty().ifEmpty { "exit ${r.exit}" }
        applied = true
        return null
    }

    fun restore(ctx: Context) {
        if (!applied) return
        applied = false
        runCatching { RootHelper.run(ctx, "dbgset", listOf("-", "0"), timeoutSec = 700) }
    }
}
