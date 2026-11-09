// SharkDroid TLS key logger, loaded by the frida gadget that ZygiskFrida injects into ONE app.
//
// Appends every TLS key log line (NSS format) to <app data dir>/cache/sharkdroid_tlskeys.log as
// "[TLSKEY] <line>"; the root helper follows that file and SharkDroid embeds the lines in the capture
// as a pcapng Decryption Secrets Block, so tshark / Wireshark can decrypt the traffic.
// Only key material is written; no application data is logged.
//
// Works for BoringSSL/OpenSSL builds whose symbols are exported (system libssl, many app libraries).
// Only TLS sessions created after the script is loaded are covered.
(function () {
  'use strict';

  // ---- helpers that work with Frida 16 and 17 ----
  function findExport(moduleName, name) {
    try {
      if (moduleName === null) {
        return Module.findGlobalExportByName ? Module.findGlobalExportByName(name) : Module.findExportByName(null, name);
      }
      return Module.findExportByName(moduleName, name);
    } catch (e) { return null; }
  }
  function modExport(m, name) {
    try { return m.findExportByName ? m.findExportByName(name) : Module.findExportByName(m.name, name); } catch (e) { return null; }
  }

  // ---- output: the app's own cache directory (the app process may write there) ----
  function packageName() {
    var fopen = findExport(null, 'fopen'), fgets = findExport(null, 'fgets'), fclose = findExport(null, 'fclose');
    if (!(fopen && fgets && fclose)) return null;
    var f = new NativeFunction(fopen, 'pointer', ['pointer', 'pointer'])(Memory.allocUtf8String('/proc/self/cmdline'), Memory.allocUtf8String('r'));
    if (f.isNull()) return null;
    var buf = Memory.alloc(256);
    var got = new NativeFunction(fgets, 'pointer', ['pointer', 'int', 'pointer'])(buf, 256, f);
    new NativeFunction(fclose, 'int', ['pointer'])(f);
    if (got.isNull()) return null;
    return buf.readUtf8String().split(':')[0];
  }

  var out = null;
  function emit(line) {
    try {
      if (out === null) {
        var pkg = packageName();
        if (!pkg) return;
        out = new File('/data/data/' + pkg + '/cache/sharkdroid_tlskeys.log', 'a');
      }
      out.write(line + '\n');
      out.flush();
    } catch (e) {}
  }

  // ---- hooks ----
  var done = {};

  var keylogCb = new NativeCallback(function (ssl, line) {
    try { emit('[TLSKEY] ' + line.readUtf8String()); } catch (e) {}
  }, 'void', ['pointer', 'pointer']);

  function hookModule(m) {
    var key = m.base.toString();
    if (done[key]) return;

    var sslNew = modExport(m, 'SSL_new'), setCb = modExport(m, 'SSL_CTX_set_keylog_callback'), getCtx = modExport(m, 'SSL_get_SSL_CTX');
    if (!(sslNew && setCb && getCtx)) return;
    done[key] = true;

    var setKeylog = new NativeFunction(setCb, 'void', ['pointer', 'pointer']);
    var ctxOf = new NativeFunction(getCtx, 'pointer', ['pointer']);
    Interceptor.attach(sslNew, {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        try { setKeylog(ctxOf(ret), keylogCb); } catch (e) {}
      }
    });
    emit('[TLS] hooked ' + m.name);
  }

  function scan() {
    Process.enumerateModules().forEach(function (m) {
      if (/ssl|crypto|conscrypt|cronet|boring|flutter|okhttp|curl|quic/i.test(m.name)) {
        try { hookModule(m); } catch (e) {}
      }
    });
  }

  scan();

  // libraries loaded later (webviews, app-bundled stacks)
  ['android_dlopen_ext', 'dlopen'].forEach(function (n) {
    try {
      var p = findExport(null, n);
      if (p) Interceptor.attach(p, { onLeave: function () { setTimeout(scan, 50); } });
    } catch (e) {}
  });
})();
