/*
 * wsexec - tiny privileged launcher for SharkDroid.
 *
 * Runs as root (started by the app via `su -c '<nativeLibraryDir>/libwsexec.so'`).
 * The command string given to su is a constant path controlled by the package
 * manager; ALL user-controlled data (interface name, capture filter) is passed
 * on stdin as NUL-separated tokens and is never interpreted by a shell.
 * After validation the request is executed with execv() with a fixed argv.
 *
 * Request format on stdin:  "WSX1\0<cmd>\0<argc>\0<arg1>\0...<argN>\0"
 *   id                          -> prints uid/selinux context
 *   list                        -> prints interface table (one line per iface)
 *   pcaplist                    -> exec dumpcap -D
 *   capture <iface> <filter> <snaplen>
 *                               -> fork/exec dumpcap -i IF [-f FILTER] -s N -w - -n -q
 *                                  pcapng goes to stdout; the capture is stopped with
 *                                  SIGTERM when stdin reaches EOF or a 'q' byte arrives.
 *   ZygiskFrida TLS add-on (optional; needs the ZygiskFrida Magisk/KernelSU module, which provides the
 *   frida gadget and injects it into the chosen app when that app starts):
 *   zfcheck                     -> exit 0 if the module's gadget exists in /data/local/tmp/re.zyg.fri
 *   zfprep <package>            -> hard-links the module's gadget as libsharkdroid.so, writes its gadget config
 *                                  (script mode) and installs the key-logging script, which is libtlskeys.so
 *                                  next to this helper (it must be owned by root/system and not writable by
 *                                  others, so the injected script is fixed and never comes from app data)
 *   zfconfig                    -> prints the module's config.json ("{}" if there is none)
 *   zfsetconfig <json>          -> replaces config.json (the app merges its target into the existing one)
 *   zfinstall                   -> installs the ZygiskFrida module zip shipped with the app (libzygiskfrida.so next
 *                                  to this helper, same ownership rules as the script) with Magisk, KernelSU or
 *                                  APatch; a reboot (and Zygisk enabled) is needed afterwards
 *   zfrestart <package>         -> force-stops and relaunches the app so the module injects the gadget
 *   tlskeys <package>           -> follows the key file the script writes inside the app's own data directory
 *                                  and relays its lines to stdout: "[TLSKEY] <nss key log line>" and
 *                                  "[TLS] hooked <lib>", preceded by "[WAIT] <pkg>" / "[ATTACH] <pkg>" status
 *                                  lines. Stopped like 'capture'.
 *   Chromium key log (optional; for WebView / Chrome, which keep BoringSSL inside their own library):
 *   dbgstate                    -> prints debuggable=<ro.debuggable>, buildtype=<ro.build.type>, resetprop=<path|none>
 *   dbgset <package> <1|0>      -> 1: remembers ro.debuggable, sets it to 1 with resetprop (Magisk / KernelSU / APatch) and
 *                                  writes the Chromium command-line files with --ssl-key-log-file pointing into the
 *                                  app's own cache directory (the file 'tlskeys' follows); 0: removes the files and
 *                                  puts ro.debuggable back; fails when no resetprop is found
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/system_properties.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_REQ    8192
#define MAX_TOKENS 16
#define MAX_FILTER 2048

static char self_dir[PATH_MAX];
static char dumpcap_path[PATH_MAX];
static char script_path[PATH_MAX];

static void die(const char *msg) {
    fprintf(stderr, "wsexec: %s\n", msg);
    exit(2);
}

static int valid_ifname(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n >= IFNAMSIZ) return 0;
    if (s[0] == '-' || s[0] == '.') return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int iface_exists(const char *s) {
    char p[PATH_MAX];
    struct stat st;
    if (strcmp(s, "any") == 0) return 1;
    snprintf(p, sizeof p, "/sys/class/net/%s", s);
    return stat(p, &st) == 0;
}

static int valid_filter(const char *s) {
    size_t n = strlen(s);
    if (n > MAX_FILTER) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e) return 0; /* BPF syntax is printable ASCII */
    }
    return 1;
}

static int valid_snaplen(const char *s, long *out) {
    char *end;
    if (!*s || strlen(s) > 6) return 0;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return 0;
    long v = strtol(s, &end, 10);
    if (*end || v < 64 || v > 262144) return 0;
    *out = v;
    return 1;
}

/* Android package / process names: [A-Za-z0-9._:], starting with a letter (e.g. com.foo:remote). */
static int valid_procname(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 128) return 0;
    if (!((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z'))) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

/* Only execute binaries that live next to us, are regular files, not writable by
 * group/other and owned by root or system (i.e. installed by the package manager). */
static void check_binary(const char *path, const char *what) {
    struct stat st;
    char msg[96];
    if (lstat(path, &st) != 0) { snprintf(msg, sizeof msg, "%s not found next to helper", what); die(msg); }
    if (!S_ISREG(st.st_mode)) { snprintf(msg, sizeof msg, "%s is not a regular file", what); die(msg); }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) { snprintf(msg, sizeof msg, "%s is group/world writable; refusing", what); die(msg); }
    if (st.st_uid != 0 && st.st_uid != 1000) { snprintf(msg, sizeof msg, "%s has unexpected owner; refusing", what); die(msg); }
}

static void read_sys(const char *ifn, const char *attr, char *buf, size_t len) {
    char p[PATH_MAX];
    snprintf(p, sizeof p, "/sys/class/net/%s/%s", ifn, attr);
    buf[0] = 0;
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t r = read(fd, buf, len - 1);
    close(fd);
    if (r <= 0) { buf[0] = 0; return; }
    buf[r] = 0;
    for (ssize_t i = 0; i < r; i++) if (buf[i] == '\n' || buf[i] == '\t') { buf[i] = 0; break; }
}

static int cmd_list(void) {
    DIR *d = opendir("/sys/class/net");
    if (!d) { perror("opendir /sys/class/net"); return 1; }
    struct ifaddrs *ifa = NULL;
    getifaddrs(&ifa);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' || !valid_ifname(de->d_name)) continue;
        char type[32], oper[32], flags[32], carrier[8], p[PATH_MAX];
        struct stat st;
        read_sys(de->d_name, "type", type, sizeof type);
        read_sys(de->d_name, "operstate", oper, sizeof oper);
        read_sys(de->d_name, "flags", flags, sizeof flags);
        read_sys(de->d_name, "carrier", carrier, sizeof carrier);
        snprintf(p, sizeof p, "/sys/class/net/%s/wireless", de->d_name);
        int wl = stat(p, &st) == 0;
        snprintf(p, sizeof p, "/sys/class/net/%s/phy80211", de->d_name);
        wl |= stat(p, &st) == 0;
        /* IF <tab> name type operstate flags carrier wireless addrs(comma-separated) */
        printf("IF\t%s\t%s\t%s\t%s\t%s\t%d\t", de->d_name, type, oper, flags, carrier, wl);
        int first = 1;
        for (struct ifaddrs *a = ifa; a; a = a->ifa_next) {
            if (!a->ifa_addr || !a->ifa_name || strcmp(a->ifa_name, de->d_name) != 0) continue;
            char buf[INET6_ADDRSTRLEN] = {0};
            if (a->ifa_addr->sa_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in *)a->ifa_addr)->sin_addr, buf, sizeof buf);
            else if (a->ifa_addr->sa_family == AF_INET6)
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)a->ifa_addr)->sin6_addr, buf, sizeof buf);
            else continue;
            printf("%s%s", first ? "" : ",", buf);
            first = 0;
        }
        printf("\n");
    }
    closedir(d);
    if (ifa) freeifaddrs(ifa);
    return 0;
}

static int cmd_capture(char **tok, int ntok) {
    if (ntok != 5) die("capture: bad argument count");
    const char *ifn = tok[2], *filter = tok[3];
    long snap;
    if (!valid_ifname(ifn) || !iface_exists(ifn)) die("capture: invalid interface name");
    if (!valid_filter(filter)) die("capture: invalid capture filter (printable ASCII only, max 2048)");
    if (!valid_snaplen(tok[4], &snap)) die("capture: invalid snaplen");
    check_binary(dumpcap_path, "dumpcap");

    char snapbuf[16];
    snprintf(snapbuf, sizeof snapbuf, "%ld", snap);
    const char *argv[16];
    int i = 0;
    argv[i++] = dumpcap_path; /* full path as argv[0] */
    argv[i++] = "-i"; argv[i++] = ifn;
    if (filter[0]) { argv[i++] = "-f"; argv[i++] = filter; }
    argv[i++] = "-s"; argv[i++] = snapbuf;
    argv[i++] = "-F"; argv[i++] = "pcapng";
    argv[i++] = "-q";
    argv[i++] = "-w"; argv[i++] = "-";
    argv[i] = NULL;

    pid_t pid = fork();
    if (pid < 0) die("fork failed");
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        int nul = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (nul >= 0) { dup2(nul, 0); }
        execv(dumpcap_path, (char *const *)argv);
        perror("wsexec: execv dumpcap");
        _exit(127);
    }
    /* Parent: don't keep stdout busy; wait for stop request or child exit. */
    signal(SIGPIPE, SIG_IGN);
    int status = 0, stopping = 0;
    time_t stop_at = 0;
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (stopping && time(NULL) - stop_at > 4) { kill(pid, SIGKILL); }
        struct pollfd pfd = { .fd = 0, .events = POLLIN };
        int pr = poll(&pfd, 1, stopping ? 200 : 500);
        if (pr > 0 && !stopping) {
            char c[64];
            ssize_t r = read(0, c, sizeof c);
            int q = (r <= 0);
            for (ssize_t k = 0; k < r; k++) if (c[k] == 'q') q = 1;
            if (q) { kill(pid, SIGTERM); stopping = 1; stop_at = time(NULL); }
        }
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

#define ZF_DIR        "/data/local/tmp/re.zyg.fri"
#define ZF_GADGET     ZF_DIR "/libgadget.so"
#define ZF_OWN_GADGET ZF_DIR "/libsharkdroid.so"
#define ZF_OWN_CONFIG ZF_DIR "/libsharkdroid.config.so"
#define ZF_OWN_SCRIPT ZF_DIR "/sharkdroid_tlskeys.js"
#define ZF_CONFIG     ZF_DIR "/config.json"
#define MAX_CONFIG    6000
#define MAX_SCRIPT    (256 * 1024)

/* Package name: a valid process name without ':' that has at least one dot. */
static int valid_pkg(const char *s) {
    return valid_procname(s) && !strchr(s, ':') && strchr(s, '.') != NULL && s[strlen(s) - 1] != '.';
}

/* Give [path] the SELinux label of the module's gadget, so the app process spawned by zygote may read it. */
static void copy_label(const char *path) {
    char label[256];
    ssize_t n = getxattr(ZF_GADGET, "security.selinux", label, sizeof label);
    if (n > 0) lsetxattr(path, "security.selinux", label, (size_t)n, 0);
}

/* Atomically (temp file + rename) write [len] bytes to [path], world-readable, labelled like the gadget. */
static int write_file(const char *path, const char *data, size_t len) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w <= 0) { close(fd); unlink(tmp); return -1; }
        off += (size_t)w;
    }
    fchmod(fd, 0644);
    close(fd);
    copy_label(tmp);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static int cmd_zfcheck(void) { return access(ZF_GADGET, R_OK) == 0 ? 0 : 3; }

static int cmd_zfprep(char **tok, int ntok) {
    if (ntok != 3) die("zfprep: bad argument count");
    const char *pkg = tok[2];
    if (!valid_pkg(pkg)) die("zfprep: invalid package name");
    if (access(ZF_GADGET, R_OK) != 0) { fprintf(stderr, "ZygiskFrida gadget not found in " ZF_DIR "\n"); return 3; }
    check_binary(script_path, "tlskeys script");

    /* A second name for the same gadget: its config file is found by name, so ours does not touch the
     * module's own libgadget.config.so (and a hard link keeps the inode, hence the SELinux label). */
    unlink(ZF_OWN_GADGET);
    if (link(ZF_GADGET, ZF_OWN_GADGET) != 0) { perror("wsexec: link gadget"); return 4; }

    static const char gcfg[] =
        "{\n  \"interaction\": {\n    \"type\": \"script\",\n    \"path\": \"" ZF_OWN_SCRIPT "\",\n"
        "    \"on_change\": \"ignore\"\n  }\n}\n";
    if (write_file(ZF_OWN_CONFIG, gcfg, sizeof gcfg - 1) != 0) { perror("wsexec: write gadget config"); return 4; }

    int in = open(script_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) { perror("wsexec: open script"); return 4; }
    static char js[MAX_SCRIPT];
    ssize_t n = read(in, js, sizeof js);
    close(in);
    if (n <= 0 || n >= (ssize_t)sizeof js) { fprintf(stderr, "wsexec: bad script size\n"); return 4; }
    if (write_file(ZF_OWN_SCRIPT, js, (size_t)n) != 0) { perror("wsexec: write script"); return 4; }

    /* Start from an empty key file (it lives in the app's own data directory and is written by the app). */
    char key[PATH_MAX];
    snprintf(key, sizeof key, "/data/data/%s/cache/sharkdroid_tlskeys.log", pkg);
    unlink(key);
    return 0;
}

static int cmd_zfconfig(void) {
    int fd = open(ZF_CONFIG, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { puts("{}"); return 0; }
    char buf[4096];
    ssize_t r;
    while ((r = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, (size_t)r, stdout);
    close(fd);
    return 0;
}

static int cmd_zfsetconfig(char **tok, int ntok) {
    if (ntok != 3) die("zfsetconfig: bad argument count");
    const char *json = tok[2];
    size_t len = strlen(json);
    if (len < 2 || len > MAX_CONFIG || json[0] != '{') die("zfsetconfig: invalid config");
    if (access(ZF_GADGET, R_OK) != 0) { fprintf(stderr, "ZygiskFrida gadget not found in " ZF_DIR "\n"); return 3; }
    if (write_file(ZF_CONFIG, json, len) != 0) { perror("wsexec: write config"); return 4; }
    return 0;
}

static void run_quiet(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        int nul = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        execv(argv[0], argv);
        _exit(127);
    }
    int st;
    waitpid(pid, &st, 0);
}

static int cmd_zfrestart(char **tok, int ntok) {
    if (ntok != 3) die("zfrestart: bad argument count");
    char *pkg = tok[2];
    if (!valid_pkg(pkg)) die("zfrestart: invalid package name");
    char *stop[] = { "/system/bin/am", "force-stop", pkg, NULL };
    run_quiet(stop);
    usleep(500000);
    /* "am" is a shell wrapper around the native "cmd" binary, so it works with our cleared environment
     * (monkey would need app_process, which needs the Android runtime environment variables). */
    char *start[] = { "/system/bin/am", "start", "-a", "android.intent.action.MAIN",
                      "-c", "android.intent.category.LAUNCHER", "-p", pkg, NULL };
    run_quiet(start);
    return 0;
}

/* Install the module zip that ships with the app. It is copied to a plain .zip first (the installers want one)
 * and handed to whichever root manager is present; its own output goes to our stdout / stderr. */
static int cmd_zfinstall(void) {
    char src[PATH_MAX];
    snprintf(src, sizeof src, "%s/libzygiskfrida.so", self_dir);
    check_binary(src, "ZygiskFrida module");
    static const char dst[] = "/data/local/tmp/sharkdroid-zygiskfrida.zip";
    int in = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) { perror("wsexec: open module"); return 4; }
    unlink(dst);
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (out < 0) { perror("wsexec: create module copy"); close(in); return 4; }
    char buf[65536];
    ssize_t r;
    int ok = 1;
    while ((r = read(in, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w <= 0) { ok = 0; break; }
            off += w;
        }
        if (!ok) break;
    }
    close(in);
    close(out);
    if (!ok || r < 0) { unlink(dst); fprintf(stderr, "wsexec: copying the module failed\n"); return 4; }

    static const struct { const char *bin, *a1, *a2; } tools[] = {
        { "/data/adb/magisk/magisk", "--install-module", NULL },
        { "/data/adb/ksud",          "module", "install" },
        { "/data/adb/ksu/bin/ksud",  "module", "install" },
        { "/data/adb/apd",           "module", "install" },
    };
    for (size_t i = 0; i < sizeof tools / sizeof tools[0]; i++) {
        if (access(tools[i].bin, X_OK) != 0) continue;
        fflush(stdout);
        pid_t pid = fork();
        if (pid < 0) break;
        if (pid == 0) {
            const char *argv[5];
            int n = 0;
            argv[n++] = tools[i].bin;
            argv[n++] = tools[i].a1;
            if (tools[i].a2) argv[n++] = tools[i].a2;
            argv[n++] = dst;
            argv[n] = NULL;
            execv(tools[i].bin, (char *const *)argv);
            _exit(127);
        }
        int st = 0;
        waitpid(pid, &st, 0);
        unlink(dst);
        return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    }
    unlink(dst);
    fprintf(stderr, "no Magisk, KernelSU or APatch binary found\n");
    return 5;
}


/* Chromium key log: ro.debuggable via resetprop, plus the command-line files Chrome / WebView read on debuggable systems. */
#define DBG_ORIG "/data/local/tmp/sharkdroid-dbg-orig"
static const char *const RESETPROP_PATHS[] = {
    "/data/adb/magisk/resetprop", "/data/adb/ksu/bin/resetprop", "/data/adb/ap/bin/resetprop", "/system/bin/resetprop", NULL };
static const char *const CMDLINE_FILES[] = {
    "/data/local/tmp/chrome-command-line", "/data/local/tmp/webview-command-line",
    "/data/local/tmp/android-webview-command-line", NULL };

static const char *find_resetprop(void) {
    for (int i = 0; RESETPROP_PATHS[i]; i++) if (access(RESETPROP_PATHS[i], X_OK) == 0) return RESETPROP_PATHS[i];
    return NULL;
}

static void get_prop(const char *key, char *out, size_t n) {
    char v[PROP_VALUE_MAX] = "";
    __system_property_get(key, v);
    snprintf(out, n, "%s", v);
}

static int run_resetprop(const char *rp, const char *key, const char *val) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execl(rp, rp, key, val, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
}

/* Set ro.debuggable with resetprop. */
static int set_debuggable(const char *val) {
    const char *rp = find_resetprop();
    return rp ? run_resetprop(rp, "ro.debuggable", val) : -1;
}

static int cmd_dbgstate(void) {
    char dbg[PROP_VALUE_MAX], bt[PROP_VALUE_MAX];
    get_prop("ro.debuggable", dbg, sizeof dbg);
    get_prop("ro.build.type", bt, sizeof bt);
    const char *rp = find_resetprop();
    printf("debuggable=%s\nbuildtype=%s\nresetprop=%s\n", dbg, bt, rp ? rp : "none");
    return 0;
}

static int cmd_dbgset(char **tok, int ntok) {
    if (ntok != 4) die("dbgset: bad argument count");
    const char *pkg = tok[2], *on = tok[3];
    if (strcmp(on, "1") != 0 && strcmp(on, "0") != 0) die("dbgset: bad flag");
    const char *rp = find_resetprop();
    if (on[0] == '1') {
        if (!valid_pkg(pkg)) die("dbgset: invalid package name");
        if (!rp) die("dbgset: resetprop not found");
        char cur[PROP_VALUE_MAX];
        get_prop("ro.debuggable", cur, sizeof cur);
        int ofd = open(DBG_ORIG, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (ofd >= 0) { dprintf(ofd, "%s\n", cur[0] ? cur : "0"); close(ofd); }
        if (strcmp(cur, "1") != 0 && set_debuggable("1") != 0) die("dbgset: could not set ro.debuggable");
        for (int i = 0; CMDLINE_FILES[i]; i++) {
            int fd = open(CMDLINE_FILES[i], O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
            if (fd < 0) die("dbgset: cannot write command-line file");
            dprintf(fd, "_ --ssl-key-log-file=/data/data/%s/cache/sharkdroid_tlskeys.log\n", pkg);
            fchmod(fd, 0644);
            close(fd);
        }
        return 0;
    }
    for (int i = 0; CMDLINE_FILES[i]; i++) unlink(CMDLINE_FILES[i]);
    char orig[16] = "";
    int fd = open(DBG_ORIG, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t r = read(fd, orig, sizeof orig - 1);
        close(fd);
        if (r > 0) { orig[r] = 0; char *nl = strchr(orig, '\n'); if (nl) *nl = 0; }
        unlink(DBG_ORIG);
        char cur[PROP_VALUE_MAX];
        get_prop("ro.debuggable", cur, sizeof cur);
        if ((strcmp(orig, "0") == 0 || strcmp(orig, "1") == 0) && strcmp(cur, orig) != 0)
            set_debuggable(orig);
    }
    return 0;
}

/* NSS key log labels, as written by Chromium's --ssl-key-log-file. */
static int is_nss_line(const char *l) {
    static const char *const L[] = {
        "CLIENT_RANDOM ", "CLIENT_HANDSHAKE_TRAFFIC_SECRET ", "SERVER_HANDSHAKE_TRAFFIC_SECRET ", "CLIENT_TRAFFIC_SECRET_0 ",
        "SERVER_TRAFFIC_SECRET_0 ", "EXPORTER_SECRET ", "EARLY_EXPORTER_SECRET ", "CLIENT_EARLY_TRAFFIC_SECRET ", NULL };
    for (int i = 0; L[i]; i++) if (strncmp(l, L[i], strlen(L[i])) == 0) return 1;
    return 0;
}

/* Follow the key file the injected script appends to inside the app's data directory and relay the
 * lines we know ("[TLSKEY] ..." and "[TLS] ..."); anything else the (untrusted) app wrote there is dropped. */
static int cmd_tlskeys(char **tok, int ntok) {
    if (ntok != 3) die("tlskeys: bad argument count");
    const char *pkg = tok[2];
    if (!valid_pkg(pkg)) die("tlskeys: invalid package name");
    char path[PATH_MAX];
    snprintf(path, sizeof path, "/data/data/%s/cache/sharkdroid_tlskeys.log", pkg);
    signal(SIGPIPE, SIG_IGN);
    dprintf(1, "[WAIT] %s\n", pkg);

    int fd = -1, attached = 0;
    ino_t cur_ino = 0;
    off_t pos = 0;
    static char line[1024];
    size_t ll = 0;
    for (;;) {
        struct stat st;
        if (stat(path, &st) != 0) {
            if (fd >= 0) { close(fd); fd = -1; }
        } else if (fd < 0 || st.st_ino != cur_ino || st.st_size < pos) {
            if (fd >= 0) close(fd);
            fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            cur_ino = st.st_ino; pos = 0; ll = 0;
        }
        if (fd >= 0) {
            char buf[4096];
            ssize_t r;
            while ((r = pread(fd, buf, sizeof buf, pos)) > 0) {
                pos += r;
                if (!attached) { dprintf(1, "[ATTACH] %s\n", pkg); attached = 1; }
                for (ssize_t i = 0; i < r; i++) {
                    char c = buf[i];
                    if (c == '\n') {
                        line[ll] = 0;
                        if (strncmp(line, "[TLSKEY] ", 9) == 0 || strncmp(line, "[TLS] ", 6) == 0) {
                            if (dprintf(1, "%s\n", line) < 0) return 0;
                        } else if (is_nss_line(line)) { /* raw key log written by Chromium itself */
                            if (dprintf(1, "[TLSKEY] %s\n", line) < 0) return 0;
                        }
                        ll = 0;
                    } else if (ll < sizeof line - 1) {
                        line[ll++] = c;
                    }
                }
            }
        }
        struct pollfd p = { .fd = 0, .events = POLLIN };
        int pr = poll(&p, 1, 250);
        if (pr > 0 && (p.revents & (POLLIN | POLLHUP))) {
            char c[64];
            ssize_t n = read(0, c, sizeof c);
            int q = (n <= 0);
            for (ssize_t k = 0; k < n; k++) if (c[k] == 'q') q = 1;
            if (q) return 0;
        }
    }
}

int main(void) {
    umask(077);
    /* Minimal, known environment for anything we exec as root. */
    clearenv();
    setenv("PATH", "/system/bin", 1);
    setenv("HOME", "/data/local/tmp", 1);

    ssize_t n = readlink("/proc/self/exe", self_dir, sizeof self_dir - 1);
    if (n <= 0) die("readlink /proc/self/exe failed");
    self_dir[n] = 0;
    char *slash = strrchr(self_dir, '/');
    if (!slash) die("bad self path");
    *slash = 0;
    snprintf(dumpcap_path, sizeof dumpcap_path, "%s/libdumpcap.so", self_dir);
    snprintf(script_path, sizeof script_path, "%s/libtlskeys.so", self_dir);

    /* Read request: "WSX1\0<cmd>\0<argc>\0<arg>\0..." (exactly argc args, which may be
     * empty strings). Read byte-wise so that we never consume the stop byte that may
     * follow the request. */
    static char req[MAX_REQ];
    size_t len = 0;
    char *tok[MAX_TOKENS];
    int ntok = 0, want = 3;
    size_t tok_start = 0;
    while (ntok < want) {
        if (len >= sizeof req) die("request too large");
        ssize_t r = read(0, &req[len], 1);
        if (r <= 0) die("unexpected EOF in request");
        len++;
        if (req[len - 1] != 0) continue;
        if (ntok >= MAX_TOKENS) die("too many tokens");
        tok[ntok++] = &req[tok_start];
        tok_start = len;
        if (ntok == 1 && strcmp(tok[0], "WSX1") != 0) die("bad request magic");
        if (ntok == 3) {
            const char *a = tok[2];
            if (strlen(a) != 1 || a[0] < '0' || a[0] > '8') die("bad argc");
            want = 3 + (a[0] - '0');
        }
    }
    /* Re-pack as: tok[0]=magic, tok[1]=cmd, tok[2..]=args (drop the argc token). */
    for (int k = 2; k + 1 < ntok; k++) tok[k] = tok[k + 1];
    ntok--;
    if (ntok < 2 || strcmp(tok[0], "WSX1") != 0) die("bad request magic");
    const char *cmd = tok[1];

    if (strcmp(cmd, "id") == 0) {
        char ctx[256] = "?";
        int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { ssize_t r = read(fd, ctx, sizeof ctx - 1); if (r > 0) ctx[r] = 0; else strcpy(ctx, "?"); close(fd); }
        for (char *p = ctx; *p; p++) if (*p == '\n' || *p == '\0') *p = 0;
        printf("uid=%d euid=%d ctx=%s\n", getuid(), geteuid(), ctx);
        return 0;
    }
    if (strcmp(cmd, "list") == 0) return cmd_list();
    if (strcmp(cmd, "pcaplist") == 0) {
        check_binary(dumpcap_path, "dumpcap");
        execl(dumpcap_path, dumpcap_path, "-D", (char *)NULL);
        perror("wsexec: execl dumpcap");
        return 127;
    }
    if (strcmp(cmd, "capture") == 0) return cmd_capture(tok, ntok);
    if (strcmp(cmd, "tlskeys") == 0) return cmd_tlskeys(tok, ntok);
    if (strcmp(cmd, "zfcheck") == 0) return cmd_zfcheck();
    if (strcmp(cmd, "zfprep") == 0) return cmd_zfprep(tok, ntok);
    if (strcmp(cmd, "zfconfig") == 0) return cmd_zfconfig();
    if (strcmp(cmd, "zfsetconfig") == 0) return cmd_zfsetconfig(tok, ntok);
    if (strcmp(cmd, "zfinstall") == 0) return cmd_zfinstall();
    if (strcmp(cmd, "zfrestart") == 0) return cmd_zfrestart(tok, ntok);
    if (strcmp(cmd, "dbgstate") == 0) return cmd_dbgstate();
    if (strcmp(cmd, "dbgset") == 0) return cmd_dbgset(tok, ntok);
    die("unknown command");
    return 2;
}
