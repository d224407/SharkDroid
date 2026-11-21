# SharkDroid

Wireshark for rooted Android (arm64, Android 10+). A Material 3 / Compose app that captures with `dumpcap` and dissects with the real `tshark` (Wireshark 4.6.9).

## Features

- Live capture on any interface (Wi-Fi, cellular, VPN, `any`) with BPF capture filters; foreground service with a Stop action
- Packet list with Wireshark display filters (validated by tshark), protocol tree, hex view, follow TCP/UDP stream
- Saved captures, open pcap/pcapng, export, share, statistics reports
- Stream live to desktop Wireshark over adb
- Optional TLS decryption for a target app (ZygiskFrida), HTTP object viewer, decrypted-stream export
- English and Simplified Chinese

## Requirements

- Root (Magisk, KernelSU or APatch); no SELinux changes needed
- Android 10 (API 29)+, arm64-v8a

## Build

JDK 17, Gradle 9.6.0, Android SDK 37, NDK r27c. The repo has no Gradle wrapper jar: `gradle wrapper --gradle-version 9.6.0`.

Native tools (tshark, dumpcap, root helper, JNI library) are cross-compiled from pinned upstream sources (`SOURCES.txt`, `patches/`, `stubs/`, `helper/`) into `app/src/main/jniLibs/arm64-v8a/`:

```bash
export NDK=/path/to/android-ndk-r27c
python3 scripts/prepare-sources.py
bash scripts/build-native.sh
gradle assembleRelease
```

Host needs GCC, Make, CMake, Ninja, Meson, pkg-config, Python 3.11.4+, patch, flex, bison. `JOBS` sets parallelism.

TLS add-on (optional): `addon/tlskeys.js` is installed as `libtlskeys.so`, and the ZygiskFrida module zip as `libzygiskfrida.so` (both done by CI). Without them the app builds and the add-on row shows as unavailable.

CI (`.github/workflows/android.yml`) does all of this with caching. Release builds are signed when the secrets `KEYSTORE_CONTENT`, `KEYSTORE_ALIAS` and `KEYSTORE_PASSWORD` exist.

Releases use [semantic-release](https://semantic-release.gitbook.io) on `main` with Conventional Commits: `fix:` → patch, `feat:` → minor, `feat!:` / `BREAKING CHANGE:` → major. The tag, release notes and signed APK are published automatically, and the app version is set from the tag.

Local signing: point `SHARKDROID_KEYSTORE_PROPS` (or `-PkeystoreProps=`) at a properties file with `storeFile`, `storePassword`, `keyAlias`, `keyPassword`; without it the release APK is unsigned.

## Live view in desktop Wireshark

```bash
adb exec-out "su -c '<app native library dir>/libdumpcap.so -i wlan0 -F pcapng -q -w -'" | wireshark -k -i -
```

The app's **Stream to desktop Wireshark** menu item shows the command with the real path. On Windows use cmd.exe (PowerShell corrupts binary pipes).

## Limits

- No monitor mode
- `rmnet_data*` (raw IP) untested on real cellular
- Encrypted TLS/QUIC content is visible only with the TLS add-on (TLS only, apps whose library exports the hooked symbols)
- Up to 1,000,000 rows listed; captures stop at 2 GiB
- arm64-v8a only

## Security

- Root is used only for dumpcap, through a fixed `su -c` path; interface and filter go over stdin and are validated by the helper
- tshark runs in an isolated, permission-less service, never as root
- Captures live in app-private storage; sharing uses a non-exported read-only provider
- INTERNET is used only by the manual update check

## License

GPL-2.0-or-later, see [LICENSE](LICENSE). Third-party notices are in the app's licenses screen.

"Wireshark" is a trademark of the Wireshark Foundation; SharkDroid is an independent port and is not affiliated with it.
