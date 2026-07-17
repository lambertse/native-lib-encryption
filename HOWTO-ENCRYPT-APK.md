# How to build the encrypted APK yourself

Reproducible steps to turn `assets/app-release.apk` into `output/app-release.apk` with
`libapp.so` encrypted for all ABIs. Two setups: **A)** this aarch64 container (no root),
**B)** any machine with the normal Android SDK/NDK. Do the setup once, then run the
"Pack" step whenever you want.

---

## A. In THIS container (aarch64, no root) — already provisioned

The toolchain is already installed here (Python+LIEF, clang/lld, JDK, apksigner.jar).
Every shell, first export:

```bash
cd /workspace
export PATH="$HOME/miniforge3/bin:$PATH"
export SOPACK_APKSIGNER_JAR="$HOME/android-build-tools/android-14/lib/apksigner.jar"
```

If you ever start from a FRESH container, recreate the toolchain once (no root needed):

```bash
# 1) Python + LIEF + pytest
curl -fsSL -o /tmp/mf.sh \
  https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-aarch64.sh
bash /tmp/mf.sh -b -p "$HOME/miniforge3"
"$HOME/miniforge3/bin/pip" install lief pytest
# 2) LLVM (builds the freestanding stub blobs — no NDK needed) + JDK (runs apksigner)
"$HOME/miniforge3/bin/conda" install -y -c conda-forge clang lld llvm-tools openjdk
# 3) apksigner.jar (from Android build-tools; the jar is pure Java, runs on any arch)
curl -fsSL -o /tmp/bt.zip https://dl.google.com/android/repository/build-tools_r34-linux.zip
"$HOME/miniforge3/bin/python" -c "import zipfile;zipfile.ZipFile('/tmp/bt.zip').extractall('$HOME/android-build-tools')"
```

Then continue to **Build the stub blobs** below.

---

## B. On a normal machine with Android SDK + NDK

```bash
cd /path/to/this/repo
export ANDROID_NDK_HOME=/path/to/Android/sdk/ndk/<version>   # to build stubs
export ANDROID_SDK_ROOT=/path/to/Android/sdk                 # for apksigner/zipalign
python3 -m venv .venv && . .venv/bin/activate
pip install -e .        # installs the `sopack` command + LIEF
```

`apksigner`, `zipalign`, `keytool` must be reachable (SDK build-tools + a JDK).
`build_stubs.sh` uses the NDK when `ANDROID_NDK_HOME` is set, otherwise plain `clang`.

### Required versions

| Tool | Minimum | Notes |
|------|---------|-------|
| **NDK** | **r19+** (recommend r26–r28) | Must bundle `lld` — every NDK since r19 (2019) does. A real version looks like `27.0.12077973`; `4.8.0` is **not** a valid NDK and will fail. Install via Android Studio → SDK Manager → SDK Tools → NDK, or `sdkmanager "ndk;27.0.12077973"`. |
| **SDK build-tools** | **34.0.0+** | Provides `apksigner` (v2/v3 signing) and `zipalign` (`-P` for 16 KB). |
| **JDK** | **17+** (8 works) | For `keytool` and to run `apksigner`. |
| **Python** | **3.10+** | Runs the packer. |
| **LIEF** | **0.15+** | `pip install lief` (tested with 1.0). |

**Don't have/ want the NDK?** The stub is freestanding, so any modern LLVM works instead
(no Android sysroot needed). On macOS: `brew install llvm`, then
`export PATH="$(brew --prefix llvm)/bin:$PATH"` and leave `ANDROID_NDK_HOME` unset —
`build_stubs.sh` falls back to plain `clang`/`lld`/`llvm-objcopy`/`llvm-readelf`.

---

## Build the stub blobs (once)

Compiles the tiny per-ABI decryption stub into `sopack/stubs/*.bin`. It fails loudly if
any blob isn't self-contained (a safety check), so a clean run means good blobs.

```bash
bash stub/build_stubs.sh 24        # 24 = Android API level (any modern level is fine)
# -> sopack/stubs/stub_{arm64-v8a,armeabi-v7a,x86_64}.bin (+ .json)
```

Install the tool if you didn't already:

```bash
pip install -e .                   # gives you the `sopack` command
```

---

## Pack (the actual build)

```bash
mkdir -p output
sopack pack assets/app-release.apk \
    --lib libapp.so \
    -o output/app-release.apk \
    --abi arm64-v8a,armeabi-v7a,x86_64 \
    --cipher chacha20 \
    --log \
    --keystore "$HOME/.sopack/debug.keystore" \
    --verify
```

- `--lib libapp.so` — bare name matches `lib/<abi>/libapp.so` in every selected ABI.
  (Use `--libs libs.txt` with one entry per line for many libraries, or full paths like
  `lib/arm64-v8a/libapp.so` to target a single ABI.)
- `--abi` — omit to encrypt all three ABIs by default.
- `--log` — the stub prints a logcat confirmation on device (see below). Drop it for a
  silent stub.
- `--keystore` — auto-generated on first use (self-signed, pass `sopack`). Reuse the
  same file to keep a stable signing identity across rebuilds.
- Without `--keystore` it defaults to `~/.sopack/debug.keystore`.

Output: **`output/app-release.apk`**.

---

## Verify

**Static** — confirm `libapp.so` is encrypted and well-formed (needs `$PATH`/LLVM):

```bash
unzip -o output/app-release.apk lib/arm64-v8a/libapp.so -d /tmp/chk
llvm-readelf -x .text /tmp/chk/lib/arm64-v8a/libapp.so | head     # random bytes
llvm-readelf -lW /tmp/chk/lib/arm64-v8a/libapp.so | grep LOAD     # aligns multiples of 0x4000
llvm-readelf -dW /tmp/chk/lib/arm64-v8a/libapp.so | grep INIT     # DT_INIT present
java -jar "$SOPACK_APKSIGNER_JAR" verify --print-certs output/app-release.apk
```

**On device** — install and watch for the decrypt confirmation:

```bash
adb install -r output/app-release.apk
adb logcat -s sopack:I
# expect:  I sopack  : native .text decrypted OK
adb logcat | grep -i 'avc: denied'    # must stay empty (SELinux)
```

One `sopack` line appears per encrypted `libapp.so` that loads (normally the one for the
device's ABI). No line ⇒ decryption didn't run.

---

## Notes / gotchas

- **New signing identity.** Re-signing replaces the certificate, so the output is a new
  app: it can't be installed as an update over the Play/original build, and in-app
  signature checks will see the new cert. Uninstall the original first if needed.
- **16 KB pages.** Libraries are stored uncompressed and 16 KB-aligned automatically
  (Python aligner, or `zipalign` if present) — required for Android 15+ devices.
- **Rebuild stubs** only when you change anything under `stub/`. Packing itself doesn't
  need the NDK/LLVM once `sopack/stubs/*.bin` exist.
- **Run `build_stubs.sh` with bash**, e.g. `bash stub/build_stubs.sh 24` or
  `./stub/build_stubs.sh 24` — not `sh stub/build_stubs.sh` (it needs bash, though it
  now works with the old bash 3.2 that ships on macOS).
- **Security caveat.** This is obfuscation, not encryption-at-rest security: the key
  ships in the binary and plaintext exists in memory at runtime.
